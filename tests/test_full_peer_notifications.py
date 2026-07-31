"""FullPeer composition around the shared notification cursor and worker."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
import threading
import time

import facts
import pytest

from core.crypto import h, keypair
from core.object_store import Versioned
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.content import message
from facts.content import notification_preference as preference
from full_peer import cli, daemon
from full_peer.daemon import FullPeerService
from full_peer.node import FullPeer
from full_peer.notifications import FullPeerNotifications
from full_peer.sync import sync
from notifications.delivery import PushAccepted, PushRetryable, seal_target
from notifications.discovery import decode_cursor
from tests.util import all_fids, closed_subset, deliver


@dataclass
class ScriptedProvider:
    outcomes: list

    def __post_init__(self):
        self.requests = []
        self.lock = threading.Lock()

    def send(self, request):
        with self.lock:
            self.requests.append(request)
            outcome = self.outcomes.pop(0) if self.outcomes else \
                PushAccepted(f"accepted-{len(self.requests)}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _world(tmp_path, provider=None):
    node = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    push_secret, push_node = keypair()
    push_endpoint.register(
        node,
        workspace,
        h(b"installation"),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        seal_target(push_node, "firebase-installation-id"),
        ts=2,
    )
    preference.set_global(node, workspace, preference.ALL, ts=3)
    provider = provider or ScriptedProvider([])
    service = FullPeerNotifications(
        node, node.dir, push_secret, provider, cadence=.05)
    bootstrap = service.bootstrap(workspace, "current")
    assert bootstrap == {
        "base": h(node.reader(workspace).root_bytes),
        "mode": "current",
        "workspace": workspace,
    }
    baseline, = service.run_once()
    assert baseline.status == "idle"
    assert provider.requests == []
    return node, workspace, provider, service


def _wait(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError("timed out waiting for notification work")


def _cursor(service, workspace):
    current = service.state_store(workspace).read_versioned("root")
    assert isinstance(current, Versioned)
    return decode_cursor(current.value)


def test_workspace_requires_explicit_notification_bootstrap(tmp_path):
    node = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    secret, _public = keypair()
    provider = ScriptedProvider([])
    service = FullPeerNotifications(node, node.dir, secret, provider)

    result, = service.run_once()

    assert result.status == "retry"
    assert service.status()["workspaces"][workspace]["error"] \
        == "CursorNotInitialized"
    assert provider.requests == []


def test_transient_fcm_retry_preserves_cursor_and_restart_resumes(
        tmp_path):
    provider = ScriptedProvider([
        PushRetryable("transient"), PushAccepted("accepted")])
    node, workspace, provider, service = _world(
        tmp_path, provider)
    event = message.post(node, workspace, "general", "hello", ts=4)

    failed, = service.run_once()
    pinned = _cursor(service, workspace)
    assert failed.status == "retry"
    assert pinned.pending is not None

    restarted = FullPeerNotifications(
        node, node.dir, service.secret, provider, cadence=.05)
    accepted, = restarted.run_once()

    assert accepted.status == "republished"
    assert _cursor(restarted, workspace).target is None
    assert len(provider.requests) == 2
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id
    assert provider.requests[0].payload == provider.requests[1].payload
    assert event in provider.requests[1].payload.decode()

    idle, = FullPeerNotifications(
        node, node.dir, service.secret, provider).run_once()
    assert idle.status == "idle"
    assert len(provider.requests) == 2


def test_crash_after_fcm_acceptance_replays_stable_delivery(tmp_path):
    node, workspace, provider, service = _world(tmp_path)
    message.post(node, workspace, "general", "crash window", ts=4)
    state = service.state_store(workspace)
    real_cas = state.cas
    calls = 0

    def crash_on_progress(key, token, value):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("crash after FCM acceptance")
        return real_cas(key, token, value)

    state.cas = crash_on_progress
    crashed, = service.run_once()
    state.cas = real_cas
    replayed, = service.run_once()

    assert crashed.status == "retry"
    assert replayed.status == "republished"
    assert len(provider.requests) == 2
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id
    assert provider.requests[0].payload == provider.requests[1].payload


@pytest.mark.parametrize("authority_change", ("mute", "remove-member"))
def test_delayed_retry_uses_current_authority(
        tmp_path, authority_change):
    provider = ScriptedProvider([PushRetryable("transient")])
    node, workspace, provider, service = _world(
        tmp_path, provider)
    message.post(node, workspace, "general", "before change", ts=4)
    failed, = service.run_once()
    assert failed.status == "retry"
    assert len(provider.requests) == 1

    if authority_change == "mute":
        preference.set_global(
            node, workspace, preference.NONE, ts=5)
    else:
        facts.auth.removal.evict(node, workspace, node.pk)
    cancelled, = service.run_once()

    assert cancelled.status == "republished"
    assert len(provider.requests) == 1
    assert _cursor(service, workspace).target is None


def test_dropped_wake_is_recovered_by_cadence_and_shutdown_is_clean(
        tmp_path):
    node, workspace, provider, service = _world(tmp_path)
    before = service.status()["workspaces"][workspace]["ts"]
    service.start()
    try:
        _wait(lambda: service.status()["workspaces"][workspace]["ts"] \
              > before)
        assert service.status()["workspaces"][workspace]["status"] == "idle"
        # No kick follows this publication: cadence is the durable recovery
        # path when an advisory local wake is dropped.
        message.post(node, workspace, "general", "cadence", ts=4)
        _wait(lambda: len(provider.requests) == 1)
    finally:
        service.stop()
        service.join(2)

    assert not service.is_alive()


def test_concurrent_turns_use_cursor_cas_without_corruption(tmp_path):
    node, workspace, provider, service = _world(tmp_path)
    message.post(node, workspace, "general", "concurrent", ts=4)
    state = service.state_store(workspace)
    real_read = state.read_versioned
    barrier = threading.Barrier(2)
    read_count = 0
    read_lock = threading.Lock()

    def overlapping_read(key):
        nonlocal read_count
        value = real_read(key)
        with read_lock:
            read_count += 1
            ordinal = read_count
        if ordinal <= 2:
            barrier.wait(timeout=5)
        return value

    state.read_versioned = overlapping_read

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _unused: service.run_once(), range(2)))
    state.read_versioned = real_read

    statuses = sorted(turn[0].status for turn in results)
    assert statuses == ["published", "raced"]
    assert len(provider.requests) == 1
    assert _cursor(service, workspace).target is None
    assert service.run_once()[0].status == "idle"


@pytest.mark.parametrize("sql_state", ("absent", "stale", "corrupt"))
def test_notification_authority_never_consults_sql(
        tmp_path, monkeypatch, sql_state):
    node, workspace, provider, service = _world(tmp_path)
    message.post(node, workspace, "general", sql_state, ts=4)

    projection = node.sql(workspace)
    database_path = Path(node.dir) / "ws" / f"{workspace}.idx.db"
    if sql_state == "stale":
        projection.db.execute("DELETE FROM fact_index")
        projection.db.commit()
    else:
        projection.db.close()
        node._sql.pop(workspace)
        database_path.unlink()
        if sql_state == "corrupt":
            database_path.write_bytes(b"not a sqlite database")

    def forbidden(*_args, **_kwargs):
        raise AssertionError(f"{sql_state} SQL projection was consulted")

    monkeypatch.setattr(node, "sql", forbidden)
    monkeypatch.setattr(node, "idx", forbidden)
    monkeypatch.setattr(node, "_sync_sql", forbidden)

    result, = service.run_once()
    assert result.status == "published"
    assert len(provider.requests) == 1


def test_two_peers_sync_through_applier_then_shared_worker_delivers(
        tmp_path):
    host = FullPeerService(
        str(tmp_path / "host"), 0, cadence=3600, control_port=0)
    source = host.node
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    destination = FullPeer(
        str(tmp_path / "destination"),
        initial_secret=source.identity(workspace)[0],
    )
    destination.add_workspace(workspace, "replica", [])
    # Bootstrap the member's first closure through the receiving door so the
    # destination can mint its later HTTP sync grant.
    deliver(
        destination,
        workspace,
        closed_subset(source, workspace, all_fids(source, workspace)),
    )

    bind(source, workspace, "phone")
    push_secret, push_node = keypair()
    push_endpoint.register(
        source,
        workspace,
        h(b"synced-installation"),
        push_node,
        "apple",
        "poc16.mobile",
        "production",
        seal_target(push_node, "synced-firebase-installation"),
        ts=2,
    )
    preference.set_global(source, workspace, preference.ALL, ts=3)
    host.start()
    try:
        assert sync(destination, workspace, host.data_address) == (1, 0)
        provider = ScriptedProvider([])
        notifications = FullPeerNotifications(
            destination, destination.dir, push_secret, provider)
        notifications.bootstrap(workspace, "current")
        assert notifications.run_once()[0].status == "idle"

        event = message.post(
            source, workspace, "general", "replicated event", ts=4)
        assert sync(destination, workspace, host.data_address) == (1, 0)
    finally:
        host.close()

    assert destination.fact_of(workspace, event) == source.fact_of(
        workspace, event)
    delivered, = notifications.run_once()
    assert delivered.status == "published"
    assert len(provider.requests) == 1
    assert provider.requests[0].target == "synced-firebase-installation"


def test_daemon_notifications_are_default_off_and_lifecycle_is_owned(
        tmp_path):
    disabled = FullPeerService(
        str(tmp_path / "disabled"), 0, control_port=0)
    try:
        assert disabled.notifications is None
        assert not (tmp_path / "disabled" / "notification-state").exists()
    finally:
        disabled.close()

    secret, public = keypair()
    provider = ScriptedProvider([])
    enabled = FullPeerService(
        str(tmp_path / "enabled"),
        0,
        control_port=0,
        notification_enabled=True,
        notification_cadence=.05,
        notification_provider=provider,
        notification_secret=secret,
    )
    enabled.start()
    try:
        status = enabled.notifications.status()
        assert status["enabled"] is True
        assert status["push_node"] == public
        assert status["running"] is True
        assert secret.encode().hex() not in repr(status)
    finally:
        enabled.close()

    assert not enabled.notifications.is_alive()


def test_notification_scheduler_failure_never_fails_peer_service(tmp_path):
    secret, _public = keypair()
    service = FullPeerService(
        str(tmp_path / "peer"),
        0,
        cadence=3600,
        control_port=0,
        notification_enabled=True,
        notification_cadence=.1,
        notification_provider=ScriptedProvider([]),
        notification_secret=secret,
    )
    real_workspaces = service.node.workspaces
    first = True

    def fail_once():
        nonlocal first
        if first:
            first = False
            raise RuntimeError("notification-only failure")
        return real_workspaces()

    service.node.workspaces = fail_once
    service.start()
    try:
        _wait(lambda: service.notifications.status()["error"] \
              == "RuntimeError")
        _wait(lambda: service.notifications.status()["error"] == "")
        assert service.failure is None
        assert service.peer_thread.is_alive()
        assert service.notifications.is_alive()
    finally:
        service.close()


def test_hung_provider_cannot_block_peer_publication_or_fail_service(
        tmp_path):
    class BlockingProvider:
        def __init__(self):
            self.entered = threading.Event()
            self.release = threading.Event()

        def send(self, _request):
            self.entered.set()
            assert self.release.wait(5)
            return PushAccepted("eventually-accepted")

    secret, public = keypair()
    provider = BlockingProvider()
    service = FullPeerService(
        str(tmp_path / "peer"),
        0,
        cadence=3600,
        control_port=0,
        notification_enabled=True,
        notification_cadence=.05,
        notification_provider=provider,
        notification_secret=secret,
    )
    node = service.node
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    push_endpoint.register(
        node,
        workspace,
        h(b"blocked-installation"),
        public,
        "android",
        "poc16.mobile",
        "production",
        seal_target(public, "blocked-firebase-installation"),
        ts=2,
    )
    preference.set_global(node, workspace, preference.ALL, ts=3)
    message.post(node, workspace, "general", "blocks provider only", ts=4)
    service.notifications.bootstrap(workspace, "backfill")
    service.start()
    try:
        assert provider.entered.wait(5)
        before = node.reader(workspace).root_bytes
        later = message.post(
            node, workspace, "general", "publication stays live", ts=5)
        assert node.reader(workspace).root_bytes != before
        assert node.fact_of(workspace, later) is not None
        assert service.failure is None
        assert service.peer_thread.is_alive()
    finally:
        provider.release.set()
        service.close()


def test_cli_keeps_notifications_off_unless_experimental_gate_is_explicit(
        tmp_path, monkeypatch):
    calls = []

    def serve(*args, **kwargs):
        calls.append((args, kwargs))
        return "served"

    monkeypatch.setattr(daemon, "serve", serve)
    assert cli._serve([
        str(tmp_path / "disabled"), "--port", "0", "--control-port", "0",
    ]) == "served"
    assert calls[-1][1]["notification_enabled"] is False
    assert calls[-1][1]["notification_provider"] is None

    with pytest.raises(SystemExit):
        cli._serve([
            str(tmp_path / "invalid"),
            "--notification-application", "poc16.mobile",
        ])

    provider = ScriptedProvider([])
    import full_peer.notifications as notification_module
    monkeypatch.setattr(
        notification_module,
        "firebase_from_default_credentials",
        lambda application, environment: (
            calls.append((application, environment)) or provider),
    )
    assert cli._serve([
        str(tmp_path / "enabled"),
        "--port", "0",
        "--control-port", "0",
        "--enable-experimental-notifications",
        "--notification-application", "poc16.mobile",
        "--notification-environment", "production",
        "--notification-cadence", "15",
    ]) == "served"
    assert calls[-2] == ("poc16.mobile", "production")
    assert calls[-1][1]["notification_enabled"] is True
    assert calls[-1][1]["notification_cadence"] == 15
    assert calls[-1][1]["notification_provider"] is provider
