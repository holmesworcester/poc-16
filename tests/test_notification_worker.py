"""Operational retry and current-authority notification worker tests."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import Barrier, Lock

import facts
import pytest

from core.crypto import h, keypair
from core.fetch_budget import FetchBudgetExceeded
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.auth.signature import signature
from facts.content import message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.delivery import (
    PublicationHint,
    PushAccepted,
    PushRetryable,
    PushUnregistered,
    derive,
    derive_awaited,
    seal_target,
)
from notifications.worker import (
    ACK,
    RETRY,
    TERMINAL,
    NotificationWorker,
    WorkerResult,
    carrier_disposition,
)
from notifications.carrier import ACK as CARRIER_ACK
from notifications.carrier import RETRY as CARRIER_RETRY
from .util import compiled_repository


@dataclass
class ScriptedPush:
    outcomes: list

    def __post_init__(self):
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        outcome = self.outcomes.pop(0) if self.outcomes else \
            PushAccepted(f"message-{len(self.requests)}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _world(tmp_path, *, sealed_target=None):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    push_secret, push_node = keypair()
    endpoint = push_endpoint.register(
        node,
        workspace,
        h(b"installation"),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        sealed_target or seal_target(push_node, "firebase-installation-id"),
        ts=2,
    )
    return node, workspace, push_secret, push_node, endpoint


def _hint(node, workspace, event, root=None):
    return PublicationHint(
        workspace,
        root or _snapshot(node, workspace),
        (event,),
    )


def _snapshot(node, workspace):
    objects = getattr(node, "_notification_test_objects", None)
    if objects is None:
        objects = {}
        node._notification_test_objects = objects
    return compiled_repository(node, workspace, objects)[0]


def _fetch(node, workspace, oid):
    _snapshot(node, workspace)
    return node._notification_test_objects.get(oid)


def _worker(node, secret, provider, now=10, *, current_root=None):
    return NotificationWorker(
        current_root or (
            lambda workspace: _snapshot(node, workspace)),
        lambda workspace, oid: _fetch(node, workspace, oid),
        secret,
        provider,
        lambda: now,
    )


def _process(worker, hint):
    return asyncio.run(worker.process(hint))


def _event(node, workspace):
    preference.set_global(node, workspace, preference.ALL, ts=3)
    return message.post(node, workspace, "general", "hello", ts=4)


def test_worker_result_maps_to_carrier_disposition_fail_closed():
    assert carrier_disposition(WorkerResult(ACK)) is CARRIER_ACK
    assert carrier_disposition(WorkerResult(TERMINAL)) is CARRIER_ACK
    assert carrier_disposition(WorkerResult(RETRY)) is CARRIER_RETRY
    assert carrier_disposition("ack") is CARRIER_RETRY


def test_transient_fcm_failure_retries_until_acceptance(tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)
    provider = ScriptedPush([
        PushRetryable("quota"),
        PushAccepted("provider-accepted"),
    ])
    worker = _worker(node, secret, provider)

    first = _process(worker, hint)
    second = _process(worker, hint)

    assert first.action is RETRY
    assert [row.status for row in first.deliveries] == ["retry"]
    assert second.action is ACK
    assert [row.status for row in second.deliveries] == ["accepted"]
    assert second.deliveries[0].message_id == "provider-accepted"
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id


def test_async_root_fetch_clock_and_provider_use_the_same_worker(tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)
    calls = []

    async def current_root(selected):
        await asyncio.sleep(0)
        calls.append(("root", selected))
        return _snapshot(node, selected)

    async def fetch(selected, oid):
        await asyncio.sleep(0)
        calls.append(("fetch", selected, oid))
        return _fetch(node, selected, oid)

    async def now_ms():
        await asyncio.sleep(0)
        calls.append(("clock",))
        return 10

    class AsyncPush:
        def __init__(self):
            self.requests = []

        async def send(self, request):
            await asyncio.sleep(0)
            self.requests.append(request)
            calls.append(("push", request.delivery_id))
            return PushAccepted("async-accepted")

    provider = AsyncPush()
    worker = NotificationWorker(
        current_root, fetch, secret, provider, now_ms)

    result = _process(worker, hint)

    assert result.action is ACK
    assert result.deliveries[0].message_id == "async-accepted"
    assert len(provider.requests) == 1
    assert calls[0] == ("root", workspace)
    assert ("clock",) in calls
    assert any(call[0] == "fetch" for call in calls)
    assert calls[-1][0] == "push"


def test_partial_delivery_retries_hint_with_same_per_endpoint_ids(tmp_path):
    node, workspace, secret, push_node, _endpoint = _world(tmp_path)
    push_endpoint.register(
        node,
        workspace,
        h(b"second-installation"),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        seal_target(push_node, "second-firebase-installation"),
        ts=3,
    )
    preference.set_global(node, workspace, preference.ALL, ts=4)
    event = message.post(node, workspace, "general", "two", ts=5)
    hint = _hint(node, workspace, event)
    provider = ScriptedPush([
        PushAccepted("first-accepted"),
        PushRetryable("quota"),
    ])
    worker = _worker(node, secret, provider)

    first = _process(worker, hint)
    second = _process(worker, hint)

    assert first.action is RETRY
    assert sorted(row.status for row in first.deliveries) \
        == ["accepted", "retry"]
    assert second.action is ACK
    assert [row.status for row in second.deliveries] \
        == ["accepted", "accepted"]
    assert {request.delivery_id for request in provider.requests[:2]} \
        == {request.delivery_id for request in provider.requests[2:]}


def test_crash_after_fcm_acceptance_replays_same_idempotency_boundary(
        tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)
    provider = ScriptedPush([])
    worker = _worker(node, secret, provider)

    # The first ACK is deliberately "lost" before a carrier can record it.
    first = _process(worker, hint)
    second = _process(worker, hint)

    assert first.action is second.action is ACK
    assert len(provider.requests) == 2
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id
    assert provider.requests[0].payload == provider.requests[1].payload


def test_retry_after_endpoint_rotation_uses_new_fid_with_same_delivery_id(
        tmp_path):
    node, workspace, secret, push_node, endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)
    provider = ScriptedPush([])
    worker = _worker(node, secret, provider)

    first = _process(worker, hint)
    push_endpoint.replace(
        node,
        workspace,
        endpoint,
        push_node,
        seal_target(push_node, "rotated-firebase-installation-id"),
        ts=5,
    )
    second = _process(worker, hint)

    assert first.action is second.action is ACK
    assert [request.target for request in provider.requests] == [
        "firebase-installation-id",
        "rotated-firebase-installation-id",
    ]
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id


def test_overlapping_workers_submit_the_same_delivery_and_collapse_id(
        tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)
    root = _snapshot(node, workspace)

    class OverlappingPush:
        def __init__(self):
            self.barrier = Barrier(2)
            self.lock = Lock()
            self.requests = []

        def send(self, request):
            with self.lock:
                self.requests.append(request)
                ordinal = len(self.requests)
            self.barrier.wait(timeout=5)
            return PushAccepted(f"concurrent-{ordinal}")

    provider = OverlappingPush()
    workers = [
        _worker(
            node,
            secret,
            provider,
            current_root=lambda _workspace: root,
        )
        for _ in range(2)
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda worker: _process(worker, hint), workers))

    assert all(result.action is ACK for result in results)
    assert len(provider.requests) == 2
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id
    assert provider.requests[0].payload == provider.requests[1].payload


def test_delayed_retry_uses_current_mute_not_historical_allow(tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)
    preference.set_global(node, workspace, preference.NONE, ts=5)
    provider = ScriptedPush([])

    result = _process(_worker(node, secret, provider), hint)

    assert result.action is ACK
    assert result.deliveries == ()
    assert provider.requests == []


def test_delayed_retry_honors_current_event_suppression(tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)
    facts.content.delete.remove(node, workspace, event, ts=5)
    provider = ScriptedPush([])

    result = _process(_worker(node, secret, provider), hint)

    assert result.action is ACK
    assert result.deliveries == ()
    assert provider.requests == []


def test_invalid_sealed_endpoint_is_typed_terminal_delivery(tmp_path):
    invalid = push_endpoint.encode_sealed_target(b"x" * 49)
    node, workspace, secret, _push_node, _endpoint = _world(
        tmp_path, sealed_target=invalid)
    event = _event(node, workspace)
    provider = ScriptedPush([])

    result = _process(
        _worker(node, secret, provider),
        _hint(node, workspace, event),
    )

    assert result.action is ACK
    assert [row.status for row in result.deliveries] \
        == ["invalid-endpoint"]
    assert provider.requests == []


def test_unregistered_fid_is_typed_terminal_delivery(tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    provider = ScriptedPush([PushUnregistered("gone")])

    result = _process(
        _worker(node, secret, provider),
        _hint(node, workspace, event),
    )

    assert result.action is ACK
    assert [row.status for row in result.deliveries] == ["unregistered"]


def test_substituted_event_root_is_terminal_without_provider_call(tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    preference.set_global(node, workspace, preference.ALL, ts=3)
    before_event = _snapshot(node, workspace)
    event = message.post(node, workspace, "general", "later", ts=4)
    provider = ScriptedPush([])

    result = _process(
        _worker(node, secret, provider),
        _hint(node, workspace, event, before_event),
    )

    assert result.action is TERMINAL
    assert result.reason == "invalid-hint"
    assert provider.requests == []


def test_current_root_behind_event_retries_without_provider_call(tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    preference.set_global(node, workspace, preference.ALL, ts=3)
    before_event = _snapshot(node, workspace)
    event = message.post(node, workspace, "general", "later", ts=4)
    hint = _hint(node, workspace, event)
    provider = ScriptedPush([])

    result = _process(
        _worker(
            node,
            secret,
            provider,
            current_root=lambda _workspace: before_event,
        ),
        hint,
    )

    assert result.action is RETRY
    assert provider.requests == []


def test_concurrent_endpoint_cell_fails_closed_before_push_node_filter(
        tmp_path):
    node, workspace, secret, push_node, _endpoint = _world(tmp_path)
    installation = h(b"installation")
    _other_secret, other_push_node = keypair()
    duplicate = push_endpoint.push_endpoint(
        workspace,
        node.pk,
        node.pk,
        installation,
        other_push_node,
        "android",
        "poc16.mobile",
        "production",
        seal_target(other_push_node, "concurrent-firebase-installation"),
        3,
    )
    signed = signature(node.sk, node.pk, duplicate, 3)
    member = node.sql(workspace).resolve_offer(
        "member", node.pk, node.pk)
    device = node.sql(workspace).resolve_offer(
        "device_key", node.pk, node.pk)
    node.ingest_new(workspace, (signed, duplicate), {
        signed.fid: (),
        duplicate.fid: (signed.fid, member, device),
    })
    preference.set_global(node, workspace, preference.ALL, ts=4)
    event = message.post(node, workspace, "general", "ambiguous", ts=5)
    provider = ScriptedPush([])

    result = _process(
        _worker(node, secret, provider),
        _hint(node, workspace, event),
    )

    assert result.action is ACK
    assert result.deliveries == ()
    assert provider.requests == []


def test_ttl_is_fresh_for_acceptance_attempt_not_event_age(tmp_path):
    node, workspace, secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    provider = ScriptedPush([])
    now = 30 * 24 * 60 * 60 * 1000

    result = _process(
        _worker(node, secret, provider, now=now),
        _hint(node, workspace, event),
    )

    assert result.action is ACK
    request, = provider.requests
    assert request.expires_at_ms > now
    assert request.ttl_seconds == 7 * 24 * 60 * 60


def test_derivation_enforces_unique_object_fetch_budget(tmp_path):
    node, workspace, _secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)

    with pytest.raises(FetchBudgetExceeded):
        derive(
            hint,
            lambda oid: _fetch(node, workspace, oid),
            _snapshot(node, workspace),
            max_fetches=0,
        )


def test_async_fetch_limit_stops_before_one_over_provider_call(tmp_path):
    node, workspace, _secret, _push_node, _endpoint = _world(tmp_path)
    event = _event(node, workspace)
    hint = _hint(node, workspace, event)
    root = _snapshot(node, workspace)

    async def run(limit):
        calls = []

        async def fetch(oid):
            calls.append(oid)
            return _fetch(node, workspace, oid)

        result = await derive_awaited(
            hint, fetch, root, max_fetches=limit)
        return result, calls

    baseline, baseline_calls = asyncio.run(run(32_768))
    needed = len(baseline_calls)
    assert needed > 1

    exact, exact_calls = asyncio.run(run(needed))
    assert exact == baseline
    assert len(exact_calls) == needed

    one_over_calls = []

    async def one_over_fetch(oid):
        one_over_calls.append(oid)
        return _fetch(node, workspace, oid)

    with pytest.raises(FetchBudgetExceeded):
        asyncio.run(derive_awaited(
            hint,
            one_over_fetch,
            root,
            max_fetches=needed - 1,
        ))
    assert len(one_over_calls) == needed - 1
