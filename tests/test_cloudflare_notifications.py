"""Cloudflare Queue/R2 notification deployment conformance."""
import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

import facts
from adapters.cloudflare.fcm_service import FcmServiceBinding
from adapters.cloudflare.notification_state import NotificationStateService
from adapters.cloudflare.queue import (
    CloudflareQueueCarrier,
    MAX_CLOUDFLARE_QUEUE_BODY_BYTES,
    delivery_from_message,
)
from adapters.r2.reader import R2ReadBindingStore
from core.crypto import h, keypair, load_sk
from core.limits import PayloadTooLarge
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.content import delete, message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.carrier import (
    MAX_CARRIER_BYTES,
    PublishOutcomeUnknown,
)
from notifications.delivery import (
    PushAccepted,
    PushInvalidEndpoint,
    PushRequest,
    PushRetryable,
    PushUnregistered,
    seal_target,
)
from notifications.hints import decode_hint
from notifications.discovery import (
    CursorNotInitialized,
    PENDING_CURRENT,
    PENDING_NONCURRENT,
)
from deploy.notification_launch import launch_record
from deploy.cloudflare_notifications import consumer, manage, reader, scanner


SOFTWARE_DIGEST = "d" * 64
RELEASE_ID = "f" * 64
WORKER_VERSIONS = {
    "reader": "11111111-1111-4111-8111-111111111111",
    "scanner": "22222222-2222-4222-8222-222222222222",
    "consumer": "33333333-3333-4333-8333-333333333333",
    "fcm": "44444444-4444-4444-8444-444444444444",
}


def _release(role, *, identity="e" * 64, enabled=True):
    return {
        "enabled": enabled,
        "format": "poc16-cloudflare-notification-runtime-v1",
        "identity": identity,
        "release_id": RELEASE_ID,
        "role": role,
        "software_digest": SOFTWARE_DIGEST,
    }


def run(awaitable):
    return asyncio.run(awaitable)


class R2Object:
    def __init__(self, key, value, etag):
        self.key, self.value, self.etag = key, value, etag
        self.size = len(value)
        self.awaited = False

    async def arrayBuffer(self):
        await asyncio.sleep(0)
        self.awaited = True
        return self.value


class R2Bucket:
    """Actually-awaited R2 fake with opaque conditional tokens."""

    def __init__(self):
        self.data, self.etags, self.calls = {}, {}, []
        self.generation = 0

    def _etag(self):
        self.generation += 1
        return f"opaque-{self.generation}"

    def seed(self, key, value):
        self.data[key] = value
        self.etags[key] = self._etag()

    async def get(self, key):
        await asyncio.sleep(0)
        self.calls.append(("get", key))
        if key not in self.data:
            return None
        return R2Object(key, self.data[key], self.etags[key])

    async def head(self, key):
        await asyncio.sleep(0)
        self.calls.append(("head", key))
        if key not in self.data:
            return None
        return R2Object(key, b"", self.etags[key])

    async def put(self, key, value, **options):
        await asyncio.sleep(0)
        self.calls.append(("put", key))
        condition = options.get("onlyIf")
        if isinstance(condition, dict) \
                and condition.get("If-None-Match") == "*" \
                and key in self.data:
            return None
        if isinstance(condition, dict) and "etagMatches" in condition \
                and self.etags.get(key) != condition["etagMatches"]:
            return None
        self.seed(key, bytes(value))
        return R2Object(key, b"", self.etags[key])

    async def delete(self, key):
        raise AssertionError("notification deployment may not delete R2")

    async def list(self, **options):
        await asyncio.sleep(0)
        prefix = options.get("prefix", "")
        limit = options.get("limit", 1000)
        start = int(options.get("cursor", "0"))
        keys = sorted(key for key in self.data if key.startswith(prefix))
        selected = keys[start:start + limit]
        end = start + len(selected)
        return SimpleNamespace(
            objects=[SimpleNamespace(key=key) for key in selected],
            truncated=end < len(keys),
            cursor=str(end) if end < len(keys) else None,
        )


class Queue:
    def __init__(self, *, fail=False, barrier=None):
        self.bodies, self.calls = [], 0
        self.fail, self.barrier = fail, barrier

    async def send(self, body, **options):
        await asyncio.sleep(0)
        self.calls += 1
        assert options == {"contentType": "text"}
        self.bodies.append(body)
        if self.barrier is not None:
            await self.barrier.wait()
        if self.fail:
            raise TimeoutError("lost Queue response")
        return {"metadata": {"metrics": {}}}


class QueueMessage:
    def __init__(self, body, identifier="queue-message", attempts=1):
        self.body, self.id, self.attempts = body, identifier, attempts
        self.action, self.delay = None, None

    def ack(self):
        assert self.action is None
        self.action = "ack"

    def retry(self, **options):
        assert self.action is None
        self.action = "retry"
        self.delay = options.get("delaySeconds")


class FcmService:
    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or [])
        self.documents = []

    async def release(self):
        return _release("notification-fcm-boundary")

    async def send(self, document, caller_release):
        await asyncio.sleep(0)
        assert caller_release == _release("notification-consumer")
        self.documents.append(document)
        outcome = self.outcomes.pop(0) if self.outcomes else {
            "status": "accepted", "message_id": "fcm-accepted"}
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FailCompleteOnce:
    def __init__(self, service, *, after=False):
        self.service, self.after, self.failed = service, after, False

    async def get_bounded(self, key, maximum):
        return await self.service.get_bounded(key, maximum)

    async def pending(self, body_oid):
        return await self.service.pending(body_oid)

    async def complete(self, body_oid):
        if not self.failed:
            self.failed = True
            if self.after:
                await self.service.complete(body_oid)
            raise TimeoutError("lost notification-state completion response")
        return await self.service.complete(body_oid)

    async def release(self):
        return await self.service.release()


class BarrierStateService:
    def __init__(self, service, parties=2):
        self.service = service
        self.barrier = asyncio.Barrier(parties)

    async def get_bounded(self, key, maximum):
        return await self.service.get_bounded(key, maximum)

    async def pending(self, body_oid):
        status = await self.service.pending(body_oid)
        await self.barrier.wait()
        return status

    async def complete(self, body_oid):
        return await self.service.complete(body_oid)

    async def release(self):
        return await self.service.release()


class PausingComplete:
    def __init__(self, service):
        self.service = service
        self.entered, self.resume = asyncio.Event(), asyncio.Event()

    async def get_bounded(self, key, maximum):
        return await self.service.get_bounded(key, maximum)

    async def pending(self, body_oid):
        return await self.service.pending(body_oid)

    async def complete(self, body_oid):
        self.entered.set()
        await self.resume.wait()
        return await self.service.complete(body_oid)

    async def release(self):
        return await self.service.release()


def _request():
    return PushRequest(
        "poc16.mobile", "production", "android", "installation-fid",
        b"payload", "a" * 64, 1_000_000, 60, "message")


def test_queue_carrier_awaits_exact_text_acceptance_and_bounds():
    queue = Queue()
    carrier = CloudflareQueueCarrier(queue)
    exact = b"x" * MAX_CLOUDFLARE_QUEUE_BODY_BYTES

    accepted = run(carrier.publish(exact))

    assert accepted.message_id == h(exact)
    assert queue.bodies == [exact.decode("ascii")]
    with pytest.raises(ValueError, match="Cloudflare Queue body"):
        run(carrier.publish(exact + b"x"))
    with pytest.raises(ValueError, match="carrier body"):
        run(carrier.publish(b"x" * (MAX_CARRIER_BYTES + 1)))


def test_lost_queue_publish_response_never_proves_acceptance():
    queue = Queue(fail=True)

    with pytest.raises(PublishOutcomeUnknown):
        run(CloudflareQueueCarrier(queue).publish(b"{}"))

    assert queue.bodies == ["{}"]


def test_queue_message_translation_rejects_non_exact_provider_envelopes():
    good = QueueMessage("{}", "provider-id", 2)
    assert delivery_from_message(good).body == b"{}"
    assert delivery_from_message(QueueMessage(b"{}")) is None
    assert delivery_from_message(QueueMessage("é")) is None
    assert delivery_from_message(QueueMessage(
        "x" * (MAX_CLOUDFLARE_QUEUE_BODY_BYTES + 1))) is None


def test_fcm_service_binding_is_awaited_and_uses_fid_not_token():
    service = FcmService()

    accepted = run(FcmServiceBinding(
        service, _release("notification-consumer")).send(_request()))

    assert accepted == PushAccepted("fcm-accepted")
    document, = service.documents
    assert document["fid"] == "installation-fid"
    assert "token" not in document
    assert document["format"] == "poc16-fcm-service-v1"


def test_notification_state_service_rejects_untyped_rpc_results():
    class Malformed:
        async def get_bounded(self, _key, _maximum):
            return None

        async def pending(self, _body_oid):
            return "probably-current"

        async def complete(self, _body_oid):
            return "done"

    state = NotificationStateService(Malformed(), "a" * 64)
    with pytest.raises(ValueError, match="pending response"):
        run(state.pending("b" * 64))
    with pytest.raises(ValueError, match="completion response"):
        run(state.complete("b" * 64))


@pytest.mark.parametrize("response,error", [
    ({"status": "unregistered"}, PushUnregistered),
    ({"status": "invalid-endpoint"}, PushInvalidEndpoint),
    ({"status": "retry"}, PushRetryable),
    ({"status": "accepted", "message_id": ""}, PushRetryable),
    ({"unknown": True}, PushRetryable),
])
def test_fcm_boundary_classifies_only_exact_endpoint_failures_terminal(
        response, error):
    with pytest.raises(error):
        run(FcmServiceBinding(
            FcmService([response]),
            _release("notification-consumer")).send(_request()))


def test_javascript_fcm_boundary_conformance_suite():
    source = Path(__file__).parents[1] / "deploy" \
        / "cloudflare_notifications" / "fcm_bridge" / "core.test.mjs"
    subprocess.run(
        ["node", "--test", str(source)], check=True,
        capture_output=True, text=True, timeout=30)


def _world(tmp_path):
    node = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    push_secret, push_node = keypair()
    push_endpoint.register(
        node, workspace, h(b"installation"), push_node,
        "android", "poc16.mobile", "production",
        seal_target(push_node, "firebase-installation-id"), ts=2)
    preference.set_global(node, workspace, preference.ALL, ts=3)
    return node, workspace, push_secret


def _copy_repository(node, workspace, bucket, prefix):
    store = node.store(workspace)
    for key in store.list(""):
        if key.startswith(("heads/", "obj/")):
            bucket.seed(f"{prefix}/{key}", store.get(key))


class CanonicalReadService:
    def __init__(self, workspace, bucket, identity="e" * 64, enabled="1"):
        self.env = SimpleNamespace(
            POC16_DEPLOYMENT_ROLE="notification-canonical-reader",
            POC16_DEPLOYMENT_IDENTITY=identity,
            POC16_SOFTWARE_DIGEST=SOFTWARE_DIGEST,
            POC16_RELEASE_ID=RELEASE_ID,
            NOTIFICATIONS_ENABLED=enabled,
            WORKSPACE=workspace,
            CANONICAL_PREFIX=f"workspaces/{workspace}",
            CANONICAL=bucket,
        )

    async def get_bounded(self, key, maximum):
        return await reader.get_bounded(self.env, key, maximum)

    async def read_versioned(self, key, maximum):
        return await reader.read_versioned(self.env, key, maximum)

    async def list_page(self, prefix, cursor=None, limit=256):
        return await reader.list_page(self.env, prefix, cursor, limit)

    async def release(self):
        return reader.release_state(self.env)


class StateService:
    def __init__(self, scanner_env):
        self.env = scanner_env

    async def get_bounded(self, key, maximum):
        return await scanner.get_state_bounded(self.env, key, maximum)

    async def pending(self, body_oid):
        return await scanner.pending(self.env, body_oid)

    async def complete(self, body_oid):
        return await scanner.complete(self.env, body_oid)

    async def release(self):
        return scanner.release_state(self.env)


def _scanner_env(
        workspace, canonical_reader, state, queue, *, enabled="1",
        identity="e" * 64, bootstrap="none"):
    return SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="notification-scanner",
        POC16_DEPLOYMENT_IDENTITY=identity,
        POC16_SOFTWARE_DIGEST=SOFTWARE_DIGEST,
        POC16_RELEASE_ID=RELEASE_ID,
        NOTIFICATIONS_ENABLED=enabled,
        NOTIFICATION_BOOTSTRAP_MODE=bootstrap,
        WORKSPACE=workspace,
        NOTIFICATION_STATE_PREFIX=f"notifications/v1/{workspace}",
        CANONICAL_READER=canonical_reader,
        NOTIFICATION_STATE=state,
        NOTIFICATION_QUEUE=queue,
    )


def _consumer_env(
        workspace, canonical_reader, state_service, secret, fcm, *,
        enabled="1", identity="e" * 64):
    return SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="notification-consumer",
        POC16_DEPLOYMENT_IDENTITY=identity,
        POC16_SOFTWARE_DIGEST=SOFTWARE_DIGEST,
        POC16_RELEASE_ID=RELEASE_ID,
        NOTIFICATIONS_ENABLED=enabled,
        WORKSPACE=workspace,
        PUSH_NODE_SECRET=secret.encode().hex(),
        PUSH_NODE=secret.verify_key.encode().hex(),
        CANONICAL_READER=canonical_reader,
        NOTIFICATION_STATE_SERVICE=state_service,
        FCM_BOUNDARY=fcm,
    )


async def _scan_idle(env, maximum=100):
    statuses = []
    for _ in range(maximum):
        status = await scanner.scan(env)
        statuses.append(status)
        if status == "idle":
            return statuses
    raise AssertionError("Cloudflare scanner did not become idle")


async def _bootstrap(env, mode):
    env.NOTIFICATION_BOOTSTRAP_MODE = mode
    try:
        return await scanner.scan(env)
    finally:
        env.NOTIFICATION_BOOTSTRAP_MODE = "none"


def _published_world(tmp_path):
    node, workspace, secret = _world(tmp_path)
    event = message.post(node, workspace, "general", "hello", ts=4)
    canonical, state, queue = R2Bucket(), R2Bucket(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    canonical_reader = CanonicalReadService(workspace, canonical)
    scan_env = _scanner_env(workspace, canonical_reader, state, queue)
    assert run(_bootstrap(scan_env, "backfill")) == "bootstrapped-backfill"
    assert run(scanner.scan(scan_env)) == "published"
    assert len(queue.bodies) == 1
    assert decode_hint(queue.bodies[0].encode()).facts == (event,)
    return (
        node, workspace, secret, event, canonical, state, queue,
        canonical_reader, StateService(scan_env))


def test_actual_r2_scanner_and_queue_consumer_share_one_awaited_path(
        tmp_path):
    (_node, workspace, secret, _event, canonical, state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    fcm = FcmService()
    item = QueueMessage(queue.bodies[0])

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=[item])))

    assert item.action == "ack"
    assert len(fcm.documents) == 1
    assert fcm.documents[0]["fid"] == "firebase-installation-id"
    assert any(call[0] == "get" for call in canonical.calls)
    assert any(call[0] == "get" for call in state.calls)
    assert run(state_service.pending(h(queue.bodies[0].encode()))) \
        == PENDING_NONCURRENT


def test_expired_queue_wake_is_recreated_from_r2_pending(tmp_path):
    (_node, _workspace, _secret, _event, _canonical, _state, queue,
     _canonical_reader, state_service) = _published_world(tmp_path)
    exact, = queue.bodies
    queue.bodies.clear()  # model Queue expiry or a completely dropped wake

    assert run(scanner.scan(state_service.env)) == "republished"

    assert queue.bodies == [exact]


def test_replacement_queue_republishes_and_completes_one_durable_cursor(
        tmp_path):
    node, workspace, secret = _world(tmp_path)
    message.post(node, workspace, "general", "fail over", ts=4)
    canonical, state = R2Bucket(), R2Bucket()
    old_queue, replacement_queue = Queue(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    canonical_reader = CanonicalReadService(workspace, canonical)
    old_env = _scanner_env(
        workspace, canonical_reader, state, old_queue)
    assert run(_bootstrap(old_env, "backfill")) == "bootstrapped-backfill"
    assert run(scanner.scan(old_env)) == "published"
    exact, = old_queue.bodies

    # The durable pending body belongs to semantic delivery authority, not to
    # the Queue that first carried it. A replacement transport can recover it.
    replacement_env = _scanner_env(
        workspace, canonical_reader, state, replacement_queue)
    assert run(scanner.scan(replacement_env)) == "republished"
    assert replacement_queue.bodies == [exact]

    state_service = StateService(replacement_env)
    fcm = FcmService()
    item = QueueMessage(exact, "replacement-queue")
    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=[item])))

    assert item.action == "ack"
    assert len(fcm.documents) == 1
    assert run(state_service.pending(h(exact.encode()))) == PENDING_NONCURRENT


def test_missing_pending_event_fact_retries_without_send(
        tmp_path):
    (_node, workspace, secret, _event, _canonical, state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    reference = decode_hint(queue.bodies[0].encode())
    key = f"notifications/v1/{workspace}/obj/{reference.events[0].oid}"
    state.data.pop(key)
    state.etags.pop(key)
    fcm = FcmService()
    body, = queue.bodies
    item = QueueMessage(body, "missing-historical-fact")

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=[item])))

    assert item.action == "retry"
    assert fcm.documents == []
    assert run(state_service.pending(h(body.encode()))) == PENDING_CURRENT


def test_crash_after_fcm_acceptance_retries_before_cursor_progress(
        tmp_path):
    (_node, workspace, secret, _event, _canonical, _state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    body, fcm = queue.bodies[0], FcmService()
    first = QueueMessage(body, "crash-before-complete")

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader,
            FailCompleteOnce(state_service), secret, fcm),
        SimpleNamespace(messages=[first])))

    assert first.action == "retry"
    assert len(fcm.documents) == 1
    assert run(state_service.pending(h(body.encode()))) == PENDING_CURRENT

    second = QueueMessage(body, "retry-after-crash", 2)
    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=[second])))

    assert second.action == "ack"
    assert len(fcm.documents) == 2
    assert run(state_service.pending(h(body.encode()))) \
        == PENDING_NONCURRENT


def test_lost_completion_response_reconciles_without_another_fcm_send(
        tmp_path):
    (_node, workspace, secret, _event, _canonical, _state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    body, fcm = queue.bodies[0], FcmService()
    first = QueueMessage(body, "lost-completion-response")

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader,
            FailCompleteOnce(state_service, after=True), secret, fcm),
        SimpleNamespace(messages=[first])))
    assert first.action == "retry"
    assert len(fcm.documents) == 1

    second = QueueMessage(body, "completion-redelivery", 2)
    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=[second])))

    assert second.action == "ack"
    assert len(fcm.documents) == 1


def test_concurrent_queue_workers_may_duplicate_but_complete_once(tmp_path):
    (_node, workspace, secret, _event, _canonical, _state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    body, fcm = queue.bodies[0], FcmService()
    barrier = BarrierStateService(state_service)
    items = (
        QueueMessage(body, "concurrent-a"),
        QueueMessage(body, "concurrent-b"),
    )

    async def race():
        await asyncio.gather(*(
            consumer.consume(
                _consumer_env(
                    workspace, canonical_reader, barrier, secret, fcm),
                SimpleNamespace(messages=[item]))
            for item in items))

    run(race())

    assert [item.action for item in items] == ["ack", "ack"]
    assert len(fcm.documents) == 2
    assert run(state_service.pending(h(body.encode()))) \
        == PENDING_NONCURRENT


def test_invalid_endpoint_is_terminal_cursor_progress(tmp_path):
    (_node, workspace, secret, _event, _canonical, _state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    fcm = FcmService([{"status": "invalid-endpoint"}])
    item = QueueMessage(queue.bodies[0], "invalid-endpoint")

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=[item])))

    assert item.action == "ack"
    assert len(fcm.documents) == 1
    assert run(state_service.pending(h(queue.bodies[0].encode()))) \
        == PENDING_NONCURRENT


@pytest.mark.parametrize("mutate", [
    lambda node, workspace, event: preference.set_global(
        node, workspace, preference.NONE, ts=5),
    lambda node, workspace, event: delete.remove(
        node, workspace, event, ts=5),
])
def test_delayed_cloudflare_work_uses_current_mute_or_suppression(
        tmp_path, mutate):
    (node, workspace, secret, event, canonical, state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    mutate(node, workspace, event)
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    fcm, item = FcmService(), QueueMessage(queue.bodies[0])

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=[item])))

    assert item.action == "ack"
    assert fcm.documents == []


def test_dropped_schedule_wake_only_delays_the_next_writer_diff(tmp_path):
    node, workspace, _secret = _world(tmp_path)
    canonical, state, queue = R2Bucket(), R2Bucket(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    env = _scanner_env(
        workspace, CanonicalReadService(workspace, canonical), state, queue)
    assert run(_bootstrap(env, "current")) == "bootstrapped-current"
    run(_scan_idle(env))
    queue.bodies.clear()

    event = message.post(node, workspace, "general", "after-wake", ts=10)
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    # No queue effect occurs while both the optional wake and one schedule
    # are absent.  The next ordinary schedule resumes from durable state.
    assert queue.bodies == []
    assert run(scanner.scan(env)) == "published"

    assert decode_hint(queue.bodies[0].encode()).facts == (event,)


def test_sealed_scanner_requires_explicit_bootstrap_and_detects_state_loss(
        tmp_path):
    node, workspace, _secret = _world(tmp_path)
    old = message.post(node, workspace, "general", "old", ts=4)
    canonical, state, queue = R2Bucket(), R2Bucket(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    env = _scanner_env(
        workspace, CanonicalReadService(workspace, canonical), state, queue)

    with pytest.raises(CursorNotInitialized):
        run(scanner.scan(env))
    assert run(_bootstrap(env, "current")) == "bootstrapped-current"
    assert run(scanner.scan(env)) == "idle"
    assert queue.bodies == []

    new = message.post(node, workspace, "general", "new", ts=5)
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    assert run(scanner.scan(env)) == "published"
    assert decode_hint(queue.bodies[0].encode()).facts == (new,)
    assert old not in decode_hint(queue.bodies[0].encode()).facts

    state.data.pop(f"notifications/v1/{workspace}/root")
    state.etags.pop(f"notifications/v1/{workspace}/root")
    with pytest.raises(CursorNotInitialized):
        run(scanner.scan(env))


def test_disabled_scanner_runs_only_explicit_bootstrap(tmp_path):
    node, workspace, _secret = _world(tmp_path)
    canonical, state, queue = R2Bucket(), R2Bucket(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    env = _scanner_env(
        workspace, CanonicalReadService(
            workspace, canonical, enabled="0"), state, queue,
        enabled="0")

    assert run(scanner.scan(env)) == "disabled"
    assert run(_bootstrap(env, "current")) == "bootstrapped-current"
    assert run(scanner.scan(env)) == "disabled"
    assert queue.bodies == []


def test_bootstrap_generation_blocks_paused_muted_worker_aba(tmp_path):
    (node, workspace, secret, _event, canonical, state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    initial = queue.bodies[0]
    assert run(state_service.complete(h(initial.encode()))) \
        == PENDING_NONCURRENT
    preference.set_global(node, workspace, preference.NONE, ts=5)
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    root_key = f"notifications/v1/{workspace}/root"
    state.data.pop(root_key)
    state.etags.pop(root_key)
    queue.bodies.clear()
    assert run(_bootstrap(state_service.env, "backfill")) \
        == "bootstrapped-backfill"
    assert run(scanner.scan(state_service.env)) == "published"
    old_body, = queue.bodies
    paused, fcm = PausingComplete(state_service), FcmService()
    old_item = QueueMessage(old_body, "old-muted")

    async def scenario():
        old_task = asyncio.create_task(consumer.consume(
            _consumer_env(
                workspace, canonical_reader, paused, secret, fcm),
            SimpleNamespace(messages=[old_item])))
        await paused.entered.wait()
        assert fcm.documents == []

        state.data.pop(root_key)
        state.etags.pop(root_key)
        queue.bodies.clear()
        assert await _bootstrap(state_service.env, "backfill") \
            == "bootstrapped-backfill"
        assert await scanner.scan(state_service.env) == "published"
        new_body, = queue.bodies
        old_hint, new_hint = map(
            lambda body: decode_hint(body.encode()),
            (old_body, new_body))
        assert old_hint.head == new_hint.head
        assert old_hint.facts == new_hint.facts
        assert old_hint.generation != new_hint.generation
        assert h(old_body.encode()) != h(new_body.encode())

        await asyncio.to_thread(
            preference.set_global,
            node, workspace, preference.ALL, ts=6)
        await asyncio.to_thread(
            _copy_repository,
            node, workspace, canonical, f"workspaces/{workspace}")
        paused.resume.set()
        await old_task
        assert old_item.action == "ack"
        assert await state_service.pending(h(new_body.encode())) \
            == PENDING_CURRENT

        new_item = QueueMessage(new_body, "new-unmuted")
        await consumer.consume(
            _consumer_env(
                workspace, canonical_reader, state_service, secret, fcm),
            SimpleNamespace(messages=[new_item]))
        assert new_item.action == "ack"

    run(scenario())
    assert len(fcm.documents) == 1


def test_concurrent_cloudflare_scanners_republish_one_pending_body(
        tmp_path):
    node, workspace, _secret = _world(tmp_path)
    canonical, state, queue = R2Bucket(), R2Bucket(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    env = _scanner_env(
        workspace, CanonicalReadService(workspace, canonical), state, queue)
    run(_bootstrap(env, "current"))
    run(_scan_idle(env))
    queue.bodies.clear()
    message.post(node, workspace, "general", "race", ts=10)
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    # Persist pending state but lose Queue acceptance. Both later invocations
    # can only republish that one exact durable body.
    queue.fail = True
    with pytest.raises(PublishOutcomeUnknown):
        run(scanner.scan(env))
    queue.fail = False
    queue.bodies.clear()
    queue.barrier = asyncio.Barrier(2)

    async def race():
        return await asyncio.gather(scanner.scan(env), scanner.scan(env))

    statuses = run(race())

    assert statuses == ["republished", "republished"]
    assert len(queue.bodies) == 2
    assert queue.bodies[0] == queue.bodies[1]


def test_different_deployments_cannot_steal_one_shared_cursor(tmp_path):
    node, workspace, _secret = _world(tmp_path)
    canonical, state = R2Bucket(), R2Bucket()
    queue_a, queue_b = Queue(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    reader_service = CanonicalReadService(
        workspace, canonical, identity="a" * 64)
    first = _scanner_env(
        workspace, reader_service, state, queue_a, identity="a" * 64)
    foreign = _scanner_env(
        workspace, reader_service, state, queue_b, identity="b" * 64)

    run(_bootstrap(first, "current"))
    run(_scan_idle(first))

    with pytest.raises(ValueError, match="release skew"):
        run(scanner.scan(foreign))
    assert any(key.endswith("/root") for key in state.data)
    assert queue_b.bodies == []


def test_consumer_acknowledges_poison_and_retries_only_retryable_work(
        tmp_path):
    (_node, workspace, secret, _event, canonical, state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    service = FcmService([
        {"status": "retry"},
        {"status": "accepted", "message_id": "accepted"},
    ])
    poison = QueueMessage({"not": "text"}, "poison", 25)
    retry = QueueMessage(queue.bodies[0], "retry", 24)
    accepted = QueueMessage(queue.bodies[0], "accepted", 1)

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, service),
        SimpleNamespace(messages=[poison, retry, accepted])))

    assert poison.action == "ack"
    assert retry.action == "retry"
    assert retry.delay == consumer.RETRY_DELAY_SECONDS
    assert accepted.action == "ack"


def test_consumer_bounds_hostile_batches_before_any_delivery(tmp_path):
    (_node, workspace, secret, _event, canonical, state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)
    messages = [
        QueueMessage(queue.bodies[0], f"m-{number}")
        for number in range(consumer.MAX_BATCH_SIZE + 1)
    ]
    fcm = FcmService()

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=messages)))

    assert {item.action for item in messages} == {"retry"}
    assert fcm.documents == []


def test_partial_release_retries_before_any_fcm_or_cursor_effect(tmp_path):
    (_node, workspace, secret, _event, _canonical, _state, queue,
     canonical_reader, state_service) = _published_world(tmp_path)

    class SkewedFcm(FcmService):
        async def release(self):
            return {
                **_release("notification-fcm-boundary"),
                "release_id": "0" * 64,
            }

    fcm = SkewedFcm()
    item = QueueMessage(queue.bodies[0])

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_service, secret, fcm),
        SimpleNamespace(messages=[item])))

    assert item.action == "retry"
    assert fcm.documents == []
    assert run(state_service.pending(
        h(queue.bodies[0].encode()))) == PENDING_CURRENT


def test_scanner_release_skew_precedes_state_or_queue_access(tmp_path):
    node, workspace, _secret = _world(tmp_path)
    canonical, state, queue = R2Bucket(), R2Bucket(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    canonical_reader = CanonicalReadService(workspace, canonical)
    env = _scanner_env(workspace, canonical_reader, state, queue)
    env.POC16_RELEASE_ID = "0" * 64

    with pytest.raises(ValueError, match="release skew"):
        run(scanner.scan(env))
    assert state.calls == []
    assert queue.calls == 0


def test_consumer_rejects_a_push_secret_rebound_under_old_config():
    secret, _public = keypair()
    canonical = SimpleNamespace(
        get_bounded=lambda *args: None,
        read_versioned=lambda *args: None,
    )
    state = SimpleNamespace(
        get_bounded=lambda *args: None,
        pending=lambda *args: None,
        complete=lambda *args: None,
    )
    env = _consumer_env(
        "a" * 64, canonical, state, secret, FcmService())
    env.PUSH_NODE = "f" * 64

    with pytest.raises(ValueError, match="does not match PUSH_NODE"):
        consumer.Settings.from_env(env)


def _manage_environment(**extra):
    return {
        "CLOUDFLARE_ACCOUNT_ID": "c" * 32,
        "CF_WORKSPACE": "a" * 64,
        "CF_DEPLOYMENT_OWNER": "production-owner",
        "CF_CANONICAL_BUCKET": "canonical",
        "CF_NOTIFICATION_STATE_BUCKET": "notification-state",
        "CF_FIREBASE_APPLICATION": "poc16.mobile",
        "CF_FIREBASE_ENVIRONMENT": "production",
        "CF_FIREBASE_PROJECT_ID": "firebase-project",
        "CF_PUSH_NODE_PUBLIC": load_sk("b" * 64).verify_key.encode().hex(),
        **extra,
    }


def _launch_binding(environment, software_digest=SOFTWARE_DIGEST):
    disabled = {
        **environment,
        "CF_NOTIFICATIONS_ENABLED": "0",
        "CF_NOTIFICATION_TEST_MODE": "0",
    }
    reader_config, scanner_config, consumer_config, fcm_config = \
        manage.generated_configs(
            disabled, software_digest=software_digest,
            release_id=RELEASE_ID)
    return manage._mobile_launch_binding((
        reader_config, scanner_config, consumer_config, fcm_config),
        WORKER_VERSIONS)


def _with_launch_records(
        tmp_path, environment, *, platforms=("ios", "android"),
        software_digest=SOFTWARE_DIGEST):
    environment = dict(environment)
    binding = _launch_binding(environment, software_digest)
    for platform in platforms:
        path = tmp_path / f"{platform}.json"
        path.write_bytes(launch_record(platform, binding))
        environment[f"CF_{platform.upper()}_LAUNCH_RECORD"] = str(path)
    return environment


def test_generated_deployment_is_disabled_and_effectless_by_default():
    reader_config, scanner_config, consumer_config, fcm_config = \
        manage.generated_configs(_manage_environment())

    assert scanner_config["triggers"]["crons"] == []
    assert scanner_config["vars"]["NOTIFICATION_BOOTSTRAP_MODE"] == "none"
    assert consumer_config["queues"]["consumers"] == []
    assert scanner_config["vars"]["NOTIFICATIONS_ENABLED"] == "0"
    assert consumer_config["vars"]["NOTIFICATIONS_ENABLED"] == "0"
    assert fcm_config["workers_dev"] is False
    assert fcm_config["routes"] == []
    assert fcm_config["version_metadata"] == {
        "binding": "CF_VERSION_METADATA"}


@pytest.mark.parametrize("mode", ["current", "backfill"])
def test_explicit_bootstrap_mode_stays_inert_until_trigger_activation(mode):
    ordinary = manage.generated_configs(_manage_environment())
    reader_config, scanner_config, consumer_config, fcm_config = \
        manage.generated_configs(
            _manage_environment(), bootstrap_mode=mode)

    assert scanner_config["vars"]["NOTIFICATION_BOOTSTRAP_MODE"] == mode
    assert scanner_config["triggers"]["crons"] == []
    assert consumer_config["queues"]["consumers"] == []
    assert scanner_config["vars"]["POC16_DEPLOYMENT_IDENTITY"] \
        == ordinary[1]["vars"]["POC16_DEPLOYMENT_IDENTITY"]
    assert reader_config == ordinary[0]
    assert consumer_config == ordinary[2]
    assert fcm_config == ordinary[3]


def test_unknown_bootstrap_mode_is_rejected():
    with pytest.raises(ValueError, match="bootstrap mode"):
        manage.generated_configs(
            _manage_environment(), bootstrap_mode="automatic")


def test_launch_gate_keeps_version_agnostic_effects_detached(tmp_path):
    environment = _with_launch_records(
        tmp_path, _manage_environment(CF_NOTIFICATIONS_ENABLED="1"))
    (_reader_config, scanner_config, consumer_config, _fcm_config) = \
        manage.generated_configs(
            environment, software_digest=SOFTWARE_DIGEST,
            release_id=RELEASE_ID, worker_versions=WORKER_VERSIONS)

    assert scanner_config["triggers"]["crons"] == []
    assert consumer_config["queues"]["consumers"] == []


def test_provision_uses_free_plan_queue_retention(monkeypatch):
    configs = manage.generated_configs(_manage_environment())
    calls = []
    monkeypatch.setenv("CF_CREATE", "1")
    monkeypatch.setattr(manage, "generated_configs", lambda: configs)
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *arguments, **options: calls.append(arguments))

    manage.provision()

    assert len(calls) == 2
    assert all(call[-2:] == (
        "--message-retention-period-secs", "86400") for call in calls)


def test_enable_is_rejected_without_real_mobile_launch_records():
    with pytest.raises(RuntimeError, match="ios.*required"):
        manage.generated_configs(
            _manage_environment(
                CF_NOTIFICATIONS_ENABLED="1",
                CF_MOBILE_LAUNCH_GATE="1"),
            software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
            worker_versions=WORKER_VERSIONS)


def test_enable_requires_both_mobile_platforms(tmp_path):
    environment = _with_launch_records(
        tmp_path, _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        platforms=("ios",))

    with pytest.raises(RuntimeError, match="android.*required"):
        manage.generated_configs(
            environment, software_digest=SOFTWARE_DIGEST,
            release_id=RELEASE_ID, worker_versions=WORKER_VERSIONS)


@pytest.mark.parametrize("change", [
    {"CF_FIREBASE_PROJECT_ID": "firebase-other"},
    {"CF_NOTIFICATION_QUEUE": "notification-other"},
    {"CF_PUSH_NODE_PUBLIC": "f" * 64},
])
def test_launch_records_are_bound_to_the_exact_deployment(
        tmp_path, change):
    environment = _with_launch_records(
        tmp_path, _manage_environment(CF_NOTIFICATIONS_ENABLED="1"))
    environment.update(change)

    with pytest.raises(RuntimeError, match="invalid ios"):
        manage.generated_configs(
            environment, software_digest=SOFTWARE_DIGEST,
            release_id=RELEASE_ID, worker_versions=WORKER_VERSIONS)


def test_launch_records_for_old_software_cannot_enable_new_code(tmp_path):
    environment = _with_launch_records(
        tmp_path, _manage_environment(CF_NOTIFICATIONS_ENABLED="1"))

    with pytest.raises(RuntimeError, match="invalid ios"):
        manage.generated_configs(
            environment, software_digest="e" * 64,
            release_id=RELEASE_ID, worker_versions=WORKER_VERSIONS)


def test_launch_records_for_another_provider_version_cannot_enable(
        tmp_path):
    environment = _with_launch_records(
        tmp_path, _manage_environment(CF_NOTIFICATIONS_ENABLED="1"))
    changed = {**WORKER_VERSIONS,
               "fcm": "55555555-5555-4555-8555-555555555555"}

    with pytest.raises(RuntimeError, match="invalid ios"):
        manage.generated_configs(
            environment, software_digest=SOFTWARE_DIGEST,
            release_id=RELEASE_ID, worker_versions=changed)


def test_nonproduction_test_enablement_does_not_claim_mobile_launch_gate():
    _reader, scanner_config, consumer_config, _fcm = \
        manage.generated_configs(_manage_environment(
            CF_FIREBASE_ENVIRONMENT="staging",
            CF_FIREBASE_TEST_PROJECT_ID="firebase-project",
            CF_NOTIFICATIONS_ENABLED="1",
            CF_NOTIFICATION_TEST_MODE="1"))

    assert scanner_config["triggers"]["crons"] == []
    assert consumer_config["queues"]["consumers"] == []
    assert consumer_config["vars"]["NOTIFICATION_TEST_MODE"] == "1"


def test_test_mode_cannot_enable_a_production_firebase_environment():
    with pytest.raises(ValueError, match="non-production"):
        manage.generated_configs(_manage_environment(
            CF_NOTIFICATIONS_ENABLED="1",
            CF_NOTIFICATION_TEST_MODE="1"))


def test_test_mode_binds_the_exact_service_account_project():
    with pytest.raises(ValueError, match="exact allowed Firebase test"):
        manage.generated_configs(_manage_environment(
            CF_FIREBASE_ENVIRONMENT="staging",
            CF_FIREBASE_TEST_PROJECT_ID="different-project",
            CF_NOTIFICATIONS_ENABLED="1",
            CF_NOTIFICATION_TEST_MODE="1"))


def test_launch_binding_command_describes_disabled_staged_release(
        monkeypatch, capsys, tmp_path):
    environment = _manage_environment(CF_NOTIFICATIONS_ENABLED="1")
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_load_release", lambda: {
        "deployment_identity": _launch_binding(environment)[
            "deployment_identity"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    })

    manage.print_launch_binding()

    assert json.loads(capsys.readouterr().out) == _launch_binding(
        environment, SOFTWARE_DIGEST)


def test_firebase_secret_must_match_the_bound_project():
    secret = json.dumps({
        "project_id": "firebase-other",
        "client_email": "worker@example.test",
        "private_key": "private-key",
    })
    with pytest.raises(ValueError, match="bound project"):
        manage._firebase_secret(
            "firebase-project", {"FIREBASE_SERVICE_ACCOUNT_JSON": secret})


def test_same_project_firebase_credential_rotation_is_availability_only():
    for email, private_key in (
            ("old@example.test", "old-private-key"),
            ("new@example.test", "new-private-key")):
        raw = json.dumps({
            "project_id": "firebase-project",
            "client_email": email,
            "private_key": private_key,
        })
        assert manage._firebase_secret(
            "firebase-project", {"FIREBASE_SERVICE_ACCOUNT_JSON": raw}) \
            == raw


@pytest.mark.parametrize("bucket,prefix", [
    ("canonical", "workspaces/" + "a" * 64 + "/obj/"),
    ("notification-state", "notifications/v1/" + "a" * 64),
])
def test_notification_history_and_cursor_are_required_not_to_expire(
        monkeypatch, bucket, prefix):
    reader_config, scanner_config, _consumer, _fcm = \
        manage.generated_configs(_manage_environment())

    def api(_method, suffix, document=None, environment=None):
        selected = suffix.split("/r2/buckets/", 1)[1].split("/", 1)[0]
        return {"rules": ([{
            "id": "unsafe-deletion",
            "enabled": True,
            "conditions": {"prefix": prefix},
            "deleteObjectsTransition": {
                "condition": {"type": "Age", "maxAge": 999999}},
        }] if selected == bucket else [])}

    monkeypatch.setattr(manage, "_api", api)
    with pytest.raises(RuntimeError, match="must never expire"):
        manage._require_retained_notification_objects(
            reader_config, scanner_config, {})


def test_non_deleting_or_disjoint_r2_lifecycle_rules_are_safe(monkeypatch):
    reader_config, scanner_config, _consumer, _fcm = \
        manage.generated_configs(_manage_environment())
    rules = {"rules": [
        {
            "id": "multipart-only",
            "enabled": True,
            "conditions": {"prefix": ""},
            "abortMultipartUploadsTransition": {
                "condition": {"type": "Age", "maxAge": 604800}},
        },
        {
            "id": "unrelated-delete",
            "enabled": True,
            "conditions": {"prefix": "temporary/"},
            "deleteObjectsTransition": {
                "condition": {"type": "Age", "maxAge": 604800}},
        },
        {
            "id": "synchronous-infrequent-access",
            "enabled": True,
            "conditions": {"prefix": ""},
            "storageClassTransitions": [{
                "condition": {"type": "Age", "maxAge": 604800},
                "storageClass": "InfrequentAccess",
            }],
        },
    ]}
    monkeypatch.setattr(manage, "_api", lambda *args, **kwargs: rules)

    manage._require_retained_notification_objects(
        reader_config, scanner_config, {})


@pytest.mark.parametrize("bucket,prefix", [
    ("canonical", "workspaces/" + "a" * 64),
    ("notification-state", "notifications/v1/" + "a" * 64),
])
def test_unknown_async_restore_class_is_rejected_for_both_r2_prefixes(
        monkeypatch, bucket, prefix):
    reader_config, scanner_config, _consumer, _fcm = \
        manage.generated_configs(_manage_environment())

    def api(_method, suffix, document=None, environment=None):
        selected = suffix.split("/r2/buckets/", 1)[1].split("/", 1)[0]
        return {"rules": ([{
            "id": "future-async-archive",
            "enabled": True,
            "conditions": {"prefix": prefix},
            "storageClassTransitions": [{
                "condition": {"type": "Age", "maxAge": 604800},
                "storageClass": "Glacier",
            }],
        }] if selected == bucket else [])}

    monkeypatch.setattr(manage, "_api", api)
    with pytest.raises(RuntimeError, match="synchronously readable"):
        manage._require_retained_notification_objects(
            reader_config, scanner_config, {})


def test_r2_reader_checks_the_actual_body_after_provider_metadata():
    bucket = R2Bucket()

    async def malicious_get(_key):
        return R2Object("root", b"too large", "opaque")

    bucket.get = malicious_get
    with pytest.raises(PayloadTooLarge):
        run(R2ReadBindingStore(bucket).get_bounded("root", 3))


def test_binding_inventory_segregates_effects_and_has_no_applier():
    reader_config, scanner_config, consumer_config, fcm_config = \
        manage.generated_configs(_manage_environment())

    assert {row["binding"] for row in reader_config["r2_buckets"]} \
        == {"CANONICAL"}
    assert {row["binding"] for row in scanner_config["r2_buckets"]} \
        == {"NOTIFICATION_STATE"}
    assert scanner_config["queues"].keys() == {"producers"}
    assert consumer_config["queues"].keys() == {"consumers"}
    assert "r2_buckets" not in consumer_config
    assert "r2_buckets" not in fcm_config
    assert "services" not in fcm_config
    identity = scanner_config["vars"]["POC16_DEPLOYMENT_IDENTITY"]
    assert len(identity) == 64
    assert {
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"]
        for config in (
            reader_config, scanner_config, consumer_config, fcm_config)
    } == {identity}
    assert fcm_config["vars"] == {
        "POC16_DEPLOYMENT_IDENTITY": identity,
        "POC16_DEPLOYMENT_OWNER": "production-owner",
        "POC16_DEPLOYMENT_ROLE": "notification-fcm-boundary",
        "POC16_SOFTWARE_DIGEST": "0" * 64,
        "POC16_RELEASE_ID": "0" * 64,
        "POC16_CLOUDFLARE_ACCOUNT_ID": "c" * 32,
        "NOTIFICATIONS_ENABLED": "0",
        "NOTIFICATION_TEST_MODE": "0",
        "FCM_APPLICATION": "poc16.mobile",
        "FCM_ENVIRONMENT": "production",
        "FCM_PROJECT_ID": "firebase-project",
    }
    assert fcm_config["main"].startswith("build/release/")
    assert fcm_config["main"].endswith("/fcm_bridge/worker.js")
    assert consumer_config["services"] == [
        {
            "binding": "CANONICAL_READER",
            "service": "poc16-notify-read-aaaaaaaaaaaa",
        },
        {
            "binding": "NOTIFICATION_STATE_SERVICE",
            "service": "poc16-notify-scan-aaaaaaaaaaaa",
        },
        {"binding": "FCM_BOUNDARY", "service": "poc16-fcm-boundary"},
    ]
    assert "repository_applier.py" not in manage.CORE_MODULES
    assert "writer_repository.py" in manage.WRITER_CONSUMER_CORE_MODULES
    assert "writer_repository.py" not in manage.CORE_MODULES
    assert "full_peer" not in scanner.__file__


def test_staged_writer_consumer_core_stays_out_of_reader_role(
        tmp_path, monkeypatch):
    build = tmp_path / "build"
    vendored = tmp_path / "python_modules"
    vendored.mkdir()
    monkeypatch.setattr(manage, "BUILD", build)
    monkeypatch.setattr(manage, "VENDORED", vendored)
    monkeypatch.setattr(manage, "patch_pynacl", lambda _path: None)

    manage.stage()

    assert not (build / "reader/core/writer_repository.py").exists()
    for role in ("scanner", "consumer"):
        assert (build / role / "core/writer_repository.py").is_file()
        assert (build / role / "notifications/forest.py").is_file()
    for forbidden in (
            "repository_applier.py", "repository_reader.py",
            "repository_snapshot.py"):
        assert not any(build.rglob(forbidden))
    for role in ("reader", "scanner", "consumer"):
        subprocess.run(
            [sys.executable, "-c", f"import {role}"],
            cwd=build / role,
            env={**os.environ, "PYTHONPATH": str(build / role)},
            check=True,
            capture_output=True,
            text=True,
        )


def test_generated_builds_lock_the_exact_prepared_software():
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)

    assert {
        config["vars"]["POC16_SOFTWARE_DIGEST"] for config in configs
    } == {SOFTWARE_DIGEST}
    assert {
        config["build"]["command"] for config in configs[:3]
    } == {f"python manage.py stage-locked {SOFTWARE_DIGEST}"}


def test_locked_stage_refuses_changed_deploy_inputs(monkeypatch):
    calls = []
    monkeypatch.setattr(manage, "stage", lambda: calls.append("stage"))
    monkeypatch.setattr(manage, "_software_digest", lambda: "e" * 64)

    with pytest.raises(RuntimeError, match="deploy inputs changed"):
        manage._stage_locked(SOFTWARE_DIGEST)
    assert calls == ["stage"]


def _lock_actor(tmp_path):
    path = tmp_path / "cloudflare_lock_actor.py"
    path.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "import sys\n"
        "import time\n"
        "from deploy.cloudflare_notifications import manage\n"
        "build = Path(sys.argv[1])\n"
        "action = sys.argv[2]\n"
        "marker = Path(sys.argv[3])\n"
        "release = Path(sys.argv[4]) if len(sys.argv) > 4 else None\n"
        "manage.BUILD = build\n"
        "manage.STAGE_LOCK = build / '.operation.lock'\n"
        "if action == 'hold':\n"
        "    with manage._worktree_operation_lock():\n"
        "        marker.write_text(os.environ[manage.STAGE_OWNER_ENV])\n"
        "        while not release.exists(): time.sleep(0.01)\n"
        "elif action == 'try':\n"
        "    with manage._worktree_operation_lock(): marker.write_text('mutated')\n"
        "elif action == 'stage-locked':\n"
        "    manage._stage_locked = lambda digest: marker.write_text(digest)\n"
        "    raise SystemExit(manage.main(['manage.py', 'stage-locked', 'd' * 64]))\n"
        "elif action == 'nested-parent':\n"
        "    with manage._worktree_operation_lock():\n"
        "        manage._run([sys.executable, __file__, str(build),\n"
        "                     'stage-locked', str(marker)])\n"
        "elif action == 'orphan-parent':\n"
        "    with manage._worktree_operation_lock():\n"
        "        manage._run([sys.executable, __file__, str(build),\n"
        "                     'wait', str(marker), str(release)])\n"
        "elif action == 'wait':\n"
        "    marker.write_text(str(os.getpid()))\n"
        "    while not release.exists(): time.sleep(0.01)\n")
    return path


def _actor_environment():
    environment = dict(os.environ)
    repository = str(Path(__file__).resolve().parents[1])
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = repository + (
        os.pathsep + existing if existing else "")
    environment.pop(manage.STAGE_OWNER_ENV, None)
    return environment


def _wait_for_path(path, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def test_unrelated_process_cannot_enter_staging_or_fake_owner(tmp_path):
    actor = _lock_actor(tmp_path)
    build = tmp_path / "build"
    ready, release = tmp_path / "ready", tmp_path / "release"
    mutated = tmp_path / "mutated"
    holder = subprocess.Popen([
        sys.executable, str(actor), str(build), "hold", str(ready),
        str(release)], cwd=Path(__file__).resolve().parents[1],
        env=_actor_environment())
    try:
        _wait_for_path(ready)
        stale_owner = ready.read_text()
        for claimed_owner in (None, "0" * 64):
            environment = _actor_environment()
            if claimed_owner is not None:
                environment[manage.STAGE_OWNER_ENV] = claimed_owner
            attempt = subprocess.run([
                sys.executable, str(actor), str(build), "try",
                str(mutated)], cwd=Path(__file__).resolve().parents[1],
                env=environment, capture_output=True, text=True)
            assert attempt.returncode != 0
            assert "another Cloudflare notification operation" \
                in attempt.stderr
            assert not mutated.exists()
    finally:
        release.write_text("release")
        holder.wait(timeout=5)

    ready2, release2 = tmp_path / "ready-2", tmp_path / "release-2"
    holder2 = subprocess.Popen([
        sys.executable, str(actor), str(build), "hold", str(ready2),
        str(release2)], cwd=Path(__file__).resolve().parents[1],
        env=_actor_environment())
    try:
        _wait_for_path(ready2)
        assert ready2.read_text() != stale_owner
        environment = _actor_environment()
        environment[manage.STAGE_OWNER_ENV] = stale_owner
        attempt = subprocess.run([
            sys.executable, str(actor), str(build), "try", str(mutated)],
            cwd=Path(__file__).resolve().parents[1], env=environment,
            capture_output=True, text=True)
        assert attempt.returncode != 0
        assert not mutated.exists()
    finally:
        release2.write_text("release")
        holder2.wait(timeout=5)


def test_main_fences_every_staging_command_before_its_function(tmp_path,
                                                               monkeypatch):
    actor = _lock_actor(tmp_path)
    build = tmp_path / "build"
    ready, release = tmp_path / "ready", tmp_path / "release"
    holder = subprocess.Popen([
        sys.executable, str(actor), str(build), "hold", str(ready),
        str(release)], cwd=Path(__file__).resolve().parents[1],
        env=_actor_environment())
    calls = []
    functions = {
        "sync": "sync",
        "stage": "stage",
        "build": "build",
        "prepare-launch": "prepare_launch",
        "stage-launch-fcm": "stage_launch_fcm",
        "deploy-launch-harness": "deploy_launch_harness",
        "remove-launch-harness": "remove_launch_harness",
        "launch-binding": "print_launch_binding",
        "deploy": "deploy",
        "disable": "disable",
        "bootstrap-current": "bootstrap_current",
        "bootstrap-backfill": "bootstrap_backfill",
        "seal-bootstrap": "seal_bootstrap",
        "verify": "verify",
        "remove": "remove",
        "provision": "provision",
        "redrive": "redrive",
    }
    for command, name in functions.items():
        monkeypatch.setattr(
            manage, name, lambda selected=command: calls.append(selected))
    monkeypatch.setattr(manage, "BUILD", build)
    monkeypatch.setattr(manage, "STAGE_LOCK", build / ".operation.lock")
    monkeypatch.delenv(manage.STAGE_OWNER_ENV, raising=False)
    try:
        _wait_for_path(ready)
        for command in set(functions) - {"provision", "redrive"}:
            with pytest.raises(RuntimeError, match="another Cloudflare"):
                manage.main(["manage.py", command])
        assert calls == []

        assert manage.main(["manage.py", "provision"]) == 0
        assert manage.main(["manage.py", "redrive"]) == 0
        assert calls == ["provision", "redrive"]
    finally:
        release.write_text("release")
        holder.wait(timeout=5)


def test_descendant_stage_locked_reuses_only_the_inherited_owner(tmp_path):
    actor = _lock_actor(tmp_path)
    marker = tmp_path / "nested-stage"
    result = subprocess.run([
        sys.executable, str(actor), str(tmp_path / "build"),
        "nested-parent", str(marker)],
        cwd=Path(__file__).resolve().parents[1], env=_actor_environment(),
        capture_output=True, text=True, timeout=5)

    assert result.returncode == 0, result.stderr
    assert marker.read_text() == SOFTWARE_DIGEST


def test_crashed_owner_releases_lock_and_stale_file_is_harmless(tmp_path):
    actor = _lock_actor(tmp_path)
    build = tmp_path / "build"
    ready, release = tmp_path / "ready", tmp_path / "never-release"
    holder = subprocess.Popen([
        sys.executable, str(actor), str(build), "hold", str(ready),
        str(release)], cwd=Path(__file__).resolve().parents[1],
        env=_actor_environment())
    _wait_for_path(ready)
    holder.kill()
    holder.wait(timeout=5)
    assert (build / ".operation.lock").exists()

    marker = tmp_path / "after-crash"
    attempt = subprocess.run([
        sys.executable, str(actor), str(build), "try", str(marker)],
        cwd=Path(__file__).resolve().parents[1], env=_actor_environment(),
        capture_output=True, text=True, timeout=5)

    assert attempt.returncode == 0, attempt.stderr
    assert marker.read_text() == "mutated"


def test_orphan_wrangler_keeps_lock_until_its_provider_call_exits(tmp_path):
    actor = _lock_actor(tmp_path)
    build = tmp_path / "build"
    child_ready, release = tmp_path / "child-ready", tmp_path / "release"
    parent = subprocess.Popen([
        sys.executable, str(actor), str(build), "orphan-parent",
        str(child_ready), str(release)],
        cwd=Path(__file__).resolve().parents[1], env=_actor_environment())
    try:
        _wait_for_path(child_ready)
        parent.kill()
        parent.wait(timeout=5)
        blocked = subprocess.run([
            sys.executable, str(actor), str(build), "try",
            str(tmp_path / "too-early")],
            cwd=Path(__file__).resolve().parents[1],
            env=_actor_environment(), capture_output=True, text=True,
            timeout=5)
        assert blocked.returncode != 0
        assert not (tmp_path / "too-early").exists()

        release.write_text("release")
        deadline = time.monotonic() + 5
        while True:
            marker = tmp_path / "after-child"
            acquired = subprocess.run([
                sys.executable, str(actor), str(build), "try", str(marker)],
                cwd=Path(__file__).resolve().parents[1],
                env=_actor_environment(), capture_output=True, text=True,
                timeout=5)
            if acquired.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise AssertionError(acquired.stderr)
            time.sleep(0.01)
        assert marker.read_text() == "mutated"
    finally:
        release.write_text("release")
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)


def test_release_manifest_is_canonical_exact_and_never_clobbered(tmp_path):
    path = tmp_path / "release.json"
    environment = {manage.RELEASE_MANIFEST_ENV: str(path)}
    document = {
        "deployment_identity": "a" * 64,
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }

    manage._write_release(document, environment)

    assert manage._load_release(environment) == document
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(RuntimeError, match="already exists"):
        manage._write_release(document, environment)
    path.write_text(json.dumps(document, indent=2))
    with pytest.raises(RuntimeError, match="non-canonical"):
        manage._load_release(environment)


def test_release_manifest_never_deletes_another_writer_staging_file(tmp_path):
    path = tmp_path / "release.json"
    pending = tmp_path / "release.json.pending"
    pending.write_bytes(b"another writer")
    document = {
        "deployment_identity": "a" * 64,
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }

    with pytest.raises(RuntimeError, match="staging file already exists"):
        manage._write_release(
            document, {manage.RELEASE_MANIFEST_ENV: str(path)})

    assert pending.read_bytes() == b"another writer"
    assert not path.exists()


def test_release_manifest_publication_does_not_clobber_a_racing_writer(
        tmp_path, monkeypatch):
    path = tmp_path / "release.json"
    original_link = manage.os.link
    document = {
        "deployment_identity": "a" * 64,
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }

    def racing_link(source, destination):
        path.write_bytes(b"other complete manifest")
        return original_link(source, destination)

    monkeypatch.setattr(manage.os, "link", racing_link)
    with pytest.raises(RuntimeError, match="manifest already exists"):
        manage._write_release(
            document, {manage.RELEASE_MANIFEST_ENV: str(path)})

    assert path.read_bytes() == b"other complete manifest"
    assert not (tmp_path / "release.json.pending").exists()


def test_version_upload_uses_machine_evidence_and_never_deploys(
        monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[3]
    observed = []

    def event(role, path, arguments, secrets_document=None):
        observed.append((role, path, arguments, secrets_document))
        return {
            "type": "version-upload", "version": 1,
            "version_id": WORKER_VERSIONS["fcm"],
            "worker_name": config["name"],
        }

    monkeypatch.setattr(manage, "_wrangler_event", event)

    version = manage._upload_version(
        "fcm", config, release_id=RELEASE_ID,
        secrets_document={"FIREBASE_SERVICE_ACCOUNT_JSON": "secret"})

    assert version == WORKER_VERSIONS["fcm"]
    arguments = observed[0][2]
    assert arguments[:2] == ["versions", "upload"]
    assert "deploy" not in arguments
    assert "secret" not in arguments


def _candidate_bindings(config, *, role=None):
    """Provider Version Detail bindings for one generated config."""
    values = dict(config["vars"])
    if role is not None:
        values["POC16_DEPLOYMENT_ROLE"] = role
    bindings = [
        {"name": name, "type": "plain_text", "text": value}
        for name, value in values.items()]
    bindings.extend({
        "name": row["binding"], "type": "r2_bucket",
        "bucket_name": row["bucket_name"],
        **({"jurisdiction": row["jurisdiction"]}
           if "jurisdiction" in row else {}),
    } for row in config.get("r2_buckets", ()))
    bindings.extend({
        "name": row["binding"], "type": "service",
        "service": row["service"],
        **({"environment": row["environment"]}
           if "environment" in row else {}),
        **({"entrypoint": row["entrypoint"]}
           if "entrypoint" in row else {}),
    } for row in config.get("services", ()))
    bindings.extend({
        "name": row["binding"], "type": "queue",
        "queue_name": row["queue"],
    } for row in config.get("queues", {}).get("producers", ()))
    if "version_metadata" in config:
        bindings.append({
            "name": config["version_metadata"]["binding"],
            "type": "version_metadata",
        })
    bindings.extend({"name": name, "type": "secret_text"}
                    for name in manage._required_secrets(config))
    return bindings


def _candidate_capability(config, *, handlers=None):
    return {
        "handlers": manage._expected_handlers(config)
        if handlers is None else tuple(sorted(handlers)),
        "named_handlers": (),
        "runtime": {
            "compatibility_date": config["compatibility_date"],
            "compatibility_flags": list(
                config.get("compatibility_flags", ())),
            "exports": {"default": {
                "cache": {"enabled": False},
                "state": "created",
                "type": "worker",
            }},
            "limits": {},
            "usage_model": "standard",
        },
    }


def _incumbent_profile(config, markers, *, bootstrap=None, test_mode=None):
    incumbent = json.loads(json.dumps(config))
    for name, value in zip((
            manage.OWNER_BINDING, manage.IDENTITY_BINDING,
            manage.SOFTWARE_BINDING, manage.RELEASE_BINDING,
            "NOTIFICATIONS_ENABLED", manage.ROLE_BINDING,
    ), markers):
        incumbent["vars"][name] = value
    if bootstrap is not None:
        incumbent["vars"]["NOTIFICATION_BOOTSTRAP_MODE"] = bootstrap
    if test_mode is not None:
        incumbent["vars"]["NOTIFICATION_TEST_MODE"] = test_mode
    return _candidate_bindings(incumbent), _candidate_capability(incumbent)


def test_candidate_validation_rejects_wrong_role_at_expected_name(
        monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[1]
    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, candidate, version: (
            _candidate_bindings(
                candidate, role="notification-consumer"),
            _candidate_capability(candidate)))

    with pytest.raises(RuntimeError, match="capability inventory"):
        manage._require_candidate(
            "scanner", config, WORKER_VERSIONS["scanner"])


def test_candidate_validation_rejects_duplicate_release_marker(monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[1]
    bindings = _candidate_bindings(config)
    bindings.append({
        "name": "POC16_RELEASE_ID",
        "type": "plain_text",
        "text": RELEASE_ID,
    })
    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, candidate, version: (
            bindings, _candidate_capability(candidate)))

    with pytest.raises(RuntimeError, match="capability inventory"):
        manage._require_candidate(
            "scanner", config, WORKER_VERSIONS["scanner"])


def _harness_config(configs):
    return manage._harness_config(configs, WORKER_VERSIONS["fcm"])


def test_exact_provider_capabilities_cover_every_role_and_harness():
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    for config in (*configs, _harness_config(configs)):
        manage._require_capabilities(
            config, _candidate_bindings(config),
            _candidate_capability(config))


@pytest.mark.parametrize("change", [
    "variable", "r2", "service", "queue", "missing-secret",
    "extra-secret", "unknown-binding", "missing-metadata", "duplicate",
])
def test_candidate_rejects_every_binding_authority_change(change):
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    config = configs[2] if change == "missing-secret" else (
        configs[3] if change == "missing-metadata" else configs[1])
    bindings = _candidate_bindings(config)
    if change == "variable":
        next(row for row in bindings if row["name"] == "WORKSPACE")[
            "text"] = "b" * 64
    elif change == "r2":
        next(row for row in bindings if row["type"] == "r2_bucket")[
            "bucket_name"] = "other-bucket"
    elif change == "service":
        next(row for row in bindings if row["type"] == "service")[
            "service"] = "other-worker"
    elif change == "queue":
        next(row for row in bindings if row["type"] == "queue")[
            "queue_name"] = "other-queue"
    elif change == "missing-secret":
        bindings = [row for row in bindings
                    if row["name"] != "PUSH_NODE_SECRET"]
    elif change == "extra-secret":
        bindings.append({"name": "UNDECLARED_SECRET", "type": "secret_text"})
    elif change == "unknown-binding":
        bindings.append({"name": "KV", "type": "kv_namespace", "id": "x"})
    elif change == "missing-metadata":
        bindings = [row for row in bindings
                    if row["type"] != "version_metadata"]
    elif change == "duplicate":
        bindings.append(dict(bindings[0]))

    with pytest.raises(RuntimeError, match="capability inventory"):
        manage._require_capabilities(
            config, bindings, _candidate_capability(config))


def test_secret_values_are_neither_read_nor_leaked():
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[2]

    class OpaqueSecret(dict):
        def get(self, name, default=None):
            if name == "text":
                raise AssertionError("secret value was read")
            return super().get(name, default)

        def __repr__(self):
            raise AssertionError("secret value was formatted")

    bindings = _candidate_bindings(config)
    index = next(index for index, row in enumerate(bindings)
                 if row["name"] == "PUSH_NODE_SECRET")
    bindings[index] = OpaqueSecret(bindings[index])

    manage._require_capabilities(
        config, bindings, _candidate_capability(config))


@pytest.mark.parametrize("change", [
    "missing-handler", "extra-handler", "wrong-handler", "named-handler",
    "durable-object", "cache", "compatibility-date", "flags", "limits",
    "migration", "usage", "unknown-runtime",
])
def test_candidate_rejects_runtime_or_invocation_authority_change(change):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[1]
    capability = _candidate_capability(config)
    if change == "missing-handler":
        capability["handlers"] = ()
    elif change == "extra-handler":
        capability["handlers"] = ("fetch", "scheduled")
    elif change == "wrong-handler":
        capability["handlers"] = ("queue",)
    elif change == "named-handler":
        capability["named_handlers"] = (("public", ("fetch",)),)
    elif change == "durable-object":
        capability["runtime"]["exports"]["Admin"] = {
            "type": "durable-object", "state": "created"}
    elif change == "cache":
        capability["runtime"]["exports"]["default"]["cache"] = {
            "enabled": True}
    elif change == "compatibility-date":
        capability["runtime"]["compatibility_date"] = "2025-01-01"
    elif change == "flags":
        capability["runtime"]["compatibility_flags"] = ["nodejs_compat"]
    elif change == "limits":
        capability["runtime"]["limits"] = {"cpu_ms": 30_000}
    elif change == "migration":
        capability["runtime"]["migration_tag"] = "v1"
    elif change == "usage":
        capability["runtime"]["usage_model"] = "unbound"
    elif change == "unknown-runtime":
        capability["runtime"]["future_authority"] = True

    with pytest.raises(RuntimeError, match="runtime capability"):
        manage._require_capabilities(
            config, _candidate_bindings(config), capability)


@pytest.mark.parametrize("role,handlers", [
    ("reader", ()),
    ("scanner", ("scheduled",)),
    ("consumer", ("queue",)),
    ("fcm", ()),
    ("harness", ("fetch",)),
])
def test_each_role_rejects_one_extra_provider_handler(role, handlers):
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    config = _harness_config(configs) if role == "harness" else (
        configs[manage.ROLE_KEYS.index(role)])
    capability = _candidate_capability(
        config, handlers=(*handlers, "email"))

    with pytest.raises(RuntimeError, match="runtime capability"):
        manage._require_capabilities(
            config, _candidate_bindings(config), capability)


def _version_document(config, version):
    capability = _candidate_capability(config)
    return {
        "id": version,
        "metadata": {"hasPreview": False},
        "resources": {
            "bindings": _candidate_bindings(config),
            "script": {
                "handlers": list(capability["handlers"]),
                "named_handlers": [],
            },
            "script_runtime": capability["runtime"],
        },
    }


@pytest.mark.parametrize("change", [
    "preview", "missing-preview", "extra-resource", "unknown-script",
    "malformed-named-handler",
])
def test_version_detail_requires_complete_fail_closed_provider_evidence(
        change):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[1]
    version = WORKER_VERSIONS["scanner"]
    document = _version_document(config, version)
    if change == "preview":
        document["metadata"]["hasPreview"] = True
    elif change == "missing-preview":
        document["metadata"] = {}
    elif change == "extra-resource":
        document["resources"]["future"] = {}
    elif change == "unknown-script":
        document["resources"]["script"]["future"] = True
    elif change == "malformed-named-handler":
        document["resources"]["script"]["named_handlers"] = [{
            "name": "public", "handlers": ["fetch"], "extra": True}]

    runner = lambda *args, **kwargs: SimpleNamespace(
        stdout=json.dumps(document))
    with pytest.raises(RuntimeError, match="Worker version"):
        manage._version_capabilities_at(
            runner, Path("worker.json"), version)


def _private_script_row(config):
    return {
        "compatibility_date": config["compatibility_date"],
        "compatibility_flags": list(config.get("compatibility_flags", ())),
        "exports": {"default": {
            "cache": {"enabled": False},
            "state": "created",
            "type": "worker",
        }},
        "handlers": list(manage._expected_handlers(config)),
        "has_assets": False,
        "has_modules": True,
        "id": config["name"],
        "logpush": False,
        "named_handlers": [],
        "observability": config.get("observability"),
        "routes": [],
        "tags": [],
        "tail_consumers": [],
        "usage_model": "standard",
    }


def _stub_private_inventory(
        monkeypatch, configs, *, rows=None, subdomain=None, domains=None,
        result_info=None):
    rows = [_private_script_row(config) for config in configs] \
        if rows is None else rows
    subdomain = {"enabled": False, "previews_enabled": False} \
        if subdomain is None else subdomain
    domains = [] if domains is None else domains
    result_info = {
        "count": len(domains),
        "page": 1,
        "per_page": 20,
        "total_count": len(domains),
        "total_pages": 1 if domains else 0,
    } if result_info is None else result_info

    def api(_method, suffix, document=None, environment=None):
        return rows if suffix == "/workers/scripts" else subdomain

    monkeypatch.setattr(manage, "_api", api)
    monkeypatch.setattr(
        manage, "_api_response",
        lambda *args, **kwargs: {
            "result": domains, "result_info": result_info})


def test_provider_inventory_proves_all_workers_are_private(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    _stub_private_inventory(monkeypatch, configs)

    manage._require_private_release(configs, {})


@pytest.mark.parametrize("change", [
    "route", "tail", "named-handler", "durable-object", "cache",
    "cache-empty", "cross-version-cache", "export-cache-false", "assets",
    "service-worker", "logpush", "placement", "tag", "handler",
    "observability",
])
def test_provider_inventory_rejects_public_or_extra_script_authority(
        monkeypatch, change):
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    rows = [_private_script_row(config) for config in configs]
    row = rows[0]
    if change == "route":
        row["routes"] = [{"pattern": "example.test/*"}]
    elif change == "tail":
        row["tail_consumers"] = [{"service": "observer"}]
    elif change == "named-handler":
        row["named_handlers"] = [{"name": "admin", "handlers": ["fetch"]}]
    elif change == "durable-object":
        row["exports"]["Admin"] = {"type": "durable-object"}
    elif change == "cache":
        row["cache_options"] = {"enabled": True}
    elif change == "cache-empty":
        row["cache_options"] = {}
    elif change == "cross-version-cache":
        row["cache_options"] = {
            "enabled": False, "cross_version_cache": True}
    elif change == "export-cache-false":
        row["exports"]["default"]["cache"] = False
    elif change == "assets":
        row["has_assets"] = True
    elif change == "service-worker":
        row["has_modules"] = False
    elif change == "logpush":
        row["logpush"] = True
    elif change == "placement":
        row["placement"] = {"mode": "smart"}
    elif change == "tag":
        row["tags"] = ["public"]
    elif change == "handler":
        row["handlers"] = ["fetch"]
    elif change == "observability":
        row["observability"] = {"enabled": True}
    _stub_private_inventory(monkeypatch, configs, rows=rows)

    with pytest.raises(RuntimeError, match="provider authority differs"):
        manage._require_private_release(configs, {})


@pytest.mark.parametrize("change", [
    "workers-dev", "preview", "domain", "hidden-domain", "truncated",
])
def test_provider_inventory_rejects_every_public_hostname_or_incomplete_page(
        monkeypatch, change):
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    subdomain = {"enabled": False, "previews_enabled": False}
    domains = []
    result_info = None
    if change == "workers-dev":
        subdomain["enabled"] = True
    elif change == "preview":
        subdomain["previews_enabled"] = True
    elif change == "domain":
        domains = [{"hostname": "push.example.test"}]
    elif change == "hidden-domain":
        result_info = {
            "count": 0, "page": 1, "per_page": 20,
            "total_count": 1, "total_pages": 0,
        }
    elif change == "truncated":
        result_info = {
            "count": 0, "page": 1, "per_page": 20,
            "total_count": 0, "total_pages": 2,
        }
    _stub_private_inventory(
        monkeypatch, configs, subdomain=subdomain, domains=domains,
        result_info=result_info)

    with pytest.raises(RuntimeError, match=(
            "public subdomain|custom domain|custom-domain inventory")):
        manage._require_private_release(configs, {})


def test_split_deployment_is_rejected(monkeypatch):
    config = manage.generated_configs(_manage_environment())[0]
    monkeypatch.setattr(manage, "_api", lambda *args, **kwargs: {
        "deployments": [{"versions": [
            {"version_id": WORKER_VERSIONS["reader"], "percentage": 50},
            {"version_id": WORKER_VERSIONS["scanner"], "percentage": 50},
        ]}],
    })

    with pytest.raises(RuntimeError, match="split deployment"):
        manage._active_version(config)


def test_uploaded_worker_without_a_deployment_is_still_active_absence(
        monkeypatch):
    config = manage.generated_configs(_manage_environment())[0]
    monkeypatch.setattr(
        manage, "_api", lambda *args, **kwargs: {"deployments": []})

    assert manage._active_version(config) is manage._ABSENT


def test_enable_promotion_is_downstream_first_and_skips_staged_fcm(
        monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    old = {
        role: f"{number:08x}-0000-4000-8000-000000000000"
        for number, role in enumerate(manage.ROLE_KEYS, 10)}
    state = dict(old)
    state["fcm"] = WORKER_VERSIONS["fcm"]
    calls = []
    monkeypatch.setattr(manage, "_require_snapshot", lambda values, expected:
                        calls.append(("check", dict(expected))))

    def promote(role, config, version):
        calls.append(("promote", role))
        state[role] = version

    monkeypatch.setattr(manage, "_promote", promote)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: state[manage._config_role(config)])

    manage._promote_release(configs, WORKER_VERSIONS, state.copy())

    assert [call[1] for call in calls if call[0] == "promote"] == [
        "reader", "consumer", "scanner"]
    assert state == WORKER_VERSIONS


def test_disable_revokes_fcm_before_other_roles(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    state = {
        role: f"{number:08x}-0000-4000-8000-000000000000"
        for number, role in enumerate(manage.ROLE_KEYS, 20)}
    calls = []
    monkeypatch.setattr(manage, "_require_snapshot", lambda *args: None)

    def promote(role, config, version):
        calls.append(role)
        state[role] = version

    monkeypatch.setattr(manage, "_promote", promote)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: state[manage._config_role(config)])

    manage._promote_release(configs, WORKER_VERSIONS, state.copy())

    assert calls == ["fcm", "scanner", "consumer", "reader"]


def test_concurrent_rollout_aborts_before_a_second_promotion(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    initial = {
        role: f"{number:08x}-0000-4000-8000-000000000000"
        for number, role in enumerate(manage.ROLE_KEYS, 30)}
    state = dict(initial)
    checks = 0

    def require_snapshot(_configs, _expected):
        nonlocal checks
        checks += 1
        if checks == 2:
            raise RuntimeError("concurrent notification deployment")

    promotions = []
    monkeypatch.setattr(manage, "_require_snapshot", require_snapshot)
    monkeypatch.setattr(
        manage, "_promote",
        lambda role, config, version:
            (promotions.append(role), state.__setitem__(role, version)))
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: state[manage._config_role(config)])

    with pytest.raises(RuntimeError, match="concurrent"):
        manage._promote_release(configs, WORKER_VERSIONS, initial)
    assert promotions == ["fcm"]


@pytest.mark.parametrize("index,replacement", [
    (0, "foreign-owner"),
    (1, "1" * 64),
    (5, "notification-scanner"),
])
def test_stage_launch_fcm_rejects_foreign_incumbent_before_promotion(
        monkeypatch, index, replacement):
    environment = _manage_environment(CF_NOTIFICATIONS_ENABLED="1")
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    configs = manage.generated_configs(
        environment, software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID, launch_gate=False)
    manifest = {
        "deployment_identity": configs[0]["vars"][
            "POC16_DEPLOYMENT_IDENTITY"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }
    active = {
        role: f"{number:08x}-0000-4000-8000-000000000000"
        for number, role in enumerate(manage.ROLE_KEYS, 70)}
    promotions = []
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_load_release", lambda: manifest)
    monkeypatch.setattr(manage, "_write_configs", lambda values: None)
    monkeypatch.setattr(manage, "_release_secrets", lambda values: {})
    monkeypatch.setattr(manage, "_stage_locked", lambda value: None)
    monkeypatch.setattr(
        manage, "_require_effects_detached", lambda values: None)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])

    def markers(role, config, version):
        values = list(manage._expected_markers(config))
        if role == "fcm":
            values[index] = replacement
        return tuple(values)

    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, config, version: _incumbent_profile(
            config, markers(role, config, version)))
    monkeypatch.setattr(
        manage, "_require_candidate",
        lambda *args: pytest.fail("foreign incumbent reached candidate use"))
    monkeypatch.setattr(
        manage, "_promote",
        lambda *args: promotions.append(args))

    with pytest.raises(RuntimeError, match="unowned or rebound"):
        manage.stage_launch_fcm()
    assert promotions == []


def test_stage_launch_fcm_rechecks_incumbent_after_candidate_validation(
        monkeypatch):
    environment = _manage_environment(CF_NOTIFICATIONS_ENABLED="1")
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    configs = manage.generated_configs(
        environment, software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID, launch_gate=False)
    manifest = {
        "deployment_identity": configs[0]["vars"][
            "POC16_DEPLOYMENT_IDENTITY"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }
    active = {
        role: f"{number:08x}-0000-4000-8000-000000000000"
        for number, role in enumerate(manage.ROLE_KEYS, 80)}
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_load_release", lambda: manifest)
    monkeypatch.setattr(manage, "_write_configs", lambda values: None)
    monkeypatch.setattr(manage, "_release_secrets", lambda values: {})
    monkeypatch.setattr(manage, "_stage_locked", lambda value: None)
    monkeypatch.setattr(
        manage, "_require_effects_detached", lambda values: None)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])
    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, config, version: _incumbent_profile(
            config, manage._expected_markers(config)))

    def candidate(role, config, version, secrets=()):
        if role == "fcm":
            active["reader"] = "99999999-9999-4999-8999-999999999999"

    monkeypatch.setattr(manage, "_require_candidate", candidate)
    monkeypatch.setattr(
        manage, "_promote",
        lambda *args: pytest.fail("rebound release must not be promoted"))

    with pytest.raises(RuntimeError, match="concurrent"):
        manage.stage_launch_fcm()


def test_stage_launch_fcm_rechecks_after_private_inventory(monkeypatch):
    environment = _manage_environment(CF_NOTIFICATIONS_ENABLED="1")
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    configs = manage.generated_configs(
        environment, software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID, launch_gate=False)
    manifest = {
        "deployment_identity": configs[0]["vars"][
            "POC16_DEPLOYMENT_IDENTITY"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }
    active = dict(WORKER_VERSIONS)
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_load_release", lambda: manifest)
    monkeypatch.setattr(manage, "_write_configs", lambda values: None)
    monkeypatch.setattr(manage, "_release_secrets", lambda values: {})
    monkeypatch.setattr(manage, "_stage_locked", lambda value: None)
    monkeypatch.setattr(manage, "_require_effects_detached", lambda values: None)
    monkeypatch.setattr(
        manage, "_owned_incumbent",
        lambda role, config, allow_absent=False: (
            active[role], manage._expected_markers(config)))
    monkeypatch.setattr(manage, "_require_candidate", lambda *args: None)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])

    def private_inventory(_configs):
        active["reader"] = "99999999-9999-4999-8999-999999999999"

    monkeypatch.setattr(manage, "_require_private_release", private_inventory)

    with pytest.raises(RuntimeError, match="concurrent"):
        manage.stage_launch_fcm()


def test_switch_during_post_attach_private_inventory_is_detached(
        monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    active = dict(WORKER_VERSIONS)
    events = []
    inventory_reads = 0
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])
    monkeypatch.setattr(manage, "_require_harness_absent", lambda *args: None)
    monkeypatch.setattr(
        manage, "_attach_effects", lambda values: events.append("attach"))
    monkeypatch.setattr(
        manage, "_detach_effects", lambda values: events.append("detach"))

    def private_inventory(_configs):
        nonlocal inventory_reads
        inventory_reads += 1
        if inventory_reads == 2:
            active["consumer"] = \
                "99999999-9999-4999-8999-999999999999"

    monkeypatch.setattr(manage, "_require_private_release", private_inventory)

    with pytest.raises(RuntimeError, match="concurrent"):
        manage._activate_effects(configs, WORKER_VERSIONS)

    assert events == ["attach", "detach"]


def test_concurrent_switch_after_effect_attachment_is_detached(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    calls = []
    checks = 0

    def require_snapshot(values, versions):
        nonlocal checks
        checks += 1
        calls.append("check")
        if checks == 3:
            raise RuntimeError("concurrent notification deployment")

    monkeypatch.setattr(manage, "_require_snapshot", require_snapshot)
    monkeypatch.setattr(
        manage, "_require_harness_absent",
        lambda values, version: calls.append("harness"))
    monkeypatch.setattr(
        manage, "_require_private_release",
        lambda values: calls.append("private"))
    monkeypatch.setattr(
        manage, "_attach_effects", lambda values: calls.append("attach"))
    monkeypatch.setattr(
        manage, "_detach_effects", lambda values: calls.append("detach"))

    with pytest.raises(RuntimeError, match="concurrent"):
        manage._activate_effects(configs, WORKER_VERSIONS)

    assert calls == [
        "check", "harness", "private", "check", "attach", "check",
        "detach", "harness", "private"]


def test_stale_launch_evidence_fails_before_provider_access(
        monkeypatch):
    environment = _manage_environment(CF_NOTIFICATIONS_ENABLED="1")
    disabled = manage.generated_configs(
        {**environment, "CF_NOTIFICATIONS_ENABLED": "0"},
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID)
    manifest = {
        "deployment_identity": disabled[0]["vars"][
            "POC16_DEPLOYMENT_IDENTITY"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_load_release", lambda: manifest)
    provider_calls = []
    for name in ("_worker_markers", "_wrangler", "_pywrangler", "_api"):
        monkeypatch.setattr(
            manage, name,
            lambda *args, _name=name, **kwargs: provider_calls.append(_name))

    with pytest.raises(RuntimeError, match="ios.*required"):
        manage.deploy()
    assert provider_calls == []


@pytest.mark.parametrize("change", [
    {"CLOUDFLARE_ACCOUNT_ID": "d" * 32},
    {"CF_WORKSPACE": "f" * 64},
    {"CF_CANONICAL_BUCKET": "canonical-other"},
    {"CF_CANONICAL_PREFIX": "canonical/other"},
    {"CF_NOTIFICATION_STATE_BUCKET": "notification-state-other"},
    {"CF_NOTIFICATION_STATE_PREFIX": "notification/other"},
    {"CF_PUSH_NODE_PUBLIC": "f" * 64},
    {"CF_FIREBASE_PROJECT_ID": "firebase-other"},
    {"CF_FIREBASE_APPLICATION": "another.app"},
])
def test_immutable_binding_changes_rotate_deployment_identity(change):
    old = manage.generated_configs(_manage_environment())[1]
    new = manage.generated_configs(_manage_environment(**change))[1]
    assert old["vars"]["POC16_DEPLOYMENT_IDENTITY"] \
        != new["vars"]["POC16_DEPLOYMENT_IDENTITY"]


def test_cursor_identity_hashes_only_semantic_completion_authority():
    environment = _manage_environment()
    configs = manage.generated_configs(environment)
    delivery_domain = manage.delivery_domain_id(
        environment["CF_PUSH_NODE_PUBLIC"], ((
            environment["CF_FIREBASE_APPLICATION"],
            environment["CF_FIREBASE_ENVIRONMENT"],
            environment["CF_FIREBASE_PROJECT_ID"],
        ),))
    document = {
        "canonical_bucket": environment["CF_CANONICAL_BUCKET"],
        "canonical_prefix": "workspaces/" + environment["CF_WORKSPACE"],
        "cloudflare_account_id": environment["CLOUDFLARE_ACCOUNT_ID"],
        "completion_protocol": manage.COMPLETION_PROTOCOL,
        "delivery_domain": delivery_domain,
        "state_bucket": environment["CF_NOTIFICATION_STATE_BUCKET"],
        "state_prefix": "notifications/v1/" + environment["CF_WORKSPACE"],
        "workspace": environment["CF_WORKSPACE"],
    }
    expected = manage.hashlib.sha256(json.dumps(
        document, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True).encode("ascii")).hexdigest()

    assert {config["vars"]["POC16_DEPLOYMENT_IDENTITY"]
            for config in configs} == {expected}


def test_completion_protocol_change_rotates_cursor_identity(monkeypatch):
    baseline = manage.generated_configs(_manage_environment())[0]["vars"][
        "POC16_DEPLOYMENT_IDENTITY"]
    monkeypatch.setattr(
        manage, "COMPLETION_PROTOCOL", "poc16-notification-completion-v2")

    changed = manage.generated_configs(_manage_environment())[0]["vars"][
        "POC16_DEPLOYMENT_IDENTITY"]

    assert changed != baseline


def test_queue_and_dlq_replacement_preserves_semantic_cursor_owner():
    old = manage.generated_configs(_manage_environment())[1]
    replacement = manage.generated_configs(_manage_environment(
        CF_NOTIFICATION_QUEUE="notification-other",
        CF_NOTIFICATION_DLQ="notification-other-dlq"))[1]

    assert old["vars"]["POC16_DEPLOYMENT_IDENTITY"] \
        == replacement["vars"]["POC16_DEPLOYMENT_IDENTITY"]
    assert old["queues"]["producers"][0]["queue"] \
        != replacement["queues"]["producers"][0]["queue"]


def test_worker_role_renames_preserve_semantic_cursor_owner():
    old = manage.generated_configs(_manage_environment())
    replacement = manage.generated_configs(_manage_environment(
        CF_NOTIFICATION_READER="replacement-reader",
        CF_NOTIFICATION_SCANNER="replacement-scanner",
        CF_NOTIFICATION_CONSUMER="replacement-consumer",
        CF_FCM_SERVICE="replacement-fcm"))

    assert {config["vars"]["POC16_DEPLOYMENT_IDENTITY"] for config in old} \
        == {config["vars"]["POC16_DEPLOYMENT_IDENTITY"]
            for config in replacement}
    assert [config["name"] for config in old] \
        != [config["name"] for config in replacement]


def test_same_owner_cannot_rebind_an_existing_worker(monkeypatch):
    old = manage.generated_configs(_manage_environment())[1]
    changed = manage.generated_configs(_manage_environment(
        CF_NOTIFICATION_STATE_BUCKET="notification-state-other"))[1]
    monkeypatch.setattr(
        manage, "_worker_markers",
        lambda config: (
            old["vars"]["POC16_DEPLOYMENT_OWNER"],
            old["vars"]["POC16_DEPLOYMENT_IDENTITY"],
            old["vars"]["POC16_SOFTWARE_DIGEST"],
            old["vars"]["POC16_RELEASE_ID"],
            "0",
            old["vars"]["POC16_DEPLOYMENT_ROLE"],
        ))

    with pytest.raises(RuntimeError, match="immutable notification"):
        manage._require_deployable(changed, create=True)


def test_worker_state_reads_digest_and_enablement_from_one_settings_result(
        monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    calls = []
    bindings = [{"name": name, "type": "plain_text", "text": value}
                for name, value in (
                    ("POC16_DEPLOYMENT_OWNER", "production-owner"),
                    ("POC16_DEPLOYMENT_IDENTITY",
                     config["vars"]["POC16_DEPLOYMENT_IDENTITY"]),
                    ("POC16_SOFTWARE_DIGEST", SOFTWARE_DIGEST),
                    ("POC16_RELEASE_ID", "0" * 64),
                    ("NOTIFICATIONS_ENABLED", "1"))]
    bindings.append({
        "name": "POC16_DEPLOYMENT_ROLE", "type": "plain_text",
        "text": config["vars"]["POC16_DEPLOYMENT_ROLE"],
    })
    monkeypatch.setattr(
        manage, "_worker_bindings",
        lambda _config, environment=None:
            calls.append(_config["name"]) or bindings)

    assert manage._worker_markers(config) == (
        "production-owner",
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        SOFTWARE_DIGEST,
        "0" * 64,
        "1",
        config["vars"]["POC16_DEPLOYMENT_ROLE"],
    )
    assert calls == [config["name"]]


def test_disabled_deploy_may_replace_software_before_retesting(monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    monkeypatch.setattr(manage, "_worker_markers", lambda _config: (
        config["vars"]["POC16_DEPLOYMENT_OWNER"],
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        "e" * 64,
        "0" * 64,
        "0",
        config["vars"]["POC16_DEPLOYMENT_ROLE"],
    ))
    monkeypatch.setattr(manage, "_require_immutable_owned", lambda value: None)

    manage._require_deployable(config, create=False)


def test_disabled_incumbent_may_stage_new_production_software(monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    config["vars"]["NOTIFICATIONS_ENABLED"] = "1"
    monkeypatch.setattr(manage, "_worker_markers", lambda _config: (
        config["vars"]["POC16_DEPLOYMENT_OWNER"],
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        "e" * 64,
        "0" * 64,
        "0",
        config["vars"]["POC16_DEPLOYMENT_ROLE"],
    ))
    monkeypatch.setattr(manage, "_require_immutable_owned", lambda value: None)

    manage._require_deployable(config, create=False)


def test_production_enable_requires_an_existing_disabled_deployment(
        monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    config["vars"]["NOTIFICATIONS_ENABLED"] = "1"
    monkeypatch.setattr(
        manage, "_worker_markers", lambda _config: manage._ABSENT)

    with pytest.raises(RuntimeError, match="deploy notifications disabled"):
        manage._require_deployable(config, create=True)


def test_disabling_and_changing_code_must_be_two_deployments(monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    monkeypatch.setattr(manage, "_worker_markers", lambda _config: (
        config["vars"]["POC16_DEPLOYMENT_OWNER"],
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        "e" * 64,
        "0" * 64,
        "1",
        config["vars"]["POC16_DEPLOYMENT_ROLE"],
    ))

    with pytest.raises(RuntimeError, match="disable the incumbent release"):
        manage._require_deployable(config, create=False)


def test_same_software_can_be_disabled_before_upgrade(monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    monkeypatch.setattr(manage, "_worker_markers", lambda _config: (
        config["vars"]["POC16_DEPLOYMENT_OWNER"],
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        SOFTWARE_DIGEST,
        "0" * 64,
        "1",
        config["vars"]["POC16_DEPLOYMENT_ROLE"],
    ))
    monkeypatch.setattr(manage, "_require_immutable_owned", lambda value: None)

    manage._require_deployable(config, create=False)


@pytest.mark.parametrize("observed", [
    [],
    [{
        "name": "NOTIFICATION_BOOTSTRAP_MODE",
        "type": "plain_text",
        "text": "current",
    }],
])
def test_verify_rejects_absent_or_unsealed_bootstrap_binding(
        monkeypatch, observed):
    scanner_config = manage.generated_configs(_manage_environment())[1]
    monkeypatch.setattr(
        manage, "_worker_bindings", lambda config, environment=None: observed)

    with pytest.raises(RuntimeError, match="bootstrap is not sealed"):
        manage._require_bootstrap_sealed(scanner_config, {})


def test_verify_accepts_exact_sealed_bootstrap_binding(monkeypatch):
    scanner_config = manage.generated_configs(_manage_environment())[1]
    monkeypatch.setattr(manage, "_worker_bindings", lambda *args: [{
        "name": "NOTIFICATION_BOOTSTRAP_MODE",
        "type": "plain_text",
        "text": "none",
    }])

    manage._require_bootstrap_sealed(scanner_config, {})


def test_verify_uses_manifest_release_and_exact_active_versions(
        monkeypatch):
    monkeypatch.setenv("CF_NOTIFICATIONS_ENABLED", "1")
    monkeypatch.setenv("CF_NOTIFICATION_TEST_MODE", "0")
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    manifest = {
        "deployment_identity": configs[0]["vars"][
            "POC16_DEPLOYMENT_IDENTITY"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }
    owned = []
    monkeypatch.setattr(
        manage, "_manifest_configs",
        lambda launch_gate: (manifest, configs))
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: WORKER_VERSIONS[manage._config_role(config)])
    monkeypatch.setattr(
        manage, "_require_owned", lambda config: owned.append(
            config["vars"]["POC16_RELEASE_ID"]))
    monkeypatch.setattr(
        manage, "_require_harness_absent", lambda values, version: None)
    monkeypatch.setattr(manage, "_require_snapshot", lambda *args: None)
    monkeypatch.setattr(manage, "_require_private_release", lambda values: None)
    monkeypatch.setattr(manage, "_require_bootstrap_sealed", lambda value: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(manage, "_require_effects_attached", lambda values: None)
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *args, **kwargs: SimpleNamespace(stdout="queue\n"))

    manage.verify()

    assert owned == [RELEASE_ID] * 4


def test_verify_rechecks_versions_after_queue_provider_reads(monkeypatch):
    monkeypatch.setenv("CF_NOTIFICATIONS_ENABLED", "1")
    monkeypatch.setenv("CF_NOTIFICATION_TEST_MODE", "0")
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    manifest = {
        "deployment_identity": configs[0]["vars"][
            "POC16_DEPLOYMENT_IDENTITY"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }
    active = dict(WORKER_VERSIONS)
    queue_reads = 0
    monkeypatch.setattr(
        manage, "_manifest_configs",
        lambda launch_gate: (manifest, configs))
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])
    monkeypatch.setattr(manage, "_require_owned", lambda config: None)
    monkeypatch.setattr(manage, "_require_harness_absent", lambda *args: None)
    monkeypatch.setattr(manage, "_require_private_release", lambda value: None)
    monkeypatch.setattr(manage, "_require_bootstrap_sealed", lambda value: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(manage, "_require_effects_attached", lambda value: None)

    def queue_info(*args, **kwargs):
        nonlocal queue_reads
        queue_reads += 1
        if queue_reads == 2:
            active["scanner"] = \
                "99999999-9999-4999-8999-999999999999"
        return SimpleNamespace(stdout="queue\n")

    monkeypatch.setattr(manage, "_wrangler", queue_info)

    with pytest.raises(RuntimeError, match="concurrent"):
        manage.verify()


def test_initial_disabled_release_verifies_without_a_manifest(monkeypatch):
    environment = _manage_environment()
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(manage.RELEASE_MANIFEST_ENV, raising=False)
    configs = manage.generated_configs(
        environment, software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID, launch_gate=False)
    detached = []
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "_load_release",
        lambda: pytest.fail("disabled verification must not need a manifest"))

    def markers(config):
        role = manage._config_role(config)
        return manage._expected_markers(configs[manage.ROLE_KEYS.index(role)])

    monkeypatch.setattr(manage, "_worker_markers", markers)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: manage._ABSENT
        if config["vars"]["POC16_DEPLOYMENT_ROLE"]
        == "notification-launch-harness"
        else WORKER_VERSIONS[manage._config_role(config)])
    monkeypatch.setattr(manage, "_require_owned", lambda value: None)
    monkeypatch.setattr(manage, "_require_snapshot", lambda *args: None)
    monkeypatch.setattr(manage, "_require_private_release", lambda values: None)
    monkeypatch.setattr(manage, "_require_bootstrap_sealed", lambda value: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(
        manage, "_require_effects_detached",
        lambda values: detached.append(True))
    monkeypatch.setattr(
        manage, "_require_effects_attached",
        lambda values: pytest.fail("disabled release must have no effects"))
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *args, **kwargs: SimpleNamespace(stdout="queue\n"))

    manage.verify()

    assert detached == [True]


def test_temporary_launch_harness_has_only_authenticated_fcm_capability():
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    harness = manage._harness_config(configs, WORKER_VERSIONS["fcm"])

    assert harness["services"] == [{
        "binding": "FCM_BOUNDARY", "service": configs[3]["name"]}]
    assert "r2_buckets" not in harness
    assert "queues" not in harness
    assert harness["vars"]["POC16_RELEASE_ID"] == RELEASE_ID
    assert harness["vars"]["POC16_DEPLOYMENT_ROLE"] \
        == "notification-launch-harness"
    assert harness["vars"]["POC16_EXPECTED_FCM_VERSION"] \
        == WORKER_VERSIONS["fcm"]
    assert harness["name"] \
        == "poc16-notify-launch-cccccccc-aaaaaaaaaaaa"
    assert harness["main"].endswith("launch_harness/worker.mjs")


def test_launch_harness_name_cannot_drift_with_an_environment_override():
    first = manage.generated_configs(
        _manage_environment(
            CF_NOTIFICATIONS_ENABLED="1",
            CF_NOTIFICATION_LAUNCH_HARNESS="old-public-name"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    second = manage.generated_configs(
        _manage_environment(
            CF_NOTIFICATIONS_ENABLED="1",
            CF_NOTIFICATION_LAUNCH_HARNESS="new-public-name"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)

    assert manage._harness_config(first, WORKER_VERSIONS["fcm"])["name"] \
        == manage._harness_config(second, WORKER_VERSIONS["fcm"])["name"] \
        == "poc16-notify-launch-cccccccc-aaaaaaaaaaaa"


def test_production_enable_rejects_a_live_temporary_harness(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    monkeypatch.setattr(
        manage, "_active_version", lambda config: WORKER_VERSIONS["fcm"])

    with pytest.raises(RuntimeError, match="remove the temporary"):
        manage._require_harness_absent(configs, WORKER_VERSIONS["fcm"])


def test_concurrent_harness_recreation_rolls_back_activation(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    events = []
    harness_checks = 0

    def require_harness_absent(_configs, _version):
        nonlocal harness_checks
        harness_checks += 1
        events.append("harness")
        if harness_checks > 1:
            raise RuntimeError("temporary launch harness was recreated")

    monkeypatch.setattr(
        manage, "_require_snapshot",
        lambda values, versions: events.append("snapshot"))
    monkeypatch.setattr(
        manage, "_require_harness_absent", require_harness_absent)
    monkeypatch.setattr(
        manage, "_require_private_release",
        lambda values: events.append("private"))
    monkeypatch.setattr(
        manage, "_attach_effects", lambda values: events.append("attach"))
    monkeypatch.setattr(
        manage, "_detach_effects", lambda values: events.append("detach"))

    with pytest.raises(RuntimeError, match="rollback verification failed"):
        manage._activate_effects(configs, WORKER_VERSIONS)

    assert events == [
        "snapshot", "harness", "private", "snapshot", "attach",
        "snapshot", "harness", "detach", "harness", "private",
    ]


def test_harness_removal_rejects_concurrent_recreation(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    manifest = {
        "deployment_identity": configs[0]["vars"][
            "POC16_DEPLOYMENT_IDENTITY"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }
    monkeypatch.setattr(
        manage, "_manifest_configs", lambda: (manifest, configs))
    monkeypatch.setattr(manage, "_write_harness", lambda config: None)
    monkeypatch.setattr(manage, "_require_owned", lambda config: None)
    monkeypatch.setattr(manage, "_wrangler", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: "55555555-5555-4555-8555-555555555555")

    with pytest.raises(RuntimeError, match="remove the temporary"):
        manage.remove_launch_harness()


@pytest.mark.parametrize("index,replacement", [
    (0, "foreign-owner"),
    (1, "1" * 64),
    (5, "notification-consumer"),
])
def test_scanner_mode_rejects_foreign_authority_before_provider_mutation(
        monkeypatch, index, replacement):
    for name, value in _manage_environment().items():
        monkeypatch.setenv(name, value)
    active = dict(WORKER_VERSIONS)
    provider_calls = []
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])

    def markers(role, config, version):
        values = list(manage._expected_markers(config))
        if role == "scanner":
            values[index] = replacement
        return tuple(values)

    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, config, version: _incumbent_profile(
            config, markers(role, config, version)))
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *args, **kwargs: provider_calls.append(("wrangler", args)))
    monkeypatch.setattr(
        manage, "_upload_version",
        lambda *args, **kwargs: provider_calls.append(("upload", args)))
    monkeypatch.setattr(
        manage, "_promote",
        lambda *args, **kwargs: provider_calls.append(("promote", args)))

    with pytest.raises(RuntimeError, match="unowned or rebound"):
        manage._deploy_scanner_mode(manage.BOOTSTRAP_NONE)
    assert provider_calls == []


def test_scanner_mode_rechecks_snapshot_before_first_provider_mutation(
        monkeypatch):
    for name, value in _manage_environment().items():
        monkeypatch.setenv(name, value)
    active = dict(WORKER_VERSIONS)
    reads = {role: 0 for role in manage.ROLE_KEYS}
    provider_calls = []
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)

    def active_version(config):
        role = manage._config_role(config)
        reads[role] += 1
        if role == "scanner" and reads[role] >= 3:
            return "99999999-9999-4999-8999-999999999999"
        return active[role]

    monkeypatch.setattr(manage, "_active_version", active_version)
    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, config, version: _incumbent_profile(
            config, manage._expected_markers(config)))
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *args, **kwargs: provider_calls.append(("wrangler", args)))
    monkeypatch.setattr(
        manage, "_upload_version",
        lambda *args, **kwargs: provider_calls.append(("upload", args)))
    monkeypatch.setattr(
        manage, "_promote",
        lambda *args, **kwargs: provider_calls.append(("promote", args)))

    with pytest.raises(RuntimeError, match="concurrent"):
        manage._deploy_scanner_mode(manage.BOOTSTRAP_NONE)
    assert provider_calls == []


@pytest.mark.parametrize("mode", ["current", "backfill", "none"])
def test_bootstrap_commands_promote_only_one_exact_scanner_version(
        monkeypatch, mode):
    calls = []
    ordinary = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    configs = manage.generated_configs(
        _manage_environment(), bootstrap_mode=mode,
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID)
    monkeypatch.setattr(
        manage, "_prepare_software",
        lambda: calls.append(("prepare",)) or SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "generated_configs",
        lambda **options: configs if "bootstrap_mode" in options else ordinary)
    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, config, version: _incumbent_profile(config, (
            config["vars"]["POC16_DEPLOYMENT_OWNER"],
            config["vars"]["POC16_DEPLOYMENT_IDENTITY"], SOFTWARE_DIGEST,
            RELEASE_ID, "0", config["vars"]["POC16_DEPLOYMENT_ROLE"],
        )))
    monkeypatch.setattr(
        manage, "_write_configs", lambda value: calls.append(("write", value)))
    monkeypatch.setattr(
        manage, "_require_effects_detached",
        lambda value: calls.append(("detached",)))
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects",
        lambda reader_config, scanner_config: calls.append(("retained",)))
    monkeypatch.setattr(
        manage, "_upload_version",
        lambda role, config, release_id: calls.append(("upload", role))
        or WORKER_VERSIONS["scanner"])
    monkeypatch.setattr(manage, "_require_candidate", lambda *args: None)
    monkeypatch.setattr(manage, "_require_private_release", lambda value: None)
    monkeypatch.setattr(
        manage, "_promote",
        lambda role, config, version: calls.append(("promote", role, version)))
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: WORKER_VERSIONS[manage._config_role(config)])
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *arguments, **options: calls.append(("wrangler", arguments)))

    manage._deploy_scanner_mode(mode)

    assert ("upload", "scanner") in calls
    assert ("promote", "scanner", WORKER_VERSIONS["scanner"]) in calls
    assert not any(
        call[0] == "wrangler" and call[1][0] == "deploy" for call in calls)


@pytest.mark.parametrize("active_mode", ["current", "backfill"])
def test_active_bootstrap_mode_can_be_sealed_without_rebinding(
        monkeypatch, active_mode):
    for name, value in _manage_environment().items():
        monkeypatch.setenv(name, value)
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    active = dict(WORKER_VERSIONS)
    promotions = []
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_write_configs", lambda values: None)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])

    def profile(role, config, version):
        return _incumbent_profile(
            config, manage._expected_markers(config),
            bootstrap=active_mode if role == "scanner" else None)

    monkeypatch.setattr(manage, "_version_capabilities", profile)
    monkeypatch.setattr(manage, "_require_effects_detached", lambda value: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(
        manage, "_upload_version",
        lambda *args, **kwargs: WORKER_VERSIONS["scanner"])
    monkeypatch.setattr(manage, "_require_candidate", lambda *args: None)
    monkeypatch.setattr(manage, "_require_private_release", lambda value: None)
    monkeypatch.setattr(manage, "_wrangler", lambda *args, **kwargs: None)

    def promote(role, config, version):
        promotions.append(role)
        active[role] = version

    monkeypatch.setattr(manage, "_promote", promote)

    manage._deploy_scanner_mode(manage.BOOTSTRAP_NONE)

    assert promotions == ["scanner"]


def test_emergency_disable_accepts_a_valid_active_bootstrap(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    active = dict(WORKER_VERSIONS)
    detached = []
    monkeypatch.setattr(manage, "generated_configs", lambda: configs)
    monkeypatch.setattr(manage, "_write_configs", lambda values: None)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])
    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, config, version: _incumbent_profile(
            config, manage._expected_markers(config),
            bootstrap="current" if role == "scanner" else None))
    monkeypatch.setattr(
        manage, "_detach_effects", lambda values: detached.append(True))

    manage.disable()

    assert detached == [True]


@pytest.mark.parametrize("requested,active", [("0", "1"), ("1", "0")])
def test_test_mode_can_transition_under_the_same_immutable_identity(
        monkeypatch, requested, active):
    environment = _manage_environment(
        CF_FIREBASE_ENVIRONMENT="staging",
        CF_FIREBASE_TEST_PROJECT_ID="firebase-project",
        CF_NOTIFICATION_TEST_MODE=requested)
    config = manage.generated_configs(
        environment, software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[2]
    version = WORKER_VERSIONS["consumer"]
    monkeypatch.setattr(manage, "_active_version", lambda value: version)
    monkeypatch.setattr(
        manage, "_capabilities_for_version",
        lambda value, observed: _incumbent_profile(
            value, manage._expected_markers(value), test_mode=active))

    manage._require_immutable_owned(config)


@pytest.mark.parametrize("name,value", [
    ("NOTIFICATION_TEST_MODE", "maybe"),
    ("NOTIFICATION_BOOTSTRAP_MODE", "automatic"),
])
def test_unknown_mutable_incumbent_state_is_rejected(
        monkeypatch, name, value):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[1]
    incumbent = json.loads(json.dumps(config))
    incumbent["vars"][name] = value
    version = WORKER_VERSIONS["scanner"]
    monkeypatch.setattr(manage, "_active_version", lambda observed: version)
    monkeypatch.setattr(
        manage, "_capabilities_for_version",
        lambda observed, active: (
            _candidate_bindings(incumbent),
            _candidate_capability(incumbent)))

    with pytest.raises(RuntimeError, match="invalid mutable"):
        manage._require_immutable_owned(config)


def test_bootstrap_swap_after_cron_attach_is_rolled_back(monkeypatch):
    for name, value in _manage_environment().items():
        monkeypatch.setenv(name, value)
    active = dict(WORKER_VERSIONS)
    replacement = "55555555-5555-4555-8555-555555555555"
    trigger_calls = []
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_write_configs", lambda values: None)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])
    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, config, version: _incumbent_profile(
            config, manage._expected_markers(config)))
    monkeypatch.setattr(manage, "_require_effects_detached", lambda value: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(
        manage, "_upload_version", lambda *args, **kwargs: replacement)
    monkeypatch.setattr(manage, "_require_candidate", lambda *args: None)
    monkeypatch.setattr(manage, "_require_private_release", lambda value: None)

    def promote(role, config, version):
        active[role] = version

    def wrangler(*arguments, **options):
        if arguments[:2] == ("triggers", "deploy"):
            trigger_calls.append(arguments)
            if "--triggers" in arguments:
                active["reader"] = \
                    "99999999-9999-4999-8999-999999999999"

    monkeypatch.setattr(manage, "_promote", promote)
    monkeypatch.setattr(manage, "_wrangler", wrangler)

    with pytest.raises(RuntimeError, match="concurrent"):
        manage._deploy_scanner_mode(manage.BOOTSTRAP_CURRENT)

    assert len(trigger_calls) == 2
    assert "--triggers" in trigger_calls[0]
    assert "--triggers" not in trigger_calls[1]


def test_redrive_accepts_primary_copy_before_acknowledging_dlq(
        monkeypatch):
    calls = []
    monkeypatch.setenv("CF_REDRIVE", "1")
    monkeypatch.setenv("CF_NOTIFICATION_QUEUE_ID", "a" * 32)
    monkeypatch.setenv("CF_NOTIFICATION_DLQ_ID", "b" * 32)
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "c" * 32)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "secret")

    def api(method, suffix, document=None, environment=None):
        calls.append((method, suffix, document))
        if suffix.endswith("/messages/pull"):
            return {"messages": [{
                "body": "{}", "lease_id": "lease-1"}]}
        return {}

    monkeypatch.setattr(manage, "_api", api)

    manage.redrive()

    assert calls == [
        ("POST", f"/queues/{'b' * 32}/messages/pull", {
            "batch_size": 10, "visibility_timeout_ms": 60_000}),
        ("POST", f"/queues/{'a' * 32}/messages", {
            "body": "{}", "content_type": "text"}),
        ("POST", f"/queues/{'b' * 32}/messages/ack", {
            "acks": [{"lease_id": "lease-1"}], "retries": []}),
    ]


def test_first_create_uploads_service_targets_before_dependents(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)
    calls = []
    counter = iter(WORKER_VERSIONS.values())
    monkeypatch.setattr(
        manage, "_upload_version",
        lambda role, config, release_id, secrets_document=None:
            calls.append((role, secrets_document)) or next(counter))
    monkeypatch.setattr(manage, "_require_candidate", lambda *args: None)

    manage._upload_release(configs, RELEASE_ID, {
        "consumer": {"PUSH_NODE_SECRET": "secret"},
        "fcm": {"FIREBASE_SERVICE_ACCOUNT_JSON": "firebase"},
    })

    assert [role for role, _secrets in calls] == [
        "fcm", "reader", "scanner", "consumer"]
    assert calls[0][1] == {"FIREBASE_SERVICE_ACCOUNT_JSON": "firebase"}
    assert calls[-1][1] == {"PUSH_NODE_SECRET": "secret"}


def test_first_create_deploy_never_touches_cron_before_scanner_exists(
        monkeypatch):
    events = []
    for name, value in _manage_environment(CF_CREATE="1").items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(manage.RELEASE_MANIFEST_ENV, raising=False)
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_write_configs", lambda configs: None)
    monkeypatch.setattr(manage, "_release_secrets", lambda configs: {})
    monkeypatch.setattr(manage, "_stage_locked", lambda digest: None)
    monkeypatch.setattr(
        manage, "_require_deployable", lambda config, create: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(
        manage, "_snapshot",
        lambda configs: {role: manage._ABSENT for role in manage.ROLE_KEYS})
    monkeypatch.setattr(
        manage, "_queue_consumers",
        lambda scanner_config: events.append("queue-read") or [])
    monkeypatch.setattr(
        manage, "_cron_schedules",
        lambda scanner_config: events.append("cron-read") or [])
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *args, **kwargs: events.append(("wrangler", args)))
    monkeypatch.setattr(
        manage, "_upload_release",
        lambda configs, release_id, credentials:
            events.append("upload") or WORKER_VERSIONS)
    monkeypatch.setattr(
        manage, "_promote_release",
        lambda configs, versions, initial: events.append("promote"))
    monkeypatch.setattr(manage, "_require_private_release", lambda values: None)
    monkeypatch.setattr(manage, "_require_snapshot", lambda *args: None)

    manage.deploy()

    assert "upload" in events
    assert "cron-read" in events
    assert events.index("upload") < events.index("cron-read")
    assert not any(
        isinstance(event, tuple) and event[1][:2] == ("triggers", "deploy")
        for event in events)


def test_first_create_uploads_workers_before_any_active_deployment(
        monkeypatch):
    for name, value in _manage_environment(CF_CREATE="1").items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(manage.RELEASE_MANIFEST_ENV, raising=False)
    uploaded = set()
    active = {role: manage._ABSENT for role in manage.ROLE_KEYS}
    promotions = []
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_write_configs", lambda configs: None)
    monkeypatch.setattr(manage, "_release_secrets", lambda configs: {})
    monkeypatch.setattr(manage, "_stage_locked", lambda digest: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(
        manage, "_detach_effects", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        manage, "_require_effects_detached", lambda *args, **kwargs: None)

    def markers(config):
        role = manage._config_role(config)
        return manage._expected_markers(config) \
            if role in uploaded else manage._ABSENT

    def upload(role, config, release_id, secrets_document=None):
        uploaded.add(role)
        return WORKER_VERSIONS[role]

    def promote(role, config, version):
        promotions.append(role)
        active[role] = version

    monkeypatch.setattr(manage, "_worker_markers", markers)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: active[manage._config_role(config)])
    monkeypatch.setattr(manage, "_upload_version", upload)
    monkeypatch.setattr(manage, "_require_candidate", lambda *args: None)
    monkeypatch.setattr(manage, "_promote", promote)
    monkeypatch.setattr(manage, "_require_private_release", lambda values: None)

    manage.deploy()

    assert uploaded == set(manage.ROLE_KEYS)
    assert active == WORKER_VERSIONS
    assert promotions == ["fcm", "scanner", "consumer", "reader"]


def test_physically_staged_fcm_resumes_the_exact_production_release(
        tmp_path, monkeypatch):
    environment = _with_launch_records(
        tmp_path,
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST)
    environment[manage.RELEASE_MANIFEST_ENV] = str(
        tmp_path / "release.json")
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    candidate = manage.generated_configs(
        environment, software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID, worker_versions=WORKER_VERSIONS,
        launch_gate=False)
    manifest = {
        "deployment_identity": candidate[0]["vars"][
            "POC16_DEPLOYMENT_IDENTITY"],
        "format": manage.RELEASE_MANIFEST_FORMAT,
        "release_id": RELEASE_ID,
        "software_digest": SOFTWARE_DIGEST,
        "worker_versions": WORKER_VERSIONS,
    }
    active = {
        role: f"{number:08x}-0000-4000-8000-000000000000"
        for number, role in enumerate(manage.ROLE_KEYS, 60)}
    markers = {
        role: (
            config["vars"]["POC16_DEPLOYMENT_OWNER"],
            config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
            "e" * 64,
            "0" * 64,
            "0",
            config["vars"]["POC16_DEPLOYMENT_ROLE"],
        )
        for role, config in zip(manage.ROLE_KEYS, candidate)
    }
    promotions = []
    attached = []
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "_load_release", lambda: manifest)
    monkeypatch.setattr(manage, "_write_configs", lambda configs: None)
    monkeypatch.setattr(manage, "_release_secrets", lambda configs: {})
    monkeypatch.setattr(manage, "_stage_locked", lambda digest: None)
    monkeypatch.setattr(
        manage, "_require_effects_detached", lambda configs: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(manage, "_require_candidate", lambda *args: None)
    monkeypatch.setattr(manage, "_require_immutable_owned", lambda value: None)
    monkeypatch.setattr(manage, "_require_private_release", lambda values: None)
    monkeypatch.setattr(
        manage, "_attach_effects", lambda configs: attached.append(True))

    def worker_markers(config):
        if config["vars"]["POC16_DEPLOYMENT_ROLE"] \
                == "notification-launch-harness":
            return manage._ABSENT
        return markers[manage._config_role(config)]

    def active_version(config):
        if config["vars"]["POC16_DEPLOYMENT_ROLE"] \
                == "notification-launch-harness":
            return manage._ABSENT
        return active[manage._config_role(config)]

    def promote(role, config, version):
        promotions.append(role)
        active[role] = version
        markers[role] = manage._expected_markers(config)

    monkeypatch.setattr(manage, "_worker_markers", worker_markers)
    monkeypatch.setattr(
        manage, "_version_capabilities",
        lambda role, config, version: _incumbent_profile(
            config, markers[role]))
    monkeypatch.setattr(manage, "_active_version", active_version)
    monkeypatch.setattr(manage, "_promote", promote)

    manage.stage_launch_fcm()
    assert promotions == ["fcm"]
    assert active["fcm"] == WORKER_VERSIONS["fcm"]
    manage.deploy()

    assert promotions == ["fcm", "reader", "consumer", "scanner"]
    assert active == WORKER_VERSIONS
    assert attached == [True]


def test_emergency_disable_only_detaches_owned_provider_effects(monkeypatch):
    configs = manage.generated_configs(_manage_environment())
    calls = []
    monkeypatch.setattr(manage, "generated_configs", lambda: configs)
    monkeypatch.setattr(
        manage, "_write_configs", lambda values: calls.append("write"))
    monkeypatch.setattr(
        manage, "_require_immutable_owned",
        lambda config: calls.append(("owned", manage._config_role(config))))
    monkeypatch.setattr(
        manage, "_detach_effects",
        lambda values: calls.append("detach"))
    monkeypatch.setattr(
        manage, "_release_secrets",
        lambda values: pytest.fail("disable must not load credentials"))
    monkeypatch.setattr(
        manage, "_upload_release",
        lambda *args: pytest.fail("disable must not upload code"))
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects",
        lambda *args: pytest.fail("disable must not inspect R2 lifecycle"))

    manage.disable()

    assert calls == [
        "write",
        ("owned", "reader"),
        ("owned", "scanner"),
        ("owned", "consumer"),
        ("owned", "fcm"),
        "detach",
    ]


def test_remove_never_deletes_queues_or_r2(monkeypatch):
    configs = manage.generated_configs(_manage_environment())
    calls = []
    monkeypatch.setattr(manage, "generated_configs", lambda: configs)
    monkeypatch.setattr(manage, "_write_configs", lambda values: None)
    monkeypatch.setattr(
        manage, "_require_immutable_owned", lambda config: None)
    monkeypatch.setattr(
        manage, "_pywrangler",
        lambda *arguments, **options: calls.append(arguments))
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *arguments, **options: calls.append(arguments))

    manage.remove()

    assert [call[0] for call in calls] == [
        "delete", "delete", "delete", "delete"]
    assert all("queues" not in call and "r2" not in call for call in calls)
