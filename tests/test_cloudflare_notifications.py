"""Cloudflare Queue/R2 notification deployment conformance."""
import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
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
        if key == "root" or key.startswith("obj/"):
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


def test_dropped_schedule_wake_only_delays_the_next_facttree_diff(tmp_path):
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
        assert old_hint.root_oid == new_hint.root_oid
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
    ]}
    monkeypatch.setattr(manage, "_api", lambda *args, **kwargs: rules)

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
    assert "full_peer" not in scanner.__file__


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
    values = dict(config["vars"])
    if role is not None:
        values["POC16_DEPLOYMENT_ROLE"] = role
    return [{"name": name, "type": "plain_text", "text": value}
            for name, value in values.items()]


def test_candidate_validation_rejects_wrong_role_at_expected_name(
        monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST,
        release_id=RELEASE_ID)[1]
    monkeypatch.setattr(
        manage, "_version_bindings",
        lambda role, candidate, version: _candidate_bindings(
            candidate, role="notification-consumer"))

    with pytest.raises(RuntimeError, match="markers differ"):
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
        manage, "_version_bindings", lambda role, candidate, version: bindings)

    with pytest.raises(RuntimeError, match="markers differ"):
        manage._require_candidate(
            "scanner", config, WORKER_VERSIONS["scanner"])


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
        if checks == 2:
            raise RuntimeError("concurrent notification deployment")

    monkeypatch.setattr(manage, "_require_snapshot", require_snapshot)
    monkeypatch.setattr(
        manage, "_attach_effects", lambda values: calls.append("attach"))
    monkeypatch.setattr(
        manage, "_detach_effects", lambda values: calls.append("detach"))

    with pytest.raises(RuntimeError, match="concurrent"):
        manage._activate_effects(configs, WORKER_VERSIONS)

    assert calls == ["check", "attach", "check", "detach"]


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
    {"CF_NOTIFICATION_STATE_BUCKET": "notification-state-other"},
    {"CF_PUSH_NODE_PUBLIC": "f" * 64},
    {"CF_FIREBASE_PROJECT_ID": "firebase-other"},
    {"CF_FIREBASE_APPLICATION": "another.app"},
])
def test_immutable_binding_changes_rotate_deployment_identity(change):
    old = manage.generated_configs(_manage_environment())[1]
    new = manage.generated_configs(_manage_environment(**change))[1]
    assert old["vars"]["POC16_DEPLOYMENT_IDENTITY"] \
        != new["vars"]["POC16_DEPLOYMENT_IDENTITY"]


def test_queue_and_dlq_replacement_preserves_semantic_cursor_owner():
    old = manage.generated_configs(_manage_environment())[1]
    replacement = manage.generated_configs(_manage_environment(
        CF_NOTIFICATION_QUEUE="notification-other",
        CF_NOTIFICATION_DLQ="notification-other-dlq"))[1]

    assert old["vars"]["POC16_DEPLOYMENT_IDENTITY"] \
        == replacement["vars"]["POC16_DEPLOYMENT_IDENTITY"]
    assert old["queues"]["producers"][0]["queue"] \
        != replacement["queues"]["producers"][0]["queue"]


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
    monkeypatch.setattr(manage, "_require_harness_absent", lambda values: None)
    monkeypatch.setattr(manage, "_require_bootstrap_sealed", lambda value: None)
    monkeypatch.setattr(manage, "_require_secret", lambda *args: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects", lambda *args: None)
    monkeypatch.setattr(manage, "_require_effects_attached", lambda values: None)
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *args, **kwargs: SimpleNamespace(stdout="queue\n"))

    manage.verify()

    assert owned == [RELEASE_ID] * 4


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
        if config["vars"]["POC16_DEPLOYMENT_ROLE"] \
                == "notification-launch-harness":
            return manage._ABSENT
        role = manage._config_role(config)
        return manage._expected_markers(configs[manage.ROLE_KEYS.index(role)])

    monkeypatch.setattr(manage, "_worker_markers", markers)
    monkeypatch.setattr(
        manage, "_active_version",
        lambda config: WORKER_VERSIONS[manage._config_role(config)])
    monkeypatch.setattr(manage, "_require_bootstrap_sealed", lambda value: None)
    monkeypatch.setattr(manage, "_require_secret", lambda *args: None)
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
    harness = manage._harness_config(configs, {})

    assert harness["services"] == [{
        "binding": "FCM_BOUNDARY", "service": configs[3]["name"]}]
    assert "r2_buckets" not in harness
    assert "queues" not in harness
    assert harness["vars"]["POC16_RELEASE_ID"] == RELEASE_ID
    assert harness["vars"]["POC16_DEPLOYMENT_ROLE"] \
        == "notification-launch-harness"
    assert harness["main"].endswith("launch_harness/worker.mjs")


def test_production_enable_rejects_a_live_temporary_harness(monkeypatch):
    configs = manage.generated_configs(
        _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        software_digest=SOFTWARE_DIGEST, release_id=RELEASE_ID,
        launch_gate=False)
    monkeypatch.setattr(
        manage, "_worker_markers", lambda config: _release(
            "notification-launch-harness"))

    with pytest.raises(RuntimeError, match="remove the temporary"):
        manage._require_harness_absent(configs)


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
    monkeypatch.setattr(manage, "_worker_markers", lambda config: (
        config["vars"]["POC16_DEPLOYMENT_OWNER"],
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"], SOFTWARE_DIGEST,
        RELEASE_ID, "0", config["vars"]["POC16_DEPLOYMENT_ROLE"],
    ))
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
    monkeypatch.setattr(
        manage, "_promote",
        lambda role, config, version: calls.append(("promote", role, version)))
    monkeypatch.setattr(
        manage, "_active_version", lambda config: WORKER_VERSIONS["scanner"])
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *arguments, **options: calls.append(("wrangler", arguments)))

    manage._deploy_scanner_mode(mode)

    assert ("upload", "scanner") in calls
    assert ("promote", "scanner", WORKER_VERSIONS["scanner"]) in calls
    assert not any(
        call[0] == "wrangler" and call[1][0] == "deploy" for call in calls)


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
    monkeypatch.setattr(
        manage, "_attach_effects", lambda configs: attached.append(True))

    def worker_markers(config):
        if config["vars"]["POC16_DEPLOYMENT_ROLE"] \
                == "notification-launch-harness":
            return manage._ABSENT
        return markers[manage._config_role(config)]

    def active_version(config):
        return active[manage._config_role(config)]

    def promote(role, config, version):
        promotions.append(role)
        active[role] = version
        markers[role] = manage._expected_markers(config)

    monkeypatch.setattr(manage, "_worker_markers", worker_markers)
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
