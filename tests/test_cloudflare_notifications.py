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

    async def send(self, document):
        await asyncio.sleep(0)
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

    accepted = run(FcmServiceBinding(service).send(_request()))

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
        run(FcmServiceBinding(FcmService([response])).send(_request()))


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
    def __init__(self, workspace, bucket):
        self.env = SimpleNamespace(
            POC16_DEPLOYMENT_ROLE="notification-canonical-reader",
            POC16_DEPLOYMENT_IDENTITY="e" * 64,
            WORKSPACE=workspace,
            CANONICAL_PREFIX=f"workspaces/{workspace}",
            CANONICAL=bucket,
        )

    async def get_bounded(self, key, maximum):
        return await reader.get_bounded(self.env, key, maximum)

    async def read_versioned(self, key, maximum):
        return await reader.read_versioned(self.env, key, maximum)


class StateService:
    def __init__(self, scanner_env):
        self.env = scanner_env

    async def get_bounded(self, key, maximum):
        return await scanner.get_state_bounded(self.env, key, maximum)

    async def pending(self, body_oid):
        return await scanner.pending(self.env, body_oid)

    async def complete(self, body_oid):
        return await scanner.complete(self.env, body_oid)


def _scanner_env(
        workspace, canonical_reader, state, queue, *, enabled="1",
        identity="e" * 64, bootstrap="none"):
    return SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="notification-scanner",
        POC16_DEPLOYMENT_IDENTITY=identity,
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
        workspace, CanonicalReadService(workspace, canonical), state, queue,
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
    reader_service = CanonicalReadService(workspace, canonical)
    first = _scanner_env(
        workspace, reader_service, state, queue_a, identity="a" * 64)
    foreign = _scanner_env(
        workspace, reader_service, state, queue_b, identity="b" * 64)

    run(_bootstrap(first, "current"))
    run(_scan_idle(first))

    with pytest.raises(ValueError, match="cursor owner"):
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
            disabled, software_digest=software_digest)
    return manage._mobile_launch_binding((
        reader_config, scanner_config, consumer_config, fcm_config))


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
def test_explicit_bootstrap_mode_schedules_only_the_scanner(mode):
    ordinary = manage.generated_configs(_manage_environment())
    reader_config, scanner_config, consumer_config, fcm_config = \
        manage.generated_configs(
            _manage_environment(), bootstrap_mode=mode)

    assert scanner_config["vars"]["NOTIFICATION_BOOTSTRAP_MODE"] == mode
    assert scanner_config["triggers"]["crons"] == ["* * * * *"]
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


def test_launch_gate_enables_exact_bounded_queue_configuration(tmp_path):
    environment = _with_launch_records(
        tmp_path, _manage_environment(CF_NOTIFICATIONS_ENABLED="1"))
    (_reader_config, scanner_config, consumer_config, _fcm_config) = \
        manage.generated_configs(
            environment, software_digest=SOFTWARE_DIGEST)

    assert scanner_config["triggers"]["crons"] == ["* * * * *"]
    row, = consumer_config["queues"]["consumers"]
    assert row == {
        "queue": "poc16-notify-aaaaaaaaaaaa",
        "max_batch_size": 10,
        "max_batch_timeout": 5,
        "max_retries": 25,
        "dead_letter_queue": "poc16-notify-aaaaaaaaaaaa-dlq",
        "max_concurrency": 4,
        "retry_delay": 30,
    }


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
            software_digest=SOFTWARE_DIGEST)


def test_enable_requires_both_mobile_platforms(tmp_path):
    environment = _with_launch_records(
        tmp_path, _manage_environment(CF_NOTIFICATIONS_ENABLED="1"),
        platforms=("ios",))

    with pytest.raises(RuntimeError, match="android.*required"):
        manage.generated_configs(
            environment, software_digest=SOFTWARE_DIGEST)


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
            environment, software_digest=SOFTWARE_DIGEST)


def test_launch_records_for_old_software_cannot_enable_new_code(tmp_path):
    environment = _with_launch_records(
        tmp_path, _manage_environment(CF_NOTIFICATIONS_ENABLED="1"))

    with pytest.raises(RuntimeError, match="invalid ios"):
        manage.generated_configs(
            environment, software_digest="e" * 64)


def test_nonproduction_test_enablement_does_not_claim_mobile_launch_gate():
    _reader, scanner_config, consumer_config, _fcm = \
        manage.generated_configs(_manage_environment(
            CF_FIREBASE_ENVIRONMENT="staging",
            CF_FIREBASE_TEST_PROJECT_ID="firebase-project",
            CF_NOTIFICATIONS_ENABLED="1",
            CF_NOTIFICATION_TEST_MODE="1"))

    assert scanner_config["triggers"]["crons"] == ["* * * * *"]
    assert consumer_config["queues"]["consumers"]
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
        monkeypatch, capsys):
    environment = _manage_environment(CF_NOTIFICATIONS_ENABLED="1")
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        manage, "_prepare_software", lambda: SOFTWARE_DIGEST)

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
        "POC16_CLOUDFLARE_ACCOUNT_ID": "c" * 32,
        "NOTIFICATIONS_ENABLED": "0",
        "NOTIFICATION_TEST_MODE": "0",
        "FCM_APPLICATION": "poc16.mobile",
        "FCM_ENVIRONMENT": "production",
        "FCM_PROJECT_ID": "firebase-project",
    }
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


@pytest.mark.parametrize("change", [
    {"CLOUDFLARE_ACCOUNT_ID": "d" * 32},
    {"CF_WORKSPACE": "f" * 64},
    {"CF_CANONICAL_BUCKET": "canonical-other"},
    {"CF_NOTIFICATION_STATE_BUCKET": "notification-state-other"},
    {"CF_NOTIFICATION_QUEUE": "notification-other"},
    {"CF_NOTIFICATION_DLQ": "notification-other-dlq"},
    {"CF_PUSH_NODE_PUBLIC": "f" * 64},
    {"CF_FIREBASE_PROJECT_ID": "firebase-other"},
    {"CF_FIREBASE_APPLICATION": "another.app"},
])
def test_immutable_binding_changes_rotate_deployment_identity(change):
    old = manage.generated_configs(_manage_environment())[1]
    new = manage.generated_configs(_manage_environment(**change))[1]
    assert old["vars"]["POC16_DEPLOYMENT_IDENTITY"] \
        != new["vars"]["POC16_DEPLOYMENT_IDENTITY"]


def test_same_owner_cannot_rebind_an_existing_worker(monkeypatch):
    old = manage.generated_configs(_manage_environment())[1]
    changed = manage.generated_configs(_manage_environment(
        CF_NOTIFICATION_QUEUE="notification-other"))[1]
    monkeypatch.setattr(
        manage, "_worker_markers",
        lambda config: (
            old["vars"]["POC16_DEPLOYMENT_OWNER"],
            old["vars"]["POC16_DEPLOYMENT_IDENTITY"],
            old["vars"]["POC16_SOFTWARE_DIGEST"],
            "0",
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
                    ("NOTIFICATIONS_ENABLED", "1"))]
    monkeypatch.setattr(
        manage, "_worker_bindings",
        lambda _config, environment=None:
            calls.append(_config["name"]) or bindings)

    assert manage._worker_markers(config) == (
        "production-owner",
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        SOFTWARE_DIGEST,
        "1",
    )
    assert calls == [config["name"]]


def test_disabled_deploy_may_replace_software_before_retesting(monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    monkeypatch.setattr(manage, "_worker_markers", lambda _config: (
        config["vars"]["POC16_DEPLOYMENT_OWNER"],
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        "e" * 64,
        "0",
    ))

    manage._require_deployable(config, create=False)


def test_production_enable_rejects_untested_incumbent_software(monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    config["vars"]["NOTIFICATIONS_ENABLED"] = "1"
    monkeypatch.setattr(manage, "_worker_markers", lambda _config: (
        config["vars"]["POC16_DEPLOYMENT_OWNER"],
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        "e" * 64,
        "0",
    ))

    with pytest.raises(RuntimeError, match="disable.*changing software"):
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
        "1",
    ))

    with pytest.raises(RuntimeError, match="disable the incumbent software"):
        manage._require_deployable(config, create=False)


def test_same_software_can_be_disabled_before_upgrade(monkeypatch):
    config = manage.generated_configs(
        _manage_environment(), software_digest=SOFTWARE_DIGEST)[1]
    monkeypatch.setattr(manage, "_worker_markers", lambda _config: (
        config["vars"]["POC16_DEPLOYMENT_OWNER"],
        config["vars"]["POC16_DEPLOYMENT_IDENTITY"],
        SOFTWARE_DIGEST,
        "1",
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


@pytest.mark.parametrize("mode", ["current", "backfill", "none"])
def test_bootstrap_commands_only_redeploy_the_owned_scanner(
        monkeypatch, mode):
    calls = []
    configs = manage.generated_configs(
        _manage_environment(), bootstrap_mode=mode)
    monkeypatch.setattr(
        manage, "_prepare_software",
        lambda: calls.append(("prepare",)) or SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "generated_configs",
        lambda *, bootstrap_mode, software_digest: configs)
    monkeypatch.setattr(
        manage, "_write_configs", lambda value: calls.append(("write", value)))
    monkeypatch.setattr(
        manage, "_require_owned",
        lambda config: calls.append(("owned", config["name"])))
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects",
        lambda reader_config, scanner_config: calls.append(("retained",)))
    monkeypatch.setattr(
        manage, "_pywrangler",
        lambda *arguments, **options: calls.append(
            ("pywrangler", arguments, options)))

    manage._deploy_scanner_mode(mode)

    assert calls[0] == ("prepare",)
    assert calls[1] == ("write", configs)
    assert calls[2] == ("owned", configs[1]["name"])
    assert calls[3] == ("retained",)
    assert calls[4] == (
        "pywrangler",
        ("deploy", "--strict", "--config", str(manage.SCANNER_CONFIG)),
        {},
    )
    assert calls[5] == ("owned", configs[1]["name"])


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


def test_deploy_installs_private_fcm_bridge_and_secret_before_consumer(
        monkeypatch):
    configs = manage.generated_configs(_manage_environment())
    calls = []
    firebase_secret = json.dumps({
        "project_id": "firebase-project",
        "client_email": "worker@example.test",
        "private_key": "private-key",
    })
    monkeypatch.setenv("CF_PUSH_NODE_SECRET", "b" * 64)
    monkeypatch.setenv("FIREBASE_SERVICE_ACCOUNT_JSON", firebase_secret)
    monkeypatch.setattr(
        manage, "_prepare_software",
        lambda: calls.append(("prepare",)) or SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "generated_configs", lambda *, software_digest: configs)
    monkeypatch.setattr(manage, "_write_configs", lambda value: None)
    monkeypatch.setattr(
        manage, "_require_deployable", lambda config, create: None)
    monkeypatch.setattr(
        manage, "_require_retained_notification_objects",
        lambda reader_config, scanner_config: None)
    monkeypatch.setattr(
        manage, "_require_owned", lambda config: calls.append(
            ("owned", config["name"])))
    monkeypatch.setattr(
        manage, "_wrangler",
        lambda *arguments, **options: calls.append(
            ("wrangler", arguments, options)))
    monkeypatch.setattr(
        manage, "_pywrangler",
        lambda *arguments, **options: calls.append(
            ("pywrangler", arguments, options)))
    monkeypatch.setattr(manage, "_stage_locked", lambda digest: None)

    manage.deploy()

    effects = [call for call in calls if call[0] in {"wrangler", "pywrangler"}]
    assert effects[0][0:2] == (
        "wrangler", ("deploy", "--config", str(manage.FCM_CONFIG)))
    assert effects[1] == (
        "wrangler",
        ("secret", "put", "FIREBASE_SERVICE_ACCOUNT_JSON",
         "--config", str(manage.FCM_CONFIG)),
        {"input_text": firebase_secret + "\n"},
    )
    assert [call[1][0] for call in effects[2:]] == [
        "deploy", "deploy", "deploy"]
    assert str(manage.CONSUMER_CONFIG) in effects[3][1]
    assert str(manage.SCANNER_CONFIG) in effects[4][1]


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
