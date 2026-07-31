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
from adapters.cloudflare.queue import (
    CloudflareQueueCarrier,
    MAX_CLOUDFLARE_QUEUE_BODY_BYTES,
    delivery_from_message,
)
from adapters.r2.reader import R2ReadBindingStore
from core.crypto import h, keypair
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
from deploy.cloudflare_notifications import consumer, manage, reader, scanner


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
            WORKSPACE=workspace,
            CANONICAL_PREFIX=f"workspaces/{workspace}",
            CANONICAL=bucket,
        )

    async def get_bounded(self, key, maximum):
        return await reader.get_bounded(self.env, key, maximum)

    async def read_versioned(self, key, maximum):
        return await reader.read_versioned(self.env, key, maximum)


class StateReadService:
    def __init__(self, scanner_env):
        self.env = scanner_env

    async def get_bounded(self, key, maximum):
        return await scanner.get_state_bounded(self.env, key, maximum)


def _scanner_env(workspace, canonical_reader, state, queue, *, enabled="1"):
    return SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="notification-scanner",
        NOTIFICATIONS_ENABLED=enabled,
        WORKSPACE=workspace,
        NOTIFICATION_STATE_PREFIX=f"notifications/v1/{workspace}",
        CANONICAL_READER=canonical_reader,
        NOTIFICATION_STATE=state,
        NOTIFICATION_QUEUE=queue,
    )


def _consumer_env(
        workspace, canonical_reader, state_reader, secret, fcm, *, enabled="1"):
    return SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="notification-consumer",
        NOTIFICATIONS_ENABLED=enabled,
        WORKSPACE=workspace,
        PUSH_NODE_SECRET=secret.encode().hex(),
        CANONICAL_READER=canonical_reader,
        NOTIFICATION_STATE_READER=state_reader,
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


def _published_world(tmp_path):
    node, workspace, secret = _world(tmp_path)
    event = message.post(node, workspace, "general", "hello", ts=4)
    canonical, state, queue = R2Bucket(), R2Bucket(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    canonical_reader = CanonicalReadService(workspace, canonical)
    scan_env = _scanner_env(workspace, canonical_reader, state, queue)
    statuses = run(_scan_idle(scan_env))
    assert "published" in statuses
    assert len(queue.bodies) == 1
    assert decode_hint(queue.bodies[0].encode()).facts == (event,)
    return (
        node, workspace, secret, event, canonical, state, queue,
        canonical_reader, StateReadService(scan_env))


def test_actual_r2_scanner_and_queue_consumer_share_one_awaited_path(
        tmp_path):
    (_node, workspace, secret, _event, canonical, state, queue,
     canonical_reader, state_reader) = _published_world(tmp_path)
    fcm = FcmService()
    item = QueueMessage(queue.bodies[0])

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_reader, secret, fcm),
        SimpleNamespace(messages=[item])))

    assert item.action == "ack"
    assert len(fcm.documents) == 1
    assert fcm.documents[0]["fid"] == "firebase-installation-id"
    assert any(call[0] == "get" for call in canonical.calls)
    assert any(call[0] == "get" for call in state.calls)


@pytest.mark.parametrize("mutate", [
    lambda node, workspace, event: preference.set_global(
        node, workspace, preference.NONE, ts=5),
    lambda node, workspace, event: delete.remove(
        node, workspace, event, ts=5),
])
def test_delayed_cloudflare_work_uses_current_mute_or_suppression(
        tmp_path, mutate):
    (node, workspace, secret, event, canonical, state, queue,
     canonical_reader, state_reader) = _published_world(tmp_path)
    mutate(node, workspace, event)
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    fcm, item = FcmService(), QueueMessage(queue.bodies[0])

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_reader, secret, fcm),
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
    run(_scan_idle(env))
    queue.bodies.clear()

    event = message.post(node, workspace, "general", "after-wake", ts=10)
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    # No queue effect occurs while both the optional wake and one schedule
    # are absent.  The next ordinary schedule resumes from durable state.
    assert queue.bodies == []
    run(_scan_idle(env))

    assert decode_hint(queue.bodies[0].encode()).facts == (event,)


def test_concurrent_cloudflare_scanners_duplicate_but_cursor_cas_wins(
        tmp_path):
    node, workspace, _secret = _world(tmp_path)
    canonical, state, queue = R2Bucket(), R2Bucket(), Queue()
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    env = _scanner_env(
        workspace, CanonicalReadService(workspace, canonical), state, queue)
    run(_scan_idle(env))
    queue.bodies.clear()
    message.post(node, workspace, "general", "race", ts=10)
    _copy_repository(
        node, workspace, canonical, f"workspaces/{workspace}")
    # Pin the target but refuse carrier acceptance.  Both racing invocations
    # now start from the same durable target/cursor token.
    queue.fail = True
    with pytest.raises(PublishOutcomeUnknown):
        run(scanner.scan(env))
    queue.fail = False
    queue.bodies.clear()
    queue.barrier = asyncio.Barrier(2)

    async def race():
        return await asyncio.gather(scanner.scan(env), scanner.scan(env))

    statuses = run(race())

    assert sorted(statuses) == ["published", "raced"]
    assert len(queue.bodies) == 2
    assert queue.bodies[0] == queue.bodies[1]


def test_consumer_acknowledges_poison_and_retries_only_retryable_work(
        tmp_path):
    (_node, workspace, secret, _event, canonical, state, queue,
     canonical_reader, state_reader) = _published_world(tmp_path)
    service = FcmService([
        {"status": "retry"},
        {"status": "accepted", "message_id": "accepted"},
    ])
    poison = QueueMessage({"not": "text"}, "poison", 25)
    retry = QueueMessage(queue.bodies[0], "retry", 24)
    accepted = QueueMessage(queue.bodies[0], "accepted", 1)

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_reader, secret, service),
        SimpleNamespace(messages=[poison, retry, accepted])))

    assert poison.action == "ack"
    assert retry.action == "retry"
    assert retry.delay == consumer.RETRY_DELAY_SECONDS
    assert accepted.action == "ack"


def test_consumer_bounds_hostile_batches_before_any_delivery(tmp_path):
    (_node, workspace, secret, _event, canonical, state, queue,
     canonical_reader, state_reader) = _published_world(tmp_path)
    messages = [
        QueueMessage(queue.bodies[0], f"m-{number}")
        for number in range(consumer.MAX_BATCH_SIZE + 1)
    ]
    fcm = FcmService()

    run(consumer.consume(
        _consumer_env(
            workspace, canonical_reader, state_reader, secret, fcm),
        SimpleNamespace(messages=messages)))

    assert {item.action for item in messages} == {"retry"}
    assert fcm.documents == []


def _manage_environment(**extra):
    return {
        "CF_WORKSPACE": "a" * 64,
        "CF_DEPLOYMENT_OWNER": "production-owner",
        "CF_CANONICAL_BUCKET": "canonical",
        "CF_NOTIFICATION_STATE_BUCKET": "notification-state",
        "CF_FIREBASE_APPLICATION": "poc16.mobile",
        "CF_FIREBASE_ENVIRONMENT": "production",
        **extra,
    }


def test_generated_deployment_is_disabled_and_effectless_by_default():
    reader_config, scanner_config, consumer_config, fcm_config = \
        manage.generated_configs(_manage_environment())

    assert scanner_config["triggers"]["crons"] == []
    assert consumer_config["queues"]["consumers"] == []
    assert scanner_config["vars"]["NOTIFICATIONS_ENABLED"] == "0"
    assert consumer_config["vars"]["NOTIFICATIONS_ENABLED"] == "0"
    assert fcm_config["workers_dev"] is False
    assert fcm_config["routes"] == []


def test_launch_gate_enables_exact_bounded_queue_configuration():
    (_reader_config, scanner_config, consumer_config, _fcm_config) = \
        manage.generated_configs(_manage_environment(
            CF_NOTIFICATIONS_ENABLED="1", CF_MOBILE_LAUNCH_GATE="1"))

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


def test_enable_is_rejected_without_real_mobile_launch_gate():
    with pytest.raises(ValueError, match="iOS and Android"):
        manage.generated_configs(_manage_environment(
            CF_NOTIFICATIONS_ENABLED="1"))


def test_nonproduction_test_enablement_does_not_claim_mobile_launch_gate():
    _reader, scanner_config, consumer_config, _fcm = \
        manage.generated_configs(_manage_environment(
            CF_FIREBASE_ENVIRONMENT="staging",
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
    assert fcm_config["vars"] == {
        "POC16_DEPLOYMENT_OWNER": "production-owner",
        "POC16_DEPLOYMENT_ROLE": "notification-fcm-boundary",
        "FCM_APPLICATION": "poc16.mobile",
        "FCM_ENVIRONMENT": "production",
    }
    assert consumer_config["services"] == [
        {
            "binding": "CANONICAL_READER",
            "service": "poc16-notify-read-aaaaaaaaaaaa",
        },
        {
            "binding": "NOTIFICATION_STATE_READER",
            "service": "poc16-notify-scan-aaaaaaaaaaaa",
        },
        {"binding": "FCM_BOUNDARY", "service": "poc16-fcm-boundary"},
    ]
    assert "repository_applier.py" not in manage.CORE_MODULES
    assert "full_peer" not in scanner.__file__


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
    monkeypatch.setattr(manage, "sync", lambda: calls.append(("sync",)))
    monkeypatch.setattr(manage, "generated_configs", lambda: configs)
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
    monkeypatch.setattr(manage, "_require_owned", lambda config: None)
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
