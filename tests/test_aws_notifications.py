"""AWS Lambdas exercise the shared scanner and current-authority worker."""
import asyncio
import base64
from dataclasses import dataclass
import hashlib
import sys
import traceback
from types import ModuleType

import facts
import pytest
from core.crypto import h, keypair
from core.store import FsStore
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.content import delete, message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.carrier import CarrierAccepted
from notifications.delivery import (
    PushAccepted,
    PushRetryable,
    PushUnregistered,
    seal_target,
)
from notifications.hints import (
    NotificationHint,
    decode_hint,
    encode_hint,
)
from notifications.worker import NotificationWorker
from adapters.aws import SqsCarrier
from deploy.aws_notifications import app


ARN = "arn:aws:sqs:us-west-2:123456789012:poc16-notifications"
URL = (
    "https://sqs.us-west-2.amazonaws.com/"
    "123456789012/poc16-notifications"
)


def test_scanner_state_store_is_separate_conditional_s3_namespace(
        monkeypatch):
    captured = []
    monkeypatch.setattr(
        app, "S3Store", lambda config: captured.append(config) or config)
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv(
        "TINYP2P_NOTIFICATION_EXPECTED_BUCKET_OWNER", "123456789012")
    monkeypatch.setenv("CANONICAL_BUCKET", "canonical-bucket")
    monkeypatch.setenv("CANONICAL_PREFIX", "workspaces/canonical")
    monkeypatch.setenv("STATE_BUCKET", "notification-state-bucket")
    monkeypatch.setenv("STATE_PREFIX", "notifications/workspace")

    canonical = app._store(
        "CANONICAL_BUCKET", "CANONICAL_PREFIX", state=False)
    state = app._store("STATE_BUCKET", "STATE_PREFIX", state=True)

    assert canonical.bucket == "canonical-bucket"
    assert canonical.prefix == "workspaces/canonical"
    assert canonical.conditional_write_403_is_absent is False
    assert state.bucket == "notification-state-bucket"
    assert state.prefix == "notifications/workspace"
    assert state.conditional_write_403_is_absent is True
    assert captured == [canonical, state]


def test_secret_parse_failures_never_echo_secret_material(monkeypatch):
    material = "private-key-must-not-appear"

    class Secrets:
        def get_secret_value(self, **_request):
            return {"SecretString": material}

    monkeypatch.setenv("TINYP2P_NOTIFICATION_SECRET_ARN", (
        "arn:aws:secretsmanager:us-west-2:123456789012:"
        "secret:poc16/notification-AbCdEf"))
    try:
        app._secret_document(Secrets())
    except RuntimeError as error:
        assert material not in str(error)
    else:
        raise AssertionError("malformed secret was accepted")


def test_partial_firebase_initialization_is_cleaned_before_retry(monkeypatch):
    firebase = ModuleType("firebase_admin")
    credentials = ModuleType("firebase_admin.credentials")
    boto3 = ModuleType("boto3")
    initialized, deleted = [], []
    credentials.Certificate = lambda value: value

    private = "private-service-account-material"

    def initialize(_credential, *, name):
        if name.endswith("-1"):
            raise RuntimeError(private)
        initialized.append(name)
        return name

    firebase.credentials = credentials
    firebase.initialize_app = initialize
    firebase.delete_app = deleted.append
    boto3.client = lambda *_args, **_kwargs: object()
    monkeypatch.setitem(sys.modules, "firebase_admin", firebase)
    monkeypatch.setitem(sys.modules, "firebase_admin.credentials", credentials)
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setattr(app, "_sdk_config", lambda: object())
    monkeypatch.setattr(app, "_secret_document", lambda _client: {
        "push_node_seed": "11" * 32,
        "firebase_apps": [
            {
                "application": "poc16.mobile",
                "environment": "production",
                "credential": {"project_id": "one"},
            },
            {
                "application": "poc16.mobile",
                "environment": "staging",
                "credential": {"project_id": "two"},
            },
        ],
    })

    with pytest.raises(
            RuntimeError, match="notification Firebase initialization") \
            as caught:
        app._push_provider()

    assert initialized == ["poc16-notification-0"]
    assert deleted == ["poc16-notification-0"]
    assert private not in str(caught.value)
    assert private not in "".join(traceback.format_exception(caught.value))


def test_firebase_credential_exception_is_redacted(monkeypatch):
    firebase = ModuleType("firebase_admin")
    credentials = ModuleType("firebase_admin.credentials")
    boto3 = ModuleType("boto3")
    private = "private-key-from-certificate-parser"

    def reject(_value):
        raise ValueError(private)

    credentials.Certificate = reject
    firebase.credentials = credentials
    firebase.initialize_app = lambda *_args, **_kwargs: object()
    firebase.delete_app = lambda _app: None
    boto3.client = lambda *_args, **_kwargs: object()
    monkeypatch.setitem(sys.modules, "firebase_admin", firebase)
    monkeypatch.setitem(sys.modules, "firebase_admin.credentials", credentials)
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setattr(app, "_sdk_config", lambda: object())
    monkeypatch.setattr(app, "_secret_document", lambda _client: {
        "push_node_seed": "11" * 32,
        "firebase_apps": [{
            "application": "poc16.mobile",
            "environment": "production",
            "credential": {"private_key": private},
        }],
    })

    with pytest.raises(
            RuntimeError, match="notification Firebase initialization") \
            as caught:
        app._push_provider()

    assert private not in str(caught.value)
    assert private not in "".join(traceback.format_exception(caught.value))


class Queue:
    def __init__(self):
        self.bodies = []

    def send_message(self, **request):
        self.bodies.append(base64.b64decode(
            request["MessageBody"], validate=True))
        return {
            "MD5OfMessageBody": hashlib.md5(
                request["MessageBody"].encode("ascii"),
                usedforsecurity=False,
            ).hexdigest(),
            "MessageId": f"message-{len(self.bodies)}",
        }


@dataclass
class Push:
    outcomes: list

    def __post_init__(self):
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        outcome = self.outcomes.pop(0) if self.outcomes else \
            PushAccepted(f"fcm-{len(self.requests)}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class AwaitedStore:
    """Yield between operations like two concurrent Lambda/S3 calls."""

    def __init__(self, store):
        self.store = store

    async def get_bounded(self, key, maximum):
        await asyncio.sleep(0)
        return self.store.get_bounded(key, maximum)

    async def read_versioned(self, key):
        await asyncio.sleep(0)
        return self.store.read_versioned(key)

    async def put_if_absent(self, key, value):
        await asyncio.sleep(0)
        return self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        await asyncio.sleep(0)
        return self.store.cas(key, token, value)


class RejectCarrier:
    async def publish(self, _body):
        raise OSError("queue unavailable")


class BarrierCarrier:
    def __init__(self):
        self.barrier = asyncio.Barrier(2)
        self.bodies = []

    async def publish(self, body):
        self.bodies.append(body)
        await self.barrier.wait()
        return CarrierAccepted(h(body))


def _world(tmp_path, *, invalid_endpoint=False):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    push_secret, push_node = keypair()
    target = push_endpoint.encode_sealed_target(b"x" * 49) \
        if invalid_endpoint else seal_target(
            push_node, "firebase-installation-id")
    push_endpoint.register(
        node,
        workspace,
        h(b"installation"),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        target,
        ts=2,
    )
    preference.set_global(node, workspace, preference.ALL, ts=3)
    event = message.post(node, workspace, "general", "hello", ts=4)
    root = node.reader(workspace).root_bytes
    state = FsStore(str(tmp_path / "notification-state"))
    state.put_if_absent("obj/" + h(root), root)
    raw = encode_hint(NotificationHint(workspace, h(root), (event,)))
    return node, workspace, push_secret, event, state, raw


def _worker(node, secret, provider):
    return NotificationWorker(
        lambda workspace: node.reader(workspace).root_bytes,
        lambda workspace, oid: node.store(workspace).get("obj/" + oid),
        secret,
        provider,
        lambda: 10,
    )


def _record(body, message_id="work", attempt=1):
    return {
        "attributes": {"ApproximateReceiveCount": str(attempt)},
        "body": base64.b64encode(body).decode("ascii"),
        "eventSource": "aws:sqs",
        "eventSourceARN": ARN,
        "messageId": message_id,
    }


async def _drain(repository, state, workspace, carrier, maximum=100):
    results = []
    for _ in range(maximum):
        result = await app.scan_once(
            repository=repository,
            state=state,
            workspace=workspace,
            carrier=carrier,
        )
        results.append(result)
        if result.status == "idle":
            return results
    raise AssertionError("AWS notification scanner did not become idle")


def test_dropped_schedule_wake_is_repaired_from_latest_facttree(tmp_path):
    node = FullPeer(str(tmp_path / "scanner-node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    state = FsStore(str(tmp_path / "scanner-state"))
    queue = Queue()
    carrier = SqsCarrier(queue, URL, ARN)
    asyncio.run(_drain(node.store(workspace), state, workspace, carrier))
    queue.bodies.clear()

    first = message.post(node, workspace, "general", "one", ts=10)
    # Its wake is dropped. A second publication and the next schedule are the
    # only liveness event the scanner receives.
    second = message.post(node, workspace, "general", "two", ts=11)
    asyncio.run(_drain(node.store(workspace), state, workspace, carrier))

    hints = [decode_hint(body) for body in queue.bodies]
    assert {fid for hint in hints for fid in hint.facts} == {first, second}
    assert len({hint.root_oid for hint in hints}) == 1


def test_concurrent_scanner_lambdas_duplicate_but_cursor_cas_advances_once(
        tmp_path):
    node = FullPeer(str(tmp_path / "race-node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    state = FsStore(str(tmp_path / "race-state"))
    asyncio.run(_drain(
        node.store(workspace), state, workspace, QueueCarrier([])))
    event = message.post(node, workspace, "general", "race", ts=10)

    # Pin the target without progressing, then let both invocations read the
    # same cursor token and publish before either CAS completes.
    try:
        asyncio.run(app.scan_once(
            repository=node.store(workspace),
            state=state,
            workspace=workspace,
            carrier=RejectCarrier(),
        ))
    except OSError:
        pass
    carrier = BarrierCarrier()

    async def race():
        return await asyncio.gather(*(
            app.scan_once(
                repository=AwaitedStore(node.store(workspace)),
                state=AwaitedStore(state),
                workspace=workspace,
                carrier=carrier,
            )
            for _ in range(2)
        ))

    results = asyncio.run(race())

    assert sorted(result.status for result in results) \
        == ["published", "raced"]
    assert len(carrier.bodies) == 2
    assert carrier.bodies[0] == carrier.bodies[1]
    assert decode_hint(carrier.bodies[0]).facts == (event,)


@dataclass
class QueueCarrier:
    bodies: list

    async def publish(self, body):
        self.bodies.append(body)
        return CarrierAccepted(h(body))


def test_transient_fcm_retries_same_sqs_item_until_acceptance(tmp_path):
    node, workspace, secret, _event, state, raw = _world(tmp_path)
    provider = Push([
        PushRetryable("quota"),
        PushAccepted("fcm-accepted"),
    ])
    worker = _worker(node, secret, provider)
    event = {"Records": [_record(raw)]}

    first = asyncio.run(app.deliver_batch(
        event, state=state, worker=worker,
        workspace=workspace, queue_arn=ARN))
    second = asyncio.run(app.deliver_batch(
        event, state=state, worker=worker,
        workspace=workspace, queue_arn=ARN))

    assert first == {
        "batchItemFailures": [{"itemIdentifier": "work"}],
    }
    assert second == {"batchItemFailures": []}
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id


def test_crash_after_fcm_acceptance_retries_with_same_delivery_id(tmp_path):
    node, workspace, secret, _event, state, raw = _world(tmp_path)
    provider = Push([])

    class CrashOnce(NotificationWorker):
        crashed = False

        async def process(self, hint):
            result = await super().process(hint)
            if not self.crashed:
                self.crashed = True
                raise RuntimeError("crash after FCM acceptance")
            return result

    worker = CrashOnce(
        lambda selected: node.reader(selected).root_bytes,
        lambda selected, oid: node.store(selected).get("obj/" + oid),
        secret,
        provider,
        lambda: 10,
    )
    event = {"Records": [_record(raw)]}

    first = asyncio.run(app.deliver_batch(
        event, state=state, worker=worker,
        workspace=workspace, queue_arn=ARN))
    second = asyncio.run(app.deliver_batch(
        event, state=state, worker=worker,
        workspace=workspace, queue_arn=ARN))

    assert first == {
        "batchItemFailures": [{"itemIdentifier": "work"}],
    }
    assert second == {"batchItemFailures": []}
    assert len(provider.requests) == 2
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id


def test_concurrent_delivery_lambdas_submit_same_stable_fcm_request(tmp_path):
    node, workspace, secret, _event, state, raw = _world(tmp_path)

    class ConcurrentPush:
        def __init__(self):
            self.barrier = asyncio.Barrier(2)
            self.requests = []

        async def send(self, request):
            self.requests.append(request)
            await self.barrier.wait()
            return PushAccepted(f"fcm-{len(self.requests)}")

    provider = ConcurrentPush()
    worker = _worker(node, secret, provider)
    event = {"Records": [_record(raw)]}

    async def deliver_twice():
        return await asyncio.gather(*(
            app.deliver_batch(
                event,
                state=state,
                worker=worker,
                workspace=workspace,
                queue_arn=ARN,
            )
            for _ in range(2)
        ))

    results = asyncio.run(deliver_twice())

    assert results == [
        {"batchItemFailures": []},
        {"batchItemFailures": []},
    ]
    assert len(provider.requests) == 2
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id


def test_delayed_current_mute_acknowledges_without_fcm(tmp_path):
    node, workspace, secret, _event, state, raw = _world(tmp_path)
    preference.set_global(node, workspace, preference.NONE, ts=5)
    provider = Push([])

    result = asyncio.run(app.deliver_batch(
        {"Records": [_record(raw)]},
        state=state,
        worker=_worker(node, secret, provider),
        workspace=workspace,
        queue_arn=ARN,
    ))

    assert result == {"batchItemFailures": []}
    assert provider.requests == []


def test_delayed_event_removal_acknowledges_without_fcm(tmp_path):
    node, workspace, secret, event, state, raw = _world(tmp_path)
    delete.remove(node, workspace, event, ts=5)
    provider = Push([])

    result = asyncio.run(app.deliver_batch(
        {"Records": [_record(raw)]},
        state=state,
        worker=_worker(node, secret, provider),
        workspace=workspace,
        queue_arn=ARN,
    ))

    assert result == {"batchItemFailures": []}
    assert provider.requests == []


def test_invalid_endpoint_is_terminal_and_does_not_wedge_sqs(tmp_path):
    node, workspace, secret, _event, state, raw = _world(
        tmp_path, invalid_endpoint=True)
    provider = Push([])

    result = asyncio.run(app.deliver_batch(
        {"Records": [_record(raw)]},
        state=state,
        worker=_worker(node, secret, provider),
        workspace=workspace,
        queue_arn=ARN,
    ))

    assert result == {"batchItemFailures": []}
    assert provider.requests == []


def test_unregistered_fid_is_terminal_but_missing_event_root_retries(
        tmp_path):
    node, workspace, secret, _event, state, raw = _world(tmp_path)
    provider = Push([PushUnregistered("gone")])
    worker = _worker(node, secret, provider)
    sqs = {"Records": [_record(raw)]}

    terminal = asyncio.run(app.deliver_batch(
        sqs, state=state, worker=worker,
        workspace=workspace, queue_arn=ARN))
    missing = asyncio.run(app.deliver_batch(
        sqs,
        state=FsStore(str(tmp_path / "missing-state")),
        worker=worker,
        workspace=workspace,
        queue_arn=ARN,
    ))

    assert terminal == {"batchItemFailures": []}
    assert missing == {
        "batchItemFailures": [{"itemIdentifier": "work"}],
    }
