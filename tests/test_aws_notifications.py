"""AWS Lambdas exercise the shared scanner and current-authority worker."""
import asyncio
import base64
from dataclasses import dataclass
import hashlib
import sys
import traceback
from types import ModuleType, SimpleNamespace

import facts
import pytest
from core.crypto import h, keypair, load_sk
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
from notifications.discovery import (
    CursorNotInitialized,
    NotificationDiscovery,
    NotificationState,
)
from notifications.hints import decode_hint
from notifications.worker import NotificationWorker
from adapters.aws import SqsCarrier
from deploy.aws_notifications import app
from deploy.aws_notifications.config import (
    DIRECT_SMOKE_RESULT_SCHEMA,
    DIRECT_SMOKE_SCHEMA,
)


ARN = "arn:aws:sqs:us-west-2:123456789012:poc16-notifications"
URL = (
    "https://sqs.us-west-2.amazonaws.com/"
    "123456789012/poc16-notifications"
)
OWNER = "c" * 64


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


def test_delivery_composes_shared_notification_state_for_cursor_completion(
        tmp_path, monkeypatch):
    workspace = "a" * 64
    canonical = FsStore(str(tmp_path / "canonical"))
    operational = FsStore(str(tmp_path / "operational"))
    push_secret, _push_node = keypair()
    stores = {
        "TINYP2P_NOTIFICATION_CANONICAL_BUCKET": canonical,
        "TINYP2P_NOTIFICATION_STATE_BUCKET": operational,
    }
    monkeypatch.setattr(app, "_delivery_cache", None)
    monkeypatch.setattr(app, "_workspace", lambda: workspace)
    monkeypatch.setattr(app, "_notification_owner", lambda: OWNER)
    monkeypatch.setattr(
        app, "_store", lambda bucket, _prefix, **_kwargs: stores[bucket])
    monkeypatch.setattr(
        app, "_push_provider", lambda: (push_secret, Push([])))

    configured = app._delivery_dependencies()

    assert configured[0] == workspace
    assert isinstance(configured[1], NotificationState)
    assert configured[1].owner == OWNER
    assert configured[1].store.store is operational


def test_cursor_owner_binds_namespace_partition_and_delivery_domain_only(
        monkeypatch):
    semantic = {
        "TINYP2P_NOTIFICATION_AWS_PARTITION": "aws",
        "TINYP2P_NOTIFICATION_CANONICAL_BUCKET": "canonical-bucket",
        "TINYP2P_NOTIFICATION_CANONICAL_PREFIX": "canonical/workspace",
        "TINYP2P_NOTIFICATION_DELIVERY_DOMAIN_ID": "d" * 64,
        "TINYP2P_NOTIFICATION_EXPECTED_BUCKET_OWNER": "123456789012",
        "TINYP2P_NOTIFICATION_STATE_BUCKET": "notification-state",
        "TINYP2P_NOTIFICATION_STATE_PREFIX": "notification/workspace",
        "TINYP2P_NOTIFICATION_WORKSPACE_ID": "a" * 64,
    }
    nonsemantic = {
        "TINYP2P_NOTIFICATION_DEPLOYMENT_ID": "notify-west",
        "TINYP2P_NOTIFICATION_PUSH_NODE_ID": "b" * 64,
        "TINYP2P_NOTIFICATION_SECRET_ARN": "secret-arn",
        "TINYP2P_NOTIFICATION_SECRET_VERSION_ID": "v" * 32,
        "TINYP2P_NOTIFICATION_SOFTWARE_DIGEST": "e" * 64,
    }
    for name, value in {**semantic, **nonsemantic}.items():
        monkeypatch.setenv(name, value)
    baseline = app._notification_owner()

    for name, value in semantic.items():
        changed = "c" * 64 if name.endswith((
            "DOMAIN_ID", "WORKSPACE_ID")) else value + "-changed"
        if name.endswith("EXPECTED_BUCKET_OWNER"):
            changed = "210987654321"
        if name.endswith("AWS_PARTITION"):
            changed = "aws-cn"
        monkeypatch.setenv(name, changed)
        assert app._notification_owner() != baseline
        monkeypatch.setenv(name, value)

    for name, value in nonsemantic.items():
        monkeypatch.setenv(name, value + "-rotated")
        assert app._notification_owner() == baseline
        monkeypatch.setenv(name, value)

    monkeypatch.setenv("TINYP2P_NOTIFICATION_AWS_PARTITION", "invalid")
    with pytest.raises(RuntimeError, match="partition"):
        app._notification_owner()


def test_secret_parse_failures_never_echo_secret_material(monkeypatch):
    material = "private-key-must-not-appear"
    version = "a" * 32
    arn = (
        "arn:aws:secretsmanager:us-west-2:123456789012:"
        "secret:poc16/notification-AbCdEf")
    requests = []

    class Secrets:
        def get_secret_value(self, **request):
            requests.append(request)
            return {
                "ARN": arn,
                "SecretString": material,
                "VersionId": version,
            }

    monkeypatch.setenv("TINYP2P_NOTIFICATION_SECRET_ARN", arn)
    monkeypatch.setenv("TINYP2P_NOTIFICATION_SECRET_VERSION_ID", version)
    try:
        app._secret(Secrets())
    except RuntimeError as error:
        assert material not in str(error)
        assert material not in "".join(traceback.format_exception(error))
    else:
        raise AssertionError("malformed secret was accepted")
    assert requests == [{"SecretId": arn, "VersionId": version}]


def test_secret_response_cannot_substitute_another_version(monkeypatch):
    arn = (
        "arn:aws:secretsmanager:us-west-2:123456789012:"
        "secret:poc16/notification-AbCdEf")
    requested = "a" * 32

    class Secrets:
        def get_secret_value(self, **request):
            assert request == {"SecretId": arn, "VersionId": requested}
            return {
                "ARN": arn,
                "SecretString": "private-material",
                "VersionId": "b" * 32,
            }

    monkeypatch.setenv("TINYP2P_NOTIFICATION_SECRET_ARN", arn)
    monkeypatch.setenv(
        "TINYP2P_NOTIFICATION_SECRET_VERSION_ID", requested)
    with pytest.raises(RuntimeError, match="secret binding"):
        app._secret(Secrets())


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
    push_secret = load_sk("11" * 32)
    monkeypatch.setenv(
        "TINYP2P_NOTIFICATION_PUSH_NODE_ID",
        push_secret.verify_key.encode().hex())
    monkeypatch.setenv(
        "TINYP2P_NOTIFICATION_DELIVERY_DOMAIN_ID",
        app.delivery_domain_id(
            push_secret.verify_key.encode().hex(), (
                ("poc16.mobile", "production", "one"),
                ("poc16.mobile", "staging", "two"),
            )))
    monkeypatch.setattr(app, "_secret", lambda _client: (
        push_secret,
        (
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
        ),
    ))

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
    push_secret = load_sk("11" * 32)
    monkeypatch.setenv(
        "TINYP2P_NOTIFICATION_PUSH_NODE_ID",
        push_secret.verify_key.encode().hex())
    monkeypatch.setenv(
        "TINYP2P_NOTIFICATION_DELIVERY_DOMAIN_ID",
        app.delivery_domain_id(
            push_secret.verify_key.encode().hex(), (
                ("poc16.mobile", "production", "project"),
            )))
    monkeypatch.setattr(app, "_secret", lambda _client: (
        push_secret,
        ({
            "application": "poc16.mobile",
            "environment": "production",
            "credential": {
                "private_key": private,
                "project_id": "project",
            },
        },),
    ))

    with pytest.raises(
            RuntimeError, match="notification Firebase initialization") \
            as caught:
        app._push_provider()

    assert private not in str(caught.value)
    assert private not in "".join(traceback.format_exception(caught.value))


def test_runtime_rejects_push_identity_different_from_stack(monkeypatch):
    firebase = ModuleType("firebase_admin")
    credentials = ModuleType("firebase_admin.credentials")
    boto3 = ModuleType("boto3")
    firebase.credentials = credentials
    boto3.client = lambda *_args, **_kwargs: object()
    monkeypatch.setitem(sys.modules, "firebase_admin", firebase)
    monkeypatch.setitem(sys.modules, "firebase_admin.credentials", credentials)
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setattr(app, "_sdk_config", lambda: object())
    monkeypatch.setattr(app, "_secret", lambda _client: (
        load_sk("11" * 32),
        ({
            "application": "poc16.mobile",
            "credential": {},
            "environment": "production",
        },),
    ))
    monkeypatch.setenv("TINYP2P_NOTIFICATION_PUSH_NODE_ID", "b" * 64)

    with pytest.raises(RuntimeError, match="push-node identity"):
        app._push_provider()


def test_delivery_validates_decoded_firebase_routes_before_provider_use(
        monkeypatch):
    firebase = ModuleType("firebase_admin")
    credentials = ModuleType("firebase_admin.credentials")
    boto3 = ModuleType("boto3")
    deleted = []
    credentials.Certificate = lambda value: value
    firebase.credentials = credentials
    firebase.initialize_app = lambda credential, **_kwargs: SimpleNamespace(
        project_id=credential["project_id"])
    firebase.delete_app = deleted.append
    boto3.client = lambda *_args, **_kwargs: object()
    monkeypatch.setitem(sys.modules, "firebase_admin", firebase)
    monkeypatch.setitem(sys.modules, "firebase_admin.credentials", credentials)
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setattr(app, "_sdk_config", lambda: object())
    push_secret = load_sk("11" * 32)
    push_node = push_secret.verify_key.encode().hex()
    routes = (("poc16.mobile", "production", "project-one"),)
    monkeypatch.setenv("TINYP2P_NOTIFICATION_PUSH_NODE_ID", push_node)
    monkeypatch.setenv(
        "TINYP2P_NOTIFICATION_DELIVERY_DOMAIN_ID",
        app.delivery_domain_id(push_node, routes))
    rows = ({
        "application": "poc16.mobile",
        "environment": "production",
        "credential": {"project_id": "project-one"},
    },)
    monkeypatch.setattr(app, "_secret", lambda _client: (push_secret, rows))

    secret, provider = app._push_provider()

    assert secret is push_secret
    assert provider.delivery_routes == routes
    assert deleted == []


def test_delivery_rejects_changed_firebase_project_before_provider_use(
        monkeypatch):
    firebase = ModuleType("firebase_admin")
    credentials = ModuleType("firebase_admin.credentials")
    boto3 = ModuleType("boto3")
    initialized, deleted = [], []
    credentials.Certificate = lambda value: value

    def initialize(credential, **_kwargs):
        item = SimpleNamespace(project_id=credential["project_id"])
        initialized.append(item)
        return item

    firebase.credentials = credentials
    firebase.initialize_app = initialize
    firebase.delete_app = deleted.append
    boto3.client = lambda *_args, **_kwargs: object()
    monkeypatch.setitem(sys.modules, "firebase_admin", firebase)
    monkeypatch.setitem(sys.modules, "firebase_admin.credentials", credentials)
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setattr(app, "_sdk_config", lambda: object())
    push_secret = load_sk("11" * 32)
    push_node = push_secret.verify_key.encode().hex()
    monkeypatch.setenv("TINYP2P_NOTIFICATION_PUSH_NODE_ID", push_node)
    monkeypatch.setenv(
        "TINYP2P_NOTIFICATION_DELIVERY_DOMAIN_ID",
        app.delivery_domain_id(push_node, (
            ("poc16.mobile", "production", "project-one"),)))
    monkeypatch.setattr(app, "_secret", lambda _client: (push_secret, ({
        "application": "poc16.mobile",
        "environment": "production",
        "credential": {"project_id": "project-two"},
    },)))

    with pytest.raises(RuntimeError, match="Firebase delivery domain"):
        app._push_provider()

    assert initialized == deleted == []


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
    state_store = FsStore(str(tmp_path / "notification-state"))
    carrier = QueueCarrier([])
    discovery = NotificationDiscovery(
        node.store(workspace), state_store, workspace, carrier,
        owner=OWNER, generation_factory=lambda: "e" * 64)
    asyncio.run(discovery.bootstrap_current())
    event = message.post(node, workspace, "general", "hello", ts=4)
    assert asyncio.run(discovery.run_once()).status == "published"
    raw, = carrier.bodies
    state = NotificationState(state_store, workspace, OWNER)
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


def test_dropped_schedule_wake_is_repaired_from_latest_facttree(tmp_path):
    node = FullPeer(str(tmp_path / "scanner-node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    state = FsStore(str(tmp_path / "scanner-state"))
    queue = Queue()
    carrier = SqsCarrier(queue, URL, ARN)
    asyncio.run(app.bootstrap_once(
        "current", repository=node.store(workspace), state=state,
        workspace=workspace, carrier=carrier, owner=OWNER))

    first = message.post(node, workspace, "general", "one", ts=10)
    second = message.post(node, workspace, "general", "two", ts=11)
    published = asyncio.run(app.scan_once(
        repository=node.store(workspace), state=state,
        workspace=workspace, carrier=carrier, owner=OWNER))
    first_body, = queue.bodies
    queue.bodies.clear()  # The accepted wake is dropped after cursor CAS.
    repeated = asyncio.run(app.scan_once(
        repository=node.store(workspace), state=state,
        workspace=workspace, carrier=carrier, owner=OWNER))

    assert (published.status, repeated.status) == ("published", "republished")
    assert queue.bodies == [first_body]
    hints = [decode_hint(first_body)]
    assert {fid for hint in hints for fid in hint.facts} == {first, second}
    assert len({hint.root_oid for hint in hints}) == 1


def test_concurrent_scanner_lambdas_duplicate_but_cursor_cas_advances_once(
        tmp_path):
    node = FullPeer(str(tmp_path / "race-node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    state = FsStore(str(tmp_path / "race-state"))
    asyncio.run(app.bootstrap_once(
        "current", repository=node.store(workspace), state=state,
        workspace=workspace, carrier=QueueCarrier([]), owner=OWNER))
    event = message.post(node, workspace, "general", "race", ts=10)

    # Pin the target without progressing, then let both invocations read the
    # same cursor token and publish before either CAS completes.
    try:
        asyncio.run(app.scan_once(
            repository=node.store(workspace),
            state=state,
            workspace=workspace,
            carrier=RejectCarrier(),
            owner=OWNER,
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
                owner=OWNER,
            )
            for _ in range(2)
        ))

    results = asyncio.run(race())

    assert [result.status for result in results] \
        == ["republished", "republished"]
    assert len(carrier.bodies) == 2
    assert carrier.bodies[0] == carrier.bodies[1]
    assert decode_hint(carrier.bodies[0]).facts == (event,)


def test_scanner_requires_explicit_bootstrap_before_first_fair_run(tmp_path):
    node = FullPeer(str(tmp_path / "bootstrap-node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    state = FsStore(str(tmp_path / "bootstrap-state"))
    carrier = QueueCarrier([])
    dependencies = {
        "repository": node.store(workspace),
        "state": state,
        "workspace": workspace,
        "carrier": carrier,
        "owner": OWNER,
    }

    with pytest.raises(CursorNotInitialized):
        asyncio.run(app.scan_once(**dependencies))
    cursor = asyncio.run(app.bootstrap_once("current", **dependencies))

    assert cursor.bootstrap == "current"
    assert asyncio.run(app.scan_once(**dependencies)).status == "idle"


def test_scanner_handler_accepts_only_explicit_bootstrap_event(
        monkeypatch):
    workspace = "a" * 64
    calls = []

    async def initialize(mode, **dependencies):
        calls.append((mode, dependencies))
        return SimpleNamespace(bootstrap=mode)

    monkeypatch.setenv("TINYP2P_NOTIFICATION_WORKSPACE_ID", workspace)
    monkeypatch.setattr(app, "bootstrap_once", initialize)

    response = app.scanner_handler({
        "mode": "backfill",
        "schema": "poc16-notification-bootstrap-v1",
        "workspace": workspace,
    }, None)

    assert response == {
        "mode": "backfill",
        "schema": "poc16-notification-bootstrap-result-v1",
        "status": "initialized",
    }
    assert calls == [("backfill", {"workspace": workspace})]


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

    class MissingRoot:
        def __init__(self, backing):
            self.owner = backing.owner
            self.pending = backing.pending
            self.complete = backing.complete

        async def get_bounded(self, _key, _maximum):
            return None

    missing = asyncio.run(app.deliver_batch(
        sqs, state=MissingRoot(state), worker=worker,
        workspace=workspace,
        queue_arn=ARN,
    ))
    terminal = asyncio.run(app.deliver_batch(
        sqs, state=state, worker=worker,
        workspace=workspace, queue_arn=ARN))

    assert terminal == {"batchItemFailures": []}
    assert missing == {
        "batchItemFailures": [{"itemIdentifier": "work"}],
    }


def _smoke_event(raw):
    return {
        "body": base64.b64encode(raw).decode("ascii"),
        "schema": DIRECT_SMOKE_SCHEMA,
    }


def test_direct_smoke_reports_only_clean_aggregate_acceptance(tmp_path):
    node, workspace, secret, _event, state, raw = _world(tmp_path)

    result = asyncio.run(app.direct_smoke(
        _smoke_event(raw),
        state=state,
        worker=_worker(node, secret, Push([])),
        workspace=workspace,
    ))

    assert result == {
        "accepted_count": 1,
        "retry_count": 0,
        "schema": DIRECT_SMOKE_RESULT_SCHEMA,
        "terminal_count": 0,
    }
    assert not any("fid" in name or "id" in name for name in result)


def test_direct_smoke_distinguishes_no_recipient_retry_and_terminal(
        tmp_path):
    muted, workspace, secret, _event, state, raw = _world(
        tmp_path / "muted")
    preference.set_global(muted, workspace, preference.NONE, ts=5)
    no_recipient = asyncio.run(app.direct_smoke(
        _smoke_event(raw), state=state,
        worker=_worker(muted, secret, Push([])), workspace=workspace))

    retry_node, retry_workspace, retry_secret, _event, retry_state, retry_raw \
        = _world(tmp_path / "retry")
    retry = asyncio.run(app.direct_smoke(
        _smoke_event(retry_raw), state=retry_state,
        worker=_worker(
            retry_node, retry_secret, Push([PushRetryable("quota")])),
        workspace=retry_workspace))

    bad_node, bad_workspace, bad_secret, _event, bad_state, bad_raw = _world(
        tmp_path / "invalid", invalid_endpoint=True)
    terminal = asyncio.run(app.direct_smoke(
        _smoke_event(bad_raw), state=bad_state,
        worker=_worker(bad_node, bad_secret, Push([])),
        workspace=bad_workspace))

    assert no_recipient == {
        "accepted_count": 0,
        "retry_count": 0,
        "schema": DIRECT_SMOKE_RESULT_SCHEMA,
        "terminal_count": 0,
    }
    assert retry["retry_count"] == 1
    assert retry["accepted_count"] == retry["terminal_count"] == 0
    assert terminal["terminal_count"] == 1
    assert terminal["accepted_count"] == terminal["retry_count"] == 0


def test_direct_smoke_handler_is_a_private_operator_mode(monkeypatch):
    async def smoke(event):
        return {"schema": event["schema"]}

    monkeypatch.setattr(app, "direct_smoke", smoke)
    assert app.delivery_handler({
        "body": base64.b64encode(b"hint").decode("ascii"),
        "schema": DIRECT_SMOKE_SCHEMA,
    }, None) == {"schema": DIRECT_SMOKE_SCHEMA}
