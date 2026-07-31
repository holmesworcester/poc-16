"""Queue-to-FCM consumption, crypto, and durable discharge tests."""
from dataclasses import dataclass
import time

import pytest

import facts
from adapters.gcp.firebase import FirebaseAdminFcm
from core.crypto import h, keypair
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.content import message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.consumer import PushConsumer
from notifications.dispatcher import dispatch_page
from notifications.outbox import NotificationOutbox
from notifications.provider import (
    FcmAccepted,
    FcmPermanent,
    FcmRetryable,
    FcmUnregistered,
)
from notifications.target import open_target, seal_target
from .queue_fakes import MemoryQueueService


EVENT_TS = 1_900_000_000_000


class FakeFcm:
    def __init__(self):
        self.requests = []
        self.error = None

    def send(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return FcmAccepted(
            f"projects/test/messages/{len(self.requests)}")


def _queued(tmp_path, platform="android", *, sealed=None):
    node = FullPeer(
        str(tmp_path / "node"),
        publication_effect_factory=lambda _workspace, _store: (
            NotificationOutbox(now_ms=lambda: EVENT_TS)),
    )
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    push_secret, push_node = keypair()
    target = "firebase-installation-id-123"
    sealed = seal_target(push_node, target) if sealed is None else sealed
    endpoint = push_endpoint.register(
        node,
        workspace,
        h(b"installation"),
        push_node,
        platform,
        "poc16.mobile",
        "production",
        push_endpoint.encode_sealed_target(sealed),
        ts=EVENT_TS - 2,
    )
    preference.set_global(
        node, workspace, preference.ALL, ts=EVENT_TS - 1)
    event = message.post(
        node, workspace, "general", "provider", ts=EVENT_TS)
    service = MemoryQueueService()
    dispatched = dispatch_page(
        node.store(workspace), service.handle(), push_node)
    assert [item.status for item in dispatched.items] == ["published"]
    return (
        node, workspace, push_secret, push_node, target, endpoint, event,
        service,
    )


@pytest.mark.parametrize("platform", ["android", "apple"])
def test_consumer_decrypts_and_discharges_android_and_apple(
        tmp_path, platform):
    (node, workspace, secret, _push_node, target, endpoint, event,
     service) = _queued(tmp_path, platform)
    provider = FakeFcm()
    consumer = PushConsumer(
        node.store(workspace),
        service.handle(),
        provider,
        secret,
        lambda: EVENT_TS + 1000,
    )

    outcome, = consumer.consume(lease_seconds=10)

    assert outcome.status == "accepted"
    request, = provider.requests
    assert request.platform == platform
    assert request.target == target
    assert 0 < request.ttl_seconds <= 7 * 24 * 60 * 60
    assert node.store(workspace).get(
        "push/done/" + outcome.delivery_id) is not None
    assert service.handle().pull(lease_seconds=10) == ()
    assert endpoint in node.store(workspace).get(
        "push/done/" + outcome.delivery_id).decode()
    assert event in request.payload.decode()


def test_sealed_target_opens_only_with_selected_push_node():
    secret, public = keypair()
    other, _other_public = keypair()
    sealed = seal_target(public, "firebase-installation-id")

    assert open_target(secret, sealed) == "firebase-installation-id"
    with pytest.raises(ValueError, match="invalid sealed"):
        open_target(other, sealed)


def test_retryable_provider_error_defers_without_discharge(tmp_path):
    (node, workspace, secret, _push_node, _target, _endpoint, _event,
     service) = _queued(tmp_path)
    provider = FakeFcm()
    provider.error = FcmRetryable("quota")
    consumer = PushConsumer(
        node.store(workspace), service.handle(), provider, secret,
        lambda: EVENT_TS + 1000)

    outcome, = consumer.consume(lease_seconds=10)

    assert outcome.status == "retry"
    assert node.store(workspace).list("push/done/") == []
    assert service.history[-1][0] == "defer"
    assert 10 <= service.history[-1][2] <= 600


def test_unregistered_target_discharges_and_records_invalidation(tmp_path):
    (node, workspace, secret, _push_node, _target, endpoint, _event,
     service) = _queued(tmp_path)
    provider = FakeFcm()
    provider.error = FcmUnregistered("gone")
    consumer = PushConsumer(
        node.store(workspace), service.handle(), provider, secret,
        lambda: EVENT_TS + 1000)

    outcome, = consumer.consume(lease_seconds=10)

    assert outcome.status == "unregistered"
    invalidation, = node.store(workspace).list(
        f"push/invalidation/{endpoint}/")
    assert b'"reason":"unregistered"' \
        in node.store(workspace).get(invalidation)
    assert service.handle().pull(lease_seconds=10) == ()


def test_expired_job_is_terminal_without_calling_fcm(tmp_path):
    (node, workspace, secret, _push_node, _target, _endpoint, _event,
     service) = _queued(tmp_path)
    provider = FakeFcm()
    consumer = PushConsumer(
        node.store(workspace), service.handle(), provider, secret,
        lambda: EVENT_TS + 8 * 24 * 60 * 60 * 1000)

    outcome, = consumer.consume(lease_seconds=10)

    assert outcome.status == "expired"
    assert provider.requests == []
    assert service.handle().pull(lease_seconds=10) == ()


def test_wrong_node_is_poison_without_token_logs(tmp_path):
    (node, workspace, _secret, push_node, _target, _endpoint, _event,
     service) = _queued(tmp_path)
    wrong_secret, _wrong_public = keypair()
    provider = FakeFcm()

    outcome, = PushConsumer(
        node.store(workspace), service.handle(), provider, wrong_secret,
        lambda: EVENT_TS + 1000).consume(lease_seconds=10)

    assert outcome.status == "failed"
    assert outcome.error == "wrong-push-node"
    assert push_node not in outcome.error
    assert provider.requests == []


def test_invalid_ciphertext_is_poison_without_calling_provider(tmp_path):
    (node, workspace, secret, _push_node, _target, _endpoint, _event,
     service) = _queued(tmp_path, sealed=b"x" * 49)
    provider = FakeFcm()

    outcome, = PushConsumer(
        node.store(workspace), service.handle(), provider, secret,
        lambda: EVENT_TS + 1000).consume(lease_seconds=10)

    assert outcome.status == "failed"
    assert outcome.error == "invalid-target"
    assert provider.requests == []


def test_crash_between_fcm_acceptance_and_done_write_may_duplicate(
        tmp_path):
    (node, workspace, secret, _push_node, _target, _endpoint, _event,
     service) = _queued(tmp_path)
    backing = node.store(workspace)

    class FailDoneOnce:
        def __init__(self):
            self.failed = False

        def __getattr__(self, name):
            return getattr(backing, name)

        def put_if_absent(self, key, value):
            if key.startswith("push/done/") and not self.failed:
                self.failed = True
                raise OSError("injected done outage")
            return backing.put_if_absent(key, value)

    provider = FakeFcm()
    consumer = PushConsumer(
        FailDoneOnce(), service.handle(), provider, secret,
        lambda: EVENT_TS + 1000)

    first, = consumer.consume(lease_seconds=10)
    assert first.status == "retry"
    assert len(provider.requests) == 1
    service.records[0].visible_at = 0
    second, = consumer.consume(lease_seconds=10)

    assert second.status == "accepted"
    assert len(provider.requests) == 2
    assert provider.requests[0].delivery_id \
        == provider.requests[1].delivery_id


class _Message:
    def __init__(self, **values):
        self.__dict__.update(values)


class FakeMessagingModule:
    class Message(_Message):
        pass

    class Notification(_Message):
        pass

    class AndroidConfig(_Message):
        pass

    class APNSConfig(_Message):
        pass

    def __init__(self):
        self.sent = []
        self.error = None

    def send(self, message, app):
        self.sent.append((message, app))
        if self.error is not None:
            raise self.error
        return "projects/project/messages/message-1"


def _request():
    from notifications.provider import FcmRequest

    return FcmRequest(
        application="poc16.mobile",
        environment="production",
        platform="apple",
        target="firebase-installation-id",
        payload=b'{"kind":"mention"}',
        delivery_id="d" * 64,
        expires_at_ms=EVENT_TS + 60_000,
        ttl_seconds=60,
        kind="mention",
    )


def test_firebase_adapter_targets_fid_and_sets_both_platform_lifetimes():
    module = FakeMessagingModule()
    app = object()
    adapter = FirebaseAdminFcm(
        {("poc16.mobile", "production"): app},
        messaging_module=module,
    )

    accepted = adapter.send(_request())

    assert accepted.message_id.endswith("message-1")
    built, selected = module.sent[0]
    assert selected is app
    assert built.fid == "firebase-installation-id"
    assert built.android.ttl.total_seconds() == 60
    assert built.apns.headers == {
        "apns-collapse-id": "d" * 64,
        "apns-expiration": str((EVENT_TS + 60_000) // 1000),
    }
    assert not hasattr(built, "token")


@pytest.mark.parametrize(
    "name,expected",
    [
        ("UnregisteredError", FcmUnregistered),
        ("QuotaExceededError", FcmRetryable),
        ("UnavailableError", FcmRetryable),
        ("ThirdPartyAuthError", FcmPermanent),
        ("SenderIdMismatchError", FcmPermanent),
    ],
)
def test_firebase_adapter_classifies_provider_errors_without_details(
        name, expected):
    module = FakeMessagingModule()
    module.error = type(name, (Exception,), {})("secret provider detail")
    adapter = FirebaseAdminFcm(
        {("poc16.mobile", "production"): object()},
        messaging_module=module,
    )

    with pytest.raises(expected) as caught:
        adapter.send(_request())
    assert "secret provider detail" not in str(caught.value)
