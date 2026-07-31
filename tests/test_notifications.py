"""Authenticated facts and stateless post-publication push delivery."""

import pytest
from types import SimpleNamespace

import facts
from adapters.gcp.firebase import FirebaseAdminFcm
from core.crypto import h, keypair
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.auth.device_invite import grant
from facts.auth.signature import signature
from facts.content import message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.delivery import (
    PublicationHint,
    PushRequest,
    PushRetryable,
    PushUnregistered,
    delivery_domain_id,
    derive,
    seal_target,
)


def _firebase_app(project="firebase-project"):
    return SimpleNamespace(project_id=project)


def _world(tmp_path, name="node"):
    node = FullPeer(str(tmp_path / name))
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
        seal_target(push_node, "firebase-installation-id"),
        ts=2,
    )
    return node, workspace, push_secret, push_node, endpoint


def _fetch(node, workspace):
    return lambda oid: node.store(workspace).get("obj/" + oid)


def _hint(node, workspace, *fids):
    return PublicationHint(
        workspace,
        node.reader(workspace).root_bytes,
        tuple(sorted(set(fids))),
    )


def _root(node, workspace):
    return node.reader(workspace).root_bytes


def _author_preference(node, workspace, scope, target, mode, ts):
    secret, public = node.identity(workspace)
    item = preference.notification_preference(
        workspace, public, node.pk, scope, target, mode, ts)
    signed = signature(secret, public, item, ts)
    member = node.sql(workspace).resolve_offer(
        "member", public, node.pk)
    device = node.sql(workspace).resolve_offer(
        "device_key", public, node.pk)
    node.ingest_new(workspace, (signed, item), {
        signed.fid: (),
        item.fid: (signed.fid, member, device),
    })
    return item


def test_endpoint_rotation_hides_ciphertext_and_reuses_fact_deletion(tmp_path):
    node, workspace, _secret, push_node, first = _world(tmp_path)
    before = node.fact_of(workspace, first)
    replacement = push_endpoint.replace(
        node,
        workspace,
        first,
        push_node,
        push_endpoint.encode_sealed_target(b"y" * 49),
        ts=3,
    )

    assert node.fact_of(workspace, first) == before
    assert isinstance(before.body["sealed_target"], str)
    assert "firebase-installation-id" not in before.body["sealed_target"]
    assert node.reader(workspace).worker().fact_active(first) is False
    assert [row["fid"] for row in push_endpoint.endpoints(
        node, workspace)] == [replacement]
    assert "sealed_target" not in push_endpoint.endpoints(
        node, workspace)[0]


def test_endpoint_and_preference_require_the_owning_enrolled_device(tmp_path):
    node, workspace, _secret, push_node, _endpoint = _world(tmp_path)
    _other_secret, other = keypair()
    forged = push_endpoint.push_endpoint(
        workspace,
        node.pk,
        other,
        h(b"forged"),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        push_endpoint.encode_sealed_target(b"x" * 49),
        10,
    )
    signed = signature(node.sk, node.pk, forged, 10)
    member = node.sql(workspace).resolve_offer(
        "member", node.pk, node.pk)
    device = node.sql(workspace).resolve_offer(
        "device_key", node.pk, node.pk)

    with pytest.raises(ValueError, match="not admitted"):
        node.ingest_new(workspace, (signed, forged), {
            signed.fid: (),
            forged.fid: (signed.fid, member, device),
        })

    forged_setting = preference.notification_preference(
        workspace,
        node.pk,
        other,
        preference.GLOBAL,
        "",
        preference.ALL,
        11,
    )
    setting_signature = signature(node.sk, node.pk, forged_setting, 11)
    with pytest.raises(ValueError, match="not admitted"):
        node.ingest_new(workspace, (setting_signature, forged_setting), {
            setting_signature.fid: (),
            forged_setting.fid: (
                setting_signature.fid, member, device),
        })


def test_settings_are_user_shared_and_replace_via_ordinary_suppression(
        tmp_path):
    node, workspace, _secret, _push_node, _endpoint = _world(tmp_path)
    founder = node.pk
    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    grant(node, workspace, founder, laptop, "laptop")
    node.bind_identity(workspace, laptop)
    first = preference.set_global(
        node, workspace, preference.MENTIONS, ts=10)
    node.bind_identity(workspace, founder)
    second = preference.set_global(
        node, workspace, preference.ALL, ts=11)

    row, = preference.preferences(node, workspace, founder)
    assert row == {
        "fids": [second],
        "mode": preference.ALL,
        "scope": preference.GLOBAL,
        "target": "",
        "user": founder,
    }
    assert node.fact_of(workspace, first).body["pk"] == laptop
    assert node.reader(workspace).worker().fact_active(first) is False


def test_concurrent_settings_meet_restrictively_then_command_joins(tmp_path):
    node, workspace, _secret, _push_node, _endpoint = _world(tmp_path)
    allow = _author_preference(
        node, workspace, preference.CHANNEL, "general",
        preference.ALL, 10)
    mute = _author_preference(
        node, workspace, preference.CHANNEL, "general",
        preference.NONE, 11)
    row, = preference.preferences(node, workspace, node.pk)
    assert row["mode"] == preference.NONE
    assert row["fids"] == sorted((allow.fid, mute.fid))

    joined = preference.set_channel(
        node, workspace, "general", preference.INHERIT, ts=12)
    row, = preference.preferences(node, workspace, node.pk)
    assert row["mode"] == preference.INHERIT
    assert row["fids"] == [joined]
    assert all(not node.reader(workspace).worker().fact_active(fid)
               for fid in (allow.fid, mute.fid))


def test_setting_an_existing_value_still_retracts_concurrent_siblings(
        tmp_path):
    node, workspace, _secret, _push_node, _endpoint = _world(tmp_path)
    allow = _author_preference(
        node, workspace, preference.CHANNEL, "general",
        preference.ALL, 10)
    mute = _author_preference(
        node, workspace, preference.CHANNEL, "general",
        preference.NONE, 11)

    result = preference.set_channel(
        node, workspace, "general", preference.ALL, ts=10)

    assert result == allow.fid
    row, = preference.preferences(node, workspace, node.pk)
    assert row["fids"] == [allow.fid]
    assert node.reader(workspace).worker().fact_active(mute.fid) is False


def test_matching_uses_explicit_mentions_and_channel_override(tmp_path):
    node, workspace, _secret, _push_node, endpoint = _world(tmp_path)
    preference.set_global(node, workspace, preference.MENTIONS, ts=3)
    text = message.post(
        node, workspace, "general", "@alice is only text", ts=4)
    explicit = message.post(
        node, workspace, "general", "explicit", ts=5,
        mentions=(node.pk,))
    preference.set_channel(
        node, workspace, "quiet", preference.ALL, ts=6)
    channel = message.post(
        node, workspace, "quiet", "channel opt-in", ts=7)

    assert derive(_hint(node, workspace, text),
                  _fetch(node, workspace), _root(node, workspace)) == ()
    mention, = derive(_hint(node, workspace, explicit),
                      _fetch(node, workspace), _root(node, workspace))
    ordinary, = derive(_hint(node, workspace, channel),
                       _fetch(node, workspace), _root(node, workspace))
    assert mention.endpoint == ordinary.endpoint == endpoint
    assert mention.kind == "mention"
    assert ordinary.kind == "message"


def test_absent_and_concurrent_inherited_preferences_fail_closed(tmp_path):
    node, workspace, _secret, _push_node, _endpoint = _world(tmp_path)
    event = message.post(node, workspace, "general", "quiet", ts=3)
    assert derive(_hint(node, workspace, event),
                  _fetch(node, workspace), _root(node, workspace)) == ()

    _author_preference(
        node, workspace, preference.CHANNEL, "general",
        preference.ALL, 4)
    _author_preference(
        node, workspace, preference.CHANNEL, "general",
        preference.INHERIT, 5)
    assert derive(_hint(node, workspace, event),
                  _fetch(node, workspace), _root(node, workspace)) == ()


class _Message:
    def __init__(self, **values):
        self.__dict__.update(values)


class FakeMessaging:
    Message = Notification = AndroidConfig = APNSConfig = _Message

    def __init__(self):
        self.sent = []
        self.error = None

    def send(self, value, app):
        self.sent.append((value, app))
        if self.error is not None:
            raise self.error
        return "provider-message"


def _request():
    return PushRequest(
        "poc16.mobile", "production", "apple", "registered-fid",
        b'{"kind":"mention"}', "d" * 64, 60_000, 60, "mention")


def test_delivery_domain_binds_routes_but_not_their_input_order():
    _secret, push_node = keypair()
    routes = (
        ("poc16.mobile", "production", "firebase-production"),
        ("poc16.preview", "staging", "firebase-staging"),
    )

    domain = delivery_domain_id(push_node, routes)

    assert domain == delivery_domain_id(push_node, tuple(reversed(routes)))
    assert domain != delivery_domain_id(push_node, (
        ("poc16.mobile", "production", "different-project"),
        routes[1],
    ))
    with pytest.raises(ValueError, match="duplicate"):
        delivery_domain_id(push_node, (routes[0], routes[0]))


def test_firebase_adapter_uses_fid_and_both_platform_collapse_ids():
    module = FakeMessaging()
    adapter = FirebaseAdminFcm(
        {("poc16.mobile", "production"): _firebase_app()},
        messaging_module=module)

    accepted = adapter.send(_request())

    assert accepted.message_id == "provider-message"
    built, _app = module.sent[0]
    assert built.fid == "registered-fid"
    assert built.android.collapse_key == "d" * 64
    assert built.apns.headers["apns-collapse-id"] == "d" * 64
    assert not hasattr(built, "token")
    assert adapter.delivery_routes == (
        ("poc16.mobile", "production", "firebase-project"),)


def test_firebase_adapter_rejects_an_unconfigured_application_before_send():
    module = FakeMessaging()
    adapter = FirebaseAdminFcm(
        {("another.app", "production"): _firebase_app()},
        messaging_module=module)

    with pytest.raises(PushRetryable, match="unconfigured"):
        adapter.send(_request())
    assert module.sent == []


@pytest.mark.parametrize(
    "name,expected",
    [
        ("UnregisteredError", PushUnregistered),
        ("InvalidArgumentError", PushRetryable),
        ("NotFoundError", PushRetryable),
        ("QuotaExceededError", PushRetryable),
        ("SenderIdMismatchError", PushRetryable),
        ("ThirdPartyAuthError", PushRetryable),
    ],
)
def test_firebase_adapter_classifies_errors_without_leaking_details(
        name, expected):
    module = FakeMessaging()
    module.error = type(name, (Exception,), {})("secret provider detail")
    adapter = FirebaseAdminFcm(
        {("poc16.mobile", "production"): _firebase_app()},
        messaging_module=module)

    with pytest.raises(expected) as caught:
        adapter.send(_request())
    assert "secret provider detail" not in str(caught.value)


def test_firebase_adapter_retries_generic_send_value_error():
    module = FakeMessaging()
    module.error = ValueError("bad provider payload with secret detail")
    adapter = FirebaseAdminFcm(
        {("poc16.mobile", "production"): _firebase_app()},
        messaging_module=module)

    with pytest.raises(PushRetryable) as caught:
        adapter.send(_request())
    assert "secret detail" not in str(caught.value)
