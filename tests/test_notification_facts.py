"""Canonical endpoint and user-scoped preference fact behavior."""
import base64

import pytest

import facts
from core.crypto import h, keypair
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.auth.device_invite import grant
from facts.auth.signature import signature
from facts.content import notification_preference as preference
from full_peer.node import FullPeer


def _world(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    _, push_node = keypair()
    return node, workspace, push_node


def _target(byte=b"x"):
    return push_endpoint.encode_sealed_target(byte * 49)


def _endpoint(node, workspace, push_node, installation=b"one", ts=10):
    return push_endpoint.register(
        node,
        workspace,
        h(installation),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        _target(),
        ts=ts,
    )


def _author_preference(
        node, workspace, scope, target, mode, clock, supersedes, ts):
    secret, public = node.identity(workspace)
    user = node.pk
    item = preference.notification_preference(
        workspace,
        public,
        user,
        scope,
        target,
        mode,
        clock,
        supersedes,
        ts,
    )
    signed = signature(secret, public, item, ts)
    member = node.sql(workspace).resolve_offer("member", public, user)
    device = node.sql(workspace).resolve_offer("device_key", public, user)
    node.ingest_new(
        workspace,
        [signed, item],
        {
            signed.fid: (),
            item.fid: (
                signed.fid, member, device, *supersedes),
        },
    )
    return item


def test_endpoint_keeps_ciphertext_out_of_queries_and_rotates_atomically(
        tmp_path):
    node, workspace, push_node = _world(tmp_path)
    first = _endpoint(node, workspace, push_node)
    before = node.fact_of(workspace, first)

    replacement = push_endpoint.replace(
        node, workspace, first, push_node, _target(b"y"), ts=11)

    assert node.fact_of(workspace, first) == before
    assert node.suppressed(workspace, before) is True
    assert [row["fid"] for row in push_endpoint.endpoints(
        node, workspace)] == [replacement]
    assert all(
        "sealed_target" not in row
        for row in push_endpoint.endpoints(node, workspace)
    )
    assert node.reader(workspace).worker().fact_active(first) is False
    assert node.reader(workspace).worker().fact_active(replacement) is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("installation", "short"),
        ("push_node", "A" * 64),
        ("platform", "ios"),
        ("application", "bad application"),
        ("environment", "bad environment"),
        ("sealed_target", b"short"),
    ],
)
def test_endpoint_shape_rejects_hostile_components(
        tmp_path, field, value):
    node, workspace, push_node = _world(tmp_path)
    values = {
        "workspace": workspace,
        "pk": node.pk,
        "owner": node.pk,
        "installation": h(b"installation"),
        "push_node": push_node,
        "platform": "apple",
        "application": "poc16.mobile",
        "environment": "production",
        "sealed_target": b"x" * 49,
        "ts": 10,
    }
    values[field] = value
    with pytest.raises(ValueError):
        push_endpoint.push_endpoint(**values)


def test_endpoint_rejects_noncanonical_base64_before_publication(tmp_path):
    node, workspace, push_node = _world(tmp_path)
    malformed = base64.b64encode(b"x" * 49).decode() + "\n"

    with pytest.raises(ValueError, match="sealed push target"):
        push_endpoint.register(
            node,
            workspace,
            h(b"installation"),
            push_node,
            "android",
            "poc16.mobile",
            "production",
            malformed,
            ts=10,
        )


def test_preferences_are_shared_by_sibling_devices(tmp_path):
    node, workspace, _push_node = _world(tmp_path)
    founder = node.pk
    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    grant(node, workspace, founder, laptop, "laptop")
    node.bind_identity(workspace, laptop)

    first = preference.set_global(node, workspace, preference.MENTIONS, ts=20)
    node.bind_identity(workspace, founder)
    second = preference.set_global(node, workspace, preference.ALL, ts=21)

    row, = preference.preferences(node, workspace, founder)
    assert row == {
        "clock": 1,
        "head_fids": [second],
        "mode": preference.ALL,
        "scope": preference.GLOBAL,
        "target": "",
        "user": founder,
    }
    assert preference.superseded_fids(
        node.fact_of(workspace, second)) == (first,)
    assert node.fact_of(workspace, first).body["pk"] == laptop
    assert node.fact_of(workspace, second).body["pk"] == founder


def test_concurrent_preference_heads_meet_restrictively_and_command_joins(
        tmp_path):
    node, workspace, _push_node = _world(tmp_path)
    allow = _author_preference(
        node,
        workspace,
        preference.CHANNEL,
        "general",
        preference.ALL,
        0,
        (),
        20,
    )
    mute = _author_preference(
        node,
        workspace,
        preference.CHANNEL,
        "general",
        preference.NONE,
        0,
        (),
        21,
    )

    row, = preference.preferences(node, workspace, node.pk)
    assert row["head_fids"] == sorted((allow.fid, mute.fid))
    assert row["mode"] == preference.NONE
    assert row["clock"] == 0

    joined = preference.set_channel(
        node, workspace, "general", preference.INHERIT, ts=22)
    fact = node.fact_of(workspace, joined)
    assert fact.body["clock"] == 1
    assert preference.superseded_fids(fact) == tuple(
        sorted((allow.fid, mute.fid)))
    row, = preference.preferences(node, workspace, node.pk)
    assert row["mode"] == preference.INHERIT
    assert row["head_fids"] == [joined]


def test_preference_validation_rejects_cross_cell_supersession(tmp_path):
    node, workspace, _push_node = _world(tmp_path)
    parent = _author_preference(
        node,
        workspace,
        preference.CHANNEL,
        "general",
        preference.ALL,
        0,
        (),
        20,
    )
    secret, public = node.identity(workspace)
    forged = preference.notification_preference(
        workspace,
        public,
        node.pk,
        preference.CHANNEL,
        "random",
        preference.NONE,
        1,
        (parent.fid,),
        21,
    )
    signed = signature(secret, public, forged, 21)
    member = node.sql(workspace).resolve_offer(
        "member", public, node.pk)
    device = node.sql(workspace).resolve_offer(
        "device_key", public, node.pk)

    with pytest.raises(ValueError, match="not admitted"):
        node.ingest_new(
            workspace,
            [signed, forged],
            {
                signed.fid: (),
                forged.fid: (
                    signed.fid, member, device, parent.fid),
            },
        )


def test_user_removal_blocks_new_settings_but_preserves_old_state_and_history(
        tmp_path):
    node, workspace, push_node = _world(tmp_path)
    endpoint = _endpoint(node, workspace, push_node)
    setting = preference.set_global(
        node, workspace, preference.ALL, ts=20)

    facts.auth.removal.evict(node, workspace, node.pk)

    old = node.fact_of(workspace, setting)
    assert old is not None
    assert node.reader(workspace).worker().fact_active(setting) is True
    assert node.reader(workspace).worker().fact_active(endpoint) is False
    assert preference.preferences(node, workspace, node.pk)[0]["mode"] \
        == preference.ALL
    with pytest.raises(ValueError, match="not a workspace member"):
        preference.set_global(
            node, workspace, preference.NONE, ts=30)
