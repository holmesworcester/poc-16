"""Explicit device removal through ordinary fact-family authority."""

import pytest

import facts
from core.crypto import h, keypair
from core.fact import Need
from facts._commands import publish
from facts._policy import ADMIN, OWNER, SidOffer
from facts.auth.device import bind, devices
from facts.auth.device_invite import grant
from facts.auth.device_removal import (
    device_removal,
    needs,
    remove,
    validate,
)
from facts.auth.signature import signature
from full_peer.node import FullPeer

from .util import add_member


def _id(label):
    return h(label.encode())


def _add_secondary(node, workspace, owner, label):
    secret, public = keypair()
    node.keychain.add_identity(secret)
    grant(node, workspace, owner, public, label)
    return secret, public


def test_device_removal_declares_exact_target_and_authority_needs():
    workspace = _id("workspace")
    owner = _id("owner")
    signer = _id("owner-device")
    target = _id("target-device")
    item = device_removal(
        workspace, signer, target, owner, OWNER, 10, owner)

    assert validate(item, None)
    assert needs(item) == (
        Need("author", "author", item.fid, signer),
        Need("member", "member", owner, owner),
        Need("device", "device_key", signer, owner),
        Need("target_device", "device_key", target, owner),
    )
    assert facts.action_sids(item) == {
        facts.principal_sid("device", target),
    }
    assert facts.auth.device_removal.POLICY.control_fact is True
    assert facts.auth.device_removal.POLICY.action_offers == (
        SidOffer("removed", "device"),
    )

    admin = device_removal(
        workspace, signer, target, owner, ADMIN, 11, _id("admin"))
    assert any(need.role == "actor_admin" for need in needs(admin))
    forged_owner = device_removal(
        workspace, signer, target, owner, OWNER, 12, _id("other"))
    assert not validate(forged_owner, None)


def test_owner_removes_an_owned_device_through_generic_cli(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    owner = node.identity_id(workspace)
    bind(node, workspace, "alice-phone")
    _, laptop = _add_secondary(node, workspace, owner, "alice-laptop")

    action_fid = facts.invoke_command(
        node,
        "auth.device_removal.remove",
        [workspace[:12], "alice-laptop"],
    )
    action = node.fact_of(workspace, action_fid)

    assert action.body == {
        "actor": owner,
        "mode": OWNER,
        "owner": owner,
        "pk": owner,
    }
    assert action.offers() == [("removed", laptop, "")]
    assert node.suppression_active(
        workspace, facts.principal_sid("device", laptop))
    assert {row["pk"] for row in devices(node, workspace)} == {owner}
    assert not node.suppression_active(
        workspace, facts.principal_sid("member", owner))


def test_an_owned_secondary_device_can_remove_itself(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    owner = node.identity_id(workspace)
    bind(node, workspace, "alice-phone")
    _, laptop = _add_secondary(node, workspace, owner, "alice-laptop")
    node.bind_identity(workspace, laptop)

    action_fid = remove(node, workspace, laptop)
    action = node.fact_of(workspace, action_fid)

    assert action.body == {
        "actor": owner,
        "mode": OWNER,
        "owner": owner,
        "pk": laptop,
    }
    assert node.suppression_active(
        workspace, facts.principal_sid("device", laptop))
    assert {row["pk"] for row in devices(node, workspace)} == {owner}
    with pytest.raises(ValueError, match="not a workspace member"):
        facts.content.message.post(
            node, workspace, "general", "removed device")


def test_admin_may_remove_any_device_but_another_member_may_not(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bind(node, workspace, "alice-phone")
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    carol_secret, carol, _ = add_member(node, workspace, "carol", ts=20)
    node.keychain.add_identity(bob_secret)
    node.keychain.add_identity(carol_secret)

    node.bind_identity(workspace, bob)
    bind(node, workspace, "bob-phone")
    _, bob_laptop = _add_secondary(
        node, workspace, bob, "bob-laptop")
    node.bind_identity(workspace, carol)
    bind(node, workspace, "carol-phone")

    with pytest.raises(ValueError, match="owner or an admin"):
        remove(node, workspace, bob_laptop)

    # The command precheck is not the authority boundary: an ordinary signed
    # action also fails because its declared actor_admin Need has no provider.
    unauthorized = device_removal(
        workspace, carol, bob_laptop, bob, ADMIN, 30, carol)
    signed = signature(carol_secret, carol, unauthorized, 30)
    with pytest.raises(ValueError, match="lacks actor_admin evidence"):
        publish(node, workspace, unauthorized, signed)

    node.bind_identity(workspace, founder)
    action = node.fact_of(
        workspace, remove(node, workspace, bob_laptop))
    assert action.body == {
        "actor": founder,
        "mode": ADMIN,
        "owner": bob,
        "pk": founder,
    }
    assert node.suppression_active(
        workspace, facts.principal_sid("device", bob_laptop))
    assert {row["pk"] for row in devices(node, workspace, bob)} == {bob}
