"""Direct-key device grants and equal-peer runtime behavior."""
import sqlite3

import pytest

from tinyp2p import cmds
from tinyp2p import facts
from tinyp2p.crypto import keypair
from tinyp2p.facts.auth.device import bind, device, devices
from tinyp2p.facts.auth.device_invite import device_invite as device_invite_fact
from tinyp2p.facts.auth.device_invite import grant
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.facts.auth.workspace import workspace as workspace_fact
from tinyp2p.kernel import drain
from tinyp2p.node import Node

from .util import add_member


def test_direct_grant_admits_a_known_key_without_a_join(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    bind(node, workspace, "phone")
    user = node.pk

    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    grant(node, workspace, user, laptop, "laptop")
    with pytest.raises(ValueError, match="already enrolled"):
        grant(node, workspace, user, laptop, "duplicate")

    members = {row["pk"]: row["role"] for row in cmds.members(node, workspace)}
    assert members[laptop] == "device"
    assert {row["pk"] for row in devices(node, workspace, user)} \
        == {user, laptop}

    node.bind_identity(workspace, laptop)
    fid = cmds.post(node, workspace, "general", "authored by laptop")
    assert node.fact_of(workspace, fid).body["pk"] == laptop


def test_any_device_set_peer_can_grant_the_next_sibling(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    bind(node, workspace, "phone")
    user = node.pk

    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    grant(node, workspace, user, laptop, "laptop")
    node.bind_identity(workspace, laptop)

    tablet_secret, tablet = keypair()
    node.keychain.add_identity(tablet_secret)
    grant(node, workspace, user, tablet, "tablet")

    assert {row["pk"] for row in devices(node, workspace, user)} \
        == {user, laptop, tablet}
    assert {row["pk"] for row in cmds.members(node, workspace)} \
        >= {user, laptop, tablet}


def test_device_commands_reject_existing_members_and_bindings(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    bind(node, workspace, "phone")
    with pytest.raises(ValueError, match="already in a device set"):
        bind(node, workspace, "renamed phone")

    _, bob, _ = add_member(node, workspace, "bob")
    with pytest.raises(ValueError, match="already enrolled"):
        grant(node, workspace, node.pk, bob, "captured bob")


def test_duplicate_device_projection_uses_the_smallest_fact_id():
    secret, public = keypair()
    root = workspace_fact(secret, public, "alice", 1)
    first = device(public, "phone", 2)
    first_sig = signature(secret, public, first, 2)
    second = device(public, "tablet", 3)
    second_sig = signature(secret, public, second, 3)

    observed = []
    for stream in (
            [root, first_sig, first, second_sig, second],
            [root, second_sig, second, first_sig, first]):
        result = drain(stream, root.fid)
        assert result.ok
        db = sqlite3.connect(":memory:")
        db.executescript(facts.APP_SCHEMA)
        for valid in result.valids:
            facts.materialize(db, root.fid, valid)
        observed.append(db.execute(
            "SELECT user, pk, label, source FROM devices").fetchall())
        db.close()

    winner = min((first, second), key=lambda fact: fact.fid)
    assert observed[0] == observed[1] == [
        (public, public, winner.body["label"], winner.fid)]


def test_bearer_user_precedes_device_role_in_every_arrival_order():
    founder_secret, founder = keypair()
    root = workspace_fact(founder_secret, founder, "alice", 1)
    primary = device(founder, "phone", 2)
    primary_sig = signature(founder_secret, founder, primary, 2)

    invite_secret, invite_public = keypair()
    invitation = user_invite(founder, invite_public, 3)
    invitation_sig = signature(founder_secret, founder, invitation, 3)
    bob_secret, bob = keypair()
    joined = user(invitation, invite_secret, bob, "Bob", 4)
    joined_sig = signature(bob_secret, bob, joined, 4)
    direct = device_invite_fact(
        founder, founder, bob, "laptop", 5)
    direct_sig = signature(founder_secret, founder, direct, 5)

    prefix = [root, primary_sig, primary]
    bearer = [invitation_sig, invitation, joined_sig, joined]
    device_grant = [direct_sig, direct]
    observed = []
    for stream in (
            prefix + bearer + device_grant,
            prefix + device_grant + bearer):
        result = drain(stream, root.fid)
        assert result.ok
        db = sqlite3.connect(":memory:")
        db.executescript(facts.APP_SCHEMA)
        for valid in result.valids:
            facts.materialize(db, root.fid, valid)
        observed.append(db.execute(
            "SELECT name, role FROM members WHERE ws=? AND pk=?",
            (root.fid, bob)).fetchone())
        db.close()

    assert observed == [("Bob", "member"), ("Bob", "member")]
