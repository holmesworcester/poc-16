"""Delegated admin authority reaches the running eviction command."""
import pytest

from core import actions, cmds
from core.crypto import keypair
from facts.auth.admin import admins
from core.node import Node, now_ms

from .util import add_member


def test_only_an_admin_can_grant_and_grants_delegate(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    founder = node.pk
    ts = now_ms()
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=ts + 1)
    carol_secret, carol, _ = add_member(node, workspace, "carol", ts=ts + 3)
    node.keychain.add_identity(bob_secret)
    node.keychain.add_identity(carol_secret)

    node.bind_identity(workspace, bob)
    with pytest.raises(ValueError, match="not an admin"):
        cmds.grant_admin(node, workspace, "carol")

    node.bind_identity(workspace, founder)
    with pytest.raises(ValueError, match="another member"):
        cmds.grant_admin(node, workspace, founder)
    cmds.grant_admin(node, workspace, "bob")
    node.bind_identity(workspace, bob)
    cmds.grant_admin(node, workspace, carol)

    assert {row["pk"] for row in admins(node, workspace)} \
        == {founder, bob, carol}

    node.bind_identity(workspace, carol)
    removal_fid = cmds.evict(node, workspace, "bob")
    removal = node.fact_of(workspace, removal_fid)
    assert removal.body["pk"] == carol
    assert actions.active(
        node.idx(workspace), actions.principal_sid("member", bob))
    assert ("removal", bob) not in node.globals(workspace)


def test_admin_target_prefers_exact_key_and_rejects_ambiguous_names(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    spoof_identity, victim_identity = sorted(
        (keypair(), keypair()), key=lambda identity: identity[1])
    _, victim, _ = add_member(
        node, workspace, "victim", member_identity=victim_identity)
    _, spoof, _ = add_member(
        node, workspace, victim, member_identity=spoof_identity)
    assert spoof < victim

    grant_fid = cmds.grant_admin(node, workspace, victim)
    assert node.fact_of(workspace, grant_fid).body["target"] == victim
    assert {row["pk"] for row in admins(node, workspace)} \
        == {node.pk, victim}
    assert spoof not in {row["pk"] for row in admins(node, workspace)}

    add_member(node, workspace, "duplicate")
    add_member(node, workspace, "duplicate")
    before = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    with pytest.raises(ValueError, match="ambiguous member name"):
        cmds.grant_admin(node, workspace, "duplicate")
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == before
