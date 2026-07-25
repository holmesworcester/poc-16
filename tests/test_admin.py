"""Delegated admin authority reaches the running eviction command."""
import pytest

from tinyp2p import cmds
from tinyp2p.facts.auth.admin import admins
from tinyp2p.node import Node, now_ms

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
    cmds.grant_admin(node, workspace, "bob")
    node.bind_identity(workspace, bob)
    cmds.grant_admin(node, workspace, carol)

    assert {row["pk"] for row in admins(node, workspace)} \
        == {founder, bob, carol}

    node.bind_identity(workspace, carol)
    removal_fid = cmds.evict(node, workspace, "bob")
    removal = node.fact_of(workspace, removal_fid)
    assert removal.body["pk"] == carol
    assert ("removal", bob) in node.globals(workspace)
