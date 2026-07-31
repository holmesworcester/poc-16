"""Delegated admin authority reaches the running eviction command."""
import pytest

import facts
from core.crypto import keypair
from facts.auth.admin import admins
from full_peer.node import FullPeer, now_ms

from .util import add_member


def test_only_an_admin_can_grant_and_grants_delegate(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice")
    founder = node.pk
    ts = now_ms()
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=ts + 1)
    carol_secret, carol, _ = add_member(node, workspace, "carol", ts=ts + 3)
    node.keychain.add_identity(bob_secret)
    node.keychain.add_identity(carol_secret)

    node.bind_identity(workspace, bob)
    with pytest.raises(ValueError, match="not an admin"):
        facts.auth.admin.grant(node, workspace, "carol")

    node.bind_identity(workspace, founder)
    with pytest.raises(ValueError, match="another member"):
        facts.auth.admin.grant(node, workspace, founder)
    facts.auth.admin.grant(node, workspace, "bob")
    node.bind_identity(workspace, bob)
    facts.auth.admin.grant(node, workspace, carol)

    assert {row["pk"] for row in admins(node, workspace)} \
        == {founder, bob, carol}

    node.bind_identity(workspace, carol)
    removal_fid = facts.auth.removal.evict(node, workspace, "bob")
    removal = node.fact_of(workspace, removal_fid)
    assert removal.body["pk"] == carol
    assert node.suppression_active(
        workspace, facts.principal_sid("member", bob))


def test_admin_target_prefers_exact_key_and_rejects_ambiguous_names(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice")
    spoof_identity, victim_identity = sorted(
        (keypair(), keypair()), key=lambda identity: identity[1])
    _, victim, _ = add_member(
        node, workspace, "victim", member_identity=victim_identity)
    _, spoof, _ = add_member(
        node, workspace, victim, member_identity=spoof_identity)
    assert spoof < victim

    grant_fid = facts.auth.admin.grant(node, workspace, victim)
    assert node.fact_of(workspace, grant_fid).body["target"] == victim
    assert {row["pk"] for row in admins(node, workspace)} \
        == {node.pk, victim}
    assert spoof not in {row["pk"] for row in admins(node, workspace)}

    add_member(node, workspace, "duplicate")
    add_member(node, workspace, "duplicate")
    before = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    with pytest.raises(ValueError, match="ambiguous member name"):
        facts.auth.admin.grant(node, workspace, "duplicate")
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == before


def test_delegated_admin_liveness_follows_grantee_after_grantor_leaves(
        tmp_path, monkeypatch):
    ticks = iter(range(100, 200))
    monkeypatch.setattr(
        "full_peer.node.now_ms", lambda: next(ticks))
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(
        node, workspace, "bob", ts=10)
    carol_secret, carol, _ = add_member(
        node, workspace, "carol", ts=20)
    _, dave, _ = add_member(
        node, workspace, "dave", ts=30)
    _, erin, _ = add_member(
        node, workspace, "erin", ts=40)
    node.keychain.add_identity(bob_secret)
    node.keychain.add_identity(carol_secret)

    facts.auth.admin.grant(node, workspace, bob)
    node.bind_identity(workspace, bob)
    carol_grant = facts.auth.admin.grant(
        node, workspace, carol)

    # Bob's admin authority was required when this immutable grant entered
    # the DAG. Once admitted, its continuing authority follows Carol.
    node.bind_identity(workspace, founder)
    facts.auth.removal.evict(node, workspace, bob)
    assert node.fact_of(workspace, carol_grant) is not None
    assert [fact.fid for fact in node.select(
        workspace, "admin", carol)] == [carol_grant]

    node.bind_identity(workspace, carol)
    facts.auth.removal.evict(node, workspace, dave)
    assert node.suppression_active(
        workspace, facts.principal_sid("member", dave))

    # The converse is equally important: Carol's own removal ends the
    # delegated authority even though Bob's historical grant remains.
    node.bind_identity(workspace, founder)
    facts.auth.removal.evict(node, workspace, carol)
    assert node.select(workspace, "admin", carol) == ()
    node.bind_identity(workspace, carol)
    with pytest.raises(ValueError, match="not a workspace admin"):
        facts.auth.removal.evict(node, workspace, erin)
    assert not node.suppression_active(
        workspace, facts.principal_sid("member", erin))
