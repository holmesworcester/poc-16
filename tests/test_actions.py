"""Running contracts for indexed suppression actions and ingress screening."""
import json
import os

import pytest

from core import actions, cmds
from core.close import close, encode_pile
from core.crypto import h
from core.kernel import resolve_deps
from core.node import Node
from core import sync as sync_module
from facts.auth.removal import removal
from facts.auth.signature import signature
from facts.content.message import message

from .util import (
    add_member,
    all_fids,
    closed_subset,
    deliver,
    member_src,
)


def _action_rows(node, workspace):
    return node.idx(workspace).execute(
        "SELECT sid, fid, evidence FROM actions ORDER BY sid").fetchall()


def _signed_pile(node, workspace, fact, signed, deps):
    incoming = {fact.fid: fact, signed.fid: signed}
    fact_of = lambda fid: incoming.get(fid) or node.fact_of(workspace, fid)
    return encode_pile(close(
        [signed, fact],
        lambda fid: deps[fid] if fid in deps else (
            resolve_deps(fact_of(fid), node.idx(workspace)) or ()),
        fact_of,
    ))


def test_composite_root_has_no_legacy_removal_object(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    target = cmds.post(node, workspace, "general", "doomed", ts=10)
    action_fid = cmds.remove(node, workspace, target, ts=20)

    root = json.loads(node.store(workspace).get("root"))
    assert set(root) == {
        "actions", "anchor", "globals", "layout_seed", "manifest", "stamp",
        "trees"}
    assert "removals" not in root
    assert _action_rows(node, workspace)[0][:2] == (
        f"fact:{target}", action_fid)


def test_action_reverse_projection_rebuilds_from_the_trees(tmp_path):
    directory = tmp_path / "node"
    node = Node(str(directory))
    workspace = cmds.create(node, "alice", ts=1)
    target = cmds.post(node, workspace, "general", "doomed", ts=10)
    cmds.remove(node, workspace, target, ts=20)
    expected_root = node.store(workspace).get("root")
    expected_actions = _action_rows(node, workspace)

    node.idx(workspace).close()
    node.app.close()
    os.unlink(directory / "ws" / f"{workspace}.idx.db")
    os.unlink(directory / "app.db")

    rebuilt = Node(str(directory))
    assert _action_rows(rebuilt, workspace) == expected_actions
    assert rebuilt.store(workspace).get("root") == expected_root
    assert rebuilt.app.execute(
        "SELECT 1 FROM projected WHERE ws=? AND src=?",
        (workspace, target)).fetchone() is None


def test_evicted_member_cannot_launder_a_valid_signed_fact(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    provider = member_src(node, workspace, bob)
    eviction = cmds.evict(node, workspace, bob)

    ts = node.fact_of(workspace, eviction).ts + 1
    item = message(bob, "general", "must not land", ts)
    signed = signature(bob_secret, bob, item, ts)
    pile = _signed_pile(
        node, workspace, item, signed,
        {signed.fid: (), item.fid: (signed.fid, provider)})
    deliver(node, workspace, pile)

    with pytest.raises(actions.ScreenRejected, match="suppressed authority"):
        node.turn(workspace)
    assert node.fact_of(workspace, item.fid) is None
    assert node.store(workspace).list("pile/") == []
    assert any(
        "ScreenRejected" in row["error"]
        for row in node.ingress_failures(workspace))


def test_delegated_admin_liveness_follows_grantee_not_grantor(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    _, carol, _ = add_member(node, workspace, "carol", ts=20)
    admin_fid = cmds.grant_admin(node, workspace, bob)
    eviction = cmds.evict(node, workspace, bob)

    ts = node.fact_of(workspace, eviction).ts + 1
    item = removal(bob, carol, ts)
    signed = signature(bob_secret, bob, item, ts)
    pile = _signed_pile(
        node, workspace, item, signed,
        {signed.fid: (), item.fid: (signed.fid, admin_fid)})
    deliver(node, workspace, pile)

    with pytest.raises(actions.ScreenRejected, match="suppressed authority"):
        node.turn(workspace)
    assert node.fact_of(workspace, item.fid) is None


def test_terminal_member_action_covers_a_future_provider(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    bob_identity = add_member(node, workspace, "bob", ts=10)[:2]
    bob_secret, bob = bob_identity
    cmds.evict(node, workspace, bob)

    _, rejoined, _ = add_member(
        node, workspace, "bob-again", ts=30,
        member_identity=(bob_secret, bob))
    assert rejoined == bob
    providers = node.idx(workspace).execute(
        "SELECT src FROM offers WHERE name='member' AND a0=? ORDER BY src",
        (bob,)).fetchall()
    assert len(providers) == 2
    assert actions.active(
        node.idx(workspace), actions.principal_sid("member", bob))


def test_action_leg_converges_before_the_ordinary_fact_diff(
        tmp_path, monkeypatch):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice", ts=1)
    target = cmds.post(source, workspace, "general", "doomed", ts=10)
    before = closed_subset(source, workspace, all_fids(source, workspace))

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "alice", peers=[])
    deliver(destination, workspace, before)
    destination.turn(workspace)
    action_fid = cmds.remove(source, workspace, target, ts=20)

    class LocalPeer:
        def __init__(self, node, ws, url):
            self.node, self.ws = node, ws
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None):
            return (
                source.store(self.ws).get("root"),
                source.store(self.ws).etag("root"),
            )

        def obj(self, oid):
            return source.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            return tuple(self.obj(oid) for oid in oids)

        def put_pile(self, raw):
            source.store(self.ws).put(
                f"pile/peer/{h(raw)}", raw)
            source.turn(self.ws)

    monkeypatch.setattr(sync_module, "Peer", LocalPeer)
    sync_module.sync(destination, workspace, "local")

    assert _action_rows(destination, workspace)[0][:2] == (
        f"fact:{target}", action_fid)
    assert destination.app.execute(
        "SELECT 1 FROM projected WHERE ws=? AND src=?",
        (workspace, target)).fetchone() is None


def test_one_poisoned_action_witness_does_not_block_an_honest_action(
        tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice", ts=1)
    poisoned_target = cmds.post(
        source, workspace, "general", "poison witness", ts=10)
    honest_target = cmds.post(
        source, workspace, "general", "honest witness", ts=11)
    before = closed_subset(source, workspace, all_fids(source, workspace))

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "alice", peers=[])
    deliver(destination, workspace, before)
    destination.turn(workspace)

    cmds.remove(source, workspace, poisoned_target, ts=20)
    cmds.remove(source, workspace, honest_target, ts=21)
    rows = {
        sid: (fid, evidence)
        for sid, fid, evidence in _action_rows(source, workspace)
    }
    poisoned_sid = f"fact:{poisoned_target}"
    honest_sid = f"fact:{honest_target}"
    poisoned_evidence = rows[poisoned_sid][1]
    store = source.store(workspace)

    def fetch(oid):
        return b"not the claimed object" if oid == poisoned_evidence \
            else store.get("obj/" + oid)

    accepted = sync_module.pull_actions(
        destination, workspace, store.get("root"), fetch, rows)

    assert rows[honest_sid][0] in accepted
    assert rows[poisoned_sid][0] not in accepted
    assert actions.active(destination.idx(workspace), honest_sid)
    assert not actions.active(destination.idx(workspace), poisoned_sid)
    assert destination.app.execute(
        "SELECT 1 FROM projected WHERE ws=? AND src=?",
        (workspace, honest_target)).fetchone() is None
    assert destination.app.execute(
        "SELECT 1 FROM projected WHERE ws=? AND src=?",
        (workspace, poisoned_target)).fetchone() is not None
