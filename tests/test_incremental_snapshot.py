"""Incremental publication is byte-identical to the full repair compiler."""

import facts
import pytest

from core import indexes, merkle_map, snapshot
from core.crypto import h
from core.fact import encode
from core.repository_snapshot import compile_snapshot, extend_snapshot
from full_peer.node import FullPeer

from .util import add_member, suppression_world


def _facts(node, workspace):
    return dict(node.reader(workspace).all_facts().facts)


def test_ordinary_insert_reads_and_writes_only_changed_paths(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    for ordinal in range(32):
        facts.content.message.post(
            node, workspace, "general", f"base-{ordinal}",
            ts=10 + ordinal)
    before = _facts(node, workspace)
    base = compile_snapshot(workspace, before)
    objects = dict(base.outbox)

    facts.content.message.post(
        node, workspace, "general", "incremental", ts=100)
    after = _facts(node, workspace)
    incoming = {
        fid: fact for fid, fact in after.items()
        if fid not in before
    }
    fetched = []
    incremental = extend_snapshot(
        workspace, base.root, incoming,
        lambda oid: fetched.append(oid) or objects.get(oid))
    full = compile_snapshot(workspace, after)

    assert incremental.root == full.root \
        == node.store(workspace).get("root")
    assert len(incremental.outbox) < len(full.outbox)
    assert not set(fetched) & {
        h(encode(fact)) for fact in before.values()
    }
    assert len(set(fetched)) < len(before)

    objects.update(incremental.outbox)
    duplicate = extend_snapshot(
        workspace, incremental.root, incoming, objects.get)
    assert duplicate.root == incremental.root
    assert duplicate.outbox == ()


def test_member_removal_does_not_visit_incident_provider_facts(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    for ordinal in range(24):
        facts.content.message.post(
            node, workspace, "general", f"bob-{ordinal}",
            ts=20 + ordinal)
    before = _facts(node, workspace)
    base = compile_snapshot(workspace, before)
    objects = dict(base.outbox)

    node.bind_identity(workspace, founder)
    facts.auth.removal.evict(node, workspace, bob)
    after = _facts(node, workspace)
    incoming = {
        fid: fact for fid, fact in after.items()
        if fid not in before
    }
    fetched = []
    incremental = extend_snapshot(
        workspace, base.root, incoming,
        lambda oid: fetched.append(oid) or objects.get(oid))

    assert incremental.root == compile_snapshot(workspace, after).root
    assert not set(fetched) & {
        h(encode(fact)) for fact in before.values()
    }
    assert len(set(fetched)) < len(before)
def test_incremental_action_checks_suppression_named_fact_evidence(tmp_path):
    source, workspace, _, deletions = suppression_world(tmp_path / "source")
    complete = _facts(source, workspace)
    incoming = complete.pop(deletions[0])
    base = compile_snapshot(workspace, complete)
    objects = dict(base.outbox)
    decoded = snapshot.decode_root(base.root)
    sid, = facts.action_sids(incoming)

    for forged_action in ("f" * 64, deletions[1]):
        pending = {}

        def emit(raw):
            oid = h(raw)
            pending[oid] = raw
            return oid

        descriptor = decoded.maps[indexes.SUPP]
        built = merkle_map.update(
            descriptor["root"],
            decoded.layout_seed,
            ((sid, indexes.suppression_slot(forged_action)),),
            objects.get,
            emit,
            expected_count=descriptor["count"],
            expected_depth=descriptor["depth"],
        )
        maps = dict(decoded.maps)
        maps[indexes.SUPP] = snapshot.descriptor(built)
        forged_root = snapshot.encode_root(
            workspace, maps, seed=decoded.layout_seed)
        forged_objects = {**objects, **pending}

        with pytest.raises(
                ValueError,
                match="missing validated fact|action evidence binding"):
            extend_snapshot(
                workspace,
                forged_root,
                {incoming.fid: incoming},
                forged_objects.get,
            )
