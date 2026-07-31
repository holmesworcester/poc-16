"""Incremental publication is byte-identical to the full repair compiler."""

import facts

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


def test_action_before_target_and_reverse_arrival_match_full_oracle(
        tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    complete = _facts(source, workspace)
    anchor = complete.pop(workspace)
    ordered = sorted(
        complete.values(), key=lambda fact: (fact.key, fact.fid))
    histories = (ordered, list(reversed(ordered)))
    roots = []

    for history in histories:
        resident = {workspace: anchor}
        compiled = compile_snapshot(workspace, resident)
        objects = dict(compiled.outbox)
        for fact in history:
            incremental = extend_snapshot(
                workspace, compiled.root, {fact.fid: fact}, objects.get)
            resident[fact.fid] = fact
            full = compile_snapshot(workspace, resident)
            assert incremental.root == full.root
            objects.update(incremental.outbox)
            compiled = incremental
        roots.append(compiled.root)

    assert roots[0] == roots[1] \
        == compile_snapshot(
            workspace, {workspace: anchor, **complete}).root
