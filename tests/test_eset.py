"""E = V minus S stays independent of delivery history."""

import pytest

import facts

from .util import signed_pile_facts
from core.kernel import drain
from full_peer.node import FullPeer
from facts.auth.signature import signature
from facts.content.delete import delete
from facts._policy import OWNER

from .util import (
    all_fids,
    closed_subset,
    member_src,
    query_state,
    replay_random,
    suppression_world,
    visible_fids,
    writer_slots,
)


def test_e_identical_across_partitions_orders_batchings(
        tmp_path, monkeypatch):
    """Random pile partitions, orders, and turn batches converge to one E."""
    source, workspace, targets, _ = suppression_world(tmp_path / "source")
    suppressed = {targets[index] for index in (1, 4, 6)}
    effective = visible_fids(source, workspace)
    assert suppressed.isdisjoint(effective)
    referenced = {
        target
        for fid in all_fids(source, workspace)
        for _, target in source.fact_of(workspace, fid).refs()
    }
    assert referenced <= source.sql(workspace).fact_ids()
    expected_facts = set(all_fids(source, workspace))
    expected_app = query_state(source)
    for seed in range(5):
        peer = replay_random(
            source, workspace, FullPeer(str(tmp_path / f"peer-{seed}")), seed)
        assert set(all_fids(peer, workspace)) == expected_facts
        assert visible_fids(peer, workspace) == effective
        assert query_state(peer) == expected_app


def test_suppression_facts_not_suppressible(tmp_path):
    """A deletion targeting a deletion cannot make S shrink: I2 rejects at
    the author command AND at the family validate (the production family,
    end to end)."""
    node, workspace, _, deletions = suppression_world(tmp_path / "node")
    first = node.fact_of(workspace, deletions[0])
    with pytest.raises(ValueError, match="never victims"):
        facts.content.delete.remove(node, workspace, deletions[0], ts=200)
    secret, public = node.identity(workspace)
    recursive = delete(workspace, public, first.key, OWNER, 200)
    sig = signature(secret, public, recursive, 200)

    with pytest.raises(ValueError, match="rejected"):
        node.ingest_new(workspace, [sig, recursive], {
            recursive.fid: [
                first.fid, sig.fid, member_src(node, workspace, public)],
            sig.fid: []})

    assert node.fact_of(workspace, recursive.fid) is None


def test_reader_rebuilds_missing_reference_projection_without_slot_write(
        tmp_path):
    """Accepted writer slots restore SQL rows without another slot CAS."""
    node, workspace, targets, deletions = suppression_world(tmp_path / "node")
    referenced = {targets[index] for index in (1, 4, 6)}
    expected = query_state(node)
    slots = writer_slots(node, workspace)
    assert slots
    index = node.idx(workspace)
    index.executemany(
        "DELETE FROM fact_index WHERE src=?",
        ((target,) for target in referenced),
    )
    index.executemany(
        "DELETE FROM facts WHERE fid=?",
        ((target,) for target in referenced),
    )
    index.commit()

    assert referenced.isdisjoint(node.sql(workspace).fact_ids())

    node.rebuild(workspace)

    assert writer_slots(node, workspace) == slots
    assert referenced <= node.sql(workspace).fact_ids()
    assert all(node.fact_of(workspace, fid) is not None
               for fid in deletions)
    assert query_state(node) == expected


def test_verdicts_never_read_s(tmp_path, monkeypatch):
    """Adding a valid deletion masks its target without changing validity."""
    source, workspace, targets, deletions = suppression_world(
        tmp_path / "source")
    target = targets[1]
    alone = signed_pile_facts(
        closed_subset(source, workspace, [target]), workspace)
    with_deletion = signed_pile_facts(closed_subset(
        source, workspace, [deletions[0]]), workspace)

    alone_result = drain(alone, workspace)
    deletion_result = drain(with_deletion, workspace)
    assert alone_result.ok and deletion_result.ok
    assert target in {valid.fact.fid for valid in alone_result.valids}
    assert target in {valid.fact.fid for valid in deletion_result.valids}
    assert target not in visible_fids(source, workspace)
