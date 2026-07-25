"""E = V minus S stays independent of delivery history."""
import pytest

from core.close import decode_pile
from core.kernel import drain
from core.node import Node
from core.suppression import victims

from .util import (
    all_fids,
    channel_delete,
    closed_subset,
    projection_state,
    replay_random,
    suppression_world,
)


def test_e_identical_across_partitions_orders_batchings(
        tmp_path, monkeypatch):
    """Random pile partitions, orders, and turn batches converge to one E."""
    source, workspace, targets, _ = suppression_world(
        tmp_path / "source", monkeypatch)
    suppressed = {targets[index] for index in (1, 4, 6)}
    effective = set(all_fids(source, workspace)) - suppressed
    referenced = {
        target
        for fid in all_fids(source, workspace)
        for _, target in source.fact_of(workspace, fid).refs()
    }
    assert referenced <= {
        fid for (fid,) in source.idx(workspace).execute(
            "SELECT fid FROM proofs")
    }
    assert {
        src for (src,) in source.app.execute(
            "SELECT src FROM projected WHERE ws=?", (workspace,))
    } == effective

    expected_root = source.store(workspace).get("root")
    expected_app = projection_state(source)
    for seed in range(5):
        peer = replay_random(
            source, workspace, Node(str(tmp_path / f"peer-{seed}")), seed)
        assert peer.store(workspace).get("root") == expected_root
        assert {
            src for (src,) in peer.app.execute(
                "SELECT src FROM projected WHERE ws=?", (workspace,))
        } == effective
        assert projection_state(peer) == expected_app


def test_suppression_facts_not_suppressible(tmp_path, monkeypatch):
    """A deletion targeting a deletion cannot make S shrink."""
    node, workspace, _, deletions = suppression_world(
        tmp_path / "node", monkeypatch)
    first = node.fact_of(workspace, deletions[0])
    recursive = channel_delete(first.fid, "channel-1", 200)

    with pytest.raises(ValueError, match="outside the canonical set"):
        node.ingest_new(
            workspace, [recursive], {recursive.fid: [first.fid]})

    assert node.fact_of(workspace, recursive.fid) is None
    assert victims(recursive, lambda fid: first if fid == first.fid else None) \
        == ()


def test_old_index_rebuilds_reference_proofs(tmp_path, monkeypatch):
    """A v7 restart repairs unranked ref targets before serving E."""
    node, workspace, targets, deletions = suppression_world(
        tmp_path / "node", monkeypatch)
    referenced = {targets[index] for index in (1, 4, 6)}
    expected = projection_state(node)
    index = node.idx(workspace)
    index.executemany(
        "DELETE FROM proofs WHERE fid=?",
        ((target,) for target in referenced))
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('index-version', ?)",
        ("family-contract-v7-pump",))
    index.commit()
    index.close()
    node.app.close()

    upgraded = Node(node.dir)

    assert all(upgraded.fact_of(workspace, fid) is not None
               for fid in deletions)
    assert {
        fid for (fid,) in upgraded.idx(workspace).execute(
            "SELECT fid FROM proofs")
    }.issuperset(referenced)
    assert projection_state(upgraded) == expected


def test_verdicts_never_read_s(tmp_path, monkeypatch):
    """Adding a valid deletion masks its target without changing validity."""
    source, workspace, targets, deletions = suppression_world(
        tmp_path / "source", monkeypatch)
    target = targets[1]
    alone, _ = decode_pile(closed_subset(source, workspace, [target]))
    with_deletion, _ = decode_pile(closed_subset(
        source, workspace, [deletions[0]]))

    alone_result = drain(alone, workspace)
    deletion_result = drain(with_deletion, workspace)
    assert alone_result.ok and deletion_result.ok
    assert target in {valid.fact.fid for valid in alone_result.valids}
    assert target in {valid.fact.fid for valid in deletion_result.valids}
    assert source.app.execute(
        "SELECT 1 FROM projected WHERE ws=? AND src=?",
        (workspace, target),
    ).fetchone() is None
