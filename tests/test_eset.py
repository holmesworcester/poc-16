"""E = V minus S stays independent of delivery history."""
import base64
import threading

import pytest

import facts

from core import catalog, daemon, indexes
from core.close import decode_pile, encode_pile
from core.kernel import drain
from core.node import Node
from core.repository_reader import RepositoryReader
from facts.auth.request import payload as request_payload
from facts.auth.signature import signature
from facts.content.delete import delete
from facts._policy import OWNER

from .util import (
    all_fids,
    closed_subset,
    invoke_mint,
    member_src,
    query_state,
    replay_random,
    suppression_world,
    visible_fids,
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
    assert referenced <= set(
        source.reader(workspace).validated().fact_ids())
    expected_root = source.store(workspace).get("root")
    expected_app = query_state(source)
    for seed in range(5):
        peer = replay_random(
            source, workspace, Node(str(tmp_path / f"peer-{seed}")), seed)
        assert peer.store(workspace).get("root") == expected_root
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

    with pytest.raises(ValueError, match="were not admitted"):
        node.ingest_new(workspace, [sig, recursive], {
            recursive.fid: [
                first.fid, sig.fid, member_src(node, workspace, public)],
            sig.fid: []})

    assert node.fact_of(workspace, recursive.fid) is None


def test_reader_rebuilds_missing_reference_projection_without_root_write(
        tmp_path):
    """The pinned root restores missing projection rows without a root CAS."""
    node, workspace, targets, deletions = suppression_world(tmp_path / "node")
    referenced = {targets[index] for index in (1, 4, 6)}
    expected = query_state(node)
    root = node.store(workspace).get("root")
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

    assert referenced.isdisjoint(node.catalog(workspace).fact_ids())

    node.rebuild(workspace)

    assert node.store(workspace).get("root") == root
    assert referenced <= node.catalog(workspace).fact_ids()
    assert all(node.fact_of(workspace, fid) is not None
               for fid in deletions)
    assert query_state(node) == expected


def test_verdicts_never_read_s(tmp_path, monkeypatch):
    """Adding a valid deletion masks its target without changing validity."""
    source, workspace, targets, deletions = suppression_world(
        tmp_path / "source")
    target = targets[1]
    alone = decode_pile(
        closed_subset(source, workspace, [target]), workspace)
    with_deletion = decode_pile(closed_subset(
        source, workspace, [deletions[0]]), workspace)

    alone_result = drain(alone, workspace)
    deletion_result = drain(with_deletion, workspace)
    assert alone_result.ok and deletion_result.ok
    assert target in {valid.fact.fid for valid in alone_result.valids}
    assert target in {valid.fact.fid for valid in deletion_result.valids}
    assert target not in visible_fids(source, workspace)


@pytest.mark.parametrize("restart", (False, True))
def test_suppression_stays_behind_the_root_commit(
        tmp_path, monkeypatch, restart):
    """Root and action projection advance atomically across a failed CAS."""
    node, workspace, _, _ = suppression_world(tmp_path / "node")
    target_fid = facts.content.message.post(
        node, workspace, "unpublished", "target", ts=300)
    target = node.fact_of(workspace, target_fid)
    deletion = delete(  # the fid facts.content.delete.remove(ts=301) authors below
        workspace, node.identity_id(workspace), target.key, OWNER, 301)
    store = node.store(workspace)
    old_root = store.get("root")

    def visible():
        return target.fid in visible_fids(node, workspace)

    def committed_action(raw):
        return RepositoryReader(
            workspace,
            raw,
            lambda oid: store.get("obj/" + oid),
        ).worker().suppression(indexes.fact_key(target.fid))

    def projected_action():
        return node.idx(workspace).execute(
            "SELECT src FROM fact_index WHERE kind=? AND k0=?",
            (catalog.ACTION_INDEX, indexes.fact_key(target.fid)),
        ).fetchone()

    assert committed_action(old_root) == {"state": "clear"}
    assert projected_action() is None
    assert visible()
    now = daemon.now_ms()
    request = encode_pile(request_payload(
        node, workspace, "sync", now + 60_000, now))
    canonical_observed = []
    old_view = node.reader(workspace).worker()
    original_mint = type(old_view).mint

    def observe_canonical(view, pile, trusted_now, *, purpose="sync"):
        canonical_observed.append(view.etag == old_view.etag)
        return original_mint(
            view, pile, trusted_now, purpose=purpose)

    monkeypatch.setattr(type(old_view), "mint", observe_canonical)

    release_reader = threading.Event()
    reader_waiting = threading.Event()
    observed = []

    def read_like_mint():
        release_reader.wait()
        reader_waiting.set()
        _, (code, body) = invoke_mint(node, workspace, request)
        observed.append((
            code,
            base64.b64decode(body["root"]) if body else None,
        ))

    reader = threading.Thread(target=read_like_mint, daemon=True)
    reader.start()
    candidate = []
    original_cas = store.cas

    def fail_before_root_commit(key, etag, raw):
        candidate.append(raw)
        assert key == "root"
        assert store.get("root") == old_root
        # SQL is only a projection of the committed root, so it cannot expose
        # the candidate action while the root CAS is still pending.
        assert projected_action() is None
        release_reader.set()
        assert reader_waiting.wait(timeout=5)
        raise RuntimeError("suppression root CAS failed")

    monkeypatch.setattr(store, "cas", fail_before_root_commit)
    with pytest.raises(ValueError, match="not admitted"):
        facts.content.delete.remove(node, workspace, target.fid, ts=301)
    reader.join(timeout=5)

    assert not reader.is_alive()
    assert len(candidate) == 1
    assert committed_action(candidate[0]) == {
        "state": "active", "action": deletion.fid}
    assert store.get("root") == old_root
    assert node.fact_of(workspace, deletion.fid) is None
    assert projected_action() is None
    assert observed == [(200, old_root)]
    assert canonical_observed == [True]
    assert visible()
    assert store.list("pile/")

    if restart:
        index = node.idx(workspace)
        index.executescript(
            "DELETE FROM facts; DELETE FROM fact_index; DELETE FROM meta;")
        index.commit()
        index.close()
        node = Node(node.dir)
        store = node.store(workspace)
    else:
        monkeypatch.setattr(store, "cas", original_cas)

    assert node.fact_of(workspace, deletion.fid) is None
    assert store.get("root") == old_root
    assert visible()
    retry_cas = store.cas
    retried = []

    def observe_retry(key, etag, raw):
        retried.append(raw)
        return retry_cas(key, etag, raw)

    monkeypatch.setattr(store, "cas", observe_retry)
    node.turn(workspace)

    assert retried == candidate
    assert store.get("root") == candidate[0]
    assert node.fact_of(workspace, deletion.fid) == deletion
    assert projected_action() == (deletion.fid,)
    assert committed_action(store.get("root")) == {
        "state": "active", "action": deletion.fid}
    assert not visible()
    _, (code, body) = invoke_mint(node, workspace, request)
    assert (code, base64.b64decode(body["root"])) == (200, candidate[0])
    assert canonical_observed == [True, False]
