"""E = V minus S stays independent of delivery history."""
import base64
import threading

import pytest

import facts

from core import cmds, daemon, tree
from core.close import decode_pile, encode_pile
from core.kernel import drain
from core.node import Node
from core.shape import SUPP, SUPP_INDEX
from core.suppression import victims
from facts.auth.request import payload as request_payload

from .util import (
    MultiGroupFamily,
    all_fids,
    channel_delete,
    closed_subset,
    invoke_mint,
    multi_group_post,
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


def test_pre_v14_index_rebuild_recreates_supp_multiplicity(
        tmp_path, monkeypatch):
    """A pre-v14 restart DROPs the old supp table, not just its rows: the
    v13 DDL (fid PK, k UNIQUE) survives CREATE IF NOT EXISTS, and its stale
    UNIQUE would silently swallow all but one victim per group on re-merge
    — the I6 under-suppression — before stamping the file v14 for good."""
    monkeypatch.setitem(
        facts.ROUTES, MultiGroupFamily.TAG, MultiGroupFamily)
    node, workspace, targets, _ = suppression_world(
        tmp_path / "node", monkeypatch)
    both = multi_group_post("channel-0", "alice", "hi", 50)
    node.ingest_new(workspace, [both], {both.fid: []})
    index = node.idx(workspace)
    fresh = sorted(index.execute("SELECT fid, k FROM supp"))
    chan0 = '["chan","channel-0"]'
    assert [k for _, k in fresh].count(chan0) == 5  # 4 posts + both
    assert sorted(k for fid, k in fresh if fid == both.fid) == [
        '["chan","author/alice"]', chan0]

    index.executescript(
        "DROP INDEX supp_by_k; DROP TABLE supp;"
        "CREATE TABLE supp(fid TEXT PRIMARY KEY, k TEXT UNIQUE);")
    index.executemany("INSERT OR IGNORE INTO supp VALUES(?,?)", fresh)
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('index-version', "
        "'family-contract-v13-one-store')")
    index.commit()
    assert index.execute(
        "SELECT COUNT(*) FROM supp").fetchone()[0] < len(fresh)
    index.close()
    node.app.close()

    upgraded = Node(node.dir)

    assert sorted(upgraded.idx(workspace).execute(
        "SELECT fid, k FROM supp")) == fresh


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


@pytest.mark.parametrize("restart", (False, True))
@pytest.mark.skip(reason="CUTOVER_SKIP: lands in oyd.5")
def test_suppression_stays_behind_the_manifest_commit(
        tmp_path, monkeypatch, restart):
    """An ahead T_supp row is invisible until the shared root CAS succeeds."""
    node, workspace, _, _ = suppression_world(
        tmp_path / "node", monkeypatch)
    target_fid = cmds.post(
        node, workspace, "unpublished", "target", ts=300)
    target = node.fact_of(workspace, target_fid)
    deletion = channel_delete(target.fid, "unpublished", 301)
    store = node.store(workspace)
    old_root = store.get("root")

    def projected():
        return node.app.execute(
            "SELECT 1 FROM projected WHERE ws=? AND src=?",
            (workspace, target.fid)).fetchone() is not None

    def published_fids(raw):
        root = tree.decode_root(raw)
        supp = root.index(SUPP_INDEX)
        return {
            SUPP.fid_of(key)
            for key in tree.leaf_keys(
                supp, lambda oid: store.get("obj/" + oid), SUPP)
        }

    assert target.fid in published_fids(old_root)
    assert deletion.fid not in published_fids(old_root)
    assert projected()
    now = daemon.now_ms()
    request = encode_pile(request_payload(
        node, workspace, "sync", now + 60_000, now))
    canonical_observed = []
    original_mint = daemon.gate.mint

    def observe_canonical(*args, **kwargs):
        canonical_observed.append(kwargs["canonical_db"].execute(
            "SELECT COUNT(*) FROM supp WHERE fid=?",
            (deletion.fid,)).fetchone()[0])
        return original_mint(*args, **kwargs)

    monkeypatch.setattr(daemon.gate, "mint", observe_canonical)

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

    def fail_before_publish(key, etag, raw):
        candidate.append(raw)
        assert key == "root"
        assert store.get("root") == old_root
        assert node.idx(workspace).execute(
            "SELECT k FROM supp WHERE fid=?",
            (deletion.fid,)).fetchone() == (SUPP.key(deletion),)
        release_reader.set()
        assert reader_waiting.wait(timeout=5)
        raise RuntimeError("suppression manifest CAS failed")

    monkeypatch.setattr(store, "cas", fail_before_publish)
    with pytest.raises(RuntimeError, match="manifest CAS failed"):
        node.ingest_new(
            workspace, [deletion], {deletion.fid: [target.fid]})
    reader.join(timeout=5)

    assert not reader.is_alive()
    assert len(candidate) == 1
    assert deletion.fid in published_fids(candidate[0])
    assert store.get("root") == old_root
    assert node.fact_of(workspace, deletion.fid) is None
    assert node.idx(workspace).execute(
        "SELECT 1 FROM supp WHERE fid=?",
        (deletion.fid,)).fetchone() is None
    assert observed == [(200, old_root)]
    assert canonical_observed == [0]
    assert projected()
    assert store.list("pile/")

    if restart:
        index = node.idx(workspace)
        index.executescript(
            "DELETE FROM facts; DELETE FROM offers; DELETE FROM proofs; "
            "DELETE FROM supp; DELETE FROM globals; DELETE FROM meta;")
        index.commit()
        index.close()
        node.app.execute("PRAGMA user_version=0")
        node.app.commit()
        node.app.close()
        node = Node(node.dir)
        store = node.store(workspace)
    else:
        monkeypatch.setattr(store, "cas", original_cas)

    assert node.fact_of(workspace, deletion.fid) is None
    assert store.get("root") == old_root
    assert projected()
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
    assert deletion.fid in published_fids(store.get("root"))
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM supp WHERE fid=?",
        (deletion.fid,)).fetchone() == (1,)
    assert not projected()
    assert store.list("pile/") == []
    _, (code, body) = invoke_mint(node, workspace, request)
    assert (code, base64.b64decode(body["root"])) == (200, candidate[0])
    assert canonical_observed == [0, 1]
