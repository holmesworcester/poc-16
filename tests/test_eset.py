"""E = V minus S stays independent of delivery history."""
import base64
import threading

import pytest

import facts

import core.manifest as manifest
import core.removals as removals
from core import cmds, daemon
from core.close import decode_pile, encode_pile
from core.kernel import drain
from core.node import Node
from facts.auth.request import payload as request_payload
from facts.auth.signature import signature
from facts.content.delete import delete
from facts._policy import OWNER

from .util import (
    MultiGroupFamily,
    all_fids,
    closed_subset,
    invoke_mint,
    member_src,
    multi_group_post,
    projection_state,
    replay_random,
    suppression_world,
)


def test_e_identical_across_partitions_orders_batchings(
        tmp_path, monkeypatch):
    """Random pile partitions, orders, and turn batches converge to one E."""
    source, workspace, targets, _ = suppression_world(tmp_path / "source")
    suppressed = {targets[index] for index in (1, 4, 6)}
    effective = {
        src for (src,) in source.app.execute(
            "SELECT src FROM projected WHERE ws=?", (workspace,))
    }
    assert suppressed.isdisjoint(effective)
    referenced = {
        target
        for fid in all_fids(source, workspace)
        for _, target in source.fact_of(workspace, fid).refs()
    }
    assert referenced <= {
        fid for (fid,) in source.idx(workspace).execute(
            "SELECT fid FROM proofs")
    }
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


def test_suppression_facts_not_suppressible(tmp_path):
    """A deletion targeting a deletion cannot make S shrink: I2 rejects at
    the author command AND at the family validate (the production family,
    end to end)."""
    node, workspace, _, deletions = suppression_world(tmp_path / "node")
    first = node.fact_of(workspace, deletions[0])
    with pytest.raises(ValueError, match="never victims"):
        cmds.remove(node, workspace, deletions[0], ts=200)
    secret, public = node.identity(workspace)
    recursive = delete(public, first.key, OWNER, 200)
    sig = signature(secret, public, recursive, 200)

    with pytest.raises(ValueError, match="outside the canonical set"):
        node.ingest_new(workspace, [sig, recursive], {
            recursive.fid: [
                first.fid, sig.fid, member_src(node, workspace, public)],
            sig.fid: []})

    assert node.fact_of(workspace, recursive.fid) is None
    assert not removals.applies(recursive, first)  # I2: never a victim


def test_old_index_rebuilds_reference_proofs(tmp_path, monkeypatch):
    """A v7 restart repairs unranked ref targets before serving E."""
    node, workspace, targets, deletions = suppression_world(tmp_path / "node")
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
    node, workspace, targets, _ = suppression_world(tmp_path / "node")
    legacy = [
        multi_group_post(
            "channel-0", f"author-{ordinal}", f"m{ordinal}", 40 + ordinal)
        for ordinal in range(4)
    ]
    node.ingest_new(
        workspace, legacy, {fact.fid: [] for fact in legacy})
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
        tmp_path / "source")
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
def test_suppression_stays_behind_the_manifest_commit(
        tmp_path, monkeypatch, restart):
    """An ahead removal — admitted deletion, consult-side entry — is
    invisible until the shared root CAS succeeds (was the ahead-T_supp-row
    law; the published state is now the root's removals slot)."""
    node, workspace, _, _ = suppression_world(tmp_path / "node")
    target_fid = cmds.post(
        node, workspace, "unpublished", "target", ts=300)
    target = node.fact_of(workspace, target_fid)
    deletion = delete(  # the fid cmds.remove(ts=301) authors below
        node.identity_id(workspace), target.key, OWNER, 301)
    store = node.store(workspace)
    old_root = store.get("root")

    def projected():
        return node.app.execute(
            "SELECT 1 FROM projected WHERE ws=? AND src=?",
            (workspace, target.fid)).fetchone() is not None

    def published_fids(raw):
        slot = manifest.decode_root(raw)[3]
        if not slot["oid"]:
            return set()
        entries, _ = removals.decode(store.get("obj/" + slot["oid"]))
        return {e.fid for e in entries}

    assert published_fids(old_root)  # the world's deletions already settled
    assert deletion.fid not in published_fids(old_root)
    assert projected()
    now = daemon.now_ms()
    request = encode_pile(request_payload(
        node, workspace, "sync", now + 60_000, now))
    canonical_observed = []
    original_mint = daemon.gate.stateless

    def observe_canonical(pile, root, fetch, trusted_now, projection=None):
        canonical_observed.append(root == old_root)
        return original_mint(
            pile, root, fetch, trusted_now, projection)

    monkeypatch.setattr(daemon.gate, "stateless", observe_canonical)

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
        # the consult-side entry table is ahead of the published slot
        assert deletion.fid in {
            e.fid for e in node.removal_entries(workspace)}
        release_reader.set()
        assert reader_waiting.wait(timeout=5)
        raise RuntimeError("suppression manifest CAS failed")

    monkeypatch.setattr(store, "cas", fail_before_publish)
    with pytest.raises(RuntimeError, match="manifest CAS failed"):
        cmds.remove(node, workspace, target.fid, ts=301)
    reader.join(timeout=5)

    assert not reader.is_alive()
    assert len(candidate) == 1
    assert deletion.fid in published_fids(candidate[0])
    assert store.get("root") == old_root
    assert node.fact_of(workspace, deletion.fid) is None
    assert deletion.fid not in {
        e.fid for e in node.removal_entries(workspace)}
    assert observed == [(200, old_root)]
    assert canonical_observed == [True]
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
    assert not projected()
    _, (code, body) = invoke_mint(node, workspace, request)
    assert (code, base64.b64decode(body["root"])) == (200, candidate[0])
    assert canonical_observed == [True, False]
