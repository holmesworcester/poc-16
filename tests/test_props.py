"""The load-bearing properties.

P-history-independence: the same candidate/proof join — any proof arrival
order and any number of turns — converges to an identical root.
P-paths-are-piles: every selected historical proof is a closed, topo-sorted
set that passes the kernel from an empty scratchpad.
P-rebuild: wipe the derived index, replay the store's own units, get the
identical root back.
P-efficient-updates: one new fact rewrites O(1) objects, not O(n).
"""
import json
import random
import sqlite3

import pytest
import facts

from core import (
    merkle_map,
    cmds,
    indexes,
    mint,
    snapshot,
)
from core.candidate_archive import CandidateView
from core.close import close, decode_pile, encode_pile
from core.crypto import h, keypair, load_sk
from core.fact import Fact, encode as encode_fact
from core.shape import fid_of
from facts.auth.request import payload as request_payload
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.content.message import message
from core.kernel import drain, resolve_deps
from core.node import Node, now_ms
from core.publication import Publisher

from . import util as test_util
from .util import (
    add_member,
    all_fids,
    author_msg,
    closed_subset,
    deliver,
    member_src,
    send_bytes,
)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Alice's node with a workspace: 3 members, messages, a file, an evict."""
    # Pin identity and time so path-cost laws never depend on random partitions.
    monkeypatch.setattr("core.node.now_ms", lambda: 2_000_000)
    identities = iter(range(2, 10))

    def keypair():
        secret = load_sk(f"{next(identities):064x}")
        return secret, secret.verify_key.encode().hex()

    monkeypatch.setattr(test_util, "keypair", keypair)
    n = Node(
        str(tmp_path / "alice"),
        initial_secret=load_sk(f"{1:064x}"),
    )
    ws = cmds.create(n, "alice", ts=1_000_000)
    t0 = 1_000_010
    bsk, bpk, _ = add_member(n, ws, "bob", t0 + 1)
    csk, cpk, _ = add_member(n, ws, "carol", t0 + 2)
    rng = random.Random(16)
    actors = [(n.sk, n.pk), (bsk, bpk), (csk, cpk)]
    for i in range(40):
        sk, pk = rng.choice(actors)
        author_msg(n, ws, sk, pk, f"m{i}", t0 + 10 + i)
    send_bytes(n, ws, "blob.bin", rng.randbytes(30_000))
    cmds.evict(n, ws, "carol")
    return n, ws


def units_of(store):
    """Each selected historical admission proof from the store alone."""
    fetch = lambda oid: store.get("obj/" + oid)
    view = CandidateView(store.get("root"), fetch)
    for fid in view.candidate_ids():
        yield fid, view.verify(fid).facts


def candidate_pile(node, workspace, fid):
    """Exact selected historical witness for one candidate."""
    store = node.store(workspace)
    view = CandidateView(
        store.get("root"), lambda oid: store.get("obj/" + oid))
    return encode_pile(view.verify(fid).facts, workspace=workspace)


def test_paths_are_piles(world):
    """Every selected historical proof judges alone, from nothing."""
    n, ws = world
    count = 0
    for fid, stream in units_of(n.store(ws)):
        result = drain(stream, ws)
        assert result.ok, f"proof failed the kernel: {fid}"
        count += 1
    assert count >= 2


def test_history_independence(tmp_path, world):
    """Random proof order and turn batching preserve the candidate join."""
    n, ws = world
    fids = all_fids(n, ws)
    selected = [
        (fid, encode_pile(stream, workspace=ws))
        for fid, stream in units_of(n.store(ws))
    ]
    for seed in range(3):
        rng = random.Random(seed)
        b = Node(str(tmp_path / f"b{seed}"))
        shuffled = selected[:]
        rng.shuffle(shuffled)
        i = 0
        while i < len(shuffled):
            take = rng.randint(1, 9)
            chunk = shuffled[i:i + take]
            i += take
            for ordinal, (_, raw) in enumerate(chunk):
                deliver(
                    b, ws, raw,
                    member=f"m{seed:03d}{i:05d}{ordinal:07d}")
            b.turn(ws)
        assert b.store(ws).get("root") == n.store(ws).get("root")
        assert all_fids(b, ws) == fids


def test_rebuild(world):
    n, ws = world
    before = h(n.store(ws).get("root"))
    n.idx(ws).executescript(
        "DELETE FROM facts; DELETE FROM fact_index; DELETE FROM staged; "
        "DELETE FROM meta;")
    n.rebuild(ws)
    n.admission(ws).publish()
    assert h(n.store(ws).get("root")) == before


def test_rebuild_rejects_a_corrupted_leaf(world):
    n, ws = world
    st = n.store(ws)
    before = all_fids(n, ws)
    root_bytes = st.get("root")
    fetch = lambda oid: st.get("obj/" + oid)
    committed = snapshot.decode_root(root_bytes)
    _, fact_oid = snapshot.fact_order_rows(
        committed.maps[snapshot.FACT_ORDER],
        committed.layout_seed,
        fetch,
    )[0]
    st._replace("obj/" + fact_oid, b"corrupt")

    with pytest.raises(ValueError, match="object integrity"):
        n.rebuild(ws)

    assert st.get("root") == root_bytes
    assert all_fids(n, ws) == before


def test_rebuild_rejects_fact_order_that_hides_or_misplaces_facts(world):
    """FactOrder cannot smuggle bytes or remap an eligible key."""
    n, ws = world
    st = n.store(ws)
    before = all_fids(n, ws)
    honest = st.get("root")
    fetch = lambda oid: st.get("obj/" + oid)
    committed = snapshot.decode_root(honest)
    rows = list(snapshot.fact_order_rows(
        committed.maps[snapshot.FACT_ORDER],
        committed.layout_seed,
        fetch,
    ))

    def emit(raw):
        oid = h(raw)
        st._replace("obj/" + oid, raw)
        return oid

    def forged_root(order_rows):
        order = snapshot.build_fact_order(
            order_rows, committed.layout_seed, emit)
        return snapshot.encode_root(
            ws,
            {
                **committed.maps,
                snapshot.FACT_ORDER: order,
            },
            seed=committed.layout_seed,
        )

    hidden = Fact("sample", 0, [], {"hidden": True}, ws)
    hidden_oid = emit(encode_fact(hidden))
    st._replace("root", forged_root(rows + [(hidden.key, hidden_oid)]))
    with pytest.raises(ValueError, match="missing FactRecord"):
        n.rebuild(ws)

    assert len(rows) >= 2
    moved = list(rows)
    moved[0] = (moved[0][0], moved[1][1])
    st._replace("root", forged_root(moved))
    with pytest.raises(ValueError, match="FactOrder projection"):
        n.rebuild(ws)

    st._replace("root", honest)
    assert all_fids(n, ws) == before


def test_rebuild_rejects_a_non_durable_resident_family(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    before = all_fids(node, workspace)
    monkeypatch.setattr(facts.family_for("workspace"), "DURABLE", False)

    with pytest.raises(ValueError, match="ephemeral fact"):
        node.rebuild(workspace)

    assert all_fids(node, workspace) == before


def test_rebuild_rejects_an_incomplete_empty_root_without_its_anchor(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    before = all_fids(node, workspace)
    store = node.store(workspace)
    store._replace("root", snapshot.encode_root(workspace))

    with pytest.raises(ValueError, match="candidate archive is incomplete"):
        node.rebuild(workspace)

    assert all_fids(node, workspace) == before


def test_commit_never_publishes_a_root_without_its_anchor(tmp_path):
    """The publisher never mints a root every reader must reject: rebuild and
    WorkerView both demand the anchor, so an index that lacks it is not
    publishable — it stays ahead of the snapshot instead."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    root = node.store(workspace).get("root")
    node.idx(workspace).executescript("DELETE FROM facts;")

    assert node.admission(workspace).publish() is None
    assert node.store(workspace).get("root") == root
    assert node.idx(workspace).execute(
        "SELECT 1 FROM meta WHERE k='root'").fetchone() is None
    node.rebuild(workspace)  # the store, not the index, stayed authoritative
    assert all_fids(node, workspace) == [workspace]


def test_pre_manifest_crash_retains_intent_behind_authoritative_root(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    old_root = h(node.store(workspace).get("root"))

    secret, public = node.identity(workspace)
    item = message(workspace, public, "general", "survives retry", 2)
    signed = signature(secret, public, item, 2)
    new = {fact.fid: fact for fact in (signed, item)}
    deps = {
        signed.fid: [],
        item.fid: [signed.fid, member_src(node, workspace, public)],
    }

    def fact_of(fid):
        return new.get(fid) or node.fact_of(workspace, fid)

    pile = encode_pile(close(
        [signed, item],
        lambda fid: deps[fid] if fid in deps else
        (resolve_deps(fact_of(fid), node.idx(workspace)) or ()),
        fact_of,
    ))
    deliver(node, workspace, pile)
    stream, _ = decode_pile(pile, workspace)
    judgment = drain(stream, workspace)
    assert judgment.ok
    node.admission(workspace).admit(stream)

    # Model process death at the exact admission/manifest boundary: no exception
    # handler gets to restore the derived index before its connections close.
    assert h(node.store(workspace).get("root")) == old_root
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == 3
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() is None
    assert cmds.msgs(node, workspace) == []
    assert node.store(workspace).list("pile/")

    for index in node._idx.values():
        index.close()

    reopened = Node(node.dir)
    assert reopened.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == 3
    assert len(reopened.catalog(workspace).staged_ids()) == 2
    assert cmds.msgs(reopened, workspace) == []
    assert reopened.store(workspace).list("pile/")

    keys = reopened.keys
    reopened.keys = lambda *args: pytest.fail(
        "recovered hot commit called Node.keys")
    try:
        reopened.turn(workspace)
    finally:
        reopened.keys = keys

    assert [message["text"] for message in cmds.msgs(
        reopened, workspace)] == ["survives retry"]
    assert reopened.catalog(workspace).staged_ids() == ()
    assert reopened.store(workspace).list("pile/") == []
    root = h(reopened.store(workspace).get("root"))
    assert reopened.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (root,)
    assert reopened.idx(workspace).execute(
        "SELECT 1 FROM sqlite_master WHERE name='log'").fetchone() is None
    assert reopened.store(workspace).get("root") \
        == full_snapshot(reopened, workspace)


def test_post_cas_crash_recovers_staged_catalog_receipts(tmp_path, monkeypatch):
    """The new root, not a pre-CAS catalog write, wins the crash boundary."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    secret, public = node.identity(workspace)
    item = message(workspace, public, "general", "after-cas", 2)
    signed = signature(secret, public, item, 2)
    deps = {
        signed.fid: [],
        item.fid: [signed.fid, member_src(node, workspace, public)],
    }
    new = {fact.fid: fact for fact in (signed, item)}

    def deps_of(fid):
        if fid in deps:
            return deps[fid]
        return resolve_deps(
            node.fact_of(workspace, fid), node.idx(workspace)) or ()

    raw = encode_pile(close(
        [signed, item],
        deps_of,
        lambda fid: new.get(fid) or node.fact_of(workspace, fid),
    ))
    deliver(node, workspace, raw)
    judgment = drain(decode_pile(raw, workspace)[0], workspace)
    admission = node.admission(workspace).admit(
        decode_pile(raw, workspace)[0])
    old_root = node.store(workspace).get("root")

    def die_after_cas(*args, **kwargs):
        raise RuntimeError("simulated post-CAS death")

    original_stamp = Publisher.stamp
    monkeypatch.setattr(Publisher, "stamp", die_after_cas)
    with pytest.raises(RuntimeError, match="post-CAS death"):
        node.admission(workspace).publish(admission.settlement)
    assert node.store(workspace).get("root") != old_root
    assert node.idx(workspace).execute(
        "SELECT 1 FROM staged WHERE fid=?",
        (item.fid,)).fetchone() == (1,)
    for index in node._idx.values():
        index.close()
    monkeypatch.setattr(Publisher, "stamp", original_stamp)

    reopened = Node(node.dir)
    assert reopened.fact_of(workspace, item.fid) == item
    assert reopened.idx(workspace).execute(
        "SELECT 1 FROM staged WHERE fid=?",
        (item.fid,)).fetchone() is None
    assert reopened.store(workspace).list("pile/")
    reopened.turn(workspace)
    assert reopened.store(workspace).list("pile/") == []
    assert [row["text"] for row in cmds.msgs(reopened, workspace)] \
        == ["after-cas"]


def test_failed_turn_restores_authoritative_state_before_return(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    ts = now_ms()
    proof = request_payload(
        node, workspace, "sync", ts + 60_000, ts)
    node.bind_identity(workspace, founder)
    proof_bytes = encode_pile(proof)
    fetch = lambda oid: node.store(workspace).get("obj/" + oid)
    assert mint.stateless(
        proof_bytes, node.store(workspace).get("root"), fetch, ts)

    store = node.store(workspace)
    old_root = h(store.get("root"))
    original_cas = store.cas

    def fail_manifest_cas(*args, **kwargs):
        raise RuntimeError("simulated pre-manifest CAS failure")

    monkeypatch.setattr(store, "cas", fail_manifest_cas)
    with pytest.raises(RuntimeError, match="pre-manifest CAS failure"):
        cmds.evict(node, workspace, bob)

    # The daemon catches command failures and keeps serving. Before turn()
    # releases its lock, the old root must again govern mint and queries.
    assert h(node.store(workspace).get("root")) == old_root
    assert mint.stateless(
        proof_bytes, node.store(workspace).get("root"), fetch, ts)
    assert next(
        member for member in cmds.members(node, workspace)
        if member["pk"] == bob
    )["evicted"] is False
    assert node.by_type(workspace, "evict") == ()
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (old_root,)
    assert not node.idx(workspace).in_transaction
    assert not (tmp_path / "node" / "app.db").exists()
    assert node.store(workspace).list("pile/")

    monkeypatch.setattr(store, "cas", original_cas)
    node.turn(workspace)

    assert mint.stateless(
        proof_bytes, store.get("root"),
        lambda oid: store.get("obj/" + oid), ts) is None
    assert next(
        member for member in cmds.members(node, workspace)
        if member["pk"] == bob
    )["evicted"] is True
    assert len(node.by_type(workspace, "evict")) == 1
    assert node.store(workspace).list("pile/") == []
    root = h(node.store(workspace).get("root"))
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (root,)
    assert node.idx(workspace).execute(
        "SELECT 1 FROM sqlite_master WHERE name='log'").fetchone() is None


def test_index_stamp_rolls_back_a_partial_write(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    index = node.idx(workspace)
    expected = index.execute(
        "SELECT k, v FROM meta ORDER BY k").fetchall()
    index.executescript(
        "CREATE TRIGGER fail_index_version "
        "BEFORE INSERT ON meta WHEN NEW.k='index-version' "
        "BEGIN SELECT RAISE(FAIL, 'simulated stamp failure'); END;"
    )

    with pytest.raises(sqlite3.IntegrityError, match="stamp failure"):
        Publisher(node, workspace).stamp(
            node.store(workspace).get("root"))

    assert not index.in_transaction
    assert index.execute(
        "SELECT k, v FROM meta ORDER BY k").fetchall() == expected
    index.execute("DROP TRIGGER fail_index_version")
    index.commit()
    Publisher(node, workspace).stamp(
        node.store(workspace).get("root"))


def test_partial_stamp_failure_retries_in_the_same_process(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    original_stamp = Publisher.stamp
    failed = False

    def fail_once_after_root(publisher, root_bytes, admitted=()):
        nonlocal failed
        root_etag = h(root_bytes) if root_bytes is not None else None
        stamped_workspace = publisher.workspace
        if not failed:
            failed = True
            node.idx(stamped_workspace).execute(
                "INSERT OR REPLACE INTO meta VALUES('root', ?)",
                (root_etag,),
            )
            raise RuntimeError("simulated partial stamp")
        original_stamp(publisher, root_bytes, admitted)

    monkeypatch.setattr(Publisher, "stamp", fail_once_after_root)
    cmds.post(node, workspace, "general", "stamp retry", ts=2)

    assert not node.idx(workspace).in_transaction
    assert [entry["text"] for entry in cmds.msgs(node, workspace)] \
        == ["stamp retry"]
    assert node.store(workspace).list("pile/")
    assert node.ingress_attempt_failures(workspace)[0]["error"] == \
        "RuntimeError: simulated partial stamp"

    node.turn(workspace)

    assert [entry["text"] for entry in cmds.msgs(node, workspace)] \
        == ["stamp retry"]
    assert node.store(workspace).list("pile/") == []
    root = h(node.store(workspace).get("root"))
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (root,)
    assert node.idx(workspace).execute(
        "SELECT 1 FROM sqlite_master WHERE name='log'").fetchone() is None


def test_bulk_index_crash_retains_but_hides_unpublished_facts(
        tmp_path, monkeypatch):
    from bench.bench_sync import bulk_author

    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    old_root = h(node.store(workspace).get("root"))
    bulk_author(
        node,
        workspace,
        [node.identity(workspace)],
        1,
        2,
        1,
        random.Random(16),
    )
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone() == (3,)
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() is None

    def fail_before_manifest(*args, **kwargs):
        raise RuntimeError("simulated bulk pre-manifest failure")

    monkeypatch.setattr(node.store(workspace), "cas", fail_before_manifest)
    with pytest.raises(RuntimeError, match="bulk pre-manifest failure"):
        node.admission(workspace).publish()

    for index in node._idx.values():
        index.close()

    reopened = Node(node.dir)
    assert h(reopened.store(workspace).get("root")) == old_root
    assert reopened.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone() == (3,)
    assert len(reopened.catalog(workspace).staged_ids()) == 2
    assert cmds.msgs(reopened, workspace) == []
    reopened.turn(workspace)
    assert h(reopened.store(workspace).get("root")) != old_root
    assert reopened.catalog(workspace).staged_ids() == ()


def test_semantic_index_upgrade_preserves_the_published_snapshot(world):
    n, ws = world
    expected = n.store(ws).get("root")
    idx = n.idx(ws)
    idx.execute("DELETE FROM meta WHERE k='index-version'")
    idx.commit()
    idx.close()

    reopened = Node(n.dir)
    assert reopened.store(ws).get("root") == expected


def test_straggler_minifold(tmp_path, world):
    """A fact landing deep below the tail recuts only its page — and both
    nodes still agree byte-for-byte."""
    n, ws = world
    b = Node(str(tmp_path / "b"))
    for ordinal, (_, stream) in enumerate(units_of(n.store(ws))):
        deliver(
            b, ws, encode_pile(stream, workspace=ws),
            member=f"a{ordinal:015d}")
    b.turn(ws)
    assert b.store(ws).get("root") == n.store(ws).get("root")

    old = min(
        n.candidate_of(ws, fid).ts
        for (fid,) in n.idx(ws).execute("SELECT fid FROM facts")
    ) + 5
    f = author_msg(n, ws, n.sk, n.pk, "late straggler", ts=old)
    assert f.fid in all_fids(n, ws)
    deliver(b, ws, candidate_pile(n, ws, f.fid))
    b.turn(ws)
    assert b.store(ws).get("root") == n.store(ws).get("root")


def test_efficient_updates(world):
    """One post touches bounded tree/range paths, not the object corpus."""
    n, ws = world
    st = n.store(ws)
    puts = []
    orig = st.put_if_absent
    st.put_if_absent = lambda k, b: (puts.append(k), orig(k, b))[1]
    cmds.post(n, ws, "general", "one more")
    objs = [k for k in puts if k.startswith("obj/")]
    total = len(st.list("obj/"))
    # A post adds a message and signature. Each rewrites bounded paths in the
    # four authenticated maps and emits its stable fact object.
    depth = max(
        row["depth"] for row in
        json.loads(st.get("root"))["maps"].values())
    assert depth <= merkle_map.MAX_PAGE_DEPTH
    assert len(objs) <= 6 + 10 * depth, \
        f"a single post rewrote {len(objs)} objects"
    assert total > 20  # against a store big enough to make the bound mean something


def full_snapshot(n, ws):
    """The root a from-scratch full recompute would write (no memo)."""
    idx = n.idx(ws)
    seed, trees = indexes.build(
        ws, idx, lambda raw: h(raw))
    order = snapshot.build_fact_order(
        (
            (fact.key, h(encode_fact(fact)))
            for fact in (
                n.fact_of(ws, fid_of(address))
                for address in n.keys(ws)
            )
            if fact is not None
        ),
        seed,
        lambda raw: h(raw),
    )
    return snapshot.encode_root(
        ws, {snapshot.FACT_ORDER: order, **trees}, seed=seed)


def test_ordinary_append_reads_only_exact_action_slots(tmp_path, monkeypatch):
    """Existing actions are not rescanned or republished for an unrelated fact."""
    node, workspace, _, _ = test_util.suppression_world(tmp_path / "node")
    statements, updates = [], []
    index = node.idx(workspace)
    index.set_trace_callback(statements.append)
    update = merkle_map.update

    def observed(root, seed, rows, fetch, emit, **kwargs):
        rows = tuple(rows)
        updates.append(rows)
        return update(root, seed, rows, fetch, emit, **kwargs)

    monkeypatch.setattr(merkle_map, "update", observed)
    try:
        added = cmds.post(
            node, workspace, "general", "bounded action consult", ts=1_000)
    finally:
        index.set_trace_callback(None)

    action_reads = [
        " ".join(statement.lower().split())
        for statement in statements
        if statement.lstrip().lower().startswith("select")
        and " from actions" in statement.lower()
    ]
    assert action_reads
    assert all(
        " where sid=" in statement or " where fid=" in statement
        for statement in action_reads
    ), action_reads
    by_tree = dict(zip(
        (*indexes.TREE_NAMES, snapshot.FACT_ORDER), updates))
    sid = indexes.fact_key(added)
    assert {
        key for key, _ in by_tree[indexes.FACT]
        if key.startswith("action:")
    } == {indexes.action_key(sid)}
    assert dict(by_tree[indexes.SUPP]) == {
        sid: {"state": "clear"},
    }
    assert node.store(workspace).get("root") == full_snapshot(
        node, workspace)


def test_action_publication_path_copies_only_its_changed_sid(
        tmp_path, monkeypatch):
    node, workspace, _, _ = test_util.suppression_world(tmp_path / "node")
    target = cmds.post(
        node, workspace, "general", "one more target", ts=40)
    updates = []
    update = merkle_map.update

    def observed(root, seed, rows, fetch, emit, **kwargs):
        rows = tuple(rows)
        updates.append(rows)
        return update(root, seed, rows, fetch, emit, **kwargs)

    monkeypatch.setattr(merkle_map, "update", observed)
    action = cmds.remove(node, workspace, target, ts=200)

    by_tree = dict(zip(
        (*indexes.TREE_NAMES, snapshot.FACT_ORDER), updates))
    sid = indexes.fact_key(target)
    active = {"state": "active", "action": action}
    assert {
        key: value for key, value in by_tree[indexes.FACT]
        if key.startswith("action:")
    } == {indexes.action_key(sid): active}
    assert dict(by_tree[indexes.SUPP]) == {sid: active}
    assert node.store(workspace).get("root") == full_snapshot(
        node, workspace)


def test_resident_action_winner_delta_matches_full_fact_tree(tmp_path):
    """A changed sid republishes the newly selected resident action evidence."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    target = cmds.post(node, workspace, "general", "target", ts=10)
    first = cmds.remove(node, workspace, target, ts=20)
    from facts import _policy
    from facts.content.delete import delete

    victim = node.fact_of(workspace, target)
    secret, public = node.identity(workspace)
    proposal = delete(
        workspace, public, victim.key, _policy.OWNER, 30)
    signed = signature(secret, public, proposal, 30)
    node.ingest_new(
        workspace, [signed, proposal], {
            signed.fid: (),
            proposal.fid: (
                target, signed.fid, member_src(node, workspace, public)),
        })
    second = proposal.fid
    sid = indexes.fact_key(target)
    index = node.idx(workspace)
    assert index.execute(
        "SELECT fid FROM actions WHERE sid=?", (sid,)
    ).fetchone() == (first,)

    index.execute(
        "UPDATE actions SET fid=? WHERE sid=?",
        (second, sid),
    )
    committed = snapshot.decode_root(node.store(workspace).get("root"))
    fetch = lambda oid: node.store(workspace).get("obj/" + oid)

    incremental = indexes.build(
        workspace, index, lambda raw: h(raw),
        previous={
            name: committed.maps[name]
            for name in indexes.TREE_NAMES
        }, fetch=fetch,
        changed_fids=(), changed_sids=(sid,))
    rebuilt = indexes.build(
        workspace, index, lambda raw: h(raw))

    assert (incremental.seed, incremental.trees) == (
        rebuilt.seed, rebuilt.trees)


def test_incremental_equals_full(tmp_path):
    """The incremental commit is byte-identical to a full recompute at every
    step — across promotions, a straggler, a new member, and an eviction."""
    n = Node(str(tmp_path / "a"))
    ws = cmds.create(n, "alice")
    assert n.store(ws).get("root") == full_snapshot(n, ws)
    t0 = now_ms()
    bsk, bpk, _ = add_member(n, ws, "bob", t0 + 1)
    assert n.store(ws).get("root") == full_snapshot(n, ws)
    for i in range(60):  # enough to promote several ranges out of the tail
        who = (n.sk, n.pk) if i % 2 else (bsk, bpk)
        author_msg(n, ws, *who, f"m{i}", t0 + 10 + i)
        assert n.store(ws).get("root") == full_snapshot(n, ws)
    send_bytes(n, ws, "f.bin", b"x" * 20_000)
    assert n.store(ws).get("root") == full_snapshot(n, ws)
    author_msg(n, ws, n.sk, n.pk, "straggler", t0 + 5)  # lands deep in history
    assert n.store(ws).get("root") == full_snapshot(n, ws)
    cmds.evict(n, ws, "bob")
    assert n.store(ws).get("root") == full_snapshot(n, ws)


def test_add_member_builds_a_monotone_delegation_chain(tmp_path):
    """The direct fixture helper follows the real member-authority spine."""
    n = Node(str(tmp_path / "chain"))
    ws = cmds.create(n, "alice")
    ts = now_ms()
    bob_sk, bob_pk, bob = add_member(n, ws, "bob", ts=ts + 1)
    _, _, carol = add_member(
        n, ws, "carol", inviter=(bob_sk, bob_pk), ts=ts + 3)

    invite_fid = carol.refs()[0][1]
    invitation = n.fact_of(ws, invite_fid)
    deps = resolve_deps(invitation, n.idx(ws))
    assert bob.fid in deps
    assert bob.ts < invitation.ts < carol.ts

    pile, _ = decode_pile(
        closed_subset(n, ws, [carol.fid]), ws)
    assert drain(pile, ws).ok

    outsider = keypair()
    with pytest.raises(ValueError, match="not a workspace member"):
        add_member(n, ws, "mallory", inviter=outsider, ts=ts + 5)
    with pytest.raises(ValueError, match="must follow"):
        add_member(n, ws, "late-bob", inviter=(bob_sk, bob_pk), ts=bob.ts)


def test_rejoining_an_existing_key_cannot_shadow_its_invite_into_a_cycle(
        tmp_path):
    """A lower-fid recursive membership remains a valid fact, but the final
    dependency graph keeps the shallower proof and every published leaf stays
    independently valid."""
    n = Node(str(tmp_path / "shadow"))
    ws = cmds.create(n, "alice")
    bob_secret, bob_public, original = add_member(n, ws, "bob")
    base_ts = now_ms() + 10

    # Exercise the exact adversarial ordering from review: keep trying fresh
    # bearer capabilities until the recursive membership's id sorts first.
    for offset in range(1000):
        invite_secret, invite_public = keypair()
        invitation = user_invite(
            ws, bob_public, invite_public, base_ts + 2 * offset)
        recursive = user(
            invitation, invite_secret, bob_public, "bob-again",
            base_ts + 2 * offset + 1)
        if recursive.fid < original.fid:
            break
    else:
        raise AssertionError("could not construct a lower-fid recursive user")

    invitation_sig = signature(
        bob_secret, bob_public, invitation, invitation.ts)
    recursive_sig = signature(
        bob_secret, bob_public, recursive, recursive.ts)
    n.ingest_new(
        ws,
        [invitation_sig, invitation, recursive_sig, recursive],
        {
            invitation_sig.fid: [],
            invitation.fid: [
                invitation_sig.fid,
                member_src(n, ws, bob_public),
            ],
            recursive_sig.fid: [],
            recursive.fid: [invitation.fid, recursive_sig.fid],
        },
    )

    assert original.fid in resolve_deps(invitation, n.idx(ws))
    for _, stream in units_of(n.store(ws)):
        assert drain(stream, ws).ok


def test_hot_commit_path_copies_four_maps_without_corpus_scan(
        world, monkeypatch):
    """An ordinary append updates exact map rows and never calls Node.keys."""
    n, ws = world
    total = n.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    puts, statements, updates = [], [], []
    keys = n.keys
    store = n.store(ws)
    real_put = store.put_if_absent
    real_update = merkle_map.update

    def observed_update(root, seed, rows, fetch, emit, **kwargs):
        rows = tuple(rows)
        updates.append(rows)
        return real_update(root, seed, rows, fetch, emit, **kwargs)

    monkeypatch.setattr(merkle_map, "update", observed_update)
    monkeypatch.setattr(
        store, "put_if_absent",
        lambda k, b: (puts.append(k), real_put(k, b))[1])
    n.keys = lambda *args: pytest.fail("hot commit called Node.keys")
    n.idx(ws).set_trace_callback(statements.append)
    try:
        cmds.post(n, ws, "general", "incremental", ts=3_000_000)
    finally:
        n.keys = keys
        n.idx(ws).set_trace_callback(None)
    assert total > 30
    ordered = [
        statement.lower() for statement in statements
        if "from fact_index" in statement.lower()
        and "i.kind='fact.key'" in statement.lower()
        and "join proofs" in statement.lower()
        and "order by" in statement.lower()
    ]
    assert not ordered
    assert len(updates) == 4
    by_map = dict(zip(
        (*indexes.TREE_NAMES, snapshot.FACT_ORDER), updates))
    assert by_map[snapshot.FACT_ORDER]
    assert all(
        value is not None and h(n.store(ws).get("obj/" + value)) == value
        for _, value in by_map[snapshot.FACT_ORDER])
    assert n.idx(ws).execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type='index' AND name IN ('fact_keys','fact_boundaries')"
    ).fetchone() is None
    objects = [k for k in puts if k.startswith("obj/")]
    depth = max(
        row["depth"] for row in
        json.loads(store.get("root"))["maps"].values())
    assert len(objects) <= 6 + 10 * depth, \
        f"bounded authenticated paths, got {objects}"
    authenticated_rows = sum(
        row["count"]
        for row in json.loads(store.get("root"))["maps"].values())
    assert len(objects) < authenticated_rows


def test_one_fact_hot_commit_never_enters_the_full_key_path(world):
    """A valid detached signature can arrive before its target as one fact."""
    n, ws = world
    target = message(
        ws, n.pk, "general", "signed before delivery", 3_100_000)
    detached = signature(n.sk, n.pk, target, 3_100_000)
    deliver(n, ws, encode_pile([detached]))
    keys = n.keys
    n.keys = lambda *args: pytest.fail("one-fact commit called Node.keys")
    try:
        n.turn(ws)
    finally:
        n.keys = keys
    assert n.fact_of(ws, detached.fid) == detached


def test_hot_deactivation_never_enters_the_full_key_path(world):
    """Removing a member deletes exact FactOrder rows without a full scan."""
    n, ws = world
    member_secret, member_public, _ = add_member(
        n, ws, "boundary-member", ts=3_190_000)
    ts = 3_200_000
    target_fid = author_msg(
        n,
        ws,
        member_secret,
        member_public,
        "boundary victim",
        ts,
    ).fid
    cmds.post(n, ws, "general", "later neighbor", ts=ts + 1)

    keys = n.keys
    n.keys = lambda *args: pytest.fail(
        "hot deactivation called Node.keys")
    try:
        cmds.evict(n, ws, member_public)
    finally:
        n.keys = keys

    assert n.fact_of(ws, target_fid) is None
    assert n.store(ws).get("root") == full_snapshot(n, ws)


def test_shadow_guard_keeps_identity(world):
    """A duplicate offer (a re-sign by the same key) could shift a frozen
    range's canonical proof winner; the shadow guard falls back to a full
    recompute, which must stay byte-identical to a clean full build."""
    from core.close import encode_pile
    n, ws = world
    m = author_msg(n, ws, n.sk, n.pk, "dup-target", now_ms())  # alice's own msg
    s2 = signature(n.sk, n.pk, m, now_ms() + 1000)  # a SECOND alice sig over it
    deliver(n, ws, encode_pile([s2]))
    n.turn(ws)  # commit's shadow guard drops the memo -> full recompute
    assert s2.fid in all_fids(n, ws)  # the duplicate sig validated and merged
    assert n.catalog(ws).shadows([s2.fid]) is True
    assert n.store(ws).get("root") == full_snapshot(n, ws)


def test_action_state_has_no_duplicate_root_metadata(world):
    n, ws = world
    root = json.loads(n.store(ws).get("root"))
    assert set(root) == {"anchor", "layout_seed", "maps", "stamp"}
    assert "globals" not in root and "actions" not in root


def test_poison_pile_is_litter_not_poison(world):
    """A hostile writer can litter but never poison: hash-consistent but
    malformed facts must reject and retire, never wedge the drain."""
    from core.close import encode_pile
    n, ws = world
    before = len(cmds.msgs(n, ws))
    poisons = [
        Fact(
            "msg", now_ms(), [["offer"]],
            {"pk": n.pk, "chan": "c", "text": "x"}, ws),
        Fact(
            "msg", now_ms(), [[]],
            {"pk": n.pk, "chan": "c", "text": "x"}, ws),
        Fact(
            "signature", now_ms(),
            [["offer", "author", "de", n.pk]], {}, ws),
        Fact(
            "workspace", now_ms(),
            [["offer", "member", n.pk]], {}, ws),
    ]
    for p in poisons:
        deliver(n, ws, encode_pile([p]))
        n.turn(ws)  # must not raise
        assert p.fid not in all_fids(n, ws)
    assert n.store(ws).list("pile/") == []  # all retired
    cmds.post(n, ws, "general", "still alive")  # workspace still works
    assert len(cmds.msgs(n, ws)) == before + 1


def test_poison_alongside_honest(world):
    """An honest pile in the same drain still lands; poison doesn't sink it."""
    from core.close import encode_pile
    n, ws = world
    deliver(n, ws, encode_pile(
        [Fact(
            "signature", now_ms(),
            [["offer", "author", "de", n.pk]], {}, ws)],
        workspace=ws),
            member="poison0poison00")
    fid = cmds.post(n, ws, "general", "survivor")  # own ingress + turn
    assert fid in all_fids(n, ws)
    assert "survivor" in [m["text"] for m in cmds.msgs(n, ws)]


def test_ephemeral_never_persists(world):
    """A stray request fact in a pile is litter: the drain deletes it."""
    from core.close import encode_pile
    n, ws = world
    ts = now_ms()
    rq = request(ws, n.pk, "sync", ts + 9999, ts)
    s = signature(n.sk, n.pk, rq, ts)
    pile = decode_pile(
        closed_subset(
            n, ws, [n.fact_of(ws, all_fids(n, ws)[0]).fid]),
        ws,
    )[0]
    with n.lock:
        from core.kernel import offer_src
        chain = decode_pile(
            closed_subset(
                n, ws, [offer_src(n.idx(ws), "member", n.pk)]),
            ws,
        )[0]
    deliver(n, ws, encode_pile(chain + [s, rq], workspace=ws))
    n.turn(ws)
    assert rq.fid not in all_fids(n, ws)
