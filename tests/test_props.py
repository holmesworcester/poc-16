"""The load-bearing properties.

P-history-independence: same set, same bytes — any pile grouping, any
arrival order, any number of turns converges to an identical root.
P-leaves-are-piles: every published leaf pile (a topo-sorted closed set) passes
the kernel from an empty scratchpad.
P-rebuild: wipe the derived index, replay the store's own units, get the
identical root back.
P-efficient-updates: one new fact rewrites O(1) objects, not O(n).
"""
import json
import random
import sqlite3

import pytest

from tinyp2p import cmds
from tinyp2p.close import close, decode_pile, encode_pile
from tinyp2p.crypto import keypair
from tinyp2p.fact import Fact
from tinyp2p.facts.auth.request import payload as request_payload
from tinyp2p.facts.auth.request import request
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.facts.content.message import message
from tinyp2p.kernel import drain, evaluate, resolve_deps
from tinyp2p.node import Node, now_ms

from .util import (
    add_member,
    all_fids,
    author_msg,
    closed_subset,
    deliver,
    member_src,
)


@pytest.fixture
def world(tmp_path):
    """Alice's node with a workspace: 3 members, messages, a file, an evict."""
    n = Node(str(tmp_path / "alice"))
    ws = cmds.create(n, "alice")
    t0 = now_ms()
    bsk, bpk, _ = add_member(n, ws, "bob", t0 + 1)
    csk, cpk, _ = add_member(n, ws, "carol", t0 + 2)
    rng = random.Random(16)
    actors = [(n.sk, n.pk), (bsk, bpk), (csk, cpk)]
    for i in range(40):
        sk, pk = rng.choice(actors)
        author_msg(n, ws, sk, pk, f"m{i}", t0 + 10 + i)
    cmds.send_file(n, ws, "general", "blob.bin", rng.randbytes(30_000))
    cmds.evict(n, ws, "carol")
    return n, ws


def units_of(store):
    man = json.loads(store.get("root"))
    for fen in man["fences"] + [man["tail"]]:
        if fen.get("pile"):
            yield fen, decode_pile(store.get("obj/" + fen["pile"]))[0]


def test_leaves_are_piles(world):
    """Treap leaves are closed piles: each unit judges alone, from nothing."""
    n, ws = world
    count = 0
    for fen, stream in units_of(n.store(ws)):
        result = drain(stream, ws)
        assert result.ok, f"unit failed the kernel: {fen}"
        count += 1
    assert count >= 5  # the set actually promoted into multiple leaves


def test_history_independence(tmp_path, world):
    """Random pile groupings, random order, random turn batching — one root."""
    n, ws = world
    fids = all_fids(n, ws)
    for seed in range(3):
        rng = random.Random(seed)
        b = Node(str(tmp_path / f"b{seed}"))
        shuffled = fids[:]
        rng.shuffle(shuffled)
        i = 0
        while i < len(shuffled):
            take = rng.randint(1, 9)
            for k in range(rng.randint(1, 3)):  # several piles per turn
                chunk = shuffled[i:i + take]
                i += take
                if chunk:
                    deliver(b, ws, closed_subset(n, ws, chunk), member=f"m{k}aaaaaaaaaaaaaa")
            b.turn(ws)
        assert b.store(ws).get("root") == n.store(ws).get("root")
        assert all_fids(b, ws) == fids


def test_rebuild(world):
    n, ws = world
    before = n.store(ws).etag("root")
    n.idx(ws).executescript(
        "DELETE FROM facts; DELETE FROM offers; DELETE FROM globals; DELETE FROM meta;")
    n.rebuild(ws)
    n.commit(ws)
    assert n.store(ws).etag("root") == before


def test_pre_manifest_crash_replays_from_the_authoritative_root(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    old_root = node.store(workspace).etag("root")

    secret, public = node.identity(workspace)
    item = message(public, "general", "survives retry", 2)
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
    stream, _ = decode_pile(pile)
    judgment = drain(stream, workspace)
    assert judgment.ok
    node.merge(workspace, judgment.valids, judgment.globals)

    # Model process death at the exact merge/manifest boundary: no exception
    # handler gets to restore the derived index before its connections close.
    assert node.store(workspace).etag("root") == old_root
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == 3
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() is None
    assert node.app.execute(
        "SELECT COUNT(*) FROM messages WHERE ws=?",
        (workspace,)).fetchone()[0] == 0
    assert node.store(workspace).list("pile/")

    for index in node._idx.values():
        index.close()
    node.app.close()

    reopened = Node(node.dir)
    assert reopened.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == 1
    assert reopened.app.execute(
        "SELECT COUNT(*) FROM messages WHERE ws=?",
        (workspace,)).fetchone()[0] == 0
    assert reopened.store(workspace).list("pile/")

    reopened.turn(workspace)

    assert [message["text"] for message in cmds.msgs(
        reopened, workspace)] == ["survives retry"]
    assert reopened.store(workspace).list("pile/") == []
    root = reopened.store(workspace).etag("root")
    assert reopened.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (root,)
    assert reopened.app.execute(
        "SELECT root FROM projection_meta WHERE ws=?",
        (workspace,)).fetchone() == (root,)


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
    assert evaluate(
        proof,
        workspace,
        node.globals(workspace),
        canonical_db=node.idx(workspace),
    )

    old_root = node.store(workspace).etag("root")
    store = node.store(workspace)
    original_cas = store.cas

    def fail_manifest_cas(*args, **kwargs):
        raise RuntimeError("simulated pre-manifest CAS failure")

    monkeypatch.setattr(store, "cas", fail_manifest_cas)
    with pytest.raises(RuntimeError, match="pre-manifest CAS failure"):
        cmds.evict(node, workspace, bob)

    # The daemon catches command failures and keeps serving. Before turn()
    # releases its lock, the old root must again govern mint, globals, and app.
    assert node.store(workspace).etag("root") == old_root
    assert evaluate(
        proof,
        workspace,
        node.globals(workspace),
        canonical_db=node.idx(workspace),
    )
    assert ("removal", bob) not in node.globals(workspace)
    assert next(
        member for member in cmds.members(node, workspace)
        if member["pk"] == bob
    )["evicted"] is False
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts WHERE t='evict'").fetchone() == (0,)
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (old_root,)
    assert node.app.execute(
        "SELECT root FROM projection_meta WHERE ws=?",
        (workspace,)).fetchone() == (old_root,)
    assert not node.idx(workspace).in_transaction
    assert not node.app.in_transaction
    assert node.store(workspace).list("pile/")

    monkeypatch.setattr(store, "cas", original_cas)
    node.turn(workspace)

    assert not evaluate(
        proof,
        workspace,
        node.globals(workspace),
        canonical_db=node.idx(workspace),
    )
    assert ("removal", bob) in node.globals(workspace)
    assert next(
        member for member in cmds.members(node, workspace)
        if member["pk"] == bob
    )["evicted"] is True
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts WHERE t='evict'").fetchone() == (1,)
    assert node.store(workspace).list("pile/") == []
    root = node.store(workspace).etag("root")
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (root,)
    assert node.app.execute(
        "SELECT root FROM projection_meta WHERE ws=?",
        (workspace,)).fetchone() == (root,)


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
        node._stamp(workspace)

    assert not index.in_transaction
    assert index.execute(
        "SELECT k, v FROM meta ORDER BY k").fetchall() == expected
    index.execute("DROP TRIGGER fail_index_version")
    index.commit()
    node._stamp(workspace)


def test_partial_stamp_failure_retries_in_the_same_process(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    original_stamp = node._stamp
    failed = False

    def fail_once_after_root(stamped_workspace):
        nonlocal failed
        if not failed:
            failed = True
            node.idx(stamped_workspace).execute(
                "INSERT OR REPLACE INTO meta VALUES('root', ?)",
                (node.store(stamped_workspace).etag("root"),),
            )
            raise RuntimeError("simulated partial stamp")
        original_stamp(stamped_workspace)

    monkeypatch.setattr(node, "_stamp", fail_once_after_root)
    with pytest.raises(RuntimeError, match="simulated partial stamp"):
        cmds.post(node, workspace, "general", "stamp retry", ts=2)

    assert not node.idx(workspace).in_transaction
    assert [entry["text"] for entry in cmds.msgs(node, workspace)] \
        == ["stamp retry"]
    assert node.store(workspace).list("pile/")

    node.turn(workspace)

    assert [entry["text"] for entry in cmds.msgs(node, workspace)] \
        == ["stamp retry"]
    assert node.store(workspace).list("pile/") == []
    root = node.store(workspace).etag("root")
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (root,)
    assert node.app.execute(
        "SELECT root FROM projection_meta WHERE ws=?",
        (workspace,)).fetchone() == (root,)


def test_bulk_index_crash_cannot_preserve_unpublished_facts(
        tmp_path, monkeypatch):
    from bench.bench_sync import bulk_author

    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    old_root = node.store(workspace).etag("root")
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
        node.commit(workspace)

    for index in node._idx.values():
        index.close()
    node.app.close()

    reopened = Node(node.dir)
    assert reopened.store(workspace).etag("root") == old_root
    assert reopened.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone() == (1,)
    assert reopened.app.execute(
        "SELECT COUNT(*) FROM messages WHERE ws=?",
        (workspace,)).fetchone() == (0,)


def test_old_index_rebuilds_generic_globals_on_open(world):
    """An index stamped before the family/global split cannot silently lose
    its removal rows when the code is upgraded."""
    n, ws = world
    expected = n.globals(ws)
    idx = n.idx(ws)
    idx.executescript(
        "DELETE FROM globals; DELETE FROM meta WHERE k='index-version';")
    idx.commit()
    idx.close()
    n.app.close()

    reopened = Node(n.dir)
    assert reopened.globals(ws) == expected


def test_straggler_minifold(tmp_path, world):
    """A fact landing deep below the tail recuts only its page — and both
    nodes still agree byte-for-byte."""
    n, ws = world
    b = Node(str(tmp_path / "b"))
    deliver(b, ws, closed_subset(n, ws, all_fids(n, ws)))
    b.turn(ws)
    assert b.store(ws).get("root") == n.store(ws).get("root")

    old = min(ts for (ts,) in n.idx(ws).execute("SELECT ts FROM facts")) + 5
    f = author_msg(n, ws, n.sk, n.pk, "late straggler", ts=old)
    assert f.fid in all_fids(n, ws)
    deliver(b, ws, closed_subset(n, ws, [f.fid]))
    b.turn(ws)
    assert b.store(ws).get("root") == n.store(ws).get("root")


def test_efficient_updates(world):
    """Content addressing is the incrementality: one post writes O(1) objects."""
    n, ws = world
    st = n.store(ws)
    puts = []
    orig = st.put
    st.put = lambda k, b: (puts.append(k), orig(k, b))[1]
    cmds.post(n, ws, "general", "one more")
    objs = [k for k in puts if k.startswith("obj/")]
    total = len(st.list("obj/"))
    assert len(objs) <= 8, f"a single post rewrote {len(objs)} objects"
    assert total > 20  # against a store big enough to make the bound mean something


def full_manifest(n, ws):
    """The manifest a from-scratch full recompute (memo disabled) would write."""
    from tinyp2p.kernel import resolve_deps
    from tinyp2p.layout import layout
    idx, cache = n.idx(ws), {}

    def deps_of(fid):
        if fid not in cache:
            cache[fid] = resolve_deps(n.fact_of(ws, fid), idx) or []
        return cache[fid]

    man, _ = layout(n.keys(ws), lambda fid: n.fact_of(ws, fid), deps_of,
                    ws, n.globals(ws), None)
    return man


def test_incremental_equals_full(tmp_path):
    """The incremental commit is byte-identical to a full recompute at every
    step — across promotions, a straggler, a new member, and an eviction."""
    n = Node(str(tmp_path / "a"))
    ws = cmds.create(n, "alice")
    assert n.store(ws).get("root") == full_manifest(n, ws)
    t0 = now_ms()
    bsk, bpk, _ = add_member(n, ws, "bob", t0 + 1)
    assert n.store(ws).get("root") == full_manifest(n, ws)
    for i in range(60):  # enough to promote several ranges out of the tail
        who = (n.sk, n.pk) if i % 2 else (bsk, bpk)
        author_msg(n, ws, *who, f"m{i}", t0 + 10 + i)
        assert n.store(ws).get("root") == full_manifest(n, ws)
    cmds.send_file(n, ws, "general", "f.bin", b"x" * 20_000)
    assert n.store(ws).get("root") == full_manifest(n, ws)
    author_msg(n, ws, n.sk, n.pk, "straggler", t0 + 5)  # lands deep in history
    assert n.store(ws).get("root") == full_manifest(n, ws)
    cmds.evict(n, ws, "bob")
    assert n.store(ws).get("root") == full_manifest(n, ws)


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

    pile, _ = decode_pile(closed_subset(n, ws, [carol.fid]))
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
            bob_public, invite_public, base_ts + 2 * offset)
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


def test_incremental_reuses_work(world):
    """Reuse is real: a post into a promoted store loads only the tail's few
    facts, not the whole set — the O(changed) compute win, not just O(1) IO."""
    n, ws = world
    total = n.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    loads = []
    orig = n.fact_of
    n.fact_of = lambda w, fid: (loads.append(fid), orig(w, fid))[1]
    try:
        cmds.post(n, ws, "general", "incremental")
    finally:
        n.fact_of = orig
    assert total > 30
    assert len(set(loads)) < total // 2, \
        f"loaded {len(set(loads))} of {total} facts — reuse isn't skipping ranges"


def test_shadow_guard_keeps_identity(world):
    """A duplicate offer (a re-sign by the same key) could shift a frozen
    range's canonical proof winner; the shadow guard falls back to a full
    recompute, which must stay byte-identical to a clean full build."""
    from tinyp2p.close import encode_pile
    n, ws = world
    m = author_msg(n, ws, n.sk, n.pk, "dup-target", now_ms())  # alice's own msg
    s2 = signature(n.sk, n.pk, m, now_ms() + 1000)  # a SECOND alice sig over it
    deliver(n, ws, encode_pile([s2]))
    n.turn(ws)  # commit's shadow guard drops the memo -> full recompute
    assert s2.fid in all_fids(n, ws)  # the duplicate sig validated and merged
    assert n._shadows(ws, [s2.fid]) is True  # (author, m, alice) now has two providers
    assert n.store(ws).get("root") == full_manifest(n, ws)  # still byte-identical


def test_removal_set_in_manifest(world):
    n, ws = world
    man = json.loads(n.store(ws).get("root"))
    carol = [m["pk"] for m in cmds.members(n, ws) if m["name"] == "carol"]
    assert man["globals"] == [["removal", carol[0]]]


def test_poison_pile_is_litter_not_poison(world):
    """A hostile writer can litter but never poison: hash-consistent but
    malformed facts must reject and retire, never wedge the drain."""
    from tinyp2p.close import encode_pile
    n, ws = world
    before = len(cmds.msgs(n, ws))
    poisons = [
        Fact("msg", now_ms(), [["offer"]], {"pk": n.pk, "chan": "c", "text": "x"}),
        Fact("msg", now_ms(), [[]], {"pk": n.pk, "chan": "c", "text": "x"}),
        Fact("signature", now_ms(), [["offer", "author", "de", n.pk]], {}),
        Fact("workspace", now_ms(), [["offer", "member", n.pk]], {}),
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
    from tinyp2p.close import encode_pile
    n, ws = world
    deliver(n, ws, encode_pile(
        [Fact("signature", now_ms(), [["offer", "author", "de", n.pk]], {})]),
            member="poison0poison00")
    fid = cmds.post(n, ws, "general", "survivor")  # own ingress + turn
    assert fid in all_fids(n, ws)
    assert "survivor" in [m["text"] for m in cmds.msgs(n, ws)]


def test_ephemeral_never_persists(world):
    """A stray request fact in a pile is litter: the drain deletes it."""
    from tinyp2p.close import encode_pile
    n, ws = world
    ts = now_ms()
    rq = request(n.pk, "sync", ts + 9999, ts)
    s = signature(n.sk, n.pk, rq, ts)
    pile = decode_pile(closed_subset(n, ws, [n.fact_of(ws, all_fids(n, ws)[0]).fid]))[0]
    with n.lock:
        from tinyp2p.kernel import offer_src
        chain = decode_pile(closed_subset(
            n, ws, [offer_src(n.idx(ws), "member", n.pk)]))[0]
    deliver(n, ws, encode_pile(chain + [s, rq]))
    n.turn(ws)
    assert rq.fid not in all_fids(n, ws)
