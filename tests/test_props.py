"""The load-bearing properties.

P-history-independence: same set, same bytes — any pile grouping, any
arrival order, any number of turns converges to an identical root.
P-leaves-are-piles: every published unit (page+annex, tail+annex) passes
the kernel from an empty scratchpad.
P-rebuild: wipe the derived index, replay the store's own units, get the
identical root back.
P-efficient-updates: one new fact rewrites O(1) objects, not O(n).
"""
import json
import random

import pytest

from tinyp2p import cmds
from tinyp2p.close import decode_pile
from tinyp2p.kernel import kernel
from tinyp2p.node import Node, now_ms

from .util import add_member, all_fids, author_msg, closed_subset, deliver


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
        stream = []
        for oh in (fen.get("annex"), fen.get("page")):
            if oh:
                stream += decode_pile(store.get("obj/" + oh))[0]
        if stream:
            yield fen, stream


def test_leaves_are_piles(world):
    """Treap leaves are closed piles: each unit judges alone, from nothing."""
    n, ws = world
    count = 0
    for fen, stream in units_of(n.store(ws)):
        ok, valids, _ = kernel(stream, ws)
        assert ok, f"unit failed the kernel: {fen}"
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
    n.idx(ws).executescript("DELETE FROM facts; DELETE FROM offers; DELETE FROM meta;")
    n.rebuild(ws)
    n.commit(ws)
    assert n.store(ws).etag("root") == before


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

    removal = [r for (r,) in idx.execute("SELECT DISTINCT a0 FROM offers WHERE name='removed'")]
    man, _ = layout(n.keys(ws), lambda fid: n.fact_of(ws, fid), deps_of, ws, removal, None)
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
    range's min-src; the shadow guard falls back to a full recompute, which
    must stay byte-identical to a clean full build."""
    from tinyp2p import fact as F
    from tinyp2p.close import encode_pile
    n, ws = world
    m = author_msg(n, ws, n.sk, n.pk, "dup-target", now_ms())  # alice's own msg
    s2 = F.sig_for(n.sk, n.pk, m, now_ms() + 1000)  # a SECOND alice sig over it
    deliver(n, ws, encode_pile([s2]))
    n.turn(ws)  # commit's shadow guard drops the memo -> full recompute
    assert s2.fid in all_fids(n, ws)  # the duplicate sig validated and merged
    assert n._shadows(ws, [s2.fid]) is True  # (author, m, alice) now has two providers
    assert n.store(ws).get("root") == full_manifest(n, ws)  # still byte-identical


def test_removal_set_in_manifest(world):
    n, ws = world
    man = json.loads(n.store(ws).get("root"))
    carol = [m["pk"] for m in cmds.members(n, ws) if m["name"] == "carol"]
    assert man["removal"] == carol


def test_poison_pile_is_litter_not_poison(world):
    """A hostile writer can litter but never poison: hash-consistent but
    malformed facts must reject and retire, never wedge the drain."""
    from tinyp2p import fact as F
    from tinyp2p.close import encode_pile
    n, ws = world
    before = len(cmds.msgs(n, ws))
    poisons = [
        F.Fact("msg", now_ms(), [["offer"]], {"pk": n.pk, "chan": "c", "text": "x"}),
        F.Fact("msg", now_ms(), [[]], {"pk": n.pk, "chan": "c", "text": "x"}),
        F.Fact("sig", now_ms(), [["offer", "author", "de", n.pk]], {}),  # passes door, crashes v_sig
        F.Fact("genesis", now_ms(), [["offer", "member", n.pk]], {}),    # missing 'sig'/'pk'
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
    from tinyp2p import fact as F
    from tinyp2p.close import encode_pile
    n, ws = world
    deliver(n, ws, encode_pile([F.Fact("sig", now_ms(), [["offer", "author", "de", n.pk]], {})]),
            member="poison0poison00")
    fid = cmds.post(n, ws, "general", "survivor")  # own ingress + turn
    assert fid in all_fids(n, ws)
    assert "survivor" in [m["text"] for m in cmds.msgs(n, ws)]


def test_ephemeral_never_persists(world):
    """A stray request fact in a pile is litter: the drain deletes it."""
    from tinyp2p import fact as F
    from tinyp2p.close import encode_pile
    n, ws = world
    ts = now_ms()
    rq = F.req(n.pk, "sync", ts + 9999, ts)
    s = F.sig_for(n.sk, n.pk, rq, ts)
    pile = decode_pile(closed_subset(n, ws, [n.fact_of(ws, all_fids(n, ws)[0]).fid]))[0]
    with n.lock:
        chain = decode_pile(closed_subset(n, ws, [n.member_src(ws)]))[0]
    deliver(n, ws, encode_pile(chain + [s, rq]))
    n.turn(ws)
    assert rq.fid not in all_fids(n, ws)
