"""Contracts for the one-store cutover (docs/CUTOVER.md).

Skeleton: names and docstrings are the contract; bodies land with the steps
of epic poc-16-oyd — each section header names the bead that fills (and
un-skips) it. Section references cite docs/CUTOVER.md unless noted.
Removal-index invariants I1-I6 live in tests/test_removals.py; nothing here
duplicates them.
"""
import json
import random

import pytest

import facts

import core.manifest as manifest
import core.removals as removals
import core.shape as shape
import core.sync as sync_module
from core import cmds
from core.close import close, decode_pile, encode_pile
from core.crypto import h, keypair
from core.fact import canon
from core.kernel import Valid, drain, resolve_deps
from core.node import Node
from facts.auth.signature import signature
from facts.content.message import message

from .util import (
    DeletionFamily,
    add_member,
    all_fids,
    author_msg,
    channel_delete,
    closed_subset,
    deliver,
    member_src,
    replay_random,
)

SKELETON = pytest.mark.skip(reason="skeleton: contract only, body unwritten")


# ---- oyd.2: manifest + residency --------------------------------------------


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    """A settled store wide enough to hold several home leaves, authored by
    an invite chain so its closures genuinely cross leaf boundaries."""
    node = Node(str(tmp_path_factory.mktemp("cutover") / "node"))
    ws = cmds.create(node, "alice", ts=1)
    actors = [node.identity(ws)]
    for step, name in enumerate(("bob", "carol", "dave")):
        sk, pk, _ = add_member(
            node, ws, name, ts=10 * step + 10, inviter=actors[-1])
        actors.append((sk, pk))
    ts, cuts = 100, 0
    while cuts < 2:  # post until the content cut has actually fired twice
        sk, pk = actors[ts % len(actors)]
        msg = author_msg(node, ws, sk, pk, f"m{ts}", ts=ts)
        cuts += shape.boundary(msg.fid)
        ts += 1
    return node, ws


def read(node, ws):
    """``(entries, fetch)`` — the store as any reader sees it."""
    st = node.store(ws)
    fetch = lambda oid: st.get("obj/" + oid)
    _, _, man, _ = manifest.decode_root(st.get("root"))
    return manifest.decode(fetch(man), fetch), fetch


def objects(node, ws):
    """``{oid: bytes}`` for every object a reader reaches from the root."""
    st, seen = node.store(ws), {}

    def fetch(oid):
        seen[oid] = st.get("obj/" + oid)
        return seen[oid]

    _, _, man, _ = manifest.decode_root(st.get("root"))
    for entry in manifest.decode(fetch(man), fetch):
        fetch(entry.leaf)
        if entry.closure:
            fetch(entry.closure)
    assert all(raw is not None for raw in seen.values())
    return seen


def members_of(entry, fetch):
    facts, blobs = decode_pile(fetch(entry.leaf))
    assert not blobs
    return facts


def test_one_pile_codec_serves_wire_and_residence(world):
    """A resident leaf pile decodes with the same decode_pile the ingress
    uses; there is exactly one pile codec (§3)."""
    node, ws = world
    entries, fetch = read(node, ws)
    assert len(entries) > 1
    for entry in entries:
        members = members_of(entry, fetch)
        keys = [fact.key for fact in members]
        assert keys == sorted(keys) and keys[0] == entry.sep
        assert h(encode_pile(members)) == entry.leaf  # the wire codec, verbatim


def test_manifest_history_independence(tmp_path, world):
    """Same fact set ⇒ same root oid, under any partition, order, or
    batching of arrival (§1; the oid-diff licence). Harness:
    tests/util.py replay_random against manifest.build output."""
    node, ws = world
    root, want = node.store(ws).get("root"), objects(node, ws)
    assert len(want) > 4  # several leaves and siblings really are in play
    for seed in range(4):
        other = replay_random(
            node, ws, Node(str(tmp_path / f"replay{seed}")), seed)
        assert all_fids(other, ws) == all_fids(node, ws)
        assert other.store(ws).get("root") == root  # byte-equal root
        assert objects(other, ws) == want  # and every object it names


def test_boundary_rule_shared_by_leaves_and_manifest(world):
    """Leaf cuts and manifest shards both come from shape.boundary; no
    second chunking rule exists (§3)."""
    def chunks(items, fid_of):
        cuts = shape.stable_cut_positions([fid_of(item) for item in items])
        return [items[start:stop]
                for start, stop in zip([0] + cuts, cuts + [len(items)])
                if stop > start]

    node, ws = world
    entries, fetch = read(node, ws)
    keys = node.keys(ws)
    assert [chunk[0] for chunk in chunks(keys, shape.fid_of)] \
        == [entry.sep for entry in entries]

    rng = random.Random(7)
    wide = sorted(
        manifest.Entry(
            shape.key_parts(index, f"{rng.getrandbits(256):064x}"), "", "")
        for index in range(400)
    )
    emitted = {}
    manifest.encode(wide, lambda raw: emitted.setdefault(h(raw), raw))
    shards = sorted(
        ([manifest.Entry(*row) for row in body["entries"]]
         for body in map(json.loads, emitted.values()) if "entries" in body),
        key=lambda rows: rows[0].sep)
    assert len(shards) > 1  # the entry list really did shard
    assert shards == chunks(wide, lambda entry: shape.fid_of(entry.sep))


def test_cut_is_64():
    """shape.CUT == 64: the knee where a whole fetch goes bandwidth-bound
    (COSTS §6). Guards against the dial silently drifting back."""
    assert shape.CUT == 64


def test_locate_maps_key_to_home_leaf(world):
    """locate() finds the home entry for any key locally, with no I/O (§2)."""
    node, ws = world
    entries, fetch = read(node, ws)
    for entry in entries:
        for fact in members_of(entry, fetch):
            assert manifest.locate(entries, fact.key) == entry
    assert manifest.locate(entries, "") is None  # below every separator
    assert manifest.locate(entries, "~") == entries[-1]


def test_root_names_manifest_and_removals(world):
    """Root bytes carry exactly anchor, globals, manifest oid, removals
    {oid, fp}, and the layout stamp (manifest.encode_root docstring); the
    removal index is the only structure with an fp (§3, REMOVALS.md I4)."""
    node, ws = world
    raw = node.store(ws).get("root")
    body = json.loads(raw)
    assert set(body) == {
        "anchor", "globals", "manifest", "removals", "stamp"}
    assert body["anchor"] == ws and body["stamp"] == manifest.LAYOUT
    assert set(body["removals"]) == {"oid", "fp"}
    assert manifest.decode_root(raw) == (
        ws, node.globals(ws), body["manifest"], body["removals"])
    entries, fetch = read(node, ws)
    assert all(len(entry) == 3 for entry in entries)  # no fp, no n-count
    assert b"fp" not in fetch(body["manifest"])


def test_closure_sibling_is_exactly_out_of_range(world):
    """closure_keys() == keys of close(members) minus keys in (lo, hi]; no
    in-range entry, no missing out-of-range entry (§1; COSTS §5)."""
    node, ws = world
    entries, fetch = read(node, ws)
    idx = node.idx(ws)
    fact_of = lambda fid: node.fact_of(ws, fid)
    deps_of = lambda fid: resolve_deps(fact_of(fid), idx) or []
    lo, siblings = "", 0
    for entry in entries:
        members = members_of(entry, fetch)
        hi = members[-1].key
        closed = {fact.key for fact in close(members, deps_of, fact_of)}
        assert {k for k in closed if lo < k <= hi} \
            == {fact.key for fact in members}
        outside = sorted(k for k in closed if not lo < k <= hi)
        if outside:
            assert json.loads(fetch(entry.closure))["keys"] == outside
            siblings += 1
        else:
            assert entry.closure == ""
        lo = hi
    assert siblings


def test_refs_carry_dep_keys(world):
    """Dep refs embed the dep's ts (full key), so resolution needs no index;
    a wrong ts only makes the author's own fact unresolvable (§1)."""
    node, ws = world
    entries, fetch = read(node, ws)
    resolved = 0
    for entry in entries:
        if not entry.closure:
            continue
        for key in json.loads(fetch(entry.closure))["keys"]:
            home = manifest.locate(entries, key)  # parse and place, no index
            held = {fact.key: fact for fact in members_of(home, fetch)}
            assert held[key].fid == shape.fid_of(key)  # self-certifying
            assert held[key] == node.fact_of(ws, shape.fid_of(key))
            stamp, fid = key.split(":", 1)
            wrong = shape.key_parts(int(stamp) + 1, fid)  # same fid, bad ts
            elsewhere = manifest.locate(entries, wrong)
            assert elsewhere is None or wrong not in {
                fact.key for fact in members_of(elsewhere, fetch)}
            resolved += 1
    assert resolved


def test_store_closure_invariant(world):
    """After any settle, every dep of every resident fact is resident at its
    own home leaf: closure(store) == store (COSTS §5)."""
    node, ws = world
    entries, fetch = read(node, ws)
    piles = {entry: {fact.key: fact for fact in members_of(entry, fetch)}
             for entry in entries}
    resident = {fact.fid: fact
                for held in piles.values() for fact in held.values()}
    assert sorted(resident) == sorted(all_fids(node, ws))
    idx, crossings = node.idx(ws), 0
    for entry, held in piles.items():
        for fact in held.values():  # every member sits at its own home leaf
            assert manifest.locate(entries, fact.key) == entry
    for fact in resident.values():
        deps = resolve_deps(fact, idx)
        assert deps is not None
        for fid in deps:
            dep = node.fact_of(ws, fid)  # the index, not the walk, names it
            home = manifest.locate(entries, dep.key)
            assert home is not None and piles[home].get(dep.key) == dep
            crossings += home != manifest.locate(entries, fact.key)
    assert crossings  # deps really do leave their dependent's leaf


def test_layout_stamp_forces_rebuild(tmp_path):
    """Old-stamp stores rebuild wholesale; no read-compat path exists (§1).
    decode_root raises on stamp mismatch and _sync_index answers with
    rebuild(republish=True)."""
    node = Node(str(tmp_path / "node"))
    ws = cmds.create(node, "alice", ts=1)
    for ts in range(10, 30):
        cmds.post(node, ws, "general", f"m{ts}", ts=ts)
    before, honest = all_fids(node, ws), node.store(ws).get("root")
    body = json.loads(honest)
    rng = random.Random(11)
    for stamp in ["one-store-v0", "fat-v3", ""] + [
            f"{rng.getrandbits(64):016x}" for _ in range(8)]:
        with pytest.raises(ValueError, match="root stamp"):  # no second reader
            manifest.decode_root(canon({**body, "stamp": stamp}))
    foreign = canon({**body, "stamp": "one-store-v0"})
    node.store(ws).put("root", foreign)
    node._sync_index(ws)
    republished = node.store(ws).get("root")
    assert republished != foreign
    assert manifest.decode_root(republished)[0] == ws  # readable again
    # Wholesale: the old bytes are never read. The republish settles the
    # derived index under the current stamp, and the rebuild that follows
    # reads only what that settle just wrote.
    assert republished == honest and all_fids(node, ws) == before


# ---- oyd.3: sync rewrite ----------------------------------------------------


def pair(tmp_path):
    """A settled multi-leaf source and a converged destination replica."""
    source = Node(str(tmp_path / "source"))
    ws = cmds.create(source, "alice", ts=1)
    ts, cuts = 100, 0
    while cuts < 2:  # several home leaves, so subtree pruning is real
        cuts += shape.boundary(cmds.post(
            source, ws, "general", f"m{ts}", ts=ts))
        ts += 1
    destination = Node(str(tmp_path / "destination"))
    deliver(
        destination, ws,
        closed_subset(source, ws, all_fids(source, ws)))
    destination.turn(ws)
    assert destination.store(ws).get("root") == source.store(ws).get("root")
    return source, ws, destination, ts


def peer_for(source, singles, batches, pushed=None):
    """A local Peer over ``source``'s store, recording every GET."""
    class LocalPeer:
        def __init__(self, node, ws, url):
            self.node, self.ws = node, ws
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None):
            return (source.store(self.ws).get("root"),
                    source.store(self.ws).etag("root"))

        def obj(self, oid):
            singles.append(oid)
            return source.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            oids = tuple(oids)
            batches.append(oids)
            return tuple(
                source.store(self.ws).get("obj/" + oid) for oid in oids)

        def put_pile(self, raw):
            if pushed is None:
                pytest.fail("dial unexpectedly pushed")
            pushed.append(raw)
            deliver(source, self.ws, raw)
            source.turn(self.ws)

    return LocalPeer


def test_oid_diff_prunes_equal_subtrees(tmp_path):
    """diff() never descends into a shard or leaf whose oid we hold (§1)."""
    source, ws, destination, ts = pair(tmp_path)
    mine, _ = read(destination, ws)
    src = source.store(ws)
    reads = []
    fetch = lambda oid: (reads.append(oid) or src.get("obj/" + oid))

    man = manifest.decode_root(src.get("root"))[2]
    assert manifest.diff(mine, man, fetch) == []
    assert reads == []  # equal root oid: pruned before a single GET

    cmds.post(source, ws, "general", "delta", ts=ts + 1)
    held = {entry.leaf for entry in mine}
    manifest.encode(mine, lambda raw: held.add(h(raw)))  # my shard oids too
    man = manifest.decode_root(src.get("root"))[2]
    differing = manifest.diff(mine, man, fetch)
    theirs = read(source, ws)[0]
    shards = set()
    manifest.encode(theirs, lambda raw: shards.add(h(raw)))
    assert differing  # the delta's home leaf really differs
    assert {e.leaf for e in differing} \
        == {e.leaf for e in theirs} - {e.leaf for e in mine}  # exactly it
    assert set(reads) == shards - held  # unheld shards read, held pruned
    assert len(reads) == len(set(reads))  # and each descended into once
    assert set(reads).isdisjoint({e.leaf for e in theirs})  # never a pile


def test_oid_diff_fetches_exactly_the_difference(tmp_path, monkeypatch):
    """After pull, fetched leaf set == entries whose oids differed — no
    misses, no refetch of held content (§2.1)."""
    source, ws, destination, ts = pair(tmp_path)
    held = {entry.leaf for entry in read(destination, ws)[0]}
    for tick in range(3):
        cmds.post(source, ws, "general", f"delta {tick}", ts=ts + 1 + tick)
    difference = {
        entry.leaf for entry in read(source, ws)[0]} - held

    singles, batches = [], []
    monkeypatch.setattr(
        sync_module, "Peer", peer_for(source, singles, batches))
    assert sync_module.sync(destination, ws, "local://source") == (1, 0)

    leaves = {entry.leaf for entry in read(source, ws)[0]}
    fetched = [oid for batch in batches for oid in batch] \
        + [oid for oid in singles if oid in leaves]
    assert set(fetched) == difference  # no misses, no refetch of held piles
    assert len(fetched) == len(difference)  # and each exactly once
    assert all_fids(destination, ws) == all_fids(source, ws)
    assert destination.store(ws).get("root") == source.store(ws).get("root")


def test_local_only_keys_still_push(tmp_path, monkeypatch):
    """A leaf whose oid differs because WE hold extra keys produces a push,
    not a fetch loop: the one dial still converges both sides (§2.1)."""
    source, ws, destination, ts = pair(tmp_path)
    secret, public = source.identity(ws)
    local_only = author_msg(
        destination, ws, secret, public, "mine alone", ts=ts + 1)

    extra = set(all_fids(destination, ws)) - set(all_fids(source, ws))
    assert local_only.fid in extra
    singles, batches, pushed = [], [], []
    monkeypatch.setattr(
        sync_module, "Peer", peer_for(source, singles, batches, pushed))
    pulled, count = sync_module.sync(destination, ws, "local://source")

    assert (pulled, count) == (0, len(extra))
    assert len(pushed) == 1  # ONE closed pile, the ordinary wire codec
    assert local_only.fid in {f.fid for f in decode_pile(pushed[0])[0]}
    assert source.fact_of(ws, local_only.fid) == local_only
    assert destination.store(ws).get("root") == source.store(ws).get("root")
    assert sync_module.sync(  # converged: the next dial is a no-op
        destination, ws, "local://source") == (0, 0)


def test_warm_sync_fetches_no_closure_siblings(tmp_path, monkeypatch):
    """A warm delta pull touches leaf piles and manifest shards only; the
    sibling objects are for cold-partial readers, and the modes that never
    use them must not pay for them (COSTS §5)."""
    source, ws, destination, ts = pair(tmp_path)
    for tick in range(3):
        cmds.post(source, ws, "general", f"delta {tick}", ts=ts + 1 + tick)

    singles, batches = [], []
    monkeypatch.setattr(
        sync_module, "Peer", peer_for(source, singles, batches))
    assert sync_module.sync(destination, ws, "local://source") == (1, 0)

    entries, _ = read(source, ws)
    siblings = {entry.closure for entry in entries if entry.closure}
    leaves = {entry.leaf for entry in entries}
    shards = set()
    manifest.encode(entries, lambda raw: shards.add(h(raw)))
    assert siblings  # the store really has out-of-range closure to skip
    fetched = set(singles) | {oid for batch in batches for oid in batch}
    assert fetched.isdisjoint(siblings)
    assert fetched <= leaves | shards  # leaf piles and manifest shards ONLY
    assert all(oid not in leaves for oid in singles)  # leaves ride batches
    assert all_fids(destination, ws) == all_fids(source, ws)


def test_cold_partial_fetch_depth_two(tmp_path, world):
    """A cold reader of one range completes closure in two dependent waves:
    leaf+sibling, then the whole frontier via fetch_plan (§2.2). Sibling
    keys are transitive — assert no third wave, don't loop. The corpus is
    ``world``'s invite chain, so the closure is genuinely deep: a wave-per-hop
    (or direct-deps-only sibling) regression fails here, not just on the
    flat one-author shape."""
    source, ws = world
    entries, fetch_src = read(source, ws)
    entry = next(  # a content range far from its auth closure
        e for e in reversed(entries) if e.closure)
    members, _ = decode_pile(fetch_src(entry.leaf))

    idx, depths = source.idx(ws), {}

    def depth(fid):  # dep-chain height; proofs are acyclic
        if fid not in depths:
            deps = resolve_deps(source.fact_of(ws, fid), idx) or []
            depths[fid] = 1 + max(map(depth, deps), default=0)
        return depths[fid]

    assert max(depth(f.fid) for f in members) >= 5  # chain-shaped, not flat

    cold = Node(str(tmp_path / "cold"))
    waves = []

    def fetch(oid):
        return fetch_src(oid)

    def many(oids):
        oids = tuple(oids)
        waves.append(oids)
        return tuple(fetch_src(oid) for oid in oids)

    fetch.many = many
    stream = sync_module.assemble(
        cold, ws, [(entry, members)], entries, fetch)

    assert len(waves) == 2  # sibling keys are transitive: no third wave
    assert set(waves[0]) == {entry.closure}  # wave 1 tail: sibling keys
    assert set(waves[1]) == set(manifest.fetch_plan(  # wave 2: the whole
        entries, json.loads(fetch_src(entry.closure))["keys"]))  # frontier
    assert drain(tuple(stream), ws).ok  # the range judges from empty


def test_pull_feeds_ordinary_admission(tmp_path, monkeypatch):
    """The assembled closed set is judged by the same ingress path as a
    pushed pile; the kernel cannot tell pull from push (§2.3): a twin
    replica fed the captured union BYTES through deliver() lands in the
    identical state, and an invalid fact riding a pulled range is rejected
    by the same judge with the same (pile-whole) effect on both paths.
    (Removal-leg-before-fact-leg ordering is
    tests/test_removals.py::test_sync_fetches_removals_before_fact_ranges.)"""
    source, ws, destination, ts = pair(tmp_path)
    twin = Node(str(tmp_path / "twin"))  # converged like destination
    deliver(twin, ws, closed_subset(source, ws, all_fids(source, ws)))
    twin.turn(ws)
    for tick in range(2):
        cmds.post(source, ws, "general", f"delta {tick}", ts=ts + 1 + tick)
    delivered = {}
    actual_pull = sync_module.pull

    def capture_pull(node, w, oid, raw):
        actual_pull(node, w, oid, raw)
        delivered[oid] = raw
        # the union sits in the SAME ingress prefix a pushed pile lands in
        assert node.store(w).get(
            f"pile/{node.member_for(w)}/{oid}") == raw

    singles, batches = [], []
    monkeypatch.setattr(sync_module, "pull", capture_pull)
    monkeypatch.setattr(
        sync_module, "Peer", peer_for(source, singles, batches))
    assert sync_module.sync(destination, ws, "local://source") == (1, 0)

    ((oid, raw),) = delivered.items()
    stream, blobs = decode_pile(raw)  # the ordinary wire codec, verbatim
    assert not blobs
    assert drain(stream, ws).ok  # one judge; no source annotation anywhere
    assert destination.store(ws).list("pile/") == []  # retired by turn()
    assert all_fids(destination, ws) == all_fids(source, ws)

    deliver(twin, ws, raw)  # the SAME bytes through the push ingress
    twin.turn(ws)
    assert all_fids(twin, ws) == all_fids(destination, ws)
    assert twin.store(ws).get("root") == destination.store(ws).get("root")

    # A compromised source publishes a forged message — merge+commit skip
    # its own judge, so the invalid fact sits in a real leaf pile and rides
    # the next pull's assembled range. Both ingress paths reject the union
    # pile whole, retire it, and land nothing: one judge, one effect.
    secret, public = source.identity(ws)
    forged = message(public, "general", "forged", ts + 10)
    unsigned = signature(keypair()[0], public, forged, ts + 10)  # wrong sk
    with source.lock:
        _, fresh = source.merge(ws, [
            Valid(unsigned, ()),
            Valid(forged, (unsigned.fid, member_src(source, ws, public)))])
        source.commit(ws, fresh)
    before = all_fids(destination, ws)
    delivered.clear()
    assert sync_module.sync(destination, ws, "local://source") == (1, 0)
    ((_, poisoned),) = delivered.items()
    poisoned_stream = decode_pile(poisoned)[0]
    assert forged.fid in {f.fid for f in poisoned_stream}  # it rode the pull
    assert not drain(poisoned_stream, ws).ok  # the one judge says no
    assert all_fids(destination, ws) == before  # same effect: nothing landed
    assert destination.store(ws).list("pile/") == []  # rejected AND retired
    deliver(twin, ws, poisoned)  # identical bytes through the push ingress
    twin.turn(ws)
    assert all_fids(twin, ws) == before
    assert twin.store(ws).list("pile/") == []


# ---- oyd.4: read contract + retraction --------------------------------------


def test_dep_evidence_not_suppressed(tmp_path, monkeypatch):
    """A removed fact fetched as an out-of-range dep still validates its
    dependents: removals gate E, never V (§2.4). On the full node the dead
    dep leaves E while every dependent stays. A cold-partial reader runs
    the real order — index leg first (REMOVALS.md §5), then one content
    range — so the dead dep is already a known victim when its dependents'
    range assembles; assembly still carries it as evidence with ZERO
    removal consults, the range judges valid, and after ingestion the
    dependents sit in V and E while the dep sits in V only — deletion
    hides content, not evidence."""
    monkeypatch.setitem(facts.ROUTES, DeletionFamily.TAG, DeletionFamily)
    node = Node(str(tmp_path / "node"))
    ws = cmds.create(node, "alice", ts=1)
    sk, pk, joined = add_member(node, ws, "bob", ts=10)
    msgs, ts, cuts = [], 100, 0
    while cuts < 2:  # bob's member proof is a dep of every content range
        msg = author_msg(node, ws, sk, pk, f"m{ts}", ts=ts)
        msgs.append(msg.fid)
        cuts += shape.boundary(msg.fid)
        ts += 1
    deletion = channel_delete(joined.fid, "general", ts)
    node.ingest_new(ws, [deletion], {deletion.fid: [joined.fid]})

    surfaced = {src for (src,) in node.app.execute(
        "SELECT src FROM projected WHERE ws=?", (ws,))}
    assert joined.fid not in surfaced  # the dead dep left E...
    assert set(msgs) <= surfaced  # ...its dependents did not

    entries, fetch_src = read(node, ws)
    entry = next(  # a content range whose sibling names the dead dep
        e for e in reversed(entries)
        if e.closure and shape.key(joined) in json.loads(
            fetch_src(e.closure))["keys"]
        and {f.fid for f in members_of(e, fetch_src)} & set(msgs))
    members = members_of(entry, fetch_src)
    dependents = [f.fid for f in members if f.fid in set(msgs)]
    cold = Node(str(tmp_path / "cold"))
    fetch = lambda oid: fetch_src(oid)
    fetch.many = lambda oids: tuple(fetch_src(oid) for oid in oids)
    sync_module.pull_removals(  # the real order: the index leg first
        cold, ws, node.store(ws).get("root"), fetch)

    consults = []
    stab = removals.overlapping
    monkeypatch.setattr(
        removals, "overlapping",
        lambda *args: consults.append(args) or stab(*args))
    stream = tuple(sync_module.assemble(
        cold, ws, [(entry, members)], entries, fetch))

    assert joined.fid in {f.fid for f in stream}  # fetched as evidence
    assert drain(stream, ws).ok  # the dead dep still validates dependents
    assert not consults  # the read entered V with no removal look

    monkeypatch.setattr(removals, "overlapping", stab)  # admission may look
    raw = encode_pile(stream)
    sync_module.pull(cold, ws, h(raw), raw)
    cold.turn(ws)
    on_screen = {src for (src,) in cold.app.execute(
        "SELECT src FROM projected WHERE ws=?", (ws,))}
    assert cold.fact_of(ws, joined.fid) is not None  # the dep entered V...
    assert joined.fid not in on_screen  # ...and V only
    for fid in dependents:  # ...while its dependents entered V AND E
        assert cold.fact_of(ws, fid) is not None and fid in on_screen


def test_removal_consult_in_range_only(tmp_path, monkeypatch):
    """Range evaluation touches the removal head plus the [a,b] slice and
    stabs no out-of-range dep keys (§2.4; REMOVALS.md §3): the stab set of
    a pull is EXACTLY the arriving members' keys — one single-fact stab
    each, none skipped, none extra — and applies() only ever judges an
    arriving member or the retro victim named by DIRECT target fid. The
    dead target — an out-of-range closure sibling — is never stabbed and
    never judged. A sibling key CAN equal an arriving member's (a boundary
    cut between a dependent and its same-batch dep); it is then stabbed as
    that member, in its own range — so disjointness from the sibling union
    is not the law and must not be asserted.
    (Entry-before-victim masking is
    tests/test_removals.py::test_removal_before_victim_retracts_on_arrival.)"""
    monkeypatch.setitem(facts.ROUTES, DeletionFamily.TAG, DeletionFamily)
    source, ws, destination, ts = pair(tmp_path)
    victim = next(
        source.fact_of(ws, fid) for fid in all_fids(source, ws)
        if source.fact_of(ws, fid).t == "msg")
    deletion = channel_delete(victim.fid, "general", ts + 50)
    source.ingest_new(ws, [deletion], {deletion.fid: [victim.fid]})
    for tick in range(3):
        cmds.post(source, ws, "general", f"delta {tick}", ts=ts + 60 + tick)
    before = set(all_fids(destination, ws))

    stabs, judged = [], []
    stab, match = removals.overlapping, removals.applies
    monkeypatch.setattr(
        removals, "overlapping",
        lambda entries, lo, hi:
        stabs.append((lo, hi)) or stab(entries, lo, hi))
    monkeypatch.setattr(
        removals, "applies",
        lambda r, f: judged.append(f.fid) or match(r, f))
    monkeypatch.setattr(sync_module, "Peer", peer_for(source, [], []))
    sync_module.sync(destination, ws, "local://source")

    new = set(all_fids(destination, ws)) - before
    arrived = {shape.key(destination.fact_of(ws, fid)) for fid in new}
    assert stabs  # the consult really ran on this pull
    assert all(lo == hi for lo, hi in stabs)  # single-fact stabs only
    assert {lo for lo, _ in stabs} == arrived  # EXACTLY the arriving keys
    siblings = set()
    for e in read(source, ws)[0]:
        if e.closure:
            siblings |= set(json.loads(
                source.store(ws).get("obj/" + e.closure))["keys"])
    assert shape.key(victim) in siblings  # out-of-range deps really exist
    assert shape.key(victim) not in arrived  # ...with keys off the range
    assert shape.key(victim) not in {lo for lo, _ in stabs}  # never stabbed
    assert victim.fid in judged  # the retro path ran, by direct target fid
    assert set(judged) <= new | {victim.fid}  # never an out-of-range dep
    assert destination.app.execute(  # yet its own range retracted it here
        "SELECT 1 FROM projected WHERE ws=? AND src=?",
        (ws, victim.fid)).fetchone() is None
    assert all_fids(destination, ws) == all_fids(source, ws)


# ---- oyd.7: measure + first production deletion family ----------------------


@SKELETON
def test_production_deletion_family():
    """facts/content/delete.py is registered in content.MODULES; its author
    command derives channel and span from the actual victim (I6); admitting
    one retracts the victim's projected row and lands one index entry —
    the first non-monkeypatched deletion end to end (REMOVALS.md §8)."""
