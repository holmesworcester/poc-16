"""Contracts for canonical fact transport and the composite root."""
import json
import random

import pytest

import facts

import core.manifest as manifest
import core.shape as shape
import core.sync as sync_module
from core import btreap, cmds
from core.close import close, decode_pile, encode_pile
from core.crypto import h, keypair, load_sk
from core.fact import canon
from core.kernel import drain, resolve_deps
from core.node import Node
from facts._policy import OWNER
from facts.auth.signature import signature
from facts.content.message import message

from . import util
from .util import (
    add_member,
    all_fids,
    author_msg,
    closed_subset,
    deliver,
    member_src,
    replay_random,
    suppression_world,
    visible_fids,
)


# ---- oyd.2: manifest + residency --------------------------------------------


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    """A settled store wide enough to hold several home leaves, authored by
    an invite chain so its closures genuinely cross leaf boundaries.

    Deterministic: every key comes from a seeded stream, so the corpus —
    cut positions, sibling contents, closure depths — is byte-identical
    every run. The shape preconditions below (deep chains, siblings on a
    content range) are then facts of THIS corpus, not of a lucky draw
    (unseeded keypairs were the cold-partial full-run blip)."""
    rng = random.Random(0xC01D)

    def det_keypair():
        sk = load_sk(f"{rng.getrandbits(256):064x}")
        return sk, sk.verify_key.encode().hex()

    real, util.keypair = util.keypair, det_keypair
    try:
        node = Node(
            str(tmp_path_factory.mktemp("cutover") / "node"),
            initial_secret=load_sk(f"{3:064x}"))
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
    finally:
        util.keypair = real
    return node, ws


def read(node, ws):
    """``(entries, fetch)`` — the store as any reader sees it."""
    st = node.store(ws)
    fetch = lambda oid: st.get("obj/" + oid)
    man = manifest.decode_root(st.get("root")).manifest
    return manifest.decode(fetch(man), fetch), fetch


def objects(node, ws):
    """``{oid: bytes}`` for every object a reader reaches from the root."""
    st, seen = node.store(ws), {}

    def fetch(oid):
        seen[oid] = st.get("obj/" + oid)
        return seen[oid]

    man = manifest.decode_root(st.get("root")).manifest
    for entry in manifest.decode(fetch(man), fetch):
        fetch(entry.leaf)
        if entry.closure:
            fetch(entry.closure)
    assert all(raw is not None for raw in seen.values())
    return seen


def members_of(entry, fetch, workspace):
    facts, blobs = decode_pile(fetch(entry.leaf), workspace)
    assert not blobs
    return facts


def test_one_pile_codec_serves_wire_and_residence(world):
    """A resident leaf pile decodes with the same decode_pile the ingress
    uses; there is exactly one pile codec (§3)."""
    node, ws = world
    entries, fetch = read(node, ws)
    assert len(entries) > 1
    for entry in entries:
        members = members_of(entry, fetch, ws)
        keys = [fact.key for fact in members]
        assert keys == sorted(keys) and keys[0] == entry.sep
        assert h(encode_pile(members, workspace=ws)) == entry.leaf


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


def test_history_independence_holds_with_actions(tmp_path):
    """The action archive and all three trees are arrival-order independent."""
    source, ws, _, _ = suppression_world(
        tmp_path / "source",
        initial_secret=load_sk(f"{1:064x}"))
    root = source.store(ws).get("root")
    assert source.idx(ws).execute(
        "SELECT COUNT(*) FROM actions").fetchone()[0] > 0
    for seed in range(3):
        other = replay_random(
            source, ws, Node(str(tmp_path / f"replay{seed}")), seed)
        assert all_fids(other, ws) == all_fids(source, ws)
        assert other.store(ws).get("root") == root  # byte-equal, slot too


def test_stable_boundary_leaves_have_one_canonical_range_tree(world):
    """Stable leaves are exactly the rows of one canonical Merkle treap."""
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

    emitted = {}
    root = manifest.encode(
        entries, lambda raw: emitted.setdefault(h(raw), raw))
    assert root == manifest.decode_root(
        node.store(ws).get("root")).manifest
    assert len(emitted) == len(entries)  # one authenticated page per range
    assert all(json.loads(raw)["format"] == btreap.FORMAT
               for raw in emitted.values())
    assert manifest.decode(emitted[root], emitted.get) == entries


def test_cut_is_64():
    """shape.CUT == 64: the knee where a whole fetch goes bandwidth-bound
    (COSTS §6). Guards against the dial silently drifting back."""
    assert shape.CUT == 64


def test_locate_maps_key_to_home_leaf(world):
    """locate() finds the home entry for any key locally, with no I/O (§2)."""
    node, ws = world
    entries, fetch = read(node, ws)
    for entry in entries:
        for fact in members_of(entry, fetch, ws):
            assert manifest.locate(entries, fact.key) == entry
    assert manifest.locate(entries, "") is None  # below every separator
    assert manifest.locate(entries, "~") == entries[-1]


def test_root_atomically_names_manifest_and_three_logical_trees(world):
    """One root CAS binds sync content and every request-time index."""
    node, ws = world
    raw = node.store(ws).get("root")
    body = json.loads(raw)
    assert set(body) == {
        "action_etag", "anchor", "layout_seed", "manifest", "stamp", "trees"}
    assert body["anchor"] == ws and body["stamp"] == manifest.LAYOUT
    assert shape.valid_fid(body["layout_seed"])
    assert set(body["trees"]) == {"fact", "supp", "authority"}
    assert all(
        set(descriptor) == {"root", "count", "depth"}
        and descriptor["root"] and descriptor["count"] > 0
            and 0 < descriptor["depth"] <= btreap.MAX_PAGE_DEPTH
        for descriptor in body["trees"].values())
    snapshot = manifest.decode_root(raw)
    assert snapshot.anchor == ws
    assert snapshot.manifest == body["manifest"]
    assert snapshot.layout_seed == body["layout_seed"]
    assert snapshot.trees == body["trees"]
    assert snapshot.action_etag == body["action_etag"]
    entries, fetch = read(node, ws)
    assert all(len(entry) == 3 for entry in entries)  # no fp, no n-count
    assert b"fp" not in fetch(body["manifest"])


def test_closure_sibling_is_exactly_out_of_range(world):
    """The sibling is exactly close(members) minus that leaf's member ids."""
    node, ws = world
    entries, fetch = read(node, ws)
    idx = node.idx(ws)
    fact_of = lambda fid: node.fact_of(ws, fid)
    deps_of = lambda fid: resolve_deps(fact_of(fid), idx) or []
    lo, siblings = "", 0
    for entry in entries:
        members = members_of(entry, fetch, ws)
        hi = members[-1].key
        closed = {fact.key for fact in close(members, deps_of, fact_of)}
        assert {k for k in closed if lo < k <= hi} \
            == {fact.key for fact in members}
        outside = sorted(closed - {fact.key for fact in members})
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
            held = {
                fact.key: fact for fact in members_of(home, fetch, ws)}
            assert held[key].fid == shape.fid_of(key)  # self-certifying
            assert held[key] == node.fact_of(ws, shape.fid_of(key))
            stamp, fid = key.split(":", 1)
            wrong = shape.key_parts(int(stamp) + 1, fid)  # same fid, bad ts
            elsewhere = manifest.locate(entries, wrong)
            assert elsewhere is None or wrong not in {
                fact.key for fact in members_of(elsewhere, fetch, ws)}
            resolved += 1
    assert resolved


def test_store_closure_invariant(world):
    """After any settle, every dep of every resident fact is resident at its
    own home leaf: closure(store) == store (COSTS §5)."""
    node, ws = world
    entries, fetch = read(node, ws)
    piles = {entry: {
        fact.key: fact for fact in members_of(entry, fetch, ws)}
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
    node.store(ws)._replace("root", foreign)
    node._sync_index(ws)
    republished = node.store(ws).get("root")
    assert republished != foreign
    assert manifest.decode_root(republished).anchor == ws  # readable again
    # Wholesale: the old bytes are never read. The republish settles the
    # derived index under the current stamp, and the rebuild that follows
    # reads only what that settle just wrote.
    assert republished == honest and all_fids(node, ws) == before


# ---- oyd.3: sync rewrite ----------------------------------------------------


def pair(tmp_path):
    """A deterministic multi-leaf source and a converged destination replica.

    The fixed source identity makes the fact addresses, range cuts, and treap
    geometry stable.  In particular, the warm-sync cost test below then
    exercises a delta that retains old manifest pages instead of depending on
    a lucky fresh keypair.
    """
    source = Node(
        str(tmp_path / "source"),
        initial_secret=load_sk(f"{1:064x}"))
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
                    h(source.store(self.ws).get("root")))

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


def test_oid_compare_prunes_equal_subtrees(tmp_path):
    """compare() never remotely reads a RangeTree page or held leaf (§1)."""
    source, ws, destination, ts = pair(tmp_path)
    mine, _ = read(destination, ws)
    src = source.store(ws)
    reads = []
    fetch = lambda oid: (reads.append(oid) or src.get("obj/" + oid))

    man = manifest.decode_root(src.get("root")).manifest
    assert manifest.compare(mine, man, fetch)[1] == []
    assert reads == []  # equal root oid: pruned before a single GET

    cmds.post(source, ws, "general", "delta", ts=ts + 1)
    held = {entry.leaf for entry in mine}
    manifest.encode(mine, lambda raw: held.add(h(raw)))  # RangeTree pages too
    man = manifest.decode_root(src.get("root")).manifest
    differing = manifest.compare(mine, man, fetch)[1]
    theirs = read(source, ws)[0]
    pages = set()
    manifest.encode(theirs, lambda raw: pages.add(h(raw)))
    assert differing  # the delta's home leaf really differs
    assert {e.leaf for e in differing} \
        == {e.leaf for e in theirs} - {e.leaf for e in mine}  # exactly it
    assert set(reads) == pages - held  # unheld pages read, held pruned
    assert len(reads) == len(set(reads))  # and each descended into once
    assert set(reads).isdisjoint({e.leaf for e in theirs})  # never a pile


def test_oid_diff_compares_the_full_mapping_at_the_same_separator(world):
    """A held leaf moved under a different separator is not 'unchanged'."""
    node, ws = world
    mine, fetch = read(node, ws)
    first, second = mine[:2]
    hostile = list(mine)
    hostile[:2] = [
        first._replace(leaf=second.leaf),
        second._replace(leaf=first.leaf),
    ]
    pages = {}
    root = manifest.encode(
        hostile, lambda raw: pages.setdefault(h(raw), raw))

    theirs, differing = manifest.compare(mine, root, pages.get)

    assert theirs == hostile
    assert differing == hostile[:2]
    for entry in differing:
        with pytest.raises(ValueError, match="manifest range"):
            manifest.range_members(entry, fetch, ws)


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
    not a fetch loop: the one dial still converges both sides (§2.1).
    This also ratchets the free-function boundary: ``walk._push`` must pass
    its explicit ``ws`` argument to the pile codec, not an imagined
    ``self.ws`` from the neighboring ``Peer`` methods."""
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
    assert local_only.fid in {
        f.fid for f in decode_pile(pushed[0], ws)[0]}
    assert source.fact_of(ws, local_only.fid) == local_only
    assert destination.store(ws).get("root") == source.store(ws).get("root")
    assert sync_module.sync(  # converged: the next dial is a no-op
        destination, ws, "local://source") == (0, 0)


def test_warm_sync_fetches_no_closure_siblings(tmp_path, monkeypatch):
    """A warm delta pull touches leaf piles and novel RangeTree pages only; the
    sibling objects are for cold-partial readers, and the modes that never
    use them must not pay for them (COSTS §5)."""
    source, ws, destination, ts = pair(tmp_path)
    held_pages = set()
    manifest.encode(
        read(destination, ws)[0], lambda raw: held_pages.add(h(raw)))
    for tick in range(3):
        cmds.post(source, ws, "general", f"delta {tick}", ts=ts + 1 + tick)

    singles, batches = [], []
    monkeypatch.setattr(
        sync_module, "Peer", peer_for(source, singles, batches))
    assert sync_module.sync(destination, ws, "local://source") == (1, 0)

    entries, _ = read(source, ws)
    siblings = {entry.closure for entry in entries if entry.closure}
    leaves = {entry.leaf for entry in entries}
    pages = set()
    manifest.encode(entries, lambda raw: pages.add(h(raw)))
    assert siblings  # the store really has out-of-range closure to skip
    fetched = set(singles) | {oid for batch in batches for oid in batch}
    assert fetched.isdisjoint(siblings)
    assert fetched <= leaves | pages  # leaf piles and RangeTree pages ONLY
    assert all(oid not in leaves for oid in singles)  # leaves ride batches
    assert held_pages & pages  # this delta really has shared tree pages
    assert fetched & pages == pages - held_pages  # no eager remote decode


def test_idle_sync_after_blob_completion_does_no_index_or_object_work(
        tmp_path, monkeypatch):
    """A 304 against an unchanged local root is a true O(1) idle dial.

    The first dial records that blob reconciliation completed for that local
    root. Every later 304 returns without scanning facts, decoding trees, or
    probing objects.
    """
    source, ws, destination, _ = pair(tmp_path)

    class ConditionalPeer:
        def __init__(self, node, workspace, url):
            self.node, self.ws = node, workspace
            self.cache = node.sync_cache.setdefault((workspace, url), {})

        def root(self, etag=None):
            current = h(source.store(self.ws).get("root"))
            if etag == current:
                return None
            return source.store(self.ws).get("root"), current

        def obj(self, oid):
            return source.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            return tuple(self.obj(oid) for oid in oids)

        def put_pile(self, raw):
            pytest.fail("converged dial unexpectedly pushed")

    monkeypatch.setattr(sync_module, "Peer", ConditionalPeer)
    assert sync_module.sync(destination, ws, "local://conditional") == (0, 0)
    monkeypatch.setattr(
        sync_module, "_fetch_blobs",
        lambda *args: pytest.fail("idle dial rescanned blob demand"))
    destination.keys = lambda *args: pytest.fail("idle dial scanned fact keys")
    assert sync_module.sync(destination, ws, "local://conditional") == (0, 0)
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
    members, _ = decode_pile(fetch_src(entry.leaf), ws)

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
    identical state. Even direct calls below the runtime cannot publish an
    invalid fact and manufacture a poisoned pull range."""
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
    stream, blobs = decode_pile(
        raw, ws)  # the ordinary wire codec, verbatim
    assert not blobs
    assert drain(stream, ws).ok  # one judge; no source annotation anywhere
    assert destination.store(ws).list("pile/") == []  # retired by turn()
    assert all_fids(destination, ws) == all_fids(source, ws)

    deliver(twin, ws, raw)  # the SAME bytes through the push ingress
    twin.turn(ws)
    assert all_fids(twin, ws) == all_fids(destination, ws)
    assert twin.store(ws).get("root") == destination.store(ws).get("root")

    # Direct merge/commit is not a judge bypass: canonical settlement
    # revalidates local edges and retains these bytes only as inactive catalog
    # receipts. The source root therefore cannot expose a poisoned pull range.
    secret, public = source.identity(ws)
    forged = message(ws, public, "general", "forged", ts + 10)
    unsigned = signature(keypair()[0], public, forged, ts + 10)  # wrong sk
    source_root = source.store(ws).get("root")
    with source.lock:
        settlement = source.merge(ws, [unsigned, forged])
        source.commit(ws, settlement)
    before = all_fids(destination, ws)
    assert source.candidate_of(ws, unsigned.fid) == unsigned
    assert source.candidate_of(ws, forged.fid) == forged
    assert source.fact_of(ws, forged.fid) is None
    assert source.store(ws).get("root") == source_root
    assert sync_module.sync(destination, ws, "local://source") == (0, 0)

    # The ordinary pile door independently rejects the same forged unit on
    # every replica and retires it whole.
    poisoned = encode_pile((unsigned, forged), workspace=ws)
    assert not drain(decode_pile(poisoned, ws)[0], ws).ok
    for current in (destination, twin):
        deliver(current, ws, poisoned)
        current.turn(ws)
        assert all_fids(current, ws) == before
        assert current.store(ws).list("pile/") == []


def test_sync_pulls_one_closed_path_union_not_a_bare_leaf(
        tmp_path, monkeypatch):
    source = Node(str(tmp_path / "source"))
    ws = cmds.create(source, "alice")
    destination = Node(str(tmp_path / "destination"))
    deliver(destination, ws, closed_subset(source, ws, [ws]))
    destination.turn(ws)
    for ordinal in range(24):
        cmds.post(
            source, ws, "general", f"message {ordinal}",
            ts=source.fact_of(ws, ws).ts + ordinal + 1,
        )
    singles, batches, delivered = [], [], []
    actual_pull = sync_module.pull

    def capture_pull(node, w, oid, raw):
        delivered.append(decode_pile(raw, w)[0])
        return actual_pull(node, w, oid, raw)

    monkeypatch.setattr(sync_module, "pull", capture_pull)
    monkeypatch.setattr(
        sync_module, "Peer", peer_for(source, singles, batches))
    pulled, pushed = sync_module.sync(destination, ws, "local://source")

    assert (pulled, pushed) == (1, 0)
    (stream,) = delivered  # ONE closed union pile, not per-leaf bare leaves
    assert drain(stream, ws).ok  # deps-first: judges from empty
    st = source.store(ws)
    entries = manifest.decode_root(st.get("root")).manifest
    leaf_oids = {
        entry.leaf for entry in manifest.decode(
            st.get("obj/" + entries), lambda oid: st.get("obj/" + oid))}
    assert batches  # leaf piles arrive in batched waves (Peer.objs)
    assert leaf_oids.isdisjoint(singles)  # never one GET per leaf
    assert all_fids(destination, ws) == all_fids(source, ws)
    assert destination.store(ws).get("root") == source.store(ws).get("root")


def test_sync_pushes_one_closed_deduplicated_pile(tmp_path, monkeypatch):
    # The push contract is ONE closed pile, each closure fact once, judged
    # whole (there is no second index leg to deduplicate against).
    source = Node(str(tmp_path / "source"))
    ws = cmds.create(source, "alice", ts=1)
    destination = Node(str(tmp_path / "destination"))
    deliver(destination, ws, closed_subset(source, ws, [ws]))
    destination.turn(ws)
    for ordinal in range(3):
        cmds.post(
            source, ws, "general", f"message {ordinal}", ts=10 + ordinal)
    before = set(all_fids(destination, ws))
    pushed_piles = []
    monkeypatch.setattr(
        sync_module, "Peer", peer_for(destination, [], [], pushed_piles))
    pulled, pushed = sync_module.sync(source, ws, "local://destination")

    seen = set()
    for raw in pushed_piles:
        unit = decode_pile(raw, ws)[0]
        fids = {fact.fid for fact in unit}
        assert drain(unit, ws).ok
        assert seen.isdisjoint(fids)
        seen.update(fids)

    assert pulled == 0
    assert pushed == len(set(all_fids(source, ws)) - before)
    assert len(pushed_piles) == 1
    assert destination.store(ws).get("root") == source.store(ws).get("root")


# ---- oyd.7: measure + first production deletion family ----------------------


def test_production_deletion_family(tmp_path):
    """facts/content/delete.py is registered in content.MODULES; its author
    command binds the exact target offer; its action and retraction survive
    both a node restart and a derived-index rebuild."""
    from facts.content import delete as delete_family

    assert delete_family in facts.MODULES
    assert facts.family_for(delete_family.TAG) is delete_family
    node = Node(str(tmp_path / "node"))
    ws = cmds.create(node, "alice", ts=1)
    victim_fid = cmds.post(node, ws, "general", "doomed", ts=10)
    spared = cmds.post(node, ws, "general", "spared", ts=11)
    victim = node.fact_of(ws, victim_fid)

    def screen(n):
        return visible_fids(n, ws)

    assert victim_fid in screen(node)  # visible before the deletion
    fid = cmds.remove(node, ws, victim_fid, ts=20)
    removal = node.fact_of(ws, fid)
    assert removal == delete_family.delete(
        ws, node.identity_id(ws), victim.key, OWNER, 20)
    action = node.idx(ws).execute(
        "SELECT fid, evidence FROM actions WHERE sid=?",
        (f"fact:{victim_fid}",)).fetchone()
    assert action and action[0] == fid
    assert node.store(ws).has("obj/" + action[1])

    assert victim_fid not in screen(node)
    assert victim_fid not in {
        row["fid"] for row in cmds.msgs(node, ws)}
    assert spared in screen(node) and fid in screen(node)  # ...alone

    node.idx(ws).close()
    survivor = Node(node.dir)
    assert survivor.fact_of(ws, victim_fid) == victim  # V keeps the victim
    assert victim_fid not in screen(survivor)
    assert survivor.idx(ws).execute(
        "SELECT fid FROM actions WHERE sid=?",
        (f"fact:{victim_fid}",)).fetchone() == (fid,)

    survivor.rebuild(ws)  # rebuild: the store's own units, same kernel
    assert survivor.fact_of(ws, victim_fid) == victim
    assert victim_fid not in screen(survivor)
    assert spared in screen(survivor)
    assert survivor.idx(ws).execute(
        "SELECT fid FROM actions WHERE sid=?",
        (f"fact:{victim_fid}",)).fetchone() == (fid,)
