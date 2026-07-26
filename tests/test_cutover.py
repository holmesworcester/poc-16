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

import core.manifest as manifest
import core.shape as shape
from core import cmds
from core.close import close, decode_pile, encode_pile
from core.crypto import h
from core.fact import canon
from core.kernel import resolve_deps
from core.node import Node

from .util import add_member, all_fids, author_msg, replay_random

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


@SKELETON
def test_oid_diff_prunes_equal_subtrees():
    """diff() never descends into a shard or leaf whose oid we hold (§1)."""


@SKELETON
def test_oid_diff_fetches_exactly_the_difference():
    """After pull, fetched leaf set == entries whose oids differed — no
    misses, no refetch of held content (§2.1)."""


@SKELETON
def test_local_only_keys_still_push():
    """A leaf whose oid differs because WE hold extra keys produces a push,
    not a fetch loop: the one dial still converges both sides (§2.1)."""


@SKELETON
def test_warm_sync_fetches_no_closure_siblings():
    """A warm delta pull touches leaf piles and manifest shards only; the
    sibling objects are for cold-partial readers, and the modes that never
    use them must not pay for them (COSTS §5)."""


@SKELETON
def test_cold_partial_fetch_depth_two():
    """A cold reader of one range completes closure in two dependent waves:
    leaf+sibling, then the whole frontier via fetch_plan (§2.2). Sibling
    keys are transitive — assert no third wave, don't loop."""


@SKELETON
def test_pull_feeds_ordinary_admission():
    """The assembled closed set is judged by the same ingress path as a
    pushed pile; the kernel cannot tell pull from push (§2.3).
    (Removal-leg-before-fact-leg ordering is
    tests/test_removals.py::test_sync_fetches_removals_before_fact_ranges.)"""


# ---- oyd.4: read contract + retraction --------------------------------------


@SKELETON
def test_dep_evidence_not_suppressed():
    """A removed fact fetched as an out-of-range dep still validates its
    dependents: removals gate E, never V (§2.4)."""


@SKELETON
def test_removal_consult_in_range_only():
    """Range evaluation touches the removal head plus the [a,b] slice and
    stabs no out-of-range dep keys (§2.4; REMOVALS.md §3).
    (Entry-before-victim masking is
    tests/test_removals.py::test_removal_before_victim_retracts_on_arrival.)"""


# ---- oyd.7: measure + first production deletion family ----------------------


@SKELETON
def test_production_deletion_family():
    """facts/content/delete.py is registered in content.MODULES; its author
    command derives channel and span from the actual victim (I6); admitting
    one retracts the victim's projected row and lands one index entry —
    the first non-monkeypatched deletion end to end (REMOVALS.md §8)."""
