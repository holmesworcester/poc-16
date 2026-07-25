"""Tree-only proof that a suppression index closes an out-of-range 1:N join."""
import random
import sqlite3

import facts as families

from core import shape, tree
from core.crypto import h
from core.fact import Fact
from core.kernel import drain
from core.suppression import (
    atom, close_deletions, deathkey, is_deletion, supp_walk, suppkey,
)

GROUP = "proof-channel"
DELETE_TS = 1_000
IN_RANGE_TS = 999
OUT_OF_RANGE_TS = frozenset(range(10)) | frozenset(range(1_991, 2_001))
TARGET_TS = OUT_OF_RANGE_TS | {IN_RANGE_TS}


class ProofFamily:
    """Minimal durable family so the synthetic suppression facts are valid."""
    TAG = "suppression_proof"
    TABLES = ()
    DURABLE = True

    @staticmethod
    def needs(fact):
        return ()

    @staticmethod
    def validate(fact, context):
        return fact.t == ProofFamily.TAG \
            and set(fact.body) == {"ordinal"} \
            and fact.body["ordinal"] == fact.ts \
            and (not fact.atoms or suppkey(fact) is not None)

    @staticmethod
    def global_rows(fact):
        return ()

    @staticmethod
    def blob_refs(fact):
        return ()


class Store:
    """Instrumented object store with an intentionally unusable SQL surface."""
    def __init__(self):
        self.objects = {}
        self.reads = []
        self.batches = []
        self.sql_calls = 0

    def emit(self, raw):
        oid = h(raw)
        self.objects.setdefault(oid, raw)
        return oid

    def fetch(self, oid):
        self.reads.append(oid)
        return self.objects[oid]

    def fetch_many(self, oids):
        oids = tuple(oids)
        self.reads.extend(oids)
        self.batches.append(oids)
        return tuple(self.objects[oid] for oid in oids)

    def execute(self, *args):
        self.sql_calls += 1
        raise AssertionError("suppression traversal touched SQL")


def seed():
    authority = Fact(ProofFamily.TAG, -1, [], {"ordinal": -1})
    facts = []
    for ts in range(2_001):
        refs = [["ref", "authority", authority.fid]]
        if ts == DELETE_TS:
            facts.append(Fact(
                ProofFamily.TAG, ts, [atom(GROUP, deletion=True), *refs],
                {"ordinal": ts}))
        else:
            channel = GROUP if ts in TARGET_TS else f"noise-{ts % 64:02d}"
            facts.append(Fact(
                ProofFamily.TAG, ts, [atom(channel), *refs],
                {"ordinal": ts}))
    items = {fact.fid: fact for fact in [authority, *facts]}
    return facts, authority, items


def cold(view):
    return tree.decode_root(tree.encode_root(
        tree.Root(view, "proof", frozenset()))).view


def effective(stream):
    """The plan's E=V-S fold, kept test-local until the wiring bead."""
    deaths = {deathkey(fact) for fact in stream if is_deletion(fact)}
    return {
        fact.fid for fact in stream
        if is_deletion(fact) or suppkey(fact) not in deaths
    }


def assert_closed(unit):
    """Every explicit dependency is present before the fact that needs it."""
    positions = {fact.fid: index for index, fact in enumerate(unit)}
    assert len(positions) == len(unit)
    assert all(
        ref in positions and positions[ref] < positions[fact.fid]
        for fact in unit for _, ref in fact.refs()
    )


def build(keys, projection, items, store):
    return tree.build(
        keys, projection, tree.fat(8), items.__getitem__,
        lambda fid: tuple(ref for _, ref in items[fid].refs()),
        store.emit,
    )


def test_suppression_walk_surfaces_out_of_range_targets_without_sql(
        monkeypatch):
    monkeypatch.setattr(shape, "CUT", 4)
    monkeypatch.setitem(families.ROUTES, ProofFamily.TAG, ProofFamily)
    facts, authority, items = seed()
    assert drain((authority, *facts), "proof").ok
    store = Store()
    fact_root = build(
        [shape.FACT.key(fact) for fact in items.values()],
        shape.FACT, items, store,
    )
    supp_root = build(
        [shape.SUPP.key(fact) for fact in facts],
        shape.SUPP, items, store,
    )
    deletion = facts[DELETE_TS]
    in_range = facts[IN_RANGE_TS]
    group = deathkey(deletion)
    target_fids = {facts[ts].fid for ts in TARGET_TS}
    out_of_range_fids = {facts[ts].fid for ts in OUT_OF_RANGE_TS}
    selected = [
        row for row in tree.leaf_ranges(fact_root, store.fetch)
        if any(row[0] < key <= row[1]
               for key in (deletion.key, in_range.key))
    ]
    lo, hi = selected[0][0], selected[-1][1]

    primary = tree.range_facts(
        cold(fact_root), (lo, hi), store.fetch, shape.FACT)
    assert {
        fact.fid for fact in primary if suppkey(fact) == group
    } == {deletion.fid, in_range.fid}
    assert out_of_range_fids.isdisjoint(fact.fid for fact in primary)

    store.reads.clear()
    store.batches.clear()
    monkeypatch.setattr(sqlite3, "connect", store.execute)
    walked = supp_walk(cold(supp_root), group, store.fetch)
    closed = close_deletions(primary, cold(supp_root), store.fetch)
    ground_truth = {deletion.fid} | target_fids
    unit_fids = {fact.fid for fact in walked.unit}

    assert {fact.fid for fact in walked.facts} == ground_truth
    assert ground_truth | {authority.fid} <= unit_fids
    assert ground_truth <= {fact.fid for fact in closed.facts}
    assert {fact.fid for fact in walked.facts} <= unit_fids
    assert_closed(walked.unit)
    assert_closed(closed.unit)
    assert target_fids.isdisjoint(effective(closed.facts))
    assert deletion.fid in effective(closed.facts)
    assert store.sql_calls == 0
    assert store.batches
    assert len(set(store.reads)) \
        <= 3 * len(walked.unit) + 4 * (supp_root.level + 1)
    assert len(set(store.reads)) < len(store.objects) // 10

    shuffled = [shape.SUPP.key(fact) for fact in facts]
    random.Random(6).shuffle(shuffled)
    rebuilt = build(shuffled, shape.SUPP, items, store)
    assert tree.encode_root(tree.Root(
        rebuilt, "proof", frozenset())) == tree.encode_root(tree.Root(
            supp_root, "proof", frozenset()))


def test_concurrent_deletion_and_targets_converge_without_a_match_write(
        monkeypatch):
    monkeypatch.setattr(shape, "CUT", 4)
    monkeypatch.setitem(families.ROUTES, ProofFamily.TAG, ProofFamily)
    facts, authority, items = seed()
    store = Store()
    deletion = facts[DELETE_TS]
    targets = [facts[ts] for ts in sorted(TARGET_TS)]
    assert drain((authority, deletion), "proof").ok
    assert drain((authority, *targets), "proof").ok
    left = build(
        [shape.SUPP.key(deletion)], shape.SUPP, items, store)
    right = build(
        [shape.SUPP.key(fact) for fact in targets],
        shape.SUPP, items, store,
    )
    expected = build(
        [shape.SUPP.key(deletion)]
        + [shape.SUPP.key(fact) for fact in targets],
        shape.SUPP, items, store,
    )

    merged = tree.merge(
        cold(left), cold(right), shape.SUPP, tree.fat(8),
        store.fetch, store.emit, prevalidated=True,
    )
    reverse = tree.merge(
        cold(right), cold(left), shape.SUPP, tree.fat(8),
        store.fetch, store.emit, prevalidated=True,
    )
    before = supp_walk(
        cold(right), suppkey(deletion), store.fetch).facts
    after = supp_walk(
        cold(merged), suppkey(deletion), store.fetch).facts
    target_fids = {fact.fid for fact in targets}

    assert merged.oid == reverse.oid == expected.oid
    assert target_fids <= effective(before)
    assert target_fids.isdisjoint(effective(after))
    assert deletion.fid in effective(after)
