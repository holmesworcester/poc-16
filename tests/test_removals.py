"""Contract for the grow-only removal index (docs/REMOVALS.md).

Section and invariant numbers cite docs/REMOVALS.md; the remaining
skeletons land with oyd.4 (retraction) and oyd.7 (production family).
"""
import pytest

import core.manifest as manifest
import core.removals as removals
import core.shape as shape
import core.sync as sync_module
from core import cmds
from core.crypto import h, load_sk
from core.fact import Fact, canon
from core.node import Node
from core.suppression import TARGET, atom, is_deletion
from facts.content.message import message

from .util import (
    all_fids,
    channel_delete,
    channel_kill,
    closed_subset,
    deliver,
    multi_group_post,
    suppression_world,
)

SKELETON = pytest.mark.skip(reason="skeleton: contract only, body unwritten")


def victim_key(*victims):
    """The author chokepoint's key lookup: span from the actual victim."""
    keys = {fact.fid: shape.key(fact) for fact in victims}
    return keys.__getitem__


def test_point_entry_sorts_to_victim_position():
    """A single-target removal's span is exactly its victim's key (§2)."""
    early = message("pk", "general", "hello", 1)
    late = message("pk", "general", "world", 9)
    kill_early = removals.entry(
        channel_delete(early.fid, "general", 20), victim_key(early))
    kill_late = removals.entry(
        channel_delete(late.fid, "general", 10), victim_key(late))

    assert (kill_early.lo, kill_early.hi) == (shape.key(early),) * 2
    # deletion order is irrelevant: entries sit at their victims' positions
    assert sorted(
        [kill_late, kill_early], key=removals.entry_key) \
        == [kill_early, kill_late]


def test_channel_kill_sorts_to_head():
    """A kill spans ("", "~") and sorts before every point entry (§2)."""
    victim = message("pk", "general", "hello", 1)
    kill = removals.entry(
        channel_kill("general", 9), victim_key())  # no victim lookup at all
    point = removals.entry(
        channel_delete(victim.fid, "general", 9), victim_key(victim))

    assert (kill.lo, kill.hi) == removals.HEAD
    assert sorted([point, kill], key=removals.entry_key) == [kill, point]


def test_overlapping_returns_head_plus_slice_only():
    """Evaluating [a, b] reads the head and the [a, b] points, nothing else
    (§3.1); sorting is the skipping mechanism, no per-key probing."""
    victims = [message("pk", "general", f"m{ts}", ts) for ts in range(1, 5)]
    points = [
        removals.entry(
            channel_delete(fact.fid, "general", 9), victim_key(fact))
        for fact in victims
    ]
    kill = removals.entry(channel_kill("general", 9), victim_key())
    entries = [points[2], kill, points[0], points[3], points[1]]  # any order

    a, b = shape.key(victims[1]), shape.key(victims[2])
    assert removals.overlapping(entries, a, b) == (kill, points[1], points[2])
    # the head rides along even when the slice is empty
    assert removals.overlapping(entries, "9" * 15, "~") == (kill,)


def test_span_never_under_approximates():
    """fid embedded in a point span must match the target ref or admission
    rejects; the author chokepoint derives spans from the victim (I6)."""
    victim = message("pk", "general", "hello", 1)
    mate = message("pk", "general", "world", 2)
    point = channel_delete(victim.fid, "general", 9)
    honest = removals.entry(point, victim_key(victim))
    kill = channel_kill("general", 9)

    assert removals.admit(honest, point)
    assert removals.admit(removals.entry(kill, victim_key()), kill)
    routed_elsewhere = removals.Entry(
        shape.key(mate), shape.key(mate), point.fid)  # span misses victim
    widened = removals.Entry(honest.lo, shape.key(mate), point.fid)
    narrowed_kill = removals.Entry(
        shape.key(victim), shape.key(victim), kill.fid)  # hides victims
    for lie in (routed_elsewhere, widened):
        assert not removals.admit(lie, point)
    assert not removals.admit(narrowed_kill, kill)

    # Right fid, lying ts: passes the syntactic gate by design — "a deleter
    # who lies anyway only neuters their own deletion" (REMOVALS.md I6).
    # The span can never route to the victim's real key, so the lie is inert.
    liar = removals.Entry(
        shape.key_parts(999_999, victim.fid),
        shape.key_parts(999_999, victim.fid), point.fid)
    assert removals.admit(liar, point)
    assert removals.overlapping(
        [liar], shape.key(victim), shape.key(victim)) == ()


def test_point_deletion_never_suppresses_channel_mates():
    """REGRESSION (§2): a point removal of m1 reaches exactly m1 — never
    channel-mate m2. This fails against scalar suppkey equality AND against
    any form where a point's death marker feeds the group clause: both
    messages share the channel group, so either defect deletes m2 (the I6
    under-approximation, span (K,K) routing to one key)."""
    m1 = message("pk", "general", "hello", 1)
    m2 = message("pk", "general", "world", 2)
    point = channel_delete(m1.fid, "general", 3)

    assert removals.applies(point, m1)
    assert not removals.applies(point, m2)


def test_multi_group_fact_reachable_by_every_declared_group():
    """MULTI-GROUP (§2): membership is a SET. A fact in {chan, author} is
    reached by a kill of either group, not by a kill of a third, and a
    point removal of it reaches it alone."""
    fact = multi_group_post("general", "alice", "hi", 1)
    twin = multi_group_post("general", "alice", "again", 2)

    assert removals.applies(channel_kill("general", 3), fact)
    assert removals.applies(channel_kill("author/alice", 3), fact)
    assert not removals.applies(channel_kill("elsewhere", 3), fact)
    point = channel_delete(fact.fid, "general", 3)
    assert removals.applies(point, fact)
    assert not removals.applies(point, twin)


def test_predicate_never_suppresses_removals():
    """not is_deletion(f) is a correctness requirement (I2): removals are
    never victims and write no supp rows, so no removal — point or kill —
    can retract another, and the index cannot self-annihilate."""
    victim = message("pk", "general", "hello", 1)
    kill = channel_kill("general", 5)
    other_kill = channel_kill("general", 6)
    point_at_kill = channel_delete(kill.fid, "general", 7)

    assert removals.applies(kill, victim)  # the group clause is live...
    assert not removals.applies(kill, kill)  # ...but never against removals
    assert not removals.applies(other_kill, kill)
    assert not removals.applies(point_at_kill, kill)


def test_exactly_one_death_marker_admission_rule():
    """0 or 2+ death markers reject at admission instead of silently
    collapsing to no marker (I3)."""
    victim = message("pk", "general", "hello", 1)
    unmarked = Fact("channel_delete", 9, [["ref", TARGET, victim.fid]], {})
    twice = Fact(
        "channel_delete", 9,
        [atom("a", deletion=True), atom("b", deletion=True),
         ["ref", TARGET, victim.fid]], {})

    for bad in (unmarked, twice):
        assert not is_deletion(bad)
        with pytest.raises(ValueError, match="not a removal"):
            removals.entry(bad, victim_key(victim))
        assert not removals.admit(
            removals.Entry(*removals.HEAD, bad.fid), bad)


def test_encode_decode_roundtrip_and_fingerprint():
    """Canonical sorted encoding round-trips; fingerprint over entry keys is
    the set identity published beside the pile oid (I4)."""
    victim = message("pk", "general", "hello", 1)
    point = channel_delete(victim.fid, "general", 9)
    kill = channel_kill("general", 9)
    entries = [
        removals.entry(point, victim_key(victim)),
        removals.entry(kill, victim_key()),
    ]
    closure = [point, kill, victim]

    emitted = []
    oid = removals.encode(entries, closure, emitted.append)
    (raw,) = emitted
    assert h(raw) == oid
    assert oid == removals.encode(  # canonical: input order never shows
        list(reversed(entries)), list(reversed(closure)), lambda raw: None)
    decoded, refs = removals.decode(raw)
    assert decoded == tuple(sorted(entries, key=removals.entry_key))
    assert refs == tuple(sorted(shape.key(fact) for fact in closure))
    assert removals.fingerprint(entries) \
        == removals.fingerprint(reversed(entries))
    assert removals.fingerprint(entries) != removals.fingerprint(entries[:1])


def _crafted_root(source, workspace, entries, refs):
    """The source's root with its removals slot swapped for a crafted
    index pile; returns ``(root bytes, {oid: raw})``."""
    raw = canon({
        "entries": [list(e) for e in sorted(entries, key=removals.entry_key)],
        "refs": sorted(refs),
    })
    _, globals_, man, _ = manifest.decode_root(
        source.store(workspace).get("root"))
    root = manifest.encode_root(
        workspace, globals_, man,
        {"oid": h(raw), "fp": removals.fingerprint(entries)})
    return root, {h(raw): raw}


def test_poisoned_entry_does_not_block_the_index(tmp_path, monkeypatch):
    """Admission is per entry: one bad entry rejects alone, never
    pile-atomically with the rest of the removal history (I3)."""
    source, workspace, _, deletions = suppression_world(
        tmp_path / "source", monkeypatch,
        initial_secret=load_sk(f"{1:064x}"))
    destination = Node(str(tmp_path / "destination"))
    survivors = set(all_fids(source, workspace)) - set(deletions)
    deliver(
        destination, workspace,
        closed_subset(source, workspace, survivors))
    destination.turn(workspace)

    src = source.store(workspace)
    slot = manifest.decode_root(src.get("root"))[3]
    honest, refs = removals.decode(src.get("obj/" + slot["oid"]))
    ghost = "d" * 64  # a removal whose closure resolves to nothing
    poisoned = removals.Entry("", "~", ghost)
    root, crafted = _crafted_root(
        source, workspace, [*honest, poisoned],
        [*refs, shape.key_parts(300, ghost)])

    def fetch(oid):
        return crafted.get(oid) or src.get("obj/" + oid)

    fetch.many = lambda oids: tuple(fetch(oid) for oid in oids)
    admitted = sync_module.pull_removals(
        destination, workspace, root, fetch)

    assert {entry.fid for entry in admitted} == set(deletions)
    assert poisoned not in admitted
    for fid in deletions:  # the honest history landed despite the poison
        assert destination.fact_of(workspace, fid) is not None


@pytest.mark.skip(reason="CUTOVER_SKIP: lands in oyd.4")
def test_removal_before_victim_retracts_on_arrival():
    """Retroactive retraction plus forward mask: a victim admitted after its
    removal never surfaces in E (§3.3)."""


@pytest.mark.skip(reason="CUTOVER_SKIP: lands in oyd.4")
def test_prune_restore_keeps_removals():
    """Quarantining a victim must not delete its removal's entry: the index
    is grow-only even locally, across prune and restore (I1)."""


@SKELETON
def test_fact_tree_fingerprints_unchanged_by_removal():
    """Admitting a removal changes no fact-leaf byte, key, or fingerprint;
    cold ranges stay cold (I5)."""


def test_sync_fetches_removals_before_fact_ranges(tmp_path, monkeypatch):
    """One index fetch ahead of the fact walk replaces the SUPP leg and
    close_deletions range augmentation (§5)."""
    source, workspace, targets, _ = suppression_world(
        tmp_path / "source", monkeypatch,
        initial_secret=load_sk(f"{1:064x}"))
    target = source.fact_of(workspace, targets[0])
    deletion = channel_delete(target.fid, target.body["chan"], 500)
    source.ingest_new(workspace, [deletion], {deletion.fid: [target.fid]})
    unsynced = [
        cmds.post(source, workspace, "general", f"late {i}", ts=600 + i)
        for i in range(4)
    ]
    destination = Node(str(tmp_path / "destination"))
    existing = set(all_fids(source, workspace)) \
        - {deletion.fid} - set(unsynced)
    deliver(
        destination, workspace,
        closed_subset(source, workspace, existing))
    destination.turn(workspace)

    order = []

    class LocalPeer:
        def __init__(self, node, ws, url):
            self.node, self.ws = node, ws
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None):
            raw = source.store(self.ws).get("root")
            return raw, source.store(self.ws).etag("root")

        def obj(self, oid):
            order.append(oid)
            return source.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            order.extend(oids)
            return tuple(
                source.store(self.ws).get("obj/" + oid) for oid in oids)

        def put_pile(self, raw):
            pytest.fail("destination unexpectedly pushed")

    monkeypatch.setattr(sync_module, "Peer", LocalPeer)
    sync_module.sync(destination, workspace, "local://source")

    src = source.store(workspace)
    _, _, man, slot = manifest.decode_root(src.get("root"))
    fetch = lambda oid: src.get("obj/" + oid)
    leaves = {
        entry.leaf for entry in manifest.decode(fetch(man), fetch)}
    fact_fetches = [
        position for position, oid in enumerate(order) if oid in leaves]
    assert fact_fetches  # the fact leg really pulled home leaves
    assert order.index(slot["oid"]) < min(fact_fetches)
    assert destination.fact_of(workspace, deletion.fid) == deletion
    assert all_fids(destination, workspace) == all_fids(source, workspace)


@SKELETON
def test_production_deletion_family():
    """facts/content/delete.py is registered in content.MODULES; its author
    command derives channel and span from the actual victim (I6); admitting
    one retracts the victim's projected row and lands one index entry —
    the first non-monkeypatched deletion end to end (REMOVALS.md §8)."""
