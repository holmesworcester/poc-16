"""Contract for the grow-only removal index (docs/REMOVALS.md).

Skeleton: names and docstrings are the contract; bodies land with
core/removals.py. Section and invariant numbers cite docs/REMOVALS.md.
"""
import pytest

import core.removals as removals

SKELETON = pytest.mark.skip(reason="skeleton: contract only, body unwritten")


@SKELETON
def test_point_entry_sorts_to_victim_position():
    """A single-target removal's span is exactly its victim's key (§2)."""


@SKELETON
def test_channel_kill_sorts_to_head():
    """A kill spans ("", "~") and sorts before every point entry (§2)."""


@SKELETON
def test_overlapping_returns_head_plus_slice_only():
    """Evaluating [a, b] reads the head and the [a, b] points, nothing else
    (§3.1); sorting is the skipping mechanism, no per-key probing."""


@SKELETON
def test_span_never_under_approximates():
    """fid embedded in a point span must match the target ref or admission
    rejects; the author chokepoint derives spans from the victim (I6)."""


@SKELETON
def test_predicate_never_suppresses_removals():
    """not is_deletion(f) is a correctness requirement: a kill's deathkey is
    its own suppkey, so without the guard the index self-annihilates (I2)."""


@SKELETON
def test_exactly_one_death_marker_admission_rule():
    """0 or 2+ death markers reject at admission instead of silently
    collapsing to no marker (I3)."""


@SKELETON
def test_encode_decode_roundtrip_and_fingerprint():
    """Canonical sorted encoding round-trips; fingerprint over entry keys is
    the set identity published beside the pile oid (I4)."""


@SKELETON
def test_poisoned_entry_does_not_block_the_index():
    """Admission is per entry: one bad entry rejects alone, never
    pile-atomically with the rest of the removal history (I3)."""


@SKELETON
def test_removal_before_victim_retracts_on_arrival():
    """Retroactive retraction plus forward mask: a victim admitted after its
    removal never surfaces in E (§3.3)."""


@SKELETON
def test_prune_restore_keeps_removals():
    """Quarantining a victim must not delete its removal's entry: the index
    is grow-only even locally, across prune and restore (I1)."""


@SKELETON
def test_fact_tree_fingerprints_unchanged_by_removal():
    """Admitting a removal changes no fact-leaf byte, key, or fingerprint;
    cold ranges stay cold (I5)."""


@SKELETON
def test_sync_fetches_removals_before_fact_ranges():
    """One index fetch ahead of the fact walk replaces the SUPP leg and
    close_deletions range augmentation (§5)."""
