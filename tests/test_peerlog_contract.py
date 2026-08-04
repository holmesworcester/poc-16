"""Phase-1 contract for peerlog (bead poc-16-6j4.30).

Named, skip-marked, bodies unwritten: the signatures in peerlog/ are
the contract, these names are the acceptance bars (from the .29 design
record). Bodies must be real interleavings per .2 — no mechanical
bypass, no store fakes that serialize.
"""
import hashlib
import random

import pytest

from peerlog.coverage import Coverage, intersect
from peerlog.treap import Treap

skeleton = pytest.mark.skip(reason="phase-1 skeleton: contract named, body unwritten")


@skeleton
def test_two_partial_peers_converge_to_coverage_union():
    """Arbitrary island/suffix states; after sync both hold the union
    of the coverage intersection, via GET/PUT only."""


@skeleton
def test_identical_sets_cost_one_conditional_get():
    """Equal coverage and equal sets: one conditional root GET, zero
    ranges recursed, zero bytes transferred."""


@skeleton
def test_range_accept_is_all_or_nothing():
    """A run either ingests completely or leaves state untouched."""


@skeleton
def test_tampered_run_rejects_whole_run():
    """One flipped byte anywhere in facts/paths/head fails verify_run
    and nothing from the run is filed."""


def test_walk_refuses_fingerprint_outside_coverage():
    """Fingerprinting a range not fully held is impossible through the
    walk, and Treap.fingerprint asserts on it."""
    tree = Treap()
    for ts in (1, 2, 21, 22):
        tree.insert(ts, hashlib.sha256(str(ts).encode()).hexdigest().encode())
    coverage = Coverage(((0, 10), (20, 30)))

    assert tree.fingerprint(0, 10, coverage)
    assert tree.fingerprint(20, 30, coverage)
    with pytest.raises(ValueError, match="uncovered"):
        tree.fingerprint(5, 25, coverage)
    with pytest.raises(ValueError, match="uncovered"):
        tree.fingerprint(10, 20, coverage)


def test_islands_are_exchanged_exactly_never_fingerprinted():
    """Partial ranges fall back to Treap.members exact exchange."""
    left, right = Treap(), Treap()
    common = (2, 4, 22)
    for ts in (*common, 14):
        left.insert(ts, hashlib.sha256(f"left:{ts}".encode()).hexdigest().encode())
    for ts in common:
        right.insert(ts, hashlib.sha256(f"left:{ts}".encode()).hexdigest().encode())
    right.insert(16, hashlib.sha256(b"right:16").hexdigest().encode())

    left_coverage = Coverage(((0, 10), (20, 30)))
    right_coverage = Coverage(((0, 8), (12, 18), (20, 30)))
    assert intersect(left_coverage, right_coverage) == Coverage(
        ((0, 8), (20, 30)))
    assert left.fingerprint(0, 8, left_coverage) \
        == right.fingerprint(0, 8, right_coverage)
    assert left.fingerprint(20, 30, left_coverage) \
        == right.fingerprint(20, 30, right_coverage)

    # Neither peer claims the whole gap. Its resident islands are therefore
    # compared as exact members, which exposes both sides of the difference.
    left_island = set(left.members(10, 20))
    right_island = set(right.members(10, 20))
    assert {ts for ts, _ in left_island ^ right_island} == {14, 16}
    with pytest.raises(ValueError, match="uncovered"):
        left.fingerprint(10, 20, left_coverage)
    with pytest.raises(ValueError, match="uncovered"):
        right.fingerprint(10, 20, right_coverage)


def test_treap_fingerprint_is_history_independent_and_detects_difference():
    """The resurrected content-priority shape depends on the set, not ingest."""
    rows = tuple(
        (ts, hashlib.sha256(f"fact:{ts}".encode()).hexdigest().encode())
        for ts in range(1, 300)
    )
    roots = set()
    coverage = Coverage(((0, 400),))
    for seed in range(8):
        shuffled = list(rows)
        random.Random(seed).shuffle(shuffled)
        tree = Treap()
        for ts, fact_id in shuffled:
            tree.insert(ts, fact_id)
        roots.add(tree.fingerprint(0, 400, coverage))
        assert tree.members(0, 400) == rows
    assert len(roots) == 1

    changed = Treap()
    for ts, fact_id in rows:
        changed.insert(ts, fact_id)
    changed.insert(350, hashlib.sha256(b"new").hexdigest().encode())
    assert changed.fingerprint(0, 400, coverage) not in roots


def test_coverage_and_treap_reject_ambiguous_protocol_shapes():
    """Overlapping claims and non-canonical fact addresses fail at the door."""
    with pytest.raises(ValueError, match="coverage order"):
        Coverage(((0, 10), (9, 20)))
    with pytest.raises(ValueError, match="coverage order"):
        Coverage(((0, 10), (10, 20)))
    with pytest.raises(ValueError, match="coverage range"):
        Coverage(((False, 10),))

    tree = Treap()
    fact_id = hashlib.sha256(b"stable").hexdigest().encode()
    tree.insert(10, fact_id)
    tree.insert(10, fact_id)  # exact replay is idempotent
    assert len(tree) == 1
    with pytest.raises(ValueError, match="timestamp"):
        tree.insert(11, fact_id)
    with pytest.raises(ValueError, match="treap fact"):
        tree.insert(12, b"not-a-fid")

    for ts in range(20, 30):
        tree.insert(ts, hashlib.sha256(f"split:{ts}".encode()).hexdigest().encode())
    points = tree.split_points(0, 40, 4)
    assert points == tuple(sorted(set(points)))
    assert len(points) == 3


@skeleton
def test_fork_heads_collide_during_gossip():
    """Two signed heads for one writer disagreeing below the shared
    seq produce ForkEvidence at any peer that sees both."""


@skeleton
def test_backdated_fact_lands_in_quarantine_band():
    """A fact with ts older than TS_QUARANTINE does not churn stable
    range fingerprints; it syncs through the late band."""


@skeleton
def test_run_proof_amortizes_over_contiguous_seqs():
    """Proof bytes per fact for a contiguous run are O(1) amortized
    versus ~0.7 KB for the degenerate single-fact carry."""


@skeleton
def test_diff_rounds_grow_logarithmically():
    """Measured over growing set sizes with a fixed small delta: round
    count grows ~log n (bench/writer_p2p_cost.py reports, no mocks)."""


@skeleton
def test_recent_window_sync_rounds_bounded():
    """Syncing only a recent ts-window costs bounded rounds regardless
    of history size."""


@skeleton
def test_driver_learns_symmetric_difference_and_pushes():
    """One driver session moves news both ways: the responder ends up
    holding the driver's news without ever running walk logic."""


@skeleton
def test_simultaneous_dials_collapse_to_single_driver():
    """Both peers dial at once: exactly one session survives and the
    lower endpoint id drives it; no duplicate transfer."""


@skeleton
def test_peer_serves_passive_interface_identically():
    """A client's seq-diff recipe run against a peer's Store returns
    byte-identical results to the same recipe against the cloud store."""
