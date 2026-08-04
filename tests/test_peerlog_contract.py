"""Phase-1 contract for peerlog (bead poc-16-6j4.30).

Named, skip-marked, bodies unwritten: the signatures in peerlog/ are
the contract, these names are the acceptance bars (from the .29 design
record). Bodies must be real interleavings per .2 — no mechanical
bypass, no store fakes that serialize.
"""
import pytest

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


@skeleton
def test_walk_refuses_fingerprint_outside_coverage():
    """Fingerprinting a range not fully held is impossible through the
    walk, and Treap.fingerprint asserts on it."""


@skeleton
def test_islands_are_exchanged_exactly_never_fingerprinted():
    """Partial ranges fall back to Treap.members exact exchange."""


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
