"""Phase-1 contract for peerlog (bead poc-16-6j4.30).

Named, skip-marked, bodies unwritten: the signatures in peerlog/ are
the contract, these names are the acceptance bars (from the .29 design
record). Bodies must be real interleavings per .2 — no mechanical
bypass, no store fakes that serialize.
"""
import hashlib
import random
import threading

import pytest

from peerlog.coverage import Coverage, intersect
from peerlog.treap import Treap, decode_root, snapshot
from peerlog.walk import (
    OBJECT_PREFIX,
    ROOT_KEY,
    diff,
    diff_entries,
    publish,
)

skeleton = pytest.mark.skip(reason="phase-1 skeleton: contract named, body unwritten")


class EndpointStore:
    """A responder-shaped GET/PUT endpoint with immutable object semantics."""

    def __init__(self):
        self.values = {}
        self.get_calls = []
        self.put_calls = []
        self.lock = threading.Lock()

    def get(self, key, rng=None):
        assert rng is None
        with self.lock:
            self.get_calls.append(key)
            return self.values.get(key)

    def put(self, key, val):
        assert isinstance(val, bytes)
        with self.lock:
            if key.startswith(OBJECT_PREFIX):
                assert key.removeprefix(OBJECT_PREFIX) == hashlib.sha256(val).hexdigest()
                incumbent = self.values.setdefault(key, val)
                if incumbent != val:
                    raise ValueError("immutable collision")
            else:
                assert key == ROOT_KEY
                self.values[key] = val
            self.put_calls.append(key)


def _fid(label):
    return hashlib.sha256(label.encode()).hexdigest().encode()


def _tree(rows):
    tree = Treap()
    for ts, label in rows:
        tree.insert(ts, _fid(label))
    return tree


@skeleton
def test_two_partial_peers_converge_to_coverage_union():
    """Arbitrary island/suffix states; after sync both hold the union
    of the coverage intersection, via GET/PUT only."""


@skeleton
def test_identical_sets_cost_one_conditional_get():
    """Equal coverage and equal sets: one conditional root GET, zero
    ranges recursed, zero bytes transferred. The conditional cache token
    belongs to the session wrapper, which is not implemented yet."""


def test_identical_sets_cost_one_root_get_and_no_page_reads():
    """The live core already provides the prune behind conditional GET."""
    rows = tuple((ts, f"same:{ts}") for ts in range(1, 500))
    coverage = Coverage(((0, 1_000),))
    remote = EndpointStore()
    publish(_tree(reversed(rows)), coverage, remote)
    remote.get_calls.clear()

    assert diff(_tree(rows), coverage, remote) == ()
    assert remote.get_calls == [ROOT_KEY]


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


def test_stable_self_addressed_pages_survive_arrival_order_and_append():
    """A rebuild reuses every subtree untouched by a new Cartesian path."""
    rows = tuple((ts, f"page:{ts}") for ts in range(1, 300))
    coverage = Coverage(((0, 1_000),))
    ordered = _tree(rows)
    shuffled_rows = list(rows)
    random.Random(89).shuffle(shuffled_rows)
    shuffled = _tree(shuffled_rows)

    first = snapshot(ordered, coverage)
    same = snapshot(shuffled, coverage)
    assert same == first
    assert all(
        hashlib.sha256(raw).digest() == oid
        for oid, raw in first.objects
    )

    ordered.insert(350, _fid("page:350"))
    changed = snapshot(ordered, coverage)
    old_oids = {oid for oid, _ in first.objects}
    new_oids = {oid for oid, _ in changed.objects}
    assert len(old_oids & new_oids) > 250
    assert changed.root != first.root


def test_driver_walk_learns_both_sides_and_exact_partial_islands():
    """Only the driver walks; remote pages reveal pull and push candidates."""
    remote_tree = _tree((
        (2, "common:2"),
        (4, "common:4"),
        (14, "remote:island"),
        (22, "common:22"),
        (24, "remote:covered"),
    ))
    local_tree = _tree((
        (2, "common:2"),
        (4, "common:4"),
        (16, "local:island"),
        (22, "common:22"),
        (26, "local:covered"),
    ))
    remote_coverage = Coverage(((0, 10), (20, 30)))
    local_coverage = Coverage(((0, 8), (12, 18), (20, 30)))
    remote = EndpointStore()
    publish(remote_tree, remote_coverage, remote)
    remote.get_calls.clear()

    result = diff_entries(local_tree, local_coverage, remote)
    assert result.remote_only == (
        (14, _fid("remote:island")),
        (24, _fid("remote:covered")),
    )
    assert result.local_only == (
        (16, _fid("local:island")),
        (26, _fid("local:covered")),
    )
    assert result.gets == len(remote.get_calls)
    assert remote.get_calls[0] == ROOT_KEY
    assert all(
        key == ROOT_KEY or key.startswith(OBJECT_PREFIX)
        for key in remote.get_calls
    )


def test_one_sided_walk_matches_naive_symmetric_difference():
    """Random arrival and coverage shapes cannot hide either side's news."""
    coverage_shapes = (
        Coverage(((0, 200),)),
        Coverage(((0, 50), (100, 150))),
        Coverage(((25, 75), (125, 175))),
        Coverage(()),
    )
    universe = tuple((ts, f"random:{ts}") for ts in range(1, 180))
    for seed in range(20):
        rng = random.Random(seed)
        remote_rows = [row for row in universe if rng.random() < 0.72]
        local_rows = [row for row in universe if rng.random() < 0.68]
        rng.shuffle(remote_rows)
        rng.shuffle(local_rows)
        remote = EndpointStore()
        publish(
            _tree(remote_rows),
            coverage_shapes[seed % len(coverage_shapes)],
            remote,
        )
        result = diff_entries(
            _tree(local_rows),
            coverage_shapes[(seed + 1) % len(coverage_shapes)],
            remote,
        )
        remote_set = {(ts, _fid(label)) for ts, label in remote_rows}
        local_set = {(ts, _fid(label)) for ts, label in local_rows}
        assert set(result.remote_only) == remote_set - local_set
        assert set(result.local_only) == local_set - remote_set


def test_publish_orders_objects_before_root_and_walk_rejects_tampering():
    coverage = Coverage(((0, 100),))
    remote = EndpointStore()
    publish(_tree(((10, "remote"),)), coverage, remote)
    assert remote.put_calls[-1] == ROOT_KEY
    assert all(key.startswith(OBJECT_PREFIX) for key in remote.put_calls[:-1])

    served = decode_root(remote.values[ROOT_KEY])
    page_key = OBJECT_PREFIX + served.covered[0][2].hex()
    remote.values[page_key] += b" "
    with pytest.raises(ValueError, match="integrity"):
        diff_entries(Treap(), coverage, remote)


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
