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
from nacl import signing

import peerlog.ingest as ingest_module

from peerlog.coverage import Coverage, intersect
from peerlog.fact import Fact, canonical, decode_slice, fid
from peerlog.endpoint import PeerEndpoint
from peerlog.ingest import PeerState, ingest, ingest_batch, observe_head
from peerlog.log import WriterLog
from peerlog.proof import Run, decode_run, prove_run, verify_run
from peerlog.session import SessionCoordinator, mesh_sync
from peerlog.treap import Treap, decode_root, snapshot
from peerlog.tree import inclusion, root_bytes, verify_inclusion
from peerlog.walk import (
    OBJECT_PREFIX,
    ROOT_KEY,
    diff,
    diff_entries,
    diff_window,
    publish,
    sync,
)

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


def test_owned_writer_detects_private_gap_without_rescanning_history():
    log = WriterLog.owned()
    log.append(Fact("msg", 1, (), b"first"))
    del log._facts[0]
    with pytest.raises(ValueError, match="own writer log gap"):
        log.append(Fact("msg", 2, (), b"must not hide the gap"))


def test_two_partial_peers_converge_to_coverage_union():
    """Arbitrary island/suffix states; after sync both hold the union
    of the coverage intersection, via GET/PUT only."""
    left_log, right_log = WriterLog.owned(), WriterLog.owned()
    for seq in range(10):
        left_log.append(Fact("msg", seq * 2, (), f"left:{seq}".encode()))
        right_log.append(Fact("msg", seq * 2 + 1, (), f"right:{seq}".encode()))
    left_state, right_state = PeerState(), PeerState()
    left_state.add_owned(left_log)
    right_state.add_owned(right_log)
    left = PeerEndpoint(left_state, Coverage(()), b"left")
    right = PeerEndpoint(right_state, Coverage(()), b"right")

    report = sync(left, right)
    expected = set((left_state.treap.entries()))
    assert expected == set(right_state.treap.entries())
    assert len(expected) == 20
    assert report["pulled_facts"] == report["pushed_facts"] == 10
    assert all(key.startswith((ROOT_KEY, OBJECT_PREFIX, "peerlog/fact/", "peerlog/run/"))
               for key in right.get_calls + right.put_calls)


def test_identical_sets_cost_one_conditional_get():
    """Equal coverage and equal sets: one conditional root GET, zero
    ranges recursed, zero bytes transferred. The conditional cache token
    belongs to the session wrapper, which is not implemented yet."""
    log = WriterLog.owned()
    for seq in range(100):
        log.append(Fact("msg", seq, (), f"same:{seq}".encode()))
    left_state = PeerState()
    left_state.add_owned(log)
    left = PeerEndpoint(left_state, endpoint_id=b"left")
    right = PeerEndpoint(endpoint_id=b"right")
    sync(right, left)
    # First equality establishes the exact responder-root/local-set token.
    sync(right, left)
    left.get_calls.clear()
    report = sync(right, left)
    assert report["conditional_hit"]
    assert left.get_calls == [ROOT_KEY]
    assert report["diff_bytes"] == report["pulled_facts"] == 0


def test_identical_sets_cost_one_root_get_and_no_page_reads():
    """The live core already provides the prune behind conditional GET."""
    rows = tuple((ts, f"same:{ts}") for ts in range(1, 500))
    coverage = Coverage(((0, 1_000),))
    remote = EndpointStore()
    publish(_tree(reversed(rows)), coverage, remote)
    remote.get_calls.clear()

    assert diff(_tree(rows), coverage, remote) == ()
    assert remote.get_calls == [ROOT_KEY]


def test_range_accept_is_all_or_nothing():
    """A run either ingests completely or leaves state untouched."""
    source = WriterLog.owned()
    for seq in range(8):
        source.append(Fact("msg", seq, (), f"message:{seq}".encode()))
    target = PeerState()
    good = prove_run(source, 2, 7)
    ingest(target, good)
    before = target.entries()
    before_coverage = target.logs[source.writer].coverage()

    # A valid proof that overlaps an already accepted sequence with different
    # bytes is equivocation. No later fact from the run may leak into state.
    fork_secret = signing.SigningKey(source._secret.encode())
    fork = WriterLog(source.writer, fork_secret)
    for seq in range(8):
        body = b"different" if seq == 4 else f"message:{seq}".encode()
        fork.append(Fact("msg", seq, (), body))
    with pytest.raises(ValueError, match="writer (fork|equivocation)"):
        ingest(target, prove_run(fork, 4, 8))
    assert target.entries() == before
    assert target.logs[source.writer].coverage() == before_coverage


def test_adjacency_batch_rejects_without_installing_valid_carry_prefix():
    secret = signing.SigningKey.generate()
    writer = bytes(secret.verify_key)
    accepted = WriterLog(writer, secret)
    forked = WriterLog(writer, secret)
    accepted.append(Fact("msg", 10, (), b"accepted"))
    forked.append(Fact("msg", 10, (), b"forked"))
    carried = WriterLog.owned()
    carried.append(Fact("member", 9, (), b"valid carry"))

    state = PeerState()
    ingest(state, prove_run(accepted, 0, 1))
    before = state.entries()
    with pytest.raises(ValueError, match="writer fork"):
        ingest_batch(state, (
            prove_run(carried, 0, 1), prove_run(forked, 0, 1)))
    assert state.entries() == before
    assert carried.writer not in state.logs


def test_incremental_owner_tree_is_exact_at_growth_boundaries():
    log = WriterLog.owned()
    controls = []
    checkpoints = {1, 2, 3, 4, 7, 8, 9, 255, 256, 257, 1024, 1025}
    for seq in range(1025):
        family = "member" if seq % 97 == 0 else "msg"
        fact = Fact(family, seq + 1, (), bytes([seq % 251]) * 17)
        log.append(fact)
        if family == "member":
            controls.append(canonical(fact))
        if seq + 1 not in checkpoints:
            continue
        raws = tuple(log._raw(index) for index in range(seq + 1))
        assert log.head().root == root_bytes(raws)
        assert log.head().control_root == root_bytes(tuple(controls))
        for target in {0, seq // 2, seq}:
            path = inclusion(log, target)
            assert verify_inclusion(
                log.head(), target, log._raw(target), path)


def test_adjacency_batch_advances_only_changed_writer_index(monkeypatch):
    logs = []
    for writer in range(12):
        log = WriterLog.owned()
        for seq in range(5):
            log.append(Fact(
                "msg", writer * 100 + seq + 1, (), bytes([writer]) * 8))
        logs.append(log)
    state = PeerState()
    ingest_batch(state, tuple(prove_run(log, 0, 5) for log in logs))
    assert len(state.treap) == 60
    changed = logs[0]
    changed.append(Fact("msg", 10_000, (), b"warm delta"))

    def forbidden(_logs):  # pragma: no cover - failure-only assertion hook
        raise AssertionError("warm batch rebuilt every unchanged writer")

    monkeypatch.setattr(ingest_module, "_rebuild", forbidden)
    ingest_batch(state, (prove_run(changed, 5, 6),))
    assert len(state.treap) == 61


def test_tampered_run_rejects_whole_run():
    """One flipped byte anywhere in facts/paths/head fails verify_run
    and nothing from the run is filed."""
    source = WriterLog.owned()
    for seq in range(12):
        source.append(Fact("msg", 100 + seq, (), bytes([seq]) * 40))
    run = prove_run(source, 2, 10)
    raw = bytearray(run.facts)
    raw[len(raw) // 2] ^= 1
    corrupt = Run(run.writer, run.lo, run.hi, bytes(raw), run.head, run.paths)
    target = PeerState()
    assert not verify_run(corrupt)
    with pytest.raises(ValueError, match="invalid writer run"):
        ingest(target, corrupt)
    assert target.entries() == ()
    assert target.logs == {}


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


def test_fork_heads_collide_during_gossip():
    """Two signed heads for one writer disagreeing below the shared
    seq produce ForkEvidence at any peer that sees both."""
    secret = signing.SigningKey.generate()
    first = WriterLog.owned(secret)
    second = WriterLog.owned(signing.SigningKey(secret.encode()))
    first.append(Fact("msg", 1, (), b"one"))
    second.append(Fact("msg", 1, (), b"two"))
    state = PeerState()
    assert observe_head(state, first.head()) is None
    evidence = observe_head(state, second.head())
    assert evidence.writer == first.writer
    assert evidence.heads == (first.head(), second.head())
    assert state.forks == [evidence]


def test_backdated_fact_lands_in_quarantine_band():
    """A fact with ts older than TS_QUARANTINE does not churn stable
    range fingerprints; it syncs through the late band."""
    log = WriterLog.owned()
    log.append(Fact("msg", 100_000_000, (), b"current"))
    state = PeerState()
    state.add_owned(log)
    coverage = Coverage(((0, 200_000_000),))
    stable = state.treap.fingerprint(0, 200_000_000, coverage)

    log.append(Fact("msg", 1, (), b"late"))
    state.add_owned(log)
    assert state.treap.fingerprint(0, 200_000_000, coverage) == stable
    assert state.treap.exact_members() == ((1, fid(log.fact(1))),)
    source = PeerEndpoint(state, coverage)
    target = PeerEndpoint(PeerState(), Coverage(()))
    sync(target, source)
    assert target.state.entries() == state.entries()


def test_run_proof_amortizes_over_contiguous_seqs():
    """Proof bytes per fact for a contiguous run are O(1) amortized
    versus ~0.7 KB for the degenerate single-fact carry."""
    source = WriterLog.owned()
    for seq in range(256):
        source.append(Fact("msg", seq, (), b"x" * 256))
    single = prove_run(source, 100, 101)
    batch = prove_run(source, 64, 192)
    assert verify_run(single)
    assert verify_run(batch)
    single_proof = sum(map(len, single.paths[0])) + len(single.head.sig)
    batch_proof = sum(len(item) for path in batch.paths for item in path) \
        + len(batch.head.sig)
    assert batch_proof / 128 < single_proof / 8
    assert decode_slice(batch.facts, 128)[0].body == b"x" * 256
    assert fid(decode_slice(batch.facts, 128)[-1]) == fid(source.fact(191))


def test_diff_rounds_grow_logarithmically():
    """Measured over growing set sizes with a fixed small delta: round
    count grows ~log n (bench/writer_p2p_cost.py reports, no mocks)."""
    gets = []
    coverage = Coverage(((0, 100_000),))
    for exponent in range(8, 14):
        rows = tuple((ts, f"scale:{ts}") for ts in range(2 ** exponent))
        remote = EndpointStore()
        publish(_tree(rows), coverage, remote)
        remote.get_calls.clear()
        local = _tree(row for row in rows if row[0] != len(rows) // 2)
        result = diff_entries(local, coverage, remote)
        assert len(result.remote_only) == 1
        gets.append(result.gets)
        assert result.gets <= 3 * exponent
    assert max(gets) <= 3 * 13


def test_recent_window_sync_rounds_bounded():
    """Syncing only a recent ts-window costs bounded rounds regardless
    of history size."""
    gets = []
    cut = 1_000_000
    coverage = Coverage(((0, cut + 64),))
    for history in (256, 1024, 4096):
        old = tuple((ts, f"old:{history}:{ts}") for ts in range(history))
        recent = tuple((cut + ts, f"recent:{ts}") for ts in range(32))
        remote = EndpointStore()
        publish(_tree((*old, *recent)), coverage, remote)
        remote.get_calls.clear()
        local = _tree((*old, *(row for row in recent if row[0] != cut + 15)))
        result = diff_window(local, coverage, remote, cut, cut + 64)
        assert result.remote_only == ((cut + 15, _fid("recent:15")),)
        gets.append(result.gets)
    assert len(set(gets)) == 1


def test_driver_learns_symmetric_difference_and_pushes():
    """One driver session moves news both ways: the responder ends up
    holding the driver's news without ever running walk logic."""
    a_log, b_log = WriterLog.owned(), WriterLog.owned()
    a_log.append(Fact("msg", 1, (), b"a"))
    b_log.append(Fact("msg", 2, (), b"b"))
    a_state, b_state = PeerState(), PeerState()
    a_state.add_owned(a_log)
    b_state.add_owned(b_log)
    a, b = PeerEndpoint(a_state), PeerEndpoint(b_state)
    report = sync(a, b)
    assert report["pulled_facts"] == report["pushed_facts"] == 1
    assert a.state.entries() == b.state.entries()
    assert any(key.startswith("peerlog/run/") for key in b.put_calls)


def test_simultaneous_dials_collapse_to_single_driver():
    """Both peers dial at once: exactly one session survives and the
    lower endpoint id drives it; no duplicate transfer."""
    left_log, right_log = WriterLog.owned(), WriterLog.owned()
    left_log.append(Fact("msg", 1, (), b"left"))
    right_log.append(Fact("msg", 2, (), b"right"))
    left_state, right_state = PeerState(), PeerState()
    left_state.add_owned(left_log)
    right_state.add_owned(right_log)
    left = PeerEndpoint(left_state, endpoint_id=b"a")
    right = PeerEndpoint(right_state, endpoint_id=b"b")
    coordinator = SessionCoordinator(collision_window=0.1)
    barrier = threading.Barrier(2)
    reports, errors = [], []

    def dial(a, b):
        try:
            barrier.wait()
            reports.append(coordinator.dial(a, b))
        except Exception as error:
            errors.append(error)

    threads = [
        threading.Thread(target=dial, args=(left, right)),
        threading.Thread(target=dial, args=(right, left)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
    assert not errors
    assert len(reports) == 2
    assert all(report["collapsed"] and report["driver"] == b"a" for report in reports)
    assert left.state.entries() == right.state.entries()
    assert sum(report["pulled_facts"] for report in reports) == 2


def test_three_peer_mesh_forwards_original_writer_proofs_to_convergence():
    peers = []
    expected = set()
    for player in range(3):
        log = WriterLog.owned()
        for seq in range(24):
            fact = Fact("msg", player * 1000 + seq, (),
                        f"player:{player}:{seq}".encode())
            log.append(fact)
            expected.add((fact.ts, fid(fact)))
        state = PeerState()
        state.add_owned(log)
        peers.append(PeerEndpoint(state, endpoint_id=bytes([player])))

    reports = mesh_sync(peers)
    assert len(reports) == 3
    assert all(set(peer.state.entries()) == expected for peer in peers)
    # The last edge transfers third-party writer facts authenticated by their
    # original heads; the forwarding peer never re-signs them.
    assert any(report["pushed_facts"] + report["pulled_facts"] >= 24
               for report in reports)


def test_peer_serves_passive_interface_identically():
    """A client's seq-diff recipe run against a peer's Store returns
    byte-identical results to the same recipe against the cloud store."""
    from peerlog.cloud import CloudQueue, MemoryCloud
    from peerlog.endpoint import run_key

    workspace = hashlib.sha256(b"passive workspace").digest()
    log = WriterLog.owned()
    for seq in range(12):
        log.append(Fact("msg", seq + 1, (), f"passive:{seq}".encode()))

    state = PeerState()
    state.add_owned(log)
    peer = PeerEndpoint(state)
    cloud = CloudQueue(MemoryCloud(), workspace)
    cloud.publish(log, 0, 12)

    peer_bytes = peer.get(run_key(log.writer, 0, 12))
    cloud_bytes = cloud.read_run(log.writer, 0, 12)
    assert peer_bytes == cloud_bytes

    from_peer, from_cloud = PeerState(), PeerState()
    ingest(from_peer, decode_run(peer_bytes))
    ingest(from_cloud, decode_run(cloud_bytes))
    assert from_peer.entries() == from_cloud.entries() == state.entries()
