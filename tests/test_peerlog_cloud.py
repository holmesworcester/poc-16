"""Phase-2 queue tests using the production peerlog codecs and ingest path."""
import hashlib
import threading
import time

import pytest
from nacl import signing

import peerlog.cloud as cloud_module
from adapters.s3 import S3Config, S3Store
from peerlog.cloud import (
    CLOUD_DIRECTORY_AUDIT_MAX_AGE_S,
    CLOUD_DIRECTORY_IDLE_DEBOUNCE_S,
    CLOUD_DIRECTORY_MAX_DELAY_S,
    CLOUD_DEMAND_MAX_INTERVALS,
    CLOUD_DEMAND_MAX_INTERVALS_PER_WRITER,
    CLOUD_DEMAND_MAX_WRITERS,
    MICRO_TAIL,
    MULTIPART_EDGE,
    CloudCache,
    CloudClosureLimits,
    CloudDemand,
    CloudMicroFork,
    CloudQueue,
    DirectoryRepairContention,
    DirectoryRepairResult,
    MaintenanceRequired,
    MemoryCloud,
    WriterDemand,
)
from peerlog.cloud import (
    Publication, Segment, Slot, _encode_segment, _micro_key, encode_slot,
)
from peerlog.cloud_s3 import S3Cloud
from peerlog.endpoint import PeerEndpoint, run_key
from peerlog.fact import Fact, Ref, fid
from peerlog.ingest import PeerState
from peerlog.ingest import ingest
from peerlog.log import WriterLog
from peerlog.log import encode_head
from peerlog.proof import carry, prove_run
from peerlog.session import mesh_sync
from tests.provider_fakes import FakeS3Bucket


def h(label):
    return hashlib.sha256(label.encode()).digest()


def owned(label, count, *, body_size=0):
    log = WriterLog.owned()
    for seq in range(count):
        body = (f"{label}:{seq}".encode() if not body_size
                else bytes([seq % 251]) * body_size)
        log.append(Fact("msg", 1_000 + seq, (), body))
    return log


def entries(log):
    return {(log.fact(seq).ts, fid(log.fact(seq))) for seq in log._facts}


def dependency_chain_cloud(label="dependency closure"):
    """A recent A fact reaches old B and C facts amid unrelated history."""
    store = MemoryCloud()
    cloud = CloudQueue(store, h(label))
    a, b, c = WriterLog.owned(), WriterLog.owned(), WriterLog.owned()
    for seq in range(5):
        c.append(Fact("msg", 100 + seq, (), f"c-old:{seq}".encode()))
    for seq in range(5):
        refs = (Ref(c.writer, 1),) if seq == 2 else ()
        b.append(Fact("msg", 200 + seq, refs, f"b-old:{seq}".encode()))
    for seq in range(5):
        a.append(Fact("msg", 300 + seq, (), f"a-old:{seq}".encode()))
    a.append(Fact("msg", 1_000, (Ref(b.writer, 2),), b"recent A"))
    holdings = PeerState()
    for log in (a, b, c):
        holdings.add_owned(log)
    receipts = {
        "c": cloud.publish(c, 0, 5, holdings=holdings),
        "b": cloud.publish(b, 0, 5, holdings=holdings),
        "a_old": cloud.publish(
            a, 0, 5, holdings=holdings),
        "a_recent": cloud.publish(
            a, 5, 6, holdings=holdings),
    }
    cloud.repair_directory()
    return store, cloud, a, b, c, receipts


def same_writer_chain_cloud(label="same writer dependency closure"):
    """Recent seq 5 reaches separately segmented old seqs 2 then 0."""
    store = MemoryCloud()
    cloud = CloudQueue(store, h(label))
    log = WriterLog.owned()
    log.append(Fact("msg", 100, (), b"old C"))
    log.append(Fact("msg", 101, (), b"unrelated one"))
    log.append(Fact("msg", 102, (Ref(log.writer, 0),), b"old B"))
    log.append(Fact("msg", 103, (), b"unrelated three"))
    log.append(Fact("msg", 104, (), b"unrelated four"))
    log.append(Fact("msg", 1_000, (Ref(log.writer, 2),), b"recent A"))
    receipts = {
        "c": cloud.publish(log, 0, 1),
        "unrelated_one": cloud.publish(log, 1, 2),
        "b": cloud.publish(log, 2, 3),
        "unrelated_late": cloud.publish(log, 3, 5),
        "a": cloud.publish(log, 5, 6),
    }
    cloud.repair_directory()
    return store, cloud, log, receipts


def assert_ref_closed(state, ref, seen=None):
    seen = set() if seen is None else seen
    if ref in seen:
        return
    seen.add(ref)
    fact = state.logs[ref.writer].fact(ref.seq)
    for dependency in fact.refs:
        assert_ref_closed(state, dependency, seen)


def test_cloud_uses_exact_peer_runs_and_one_round_no_change():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("workspace"))
    log = owned("alice", 8)
    cloud.publish(log, 0, 8)

    peer = PeerEndpoint(PeerState())
    peer.state.add_owned(log)
    peer.refresh()
    # The passive sequence recipe receives the identical authenticated bytes
    # whether its source is a live peer or the object queue.
    assert cloud.read_run(log.writer, 0, 8) == peer.get(
        run_key(log.writer, 0, 8))

    replica, cache = PeerState(), CloudCache()
    cold = cloud.sync(replica, cache)
    assert cold.changed and cold.rounds - cold.directory_audit_rounds == 1 \
        and cold.facts == 8
    assert set(replica.entries()) == entries(log)

    before = store.metrics.copy()
    noop = cloud.sync(replica, cache)
    delta = store.metrics.delta(before)
    assert not noop.changed and noop.rounds == 1
    assert delta.gets == delta.conditional_gets == 1
    assert delta.downloaded_bytes == 0


def test_publish_defaults_to_owner_only_and_poll_repairs_a_missing_directory():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("owner only publish default"))
    log = owned("quiet writer", 3)
    before = store.metrics.copy()
    cloud.publish(log)
    publish_cost = store.metrics.delta(before)
    assert publish_cost.cas == 1
    assert store.get(cloud.directory_key)[0] is None

    before = store.metrics.copy()
    slots, tag = cloud.poll()
    repair_cost = store.metrics.delta(before)
    assert tag and slots[log.writer].hi == 3
    assert repair_cost.lists == 1 and repair_cost.cas == 1

    before = store.metrics.copy()
    unchanged, same_tag = cloud.poll(tag)
    noop_cost = store.metrics.delta(before)
    assert unchanged is None and same_tag == tag
    assert noop_cost.gets == noop_cost.conditional_gets == 1
    assert noop_cost.lists == noop_cost.cas == 0


def test_owner_mutations_ack_before_any_directory_repair_can_fail(monkeypatch):
    class CrashBeforeSlotCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.crash = True

        def cas(self, key, token, value):
            if self.crash and "/slots/" in key:
                self.crash = False
                raise OSError("crash before writer-slot CAS")
            return super().cas(key, token, value)

    store = CrashBeforeSlotCloud()
    cloud = CloudQueue(store, h("owner ack before repair"))
    orphan = owned("orphan ack", 1)
    with pytest.raises(OSError, match="before writer-slot"):
        cloud.publish(orphan)

    def forbidden():
        raise AssertionError("owner mutation called directory repair")

    monkeypatch.setattr(cloud, "repair_directory", forbidden)
    readmitted = cloud.readmit_orphan(orphan.writer, 0, 1)
    assert (readmitted.segment.lo, readmitted.segment.hi) == (0, 1)

    ordinary = owned("ordinary ack", 2)
    published = cloud.publish(ordinary, 0, 1)
    assert (published.segment.lo, published.segment.hi) == (0, 1)
    cloud.publish(ordinary, 1, 2)
    folded = cloud.fold_idle(ordinary.writer)
    assert folded.hi == 2


def test_directory_maintenance_coalesces_bursts_and_honors_max_delay():
    now = [0.0]
    store = MemoryCloud()
    cloud = CloudQueue(
        store, h("coalesced directory maintenance"), clock=lambda: now[0])
    log = WriterLog.owned()
    for seq in range(10):
        now[0] = seq * (CLOUD_DIRECTORY_IDLE_DEBOUNCE_S / 2)
        log.append(Fact("msg", seq + 1, (), f"burst-{seq}".encode()))
        cloud.publish(log, seq, seq + 1)
        assert cloud.maintain_directory(idle=True) is None

    before = store.metrics.copy()
    now[0] += CLOUD_DIRECTORY_IDLE_DEBOUNCE_S
    result = cloud.maintain_directory(idle=True)
    delta = store.metrics.delta(before)
    assert isinstance(result, DirectoryRepairResult)
    assert result.changed and result.slots == 1
    assert delta.lists == 1 and delta.cas == 1
    assert cloud.maintain_directory(idle=True) is None

    other = WriterLog.owned()
    first = now[0]
    for seq in range(10):
        now[0] = first + seq * (CLOUD_DIRECTORY_IDLE_DEBOUNCE_S / 2)
        other.append(Fact("msg", 100 + seq, (), f"busy-{seq}".encode()))
        cloud.publish(other, seq, seq + 1)
        assert cloud.maintain_directory(idle=False) is None
    now[0] = first + CLOUD_DIRECTORY_MAX_DELAY_S
    assert cloud.maintain_directory(idle=False).slots == 2


def test_explicit_directory_repair_has_typed_contention_and_later_converges():
    class ContendedDirectory(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.contended = True

        def cas(self, key, token, value):
            if self.contended and key.endswith("/directory"):
                self.metrics.cas += 1
                return False
            return super().cas(key, token, value)

    store = ContendedDirectory()
    cloud = CloudQueue(store, h("typed directory repair"))
    log = owned("durable while directory contends", 3)
    receipt = cloud.publish(log)
    assert receipt.segment.hi == 3
    with pytest.raises(DirectoryRepairContention) as found:
        cloud.repair_directory()
    assert found.value.attempts == cloud_module.CLOUD_DIRECTORY_REPAIR_ATTEMPTS
    assert cloud._slot_versioned(log.writer)[0].hi == 3

    store.contended = False
    repaired = cloud.repair_directory()
    assert repaired.changed and repaired.slots == 1
    assert cloud.visible_heads() == {log.writer: 3}


def test_cold_and_max_age_audits_discover_writers_omitted_by_stale_hint():
    class RegressOneAuditRead(MemoryCloud):
        stale = None

        def get(self, key, *, if_none_match=None, suffix=None):
            if self.stale is not None and key.endswith("/directory"):
                with self._lock:
                    self._objects[key] = self.stale
                    self._versions[key] = self._versions.get(key, 0) + 1
                    self.stale = None
            return super().get(
                key, if_none_match=if_none_match, suffix=suffix)

    now = [0.0]
    store = RegressOneAuditRead()
    workspace = h("reader directory audits")
    writer = CloudQueue(store, workspace, clock=lambda: now[0])
    first, omitted, later = (
        owned("first visible", 2), owned("cold omitted", 3),
        owned("warm omitted", 4),
    )
    writer.publish(first)
    writer.repair_directory()
    stale, _tag = store.get(writer.directory_key)
    writer.publish(omitted)
    assert set(writer.visible_heads()) == {first.writer}
    store.stale = stale

    reader = CloudQueue(store, workspace, clock=lambda: now[0])
    state, cache = PeerState(), CloudCache()
    cold = reader.sync(state, cache)
    assert cold.facts == 5
    assert cold.directory_audit_rounds > 6
    assert set(state.logs) == {first.writer, omitted.writer}

    writer.publish(later)
    now[0] = CLOUD_DIRECTORY_AUDIT_MAX_AGE_S - 0.001
    before = store.metrics.copy()
    unchanged = reader.sync(state, cache)
    delta = store.metrics.delta(before)
    assert not unchanged.changed and later.writer not in state.logs
    assert delta.gets == delta.conditional_gets == 1
    assert delta.lists == delta.cas == 0

    now[0] = CLOUD_DIRECTORY_AUDIT_MAX_AGE_S
    warm = reader.sync(state, cache)
    assert warm.changed and warm.facts == 4
    assert set(state.logs) == {first.writer, omitted.writer, later.writer}


def test_warm_delta_is_directory_plus_parallel_object_round():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("warm"))
    log = owned("writer", 4)
    cloud.publish(log)
    state, cache = PeerState(), CloudCache()
    cloud.sync(state, cache)

    for seq in range(4, 7):
        log.append(Fact("msg", 1_000 + seq, (), f"writer:{seq}".encode()))
    cloud.publish(log, 4, 7)
    cloud.repair_directory()
    report = cloud.sync(state, cache)
    assert report.changed and report.rounds == 2
    assert report.object_gets == 1 and report.facts == 3
    assert set(state.entries()) == entries(log)


def test_timestamp_window_uses_directory_footer_and_body_waves():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("time window"))
    log = WriterLog.owned()
    for seq, timestamp in enumerate((1_000, 50_000, 90_000)):
        log.append(Fact("msg", timestamp, (), f"at:{timestamp}".encode()))
        cloud.publish(log, seq, seq + 1)

    state = PeerState()
    report = cloud.sync(state, ts_window=(49_000, 51_000))
    assert report.rounds - report.directory_audit_rounds == 2 \
        and report.object_gets == 4
    assert report.facts == 1
    assert set(state.logs[log.writer]._facts) == {1}


def test_per_writer_tail_clamps_across_hot_medium_and_1000_long_tail_writers():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("skewed writer tails"))
    logs = [owned("hot", 2_000)]
    logs.extend(owned(f"medium-{ordinal}", 40 + ordinal)
                for ordinal in range(5))
    # A quarter are empty/absent; the rest exercise one, two, and three facts.
    logs.extend(owned(f"quiet-{ordinal}", ordinal % 4)
                for ordinal in range(1_000))
    for log in logs:
        count = len(log)
        if not count:
            continue
        split = max(0, count - 2)
        if split:
            cloud.publish(log, 0, split)
        cloud.publish(log, split, count)
    cloud.repair_directory()

    demand = CloudDemand.tails((log.writer for log in logs), 2)
    state, cache = PeerState(), CloudCache()
    report = cloud.sync(state, cache, demand=demand)
    expected = sum(min(2, len(log)) for log in logs)
    nonempty = sum(bool(len(log)) for log in logs)
    assert report.interactive_ready and not report.pending
    assert report.initial_facts == report.facts == expected
    assert report.initial_segment_gets == nonempty
    assert report.closure_segment_gets == 0
    for log in logs:
        if not len(log):
            assert log.writer not in state.logs
            continue
        assert set(state.logs[log.writer]._facts) == set(
            range(max(0, len(log) - 2), len(log)))

    # The retired scalar range derived from the hot writer misses every quiet
    # writer; the per-writer tail above resolves independently at each slot.
    legacy_lo = len(logs[0]) - 2
    slots, _tag = cloud.poll()
    legacy_writers = {
        writer for writer, slot in slots.items()
        if any(segment.lo < len(logs[0]) and legacy_lo < segment.hi
               for segment in slot.segments)
    }
    assert legacy_writers == {logs[0].writer}
    with pytest.raises(TypeError, match="unexpected keyword"):
        cloud.sync(PeerState(), seq_window=(legacy_lo, len(logs[0])))

    before = store.metrics.copy()
    noop = cloud.sync(state, cache, demand=demand)
    delta = store.metrics.delta(before)
    assert not noop.changed and noop.rounds == 1
    assert delta.gets == delta.conditional_gets == 1
    logs[0].append(Fact("msg", 9_000_000, (), b"one hot-writer delta"))
    cloud.publish(logs[0], 2_000, 2_001)
    cloud.repair_directory()
    warm = cloud.sync(state, cache, demand=demand)
    assert warm.initial_segment_gets == warm.object_gets == warm.facts == 1
    assert warm.closure_segment_gets == 0 and warm.rounds == 2


def test_exact_writer_intervals_normalize_and_subtract_coverage_islands():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("exact demand coverage"))
    log = owned("interval writer", 12)
    receipts = [
        cloud.publish(log, 0, 4),
        cloud.publish(log, 4, 8),
        cloud.publish(log, 8, 12),
    ]
    cloud.repair_directory()
    state = PeerState()
    ingest(state, prove_run(log, 0, 4))
    demand = CloudDemand.exact({
        log.writer: ((8, 10), (2, 6), (1, 3), (2, 6)),
        h("absent exact writer"): ((0, 10),),
    })
    by_writer = {item.writer: item for item in demand.writers}
    assert by_writer[log.writer].intervals == ((1, 6), (8, 10))
    assert by_writer[h("absent exact writer")].intervals == ((0, 10),)

    before = store.metrics.copy()
    report = cloud.sync(state, demand=demand)
    delta = store.metrics.delta(before)
    assert report.interactive_ready
    assert report.initial_segment_gets == 2
    assert report.initial_bytes == receipts[1].segment.size \
        + receipts[2].segment.size
    assert report.directory_audit_gets == 3
    assert report.object_gets == delta.gets \
        - report.directory_audit_gets == 2
    assert set(state.logs[log.writer]._facts) == set(range(12))

    cache = CloudCache()
    first = cloud.sync(state, cache, demand=demand)
    second = cloud.sync(state, cache, demand=demand)
    assert first.initial_segment_gets == 0
    assert not second.changed and second.object_gets == 0
    assert second.rounds == 1


def test_cloud_demand_rejects_malformed_and_oversized_shapes():
    writer = h("demand writer")
    with pytest.raises(ValueError, match="writer demand"):
        WriterDemand(b"short", tail=1)
    with pytest.raises(ValueError, match="writer demand"):
        WriterDemand(writer, tail=-1)
    with pytest.raises(ValueError, match="mode"):
        WriterDemand(writer, tail=1, intervals=((0, 1),))
    for intervals in (((0, 0),), ((-1, 1),), ([0, 1],)):
        with pytest.raises(ValueError, match="interval"):
            WriterDemand(writer, intervals=intervals)
    with pytest.raises(ValueError, match="writer demand"):
        WriterDemand(writer, intervals=tuple(
            (ordinal, ordinal + 1)
            for ordinal in range(CLOUD_DEMAND_MAX_INTERVALS_PER_WRITER + 1)))
    with pytest.raises(ValueError, match="map"):
        CloudDemand.exact(())
    with pytest.raises(ValueError, match="map"):
        CloudDemand.exact({writer: None})
    one = WriterDemand(writer, tail=1)
    with pytest.raises(ValueError, match="cloud demand"):
        CloudDemand((one, one))
    with pytest.raises(ValueError, match="cloud demand"):
        CloudDemand(tuple(
            WriterDemand(ordinal.to_bytes(32, "big"), tail=1)
            for ordinal in range(CLOUD_DEMAND_MAX_WRITERS + 1)))
    interval_writers = CLOUD_DEMAND_MAX_INTERVALS \
        // CLOUD_DEMAND_MAX_INTERVALS_PER_WRITER + 1
    with pytest.raises(ValueError, match="cloud demand"):
        CloudDemand(tuple(
            WriterDemand(
                (ordinal + 1).to_bytes(32, "big"),
                intervals=tuple((2 * seq, 2 * seq + 1)
                                for seq in range(
                                    CLOUD_DEMAND_MAX_INTERVALS_PER_WRITER)))
            for ordinal in range(interval_writers)))

    empty = CloudDemand(())
    store = MemoryCloud()
    cloud = CloudQueue(store, h("empty demand"))
    cloud.publish(owned("unrequested", 2))
    report = cloud.sync(PeerState(), demand=empty)
    assert report.interactive_ready and report.object_gets == report.facts == 0


def test_three_players_reach_cloud_and_peer_mesh_convergence():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("three players"))
    endpoints = []
    expected = set()
    for player in range(3):
        log = owned(f"player-{player}", 18)
        cloud.publish(log)
        state = PeerState()
        state.add_owned(log)
        endpoints.append(PeerEndpoint(state, endpoint_id=bytes([player])))
        expected.update(entries(log))

    # A cold fourth client verifies the cloud's original-writer proofs.
    cold = PeerState()
    report = cloud.sync(cold)
    assert report.rounds - report.directory_audit_rounds == 1 \
        and report.facts == 54
    assert set(cold.entries()) == expected

    # The same three original writers converge over the one-driver P2P path.
    mesh_sync(endpoints)
    assert all(set(endpoint.state.entries()) == expected for endpoint in endpoints)


def test_rule2_carry_is_adjacent_and_resolves_before_citing_ingest():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("rule two"))
    target = owned("target", 1)
    citing = WriterLog.owned()
    citing.append(Fact(
        "member", 2_000, (Ref(target.writer, 0),), b"needs target"))

    with pytest.raises(ValueError, match="Rule-2"):
        cloud.publish(citing)
    cloud.publish(citing, carries=(carry(target, 0),))

    state = PeerState()
    report = cloud.sync(state)
    assert report.carries == 1 and report.facts == 1 and not report.pending
    assert state.logs[target.writer].fact(0) == target.fact(0)
    assert state.logs[citing.writer].fact(0) == citing.fact(0)


def test_folded_segment_inherits_deterministic_cross_writer_annex():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("folded cross writer annex"))
    target = owned("annex targets", 4, body_size=128)
    citing = WriterLog.owned()
    for seq in range(MICRO_TAIL):
        refs = ()
        if seq % 8 == 0:
            refs = (Ref(target.writer, seq // 8),)
        elif seq == MICRO_TAIL - 1:
            refs = (Ref(citing.writer, 0),)  # same-writer backfill stays a cite
        citing.append(Fact("msg", 10_000 + seq, refs, b"m" * 128))
    holdings = PeerState()
    holdings.add_owned(target)
    holdings.add_owned(citing)
    with pytest.raises(ValueError, match="adjacent annex"):
        cloud.publish(citing, 0, 1)
    for seq in range(MICRO_TAIL):
        cloud.publish(
            citing, seq, seq + 1, holdings=holdings)
    folded = cloud.fold_idle(citing.writer)
    assert len(folded.segments) == 1
    segment = folded.segments[0]
    publications = cloud._read_segment(segment)
    annex = tuple(run for publication in publications
                  for run in publication.carries)
    assert {(run.writer, run.lo) for run in annex} == {
        (target.writer, seq) for seq in range(4)}
    baseline = _encode_segment(tuple(
        Publication(publication.main, ())
        for publication in publications), "ladder")
    annex_ratio = segment.size / len(baseline)
    assert 1.05 < annex_ratio < 1.30

    state = PeerState()
    report = cloud.sync(state, demand=CloudDemand.exact({
        citing.writer: ((24, 32),),
    }))
    assert report.interactive_ready and not report.pending
    assert report.closure_segment_gets == report.closure_facts == 0
    assert report.carries == 4
    assert_ref_closed(state, Ref(citing.writer, 24))


def test_applied_annex_publish_retries_without_rebuilding_local_holdings():
    class LostResponseCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.lose = True

        def cas(self, key, token, value):
            result = super().cas(key, token, value)
            if self.lose and result and "/slots/" in key:
                self.lose = False
                raise OSError("annex slot response lost")
            return result

    store = LostResponseCloud()
    cloud = CloudQueue(store, h("annex lost response"))
    target = owned("annex retry target", 1)
    citing = WriterLog.owned()
    citing.append(Fact(
        "msg", 10, (Ref(target.writer, 0),), b"annex retry"))
    holdings = PeerState()
    holdings.add_owned(target)
    holdings.add_owned(citing)
    with pytest.raises(OSError, match="response lost"):
        cloud.publish(citing, holdings=holdings)
    receipt = cloud.publish(citing)  # incumbent annex is self-authenticating
    assert (receipt.segment.lo, receipt.segment.hi) == (0, 1)


def test_recent_window_carries_minimal_transitive_out_of_range_annex():
    store, cloud, a, b, c, receipts = dependency_chain_cloud()
    expected_bodies = receipts["a_recent"].segment.size
    state = PeerState()
    before = store.metrics.copy()
    report = cloud.sync(state, demand=CloudDemand.exact({
        a.writer: ((5, 6),),
    }))
    delta = store.metrics.delta(before)

    assert report.interactive_ready and not report.pending
    assert report.initial_segment_gets == 1
    assert report.closure_segment_gets == 0
    assert report.directory_audit_gets == 5
    assert report.object_gets == delta.gets \
        - report.directory_audit_gets == 1
    assert report.rounds - report.directory_audit_rounds == 1
    assert report.initial_bytes == receipts["a_recent"].segment.size
    assert report.closure_bytes == 0
    assert report.received_bytes - report.directory_audit_bytes \
        == expected_bodies
    assert report.initial_facts == 1
    assert report.closure_facts == 0
    assert report.facts == 1 and report.carries == 2
    assert report.segment_overfetch_facts == 0
    assert report.closure_depth == 2
    assert set(state.logs[a.writer]._facts) == {5}
    assert set(state.logs[b.writer]._facts) == {2}
    assert set(state.logs[c.writer]._facts) == {1}
    assert_ref_closed(state, Ref(a.writer, 5))


def test_dependency_closure_deduplicates_refs_cycles_and_local_targets():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("closure cycle"))
    a, b, c = WriterLog.owned(), WriterLog.owned(), WriterLog.owned()
    c.append(Fact("msg", 10, (Ref(b.writer, 0),), b"cycle back"))
    b.append(Fact(
        "msg", 20, (Ref(c.writer, 0), Ref(c.writer, 0)), b"duplicate"))
    a.append(Fact("msg", 25, (), b"unrelated old A"))
    a.append(Fact(
        "msg", 30, (Ref(b.writer, 0), Ref(b.writer, 0)), b"recent"))
    holdings = PeerState()
    for log in (a, b, c):
        holdings.add_owned(log)
    cloud.publish(b, holdings=holdings)
    cloud.publish(c, holdings=holdings)
    cloud.publish(a, 0, 1, holdings=holdings)
    cloud.publish(a, 1, 2, holdings=holdings)
    cloud.repair_directory()
    state = PeerState()
    state.add_owned(c)

    report = cloud.sync(state, demand=CloudDemand.exact({
        a.writer: ((1, 2),),
    }))
    assert report.interactive_ready and not report.pending
    assert report.initial_segment_gets == 1
    assert report.closure_segment_gets == report.closure_facts == 0
    assert report.carries == 2
    assert report.closure_depth == 2
    assert set(state.logs[a.writer]._facts) == {1}
    assert set(state.logs[b.writer]._facts) == {0}
    assert_ref_closed(state, Ref(a.writer, 1))


def test_cloud_closes_a_requested_citer_already_held_from_p2p():
    _store, cloud, a, b, c, _receipts = dependency_chain_cloud(
        "held p2p citing root")
    state = PeerState()
    ingest(state, prove_run(a, 5, 6))
    report = cloud.sync(state, demand=CloudDemand.exact({
        a.writer: ((5, 6),),
    }))
    assert report.interactive_ready and not report.pending
    assert report.initial_segment_gets == report.initial_facts == 0
    assert report.closure_segment_gets == report.closure_facts == 1
    assert report.carries == 1
    assert report.closure_depth == 2
    assert state.logs[b.writer].fact(2) == b.fact(2)
    assert state.logs[c.writer].fact(1) == c.fact(1)


def test_cloud_cache_cannot_hide_downloads_when_reused_with_an_empty_state():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("cache state binding"))
    log = owned("cache writer", 2)
    cloud.publish(log)
    cache = CloudCache()
    first = PeerState()
    assert cloud.sync(first, cache).facts == 2
    second = PeerState()
    report = cloud.sync(second, cache)
    assert report.changed and report.facts == 2
    assert set(second.entries()) == entries(log)


@pytest.mark.parametrize("limits", [
    CloudClosureLimits(max_depth=1),
    CloudClosureLimits(max_refs=1),
    CloudClosureLimits(max_segments=1),
    CloudClosureLimits(max_bytes=1),
])
def test_dependency_closure_bounds_fail_closed(limits):
    _store, cloud, log, _receipts = same_writer_chain_cloud(
        f"closure bound {limits}")
    state = PeerState()
    report = cloud.sync(
        state,
        demand=CloudDemand.exact({log.writer: ((5, 6),)}),
        closure_limits=limits)
    assert report.closure_exhausted
    assert not report.interactive_ready
    assert report.pending
    assert state.logs[log.writer].fact(5) == log.fact(5)
    assert any(ref in report.pending for ref in (
        Ref(log.writer, 2), Ref(log.writer, 0)))


def test_depth_exhaustion_keeps_a_resident_annex_target_pending():
    _store, cloud, a, _b, c, _receipts = dependency_chain_cloud(
        "resident annex depth bound")
    report = cloud.sync(
        PeerState(),
        demand=CloudDemand.exact({a.writer: ((5, 6),)}),
        closure_limits=CloudClosureLimits(max_depth=1),
    )
    assert report.closure_exhausted and not report.interactive_ready
    assert report.pending == (Ref(c.writer, 1),)


def test_missing_dependency_stays_pending_and_never_becomes_interactive():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("missing dependency"))
    log = WriterLog.owned()
    missing = Ref(log.writer, 17)
    log.append(Fact("msg", 1, (missing,), b"cannot render"))
    cloud.publish(log)
    state, cache = PeerState(), CloudCache()
    report = cloud.sync(state, cache)
    assert report.pending == (missing,)
    assert not report.closure_exhausted
    assert not report.interactive_ready
    unchanged = cloud.sync(state, cache)
    assert unchanged.pending == (missing,)
    assert not unchanged.interactive_ready


def test_target_published_after_citer_closes_on_the_next_window_sync():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("target after citer"))
    log = WriterLog.owned()
    log.append(Fact("msg", 1, (), b"old citing history"))
    log.append(Fact(
        "msg", 2, (Ref(log.writer, 2),), b"recent citing fact"))
    cloud.publish(log, 0, 1)
    cloud.publish(log, 1, 2)
    cloud.repair_directory()
    state, cache = PeerState(), CloudCache()

    demand = CloudDemand.exact({log.writer: ((1, 2),)})
    first = cloud.sync(state, cache, demand=demand)
    assert first.pending == (Ref(log.writer, 2),)
    assert not first.interactive_ready

    log.append(Fact("msg", 3, (), b"late cloud target"))
    cloud.publish(log, 2, 3)
    cloud.repair_directory()
    second = cloud.sync(state, cache, demand=demand)
    assert second.interactive_ready and not second.pending
    assert second.initial_segment_gets == 0
    assert second.closure_segment_gets == second.closure_facts == 1
    assert state.logs[log.writer].fact(2) == log.fact(2)


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_missing_or_corrupt_dependency_object_fails_without_ready_result(damage):
    store, cloud, log, receipts = same_writer_chain_cloud(
        f"dependency object {damage}")
    key = receipts["b"].segment.key
    if damage == "missing":
        del store._objects[key]
    else:
        store._objects[key] = store._objects[key][:-1] + b"!"
    state = PeerState()
    with pytest.raises(ValueError, match="cloud segment"):
        cloud.sync(state, demand=CloudDemand.exact({
            log.writer: ((5, 6),),
        }))


@pytest.mark.parametrize("family", ["member", "msg"])
def test_consumer_rejects_writer_that_bypasses_annex_check(family):
    store = MemoryCloud()
    cloud = CloudQueue(store, h("hostile rule two"))
    target = owned("unpublished target", 1)
    citing = WriterLog.owned()
    citing.append(Fact(
        family, 2_000, (Ref(target.writer, 0),), b"missing carry"))
    run = prove_run(citing, 0, 1)
    raw = _encode_segment((Publication(run),), "micro")
    key = _micro_key(cloud.workspace, citing.writer, 0, 1)
    store.create(key, raw)
    slot = Slot(
        cloud.workspace, citing.writer, encode_head(citing.head()),
        (Segment(key, 0, 1, len(raw), 1, "micro"),),
    )
    assert store.cas(cloud._slot_key(citing.writer), None, encode_slot(slot))
    cloud.repair_directory()

    state = PeerState()
    with pytest.raises(ValueError, match="Rule-2"):
        cloud.sync(state)
    assert not state.logs


def test_handoff_facts_cannot_enter_cloud_without_ordinary_closed_carry():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("handoff"))
    authority = owned("authority", 1)
    inviter = WriterLog.owned()
    inviter.append(Fact(
        "invite", 3_000, (Ref(authority.writer, 0),), b"sealed invitation"))

    with pytest.raises(ValueError, match="Rule-2"):
        cloud.publish(inviter)
    # Nothing is written for a failed publication, and the store has no
    # recipient-addressed retrieval primitive. Once the complete ordinary
    # Rule-2 carry is available, the homed fact publishes like any control.
    assert store._objects == {}
    receipt = cloud.publish(inviter, carries=(carry(authority, 0),))
    assert receipt.segment.kind == "micro"
    assert all("handoff" not in key and "recipient" not in key
               for key in store._objects)


def test_micro_tail_folds_to_binary_ladder_and_footer_is_suffix_readable():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("ladder"))
    log = WriterLog.owned()
    for seq in range(MICRO_TAIL):
        log.append(Fact("msg", seq + 1, (), f"event:{seq}".encode()))
        cloud.publish(log, seq, seq + 1)

    slot, _token = cloud._slot_versioned(log.writer)
    assert sum(segment.kind == "micro" for segment in slot.segments) == MICRO_TAIL
    log.append(Fact("msg", MICRO_TAIL + 1, (), b"requires idle fold"))
    with pytest.raises(MaintenanceRequired):
        cloud.publish(log, MICRO_TAIL, MICRO_TAIL + 1)
    assert cloud.visible_heads() == {}
    slot = cloud.fold_idle(log.writer)
    assert sum(segment.kind == "micro" for segment in slot.segments) == 0
    assert len(slot.segments) < MICRO_TAIL
    assert all(segment.size < MULTIPART_EDGE for segment in slot.segments)
    cloud.repair_directory()
    assert cloud.visible_heads()[log.writer] == MICRO_TAIL
    footers = [cloud.footer(segment) for segment in slot.segments]
    assert footers[0]["lo"] == 0 and footers[-1]["hi"] == MICRO_TAIL


def test_each_chat_publish_upload_is_suffix_bounded_not_log_sized():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("publish bound"))
    log = WriterLog.owned()
    uploads = []
    for seq in range(128):
        if seq and seq % MICRO_TAIL == 0:
            cloud.fold_idle(log.writer)
        log.append(Fact("msg", seq + 1, (), b"x" * 90))
        before = store.metrics.copy()
        cloud.publish(log, seq, seq + 1)
        uploads.append(store.metrics.delta(before).object_upload_bytes)
    assert max(uploads) < 8 * 1024
    assert uploads[-1] < uploads[0] + 512


def test_multipart_exact_five_mib_edge_is_invisible_until_complete():
    store = MemoryCloud()
    source = b"a" * MULTIPART_EDGE
    store.create("source", source)
    upload = store.begin_multipart("destination")
    store.copy_part(upload, "source", MULTIPART_EDGE)
    store.upload_part(upload, b"tail")
    assert store.get("destination")[0] is None
    assert store.complete_multipart(upload) == source + b"tail"
    assert store.get("destination")[0] == source + b"tail"
    assert store.metrics.copied_bytes == MULTIPART_EDGE


def test_s3_compatible_adapter_runs_cloud_recipe_and_exact_part_copy():
    bucket = FakeS3Bucket(page_size=2)
    configured = S3Store(
        S3Config(bucket="peerlog-cloud", prefix="queue-test"),
        client=bucket.client("queue"),
    )
    provider = S3Cloud(configured)
    cloud = CloudQueue(provider, h("s3 compatible"))
    log = owned("provider writer", 6)
    cloud.publish(log)
    replica = PeerState()
    assert cloud.sync(replica).facts == 6
    assert set(replica.entries()) == entries(log)

    source = b"x" * MULTIPART_EDGE + b"guarded source suffix"
    provider.create("multipart/source", source)
    upload = provider.begin_multipart("multipart/destination")
    provider.copy_part(upload, "multipart/source", MULTIPART_EDGE)
    provider.upload_part(upload, b"tail")
    assert [item["PartNumber"]
            for item in provider._uploads[upload].parts] == [1, 2]
    assert provider.get("multipart/destination")[0] is None
    provider.complete_multipart(upload)
    assert provider.get("multipart/destination")[0] \
        == b"x" * MULTIPART_EDGE + b"tail"
    assert provider.get("multipart/source")[0] == source

    aborted = provider.begin_multipart("multipart/aborted")
    provider.copy_part(aborted, "multipart/source", MULTIPART_EDGE)
    assert provider.get("multipart/aborted")[0] is None
    provider.abort_multipart(aborted)
    assert provider.get("multipart/aborted")[0] is None
    assert any(item[1] == "part-copy" and item[3] == MULTIPART_EDGE
               for item in bucket.history)
    assert any(item[1] == "multipart-abort" for item in bucket.history)


def test_part_copy_failure_automatically_starts_complete_epoch():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("epoch fallback"))
    log = owned("large", 2, body_size=2_000_000)
    cloud.publish(log, 0, 1)
    cloud.publish(log, 1, 2)
    initial = cloud.fold_idle(log.writer)
    assert initial.segments[-1].kind == "mono"
    assert initial.segments[-1].size >= MULTIPART_EDGE

    log.append(Fact("msg", 2_000, (), b"small tail"))
    cloud.publish(log, 2, 3)
    store.fail_next_copy = True
    folded = cloud.fold_idle(log.writer)
    assert [segment.kind for segment in folded.segments] == ["mono", "epoch"]
    assert folded.segments[0].hi == folded.segments[1].lo == 2

    replica = PeerState()
    report = cloud.sync(replica)
    assert report.facts == 3 and set(replica.entries()) == entries(log)


def test_mono_append_copies_history_and_uploads_only_bounded_tail():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("copy amplification"))
    log = owned("large", 2, body_size=2_000_000)
    cloud.publish(log, 0, 1)
    cloud.publish(log, 1, 2)
    old = cloud.fold_idle(log.writer).segments[0]
    log.append(Fact("msg", 2_000, (), b"delta" * 100))
    cloud.publish(log, 2, 3)

    before = store.metrics.copy()
    current = cloud.fold_idle(log.writer).segments[0]
    delta = store.metrics.delta(before)
    assert current.lo == 0 and current.hi == 3
    assert delta.part_copies == delta.multipart_completes == 1
    assert delta.copied_bytes >= MULTIPART_EDGE
    assert delta.uploaded_bytes < old.size // 10


def test_two_workspaces_publish_concurrently_without_shared_writer_slot():
    store = MemoryCloud()
    first = CloudQueue(store, h("workspace one"))
    second = CloudQueue(store, h("workspace two"))
    logs = (owned("first", 10), owned("second", 12))
    barrier = threading.Barrier(2)
    errors = []

    def publish(queue, log):
        try:
            barrier.wait()
            queue.publish(log)
        except Exception as error:  # pragma: no cover - asserted below
            errors.append(error)

    threads = [
        threading.Thread(target=publish, args=(first, logs[0])),
        threading.Thread(target=publish, args=(second, logs[1])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(3)
    assert not errors

    left, right = PeerState(), PeerState()
    first.sync(left)
    second.sync(right)
    assert set(left.entries()) == entries(logs[0])
    assert set(right.entries()) == entries(logs[1])
    assert set(left.entries()).isdisjoint(right.entries())


def test_same_workspace_writer_races_are_repaired_without_authority_loss():
    store = MemoryCloud()
    workspace = h("same workspace")
    queues = (CloudQueue(store, workspace), CloudQueue(store, workspace))
    logs = (owned("alice", 7), owned("bob", 9))
    barrier = threading.Barrier(2)

    def publish(queue, log):
        barrier.wait()
        queue.publish(log)
        barrier.wait()
        queue.repair_directory()

    threads = [threading.Thread(target=publish, args=pair)
               for pair in zip(queues, logs)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(3)
    assert all(not thread.is_alive() for thread in threads)

    # The digest is a hint: one deterministic repair after any racing writes
    # must recover the exact writer forest from owner slots.
    queues[0].repair_directory()
    state = PeerState()
    queues[0].sync(state)
    assert set(state.entries()) == entries(logs[0]) | entries(logs[1])


def test_cold_body_gets_really_overlap_under_the_named_wave_bound():
    class DelayedCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.activity_lock = threading.Lock()
            self.active = 0
            self.maximum_active = 0

        def get(self, key, *, if_none_match=None, suffix=None):
            body_get = "/writers/" in key and suffix is None
            if body_get:
                with self.activity_lock:
                    self.active += 1
                    self.maximum_active = max(self.maximum_active, self.active)
                time.sleep(0.005)
            try:
                return super().get(
                    key, if_none_match=if_none_match, suffix=suffix)
            finally:
                if body_get:
                    with self.activity_lock:
                        self.active -= 1

    store = DelayedCloud()
    cloud = CloudQueue(store, h("parallel body reads"))
    for ordinal in range(70):
        cloud.publish(owned(f"parallel-{ordinal}", 1))
    cloud.repair_directory()
    report = cloud.sync(PeerState())
    assert report.facts == report.object_gets == 70
    assert report.rounds - report.directory_audit_rounds == 2
    assert store.maximum_active >= 8


def test_completed_body_ingests_while_another_writer_get_is_in_flight(
        monkeypatch):
    class PipelinedCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.blocked_key = None
            self.blocked = threading.Event()
            self.release = threading.Event()

        def get(self, key, *, if_none_match=None, suffix=None):
            if key == self.blocked_key and suffix is None:
                self.blocked.set()
                if not self.release.wait(2):
                    raise AssertionError("ingest did not overlap body GET")
            return super().get(
                key, if_none_match=if_none_match, suffix=suffix)

    store = PipelinedCloud()
    cloud = CloudQueue(store, h("pipelined body ingest"))
    for ordinal in range(2):
        cloud.publish(owned(f"pipeline-{ordinal}", 8))
    cloud.repair_directory()
    slots, _tag = cloud.poll()
    keys = sorted(
        segment.key for slot in slots.values() for segment in slot.segments)
    store.blocked_key = keys[1]
    original = cloud_module.ingest_batch
    overlapped = []

    def observe_ingest(state, runs):
        assert store.blocked.wait(2)
        overlapped.append(True)
        store.release.set()
        return original(state, runs)

    monkeypatch.setattr(cloud_module, "ingest_batch", observe_ingest)
    report = cloud.sync(PeerState())
    assert report.facts == 16
    assert overlapped


def test_lost_slot_cas_response_retries_as_exact_idempotent_ack():
    class LostResponseCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.lose = True

        def cas(self, key, token, value):
            result = super().cas(key, token, value)
            if self.lose and "/slots/" in key and result:
                self.lose = False
                raise OSError("slot CAS response lost")
            return result

    store = LostResponseCloud()
    cloud = CloudQueue(store, h("lost slot response"))
    log = owned("lost response writer", 4)
    with pytest.raises(OSError, match="response lost"):
        cloud.publish(log, 0, 4)
    before = store.metrics.copy()
    receipt = cloud.publish(log, 0, 4)
    delta = store.metrics.delta(before)
    assert (receipt.segment.lo, receipt.segment.hi) == (0, 4)
    assert delta.cas == 0  # exact slot retry; announcement is idle work
    replica = PeerState()
    assert cloud.sync(replica).facts == 4
    assert set(replica.entries()) == entries(log)


def test_exact_publish_and_readmission_retry_survive_a_later_fold():
    cloud = CloudQueue(MemoryCloud(), h("retry after physical fold"))
    log = owned("retry folded writer", 2)
    cloud.publish(log, 0, 1)
    second = cloud.publish(log, 1, 2)
    cloud.fold_idle(log.writer)

    assert cloud.publish(log, 1, 2).segment == cloud.readmit_orphan(
        log.writer, 1, 2).segment
    assert cloud.readmit_orphan(log.writer, 1, 2).segment == second.segment


def test_crash_orphan_exact_retry_finishes_the_original_slot_transition():
    class CrashBeforeSlotCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.crash = True

        def cas(self, key, token, value):
            if self.crash and "/slots/" in key:
                self.crash = False
                raise OSError("crash before writer-slot CAS")
            return super().cas(key, token, value)

    store = CrashBeforeSlotCloud()
    cloud = CloudQueue(store, h("exact crash orphan"))
    log = owned("orphaned exact branch", 1)
    with pytest.raises(OSError, match="before writer-slot"):
        cloud.publish(log)
    assert cloud._slot_versioned(log.writer)[0] is None
    receipt = cloud.publish(log)
    assert (receipt.segment.lo, receipt.segment.hi) == (0, 1)
    assert cloud._slot_versioned(log.writer)[0].hi == 1


def test_divergent_crash_orphan_has_typed_evidence_and_readmission_recovery():
    class CrashBeforeSlotCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.crash = True

        def cas(self, key, token, value):
            if self.crash and "/slots/" in key:
                self.crash = False
                raise OSError("crash before writer-slot CAS")
            return super().cas(key, token, value)

    secret = signing.SigningKey.generate()
    orphan = WriterLog.owned(secret)
    divergent = WriterLog.owned(signing.SigningKey(secret.encode()))
    orphan.append(Fact("msg", 1, (), b"orphan branch"))
    divergent.append(Fact("msg", 1, (), b"divergent restart"))
    store = CrashBeforeSlotCloud()
    cloud = CloudQueue(store, h("divergent crash orphan"))
    with pytest.raises(OSError, match="before writer-slot"):
        cloud.publish(orphan)

    with pytest.raises(CloudMicroFork) as found:
        cloud.publish(divergent)
    evidence = found.value.evidence
    assert evidence.writer == orphan.writer
    assert (evidence.lo, evidence.hi) == (0, 1)
    assert evidence.incumbent_hash != evidence.proposed_hash
    assert "readmit" in str(found.value)
    receipt = cloud.readmit_orphan(orphan.writer, 0, 1)
    assert receipt.segment.key == evidence.key
    assert cloud.readmit_orphan(orphan.writer, 0, 1) == receipt
    cloud.repair_directory()
    state = PeerState()
    report = cloud.sync(state)
    assert report.interactive_ready and report.facts == 1
    assert state.logs[orphan.writer].fact(0) == orphan.fact(0)


def test_same_base_identical_publishers_have_one_slot_winner_and_retry_ack():
    class PausedSlotCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.entered = threading.Event()
            self.release = threading.Event()
            self.pause_once = True

        def cas(self, key, token, value):
            if self.pause_once and "/slots/" in key:
                self.pause_once = False
                self.entered.set()
                assert self.release.wait(3)
            return super().cas(key, token, value)

    store = PausedSlotCloud()
    queues = (
        CloudQueue(store, h("same writer interleave")),
        CloudQueue(store, h("same writer interleave")),
    )
    log = owned("one writer", 3)
    failures = []

    def first():
        try:
            queues[0].publish(log, 0, 3)
        except Exception as error:  # pragma: no cover - asserted below
            failures.append(error)

    thread = threading.Thread(target=first)
    thread.start()
    assert store.entered.wait(3)
    queues[1].publish(log, 0, 3)
    store.release.set()
    thread.join(3)
    assert len(failures) == 1
    assert str(failures[0]) == "stale cloud writer slot"

    # The loser rereads the exact signed head and immutable publication rather
    # than issuing a second writer-slot CAS or reporting a false sequence gap.
    before = store.metrics.copy()
    queues[0].publish(log, 0, 3)
    delta = store.metrics.delta(before)
    assert delta.cas == 0  # exact slot retry; announcement is idle work
    state = PeerState()
    assert queues[0].sync(state).facts == 3
    assert set(state.entries()) == entries(log)


def test_same_writer_divergent_same_sequence_fails_at_immutable_address():
    class PausedSlotCloud(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.entered = threading.Event()
            self.release = threading.Event()

        def cas(self, key, token, value):
            if "/slots/" in key and not self.entered.is_set():
                self.entered.set()
                assert self.release.wait(3)
            return super().cas(key, token, value)

    secret = signing.SigningKey.generate()
    first = WriterLog.owned(secret)
    second = WriterLog.owned(signing.SigningKey(secret.encode()))
    first.append(Fact("msg", 1, (), b"first fork"))
    second.append(Fact("msg", 1, (), b"second fork"))
    store = PausedSlotCloud()
    workspace = h("divergent writer")
    failures = []

    def publish_first():
        try:
            CloudQueue(store, workspace).publish(first)
        except Exception as error:  # pragma: no cover - asserted below
            failures.append(error)

    thread = threading.Thread(target=publish_first)
    thread.start()
    assert store.entered.wait(3)
    with pytest.raises(CloudMicroFork) as found:
        CloudQueue(store, workspace).publish(second)
    assert found.value.evidence.writer == first.writer
    assert found.value.evidence.incumbent_hash \
        != found.value.evidence.proposed_hash
    store.release.set()
    thread.join(3)
    assert not failures and not thread.is_alive()


def test_delayed_directory_snapshot_regresses_only_hint_until_fair_repair():
    class DelayedFirstList(MemoryCloud):
        def __init__(self):
            super().__init__()
            self.entered = threading.Event()
            self.release = threading.Event()
            self.delay = True

        def list(self, prefix):
            result = super().list(prefix)
            if self.delay:
                self.delay = False
                self.entered.set()
                assert self.release.wait(3)
            return result

    store = DelayedFirstList()
    queue = CloudQueue(store, h("delayed directory"))
    first, second = owned("first listed", 2), owned("second listed", 2)
    queue.publish(first)
    failures = []

    def stale_repair():
        try:
            queue.repair_directory()
        except Exception as error:  # pragma: no cover - asserted below
            failures.append(error)

    thread = threading.Thread(target=stale_repair)
    thread.start()
    assert store.entered.wait(3)
    queue.publish(second)
    queue.repair_directory()
    assert set(queue.visible_heads()) == {first.writer, second.writer}
    store.release.set()
    thread.join(3)
    assert not failures and not thread.is_alive()

    # The stale repair may hide a newer writer from the derived directory, but
    # cannot alter either owner slot. One fair deterministic LIST repair brings
    # the hint back to the exact forest.
    assert set(queue.visible_heads()) == {first.writer}
    queue.repair_directory()
    assert set(queue.visible_heads()) == {first.writer, second.writer}
    state = PeerState()
    assert queue.sync(state).facts == 4
    assert set(state.entries()) == entries(first) | entries(second)
