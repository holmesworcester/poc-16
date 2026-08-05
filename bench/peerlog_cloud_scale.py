"""Production-path scale profiles for passive writer-forest catchup.

These fixtures create real signed ``WriterLog`` histories, publish exact
authenticated runs through ``CloudQueue``, and ingest them into ``PeerState``.
Only elapsed-network projection is modeled; bytes, requests, facts, proofs,
and local execution are measured from the running implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import asdict, dataclass

from nacl import signing

from peerlog.cloud import (
    CLOUD_GET_CONCURRENCY,
    MICRO_TAIL,
    CloudCache,
    CloudDemand,
    CloudQueue,
    MemoryCloud,
)
from peerlog.fact import Fact, Ref
from peerlog.ingest import PeerState
from peerlog.log import WriterLog


RTT_S = 0.090
BANDWIDTH_BYTES_S = 2_500_000
SKEW_PUBLICATION_FACTS = 20_000
SKEW_FOLD_PUBLICATIONS = 8


@dataclass(frozen=True)
class ColdScale:
    writers: int
    facts: int
    directory_bytes: int
    object_gets: int
    rounds: int
    received_bytes: int
    build_s: float
    sync_s: float
    pipelined_facts_per_s: float
    pipelined_bytes_per_s: float
    bandwidth_floor_s: float
    projected_network_s: float
    rtt_margin: float


@dataclass(frozen=True)
class FanoutScale:
    writers: int
    cold_gets: int
    cold_rounds: int
    noop_gets: int
    noop_rounds: int
    warm_gets: int
    warm_rounds: int
    warm_facts: int
    directory_bytes: int


@dataclass(frozen=True)
class RangeScale:
    total_facts: int
    requested_lo: int
    requested_hi: int
    received_facts: int
    object_gets: int
    rounds: int


@dataclass(frozen=True)
class InteractiveScale:
    history_facts: int
    recent_facts: int
    writers: int
    object_gets: int
    initial_segment_gets: int
    closure_segment_gets: int
    rounds: int
    received_bytes: int
    initial_bytes: int
    closure_bytes: int
    closure_facts: int
    segment_overfetch_facts: int
    closure_depth: int
    interactive_ready: bool
    time_to_interactive_s: float
    recent_facts_per_s: float
    semantic_facts_per_s: float
    projected_network_s: float


@dataclass(frozen=True)
class SkewedInteractiveScale:
    history_facts: int
    hot_facts: int
    medium_writers: int
    long_tail_writers: int
    requested_tail: int
    requested_writers: int
    selected_facts: int
    object_gets: int
    initial_segment_gets: int
    closure_segment_gets: int
    rounds: int
    received_bytes: int
    initial_bytes: int
    closure_bytes: int
    closure_facts: int
    segment_overfetch_facts: int
    closure_depth: int
    interactive_ready: bool
    time_to_interactive_s: float
    semantic_facts_per_s: float
    projected_network_s: float


def _workspace(label):
    return hashlib.sha256(("peerlog-scale/" + label).encode()).digest()


def _writer_secret(ordinal):
    return signing.SigningKey(hashlib.sha256(
        f"peerlog-scale-writer/{ordinal}".encode()).digest())


def _writer_id(ordinal):
    return bytes(_writer_secret(ordinal).verify_key)


def _log(ordinal, count, body_bytes, refs_by_seq=None):
    log = WriterLog.owned(_writer_secret(ordinal))
    body = bytes([ordinal % 251]) * body_bytes
    refs_by_seq = {} if refs_by_seq is None else refs_by_seq
    for seq in range(count):
        log.append(Fact(
            "msg", ordinal * 1_000_000 + seq + 1,
            refs_by_seq.get(seq, ()), body))
    return log


def measure_cold(*, writers=50, facts=100_000, body_bytes=80):
    if type(writers) is not int or writers <= 0 \
            or type(facts) is not int or facts <= 0 or facts % writers:
        raise ValueError("cold scale shape")
    store = MemoryCloud()
    queue = CloudQueue(store, _workspace(f"cold/{writers}/{facts}"))
    started = time.perf_counter()
    per_writer = facts // writers
    for ordinal in range(writers):
        log = _log(ordinal, per_writer, body_bytes)
        queue.publish(log, announce=False)
    queue.repair_directory()
    build_s = time.perf_counter() - started
    directory = store.get(queue.directory_key)[0]

    state = PeerState()
    started = time.perf_counter()
    report = queue.sync(state)
    sync_s = time.perf_counter() - started
    if len(state.treap) != facts:
        raise AssertionError("cold scale convergence")
    floor = report.received_bytes / BANDWIDTH_BYTES_S
    projected = floor + report.rounds * RTT_S
    return ColdScale(
        writers, facts, len(directory), report.object_gets, report.rounds,
        report.received_bytes, build_s, sync_s,
        facts / sync_s, report.received_bytes / sync_s,
        floor, projected,
        0.0 if not floor else projected / floor - 1.0,
    )


def measure_fanout(writers):
    if type(writers) is not int or writers <= 0:
        raise ValueError("fanout scale shape")
    store = MemoryCloud()
    queue = CloudQueue(store, _workspace(f"fanout/{writers}"))
    logs = []
    for ordinal in range(writers):
        log = _log(ordinal, 1, 24)
        logs.append(log)
        queue.publish(log, announce=False)
    queue.repair_directory()
    directory = store.get(queue.directory_key)[0]

    state, cache = PeerState(), CloudCache()
    before = store.metrics.copy()
    cold = queue.sync(state, cache)
    cold_cost = store.metrics.delta(before)
    before = store.metrics.copy()
    noop = queue.sync(state, cache)
    noop_cost = store.metrics.delta(before)

    changed = logs[0]
    changed.append(Fact("msg", 9_000_000, (), b"one warm update"))
    queue.publish(changed, 1, 2, announce=False)
    queue.repair_directory()
    before = store.metrics.copy()
    warm = queue.sync(state, cache)
    warm_cost = store.metrics.delta(before)
    return FanoutScale(
        writers, cold_cost.gets - 1, cold.rounds,
        noop_cost.gets, noop.rounds,
        warm_cost.gets - 1, warm.rounds, warm.facts, len(directory),
    )


def measure_range():
    store = MemoryCloud()
    queue = CloudQueue(store, _workspace("range"))
    log = WriterLog.owned(signing.SigningKey(hashlib.sha256(
        b"peerlog-scale-range-writer").digest()))
    for seq in range(3 * MICRO_TAIL):
        if seq and seq % MICRO_TAIL == 0:
            queue.fold_idle(log.writer, announce=False)
        log.append(Fact("msg", seq + 1, (), b"range" * 8))
        queue.publish(log, seq, seq + 1, announce=False)
    queue.fold_idle(log.writer, announce=False)
    queue.repair_directory()
    lo, hi = 2 * MICRO_TAIL, 3 * MICRO_TAIL
    report = queue.sync(PeerState(), demand=CloudDemand.exact({
        log.writer: ((lo, hi),),
    }))
    return RangeScale(
        len(log), lo, hi, report.facts, report.object_gets, report.rounds)


def measure_interactive(*, history_facts, recent_facts=1_000,
                        writers=1_000, body_bytes=24):
    """Measure the recent-window demand pump over a larger cold history.

    Each writer has one old immutable segment and one recent segment.  One
    recent fact from writer 0 cites an old writer-1 fact, which cites an older
    writer-2 fact.  TTI therefore includes two out-of-window dependency waves
    and ends only at a pending-empty, renderable view.
    """
    if type(history_facts) is not int or history_facts <= 0 \
            or type(recent_facts) is not int or recent_facts <= 0 \
            or type(writers) is not int or writers <= 0 \
            or writers < 3 or history_facts % writers \
            or recent_facts % writers \
            or recent_facts >= history_facts:
        raise ValueError("interactive scale shape")
    store = MemoryCloud()
    queue = CloudQueue(
        store, _workspace(
            f"interactive/{history_facts}/{recent_facts}/{writers}"))
    per_writer = history_facts // writers
    recent_per_writer = recent_facts // writers
    recent_lo = per_writer - recent_per_writer
    b_target = max(0, recent_lo // 2)
    c_target = max(0, b_target // 2)
    for ordinal in range(writers):
        refs = {}
        if ordinal == 0:
            refs[recent_lo] = (Ref(_writer_id(1), b_target),)
        elif ordinal == 1:
            refs[b_target] = (Ref(_writer_id(2), c_target),)
        log = _log(ordinal, per_writer, body_bytes, refs)
        queue.publish(log, 0, recent_lo, announce=False)
        queue.publish(log, recent_lo, per_writer, announce=False)
    queue.repair_directory()

    state = PeerState()
    started = time.perf_counter()
    report = queue.sync(
        state,
        demand=CloudDemand.tails(
            (_writer_id(ordinal) for ordinal in range(writers)),
            recent_per_writer),
    )
    elapsed = time.perf_counter() - started
    if not report.interactive_ready or report.pending \
            or report.initial_facts != recent_facts \
            or report.closure_facts != 2:
        raise AssertionError("interactive scale convergence")
    projected = report.received_bytes / BANDWIDTH_BYTES_S \
        + report.rounds * RTT_S
    return InteractiveScale(
        history_facts, recent_facts, writers, report.object_gets,
        report.initial_segment_gets, report.closure_segment_gets,
        report.rounds, report.received_bytes,
        report.initial_bytes, report.closure_bytes, report.closure_facts,
        report.segment_overfetch_facts, report.closure_depth,
        report.interactive_ready, elapsed, recent_facts / elapsed,
        (recent_facts + report.closure_facts) / elapsed, projected,
    )


def measure_skewed_interactive(*, history_facts, requested_tail=2,
                               medium_writers=5, long_tail_writers=1_000,
                               body_bytes=24):
    """Measure per-writer tails with one hot writer and a sparse long tail."""
    if type(history_facts) is not int or history_facts < 10_000 \
            or type(requested_tail) is not int or requested_tail <= 0 \
            or medium_writers < 2 or long_tail_writers < 1_000:
        raise ValueError("skew scale shape")
    quiet_counts = tuple(ordinal % 4 for ordinal in range(long_tail_writers))
    quiet_total = sum(quiet_counts)
    remaining = history_facts - quiet_total
    medium_count = remaining // 20
    hot_count = remaining - medium_writers * medium_count
    if medium_count <= requested_tail or hot_count <= requested_tail:
        raise ValueError("skew scale history")
    counts = (hot_count, *(medium_count for _ in range(medium_writers)),
              *quiet_counts)
    if sum(counts) != history_facts:
        raise AssertionError("skew scale accounting")

    store = MemoryCloud()
    queue = CloudQueue(store, _workspace(
        f"skew/{history_facts}/{requested_tail}/"
        f"{medium_writers}/{long_tail_writers}"))
    logs = []
    first_medium_target = (medium_count - requested_tail) // 2
    second_medium_target = first_medium_target // 2
    for ordinal, count in enumerate(counts):
        refs = {}
        if ordinal == 0:
            refs[count - requested_tail] = (
                Ref(_writer_id(1), first_medium_target),)
        elif ordinal == 1:
            refs[first_medium_target] = (
                Ref(_writer_id(2), second_medium_target),)
        log = _log(ordinal, count, body_bytes, refs)
        logs.append(log)
        if not count:
            continue
        split = max(0, count - requested_tail)
        cursor = micros = 0
        while cursor < split:
            stop = min(split, cursor + SKEW_PUBLICATION_FACTS)
            queue.publish(log, cursor, stop, announce=False)
            cursor = stop
            micros += 1
            if micros == SKEW_FOLD_PUBLICATIONS:
                queue.fold_idle(log.writer, announce=False)
                micros = 0
        if micros:
            queue.fold_idle(log.writer, announce=False)
        queue.publish(log, split, count, announce=False)
    queue.repair_directory()

    demand = CloudDemand.tails(
        (log.writer for log in logs), requested_tail)
    state = PeerState()
    started = time.perf_counter()
    report = queue.sync(state, demand=demand)
    elapsed = time.perf_counter() - started
    selected = sum(min(requested_tail, count) for count in counts)
    if not report.interactive_ready or report.pending \
            or report.initial_facts != selected \
            or report.closure_facts != 2:
        raise AssertionError("skew scale convergence")
    projected = report.received_bytes / BANDWIDTH_BYTES_S \
        + report.rounds * RTT_S
    return SkewedInteractiveScale(
        history_facts, hot_count, medium_writers, long_tail_writers,
        requested_tail, len(logs), selected, report.object_gets,
        report.initial_segment_gets, report.closure_segment_gets,
        report.rounds, report.received_bytes, report.initial_bytes,
        report.closure_bytes,
        report.closure_facts, report.segment_overfetch_facts,
        report.closure_depth, report.interactive_ready, elapsed,
        (selected + report.closure_facts) / elapsed, projected,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true",
                        help="run the 100k-fact authenticated cold profile")
    parser.add_argument(
        "--interactive-full", action="store_true",
        help="measure a 1k-fact recent view over 10k/100k/1M histories")
    parser.add_argument(
        "--skew-full", action="store_true",
        help="measure skew-aware tails over 10k/100k/1M histories")
    args = parser.parse_args()
    result = {
        "concurrency": CLOUD_GET_CONCURRENCY,
        "fanout_100": asdict(measure_fanout(100)),
        "fanout_1000": asdict(measure_fanout(1000)),
        "range": asdict(measure_range()),
    }
    if args.full:
        result["cold_100k"] = asdict(measure_cold())
    if args.interactive_full:
        result["interactive"] = [
            asdict(measure_interactive(history_facts=facts))
            for facts in (10_000, 100_000, 1_000_000)
        ]
    if args.skew_full:
        result["skewed_interactive"] = [
            asdict(measure_skewed_interactive(history_facts=facts))
            for facts in (10_000, 100_000, 1_000_000)
        ]
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
