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
    CloudQueue,
    MemoryCloud,
)
from peerlog.fact import Fact
from peerlog.ingest import PeerState
from peerlog.log import WriterLog


RTT_S = 0.090
BANDWIDTH_BYTES_S = 2_500_000


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
    rounds: int
    received_bytes: int
    time_to_interactive_s: float
    recent_facts_per_s: float
    projected_network_s: float


def _workspace(label):
    return hashlib.sha256(("peerlog-scale/" + label).encode()).digest()


def _log(ordinal, count, body_bytes):
    secret = signing.SigningKey(hashlib.sha256(
        f"peerlog-scale-writer/{ordinal}".encode()).digest())
    log = WriterLog.owned(secret)
    body = bytes([ordinal % 251]) * body_bytes
    for seq in range(count):
        log.append(Fact("msg", ordinal * 1_000_000 + seq + 1, (), body))
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
    report = queue.sync(PeerState(), seq_window=(lo, hi))
    return RangeScale(
        len(log), lo, hi, report.facts, report.object_gets, report.rounds)


def measure_interactive(*, history_facts, recent_facts=1_000,
                        writers=1_000, body_bytes=24):
    """Measure the recent-window demand pump over a larger cold history.

    Each writer has one old immutable segment and one recent segment.  The
    production sequence-window recipe must fetch and semantically ingest only
    the latter, so this measures time to an interactive recent view instead of
    disguising a full-history transfer as latency.
    """
    if type(history_facts) is not int or history_facts <= 0 \
            or type(recent_facts) is not int or recent_facts <= 0 \
            or type(writers) is not int or writers <= 0 \
            or history_facts % writers or recent_facts % writers \
            or recent_facts >= history_facts:
        raise ValueError("interactive scale shape")
    store = MemoryCloud()
    queue = CloudQueue(
        store, _workspace(
            f"interactive/{history_facts}/{recent_facts}/{writers}"))
    per_writer = history_facts // writers
    recent_per_writer = recent_facts // writers
    recent_lo = per_writer - recent_per_writer
    for ordinal in range(writers):
        log = _log(ordinal, per_writer, body_bytes)
        queue.publish(log, 0, recent_lo, announce=False)
        queue.publish(log, recent_lo, per_writer, announce=False)
    queue.repair_directory()

    state = PeerState()
    started = time.perf_counter()
    report = queue.sync(state, seq_window=(recent_lo, per_writer))
    elapsed = time.perf_counter() - started
    if len(state.treap) != recent_facts:
        raise AssertionError("interactive scale convergence")
    projected = report.received_bytes / BANDWIDTH_BYTES_S \
        + report.rounds * RTT_S
    return InteractiveScale(
        history_facts, recent_facts, writers, report.object_gets,
        report.rounds, report.received_bytes, elapsed,
        recent_facts / elapsed, projected,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true",
                        help="run the 100k-fact authenticated cold profile")
    parser.add_argument(
        "--interactive-full", action="store_true",
        help="measure a 1k-fact recent view over 10k/100k/1M histories")
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
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
