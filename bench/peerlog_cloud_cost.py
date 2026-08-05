"""Measured local-provider request and byte vectors for the phase-2 queue."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

from peerlog.cloud import MICRO_TAIL, CloudCache, CloudQueue, MemoryCloud
from peerlog.fact import Fact, canonical
from peerlog.ingest import PeerState
from peerlog.log import WriterLog
from peerlog.proof import encode_run, prove_run
from scratchpad.store_model import append_projection, sync_projection


@dataclass(frozen=True)
class CloudCostReport:
    writers: int
    facts_per_writer: int
    semantic_bytes: int
    publication_uploaded_bytes: int
    publication_puts: int
    publication_cas: int
    cold_rounds: int
    cold_gets: int
    cold_bytes: int
    noop_rounds: int
    noop_gets: int
    warm_rounds: int
    warm_gets: int
    warm_bytes: int
    measured_upload_amplification: float
    model_upload_ceiling: float
    million_fact_floor_margin: float


def measure(writers=3, facts_per_writer=64, body_bytes=90):
    store = MemoryCloud()
    cloud = CloudQueue(store, __import__("hashlib").sha256(
        b"peerlog cloud benchmark").digest())
    logs = []
    semantic_bytes = 0
    authenticated_run_bytes = 0
    start = store.metrics.copy()
    for writer_number in range(writers):
        log = WriterLog.owned()
        logs.append(log)
        for seq in range(facts_per_writer):
            if seq and seq % MICRO_TAIL == 0:
                cloud.fold_idle(log.writer, announce=False)
            fact = Fact(
                "msg", writer_number * 1_000_000 + seq + 1, (),
                bytes([writer_number % 251]) * body_bytes)
            semantic_bytes += len(canonical(fact))
            log.append(fact)
            authenticated_run_bytes += len(encode_run(prove_run(
                log, seq, seq + 1)))
            cloud.publish(log, seq, seq + 1, announce=False)
        cloud.fold_idle(log.writer, announce=False)
    cloud.repair_directory()
    publication = store.metrics.delta(start)

    state, cache = PeerState(), CloudCache()
    start = store.metrics.copy()
    cold = cloud.sync(state, cache)
    cold_cost = store.metrics.delta(start)
    start = store.metrics.copy()
    noop = cloud.sync(state, cache)
    noop_cost = store.metrics.delta(start)

    changed = logs[0]
    seq = len(changed)
    fact = Fact("msg", 9_000_000, (), b"delta".ljust(body_bytes, b"!"))
    changed.append(fact)
    start = store.metrics.copy()
    cloud.publish(changed, seq, seq + 1)
    warm_publish = store.metrics.delta(start)
    cloud.repair_directory()
    start = store.metrics.copy()
    warm = cloud.sync(state, cache)
    warm_cost = store.metrics.delta(start)

    cold_model = sync_projection()
    return CloudCostReport(
        writers, facts_per_writer, semantic_bytes,
        publication.uploaded_bytes + warm_publish.uploaded_bytes,
        publication.puts + warm_publish.puts,
        publication.cas + warm_publish.cas,
        cold.rounds, cold_cost.gets, cold.received_bytes,
        noop.rounds, noop_cost.gets,
        warm.rounds, warm_cost.gets, warm.received_bytes,
        publication.object_upload_bytes / authenticated_run_bytes,
        append_projection(max(1, authenticated_run_bytes // writers))
        .worst_amplification,
        cold_model.margin,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--writers", type=int, default=3)
    parser.add_argument("--facts", type=int, default=64)
    parser.add_argument("--body-bytes", type=int, default=90)
    args = parser.parse_args()
    print(json.dumps(asdict(measure(
        args.writers, args.facts, args.body_bytes)),
        sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
