"""Rate-independent calibration model for bead poc-16-6j4.31.

The defaults are the decision-record fixture: one million 80-byte fact bodies,
50 writers, 90 ms provider RTT, and 2.5 MB/s useful transfer.  Provider prices
are intentionally absent; operation and byte vectors can be priced later.
"""
from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass


MIB = 1024 * 1024


@dataclass(frozen=True)
class SyncProjection:
    facts: int
    writers: int
    bytes: int
    rounds: int
    bandwidth_floor_s: float
    elapsed_s: float
    margin: float


@dataclass(frozen=True)
class AppendProjection:
    log_bytes: int
    fold_threshold: int
    part_edge: int
    ladder_levels: int
    worst_lifetime_upload_bytes: int
    worst_amplification: float
    maximum_publish_upload_bytes: int


def sync_projection(
        facts=1_000_000, writers=50, fact_bytes=80, *, rounds=3,
        rtt_s=0.090, bandwidth_bytes_s=2_500_000, rho=1.0):
    transferred = math.ceil(facts * fact_bytes * rho)
    floor = transferred / bandwidth_bytes_s
    elapsed = floor + rounds * rtt_s
    return SyncProjection(
        facts, writers, transferred, rounds, floor, elapsed,
        0.0 if floor == 0 else (elapsed / floor) - 1.0,
    )


def append_projection(log_bytes, *, fold_threshold=8 * 1024,
                      part_edge=5 * MIB):
    if any(type(item) is not int or item <= 0
           for item in (log_bytes, fold_threshold, part_edge)):
        raise ValueError("append projection")
    folded = min(log_bytes, part_edge)
    levels = max(0, math.ceil(math.log2(
        max(1, folded / fold_threshold))))
    # A deliberately conservative binary-ladder ceiling. Once the multipart
    # edge is reached, every remaining byte is uploaded once and old bytes are
    # server-copied rather than returning through the writer.
    uploaded = folded * (2 + levels) + max(0, log_bytes - part_edge)
    return AppendProjection(
        log_bytes, fold_threshold, part_edge, levels, uploaded,
        uploaded / log_bytes, fold_threshold,
    )


def report():
    return {
        "cold": asdict(sync_projection()),
        "warm": asdict(sync_projection(
            facts=1, writers=1, fact_bytes=180, rounds=2,
            bandwidth_bytes_s=2_500_000)),
        "window": asdict(sync_projection(
            facts=10_000, writers=50, fact_bytes=80, rounds=3,
            bandwidth_bytes_s=2_500_000)),
        "append_4mib": asdict(append_projection(4 * MIB)),
        "append_64mib": asdict(append_projection(64 * MIB)),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print(json.dumps(report(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
