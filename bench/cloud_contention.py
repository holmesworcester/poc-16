"""Adversarial contention probe for the passive cloud queue.

Every data object in ``peerlog.cloud`` is immutable and content-addressed, so
only two objects can be clobbered at all: the per-writer slot (CAS, single
owner) and the workspace directory (CAS, shared by every writer).  This probe
attacks both with genuinely concurrent clients — separate ``CloudQueue``
instances over separate provider clients, the real multi-device topology —
and reports durability, convergence, retry, and provider-throttle counts.

Durability and announcement are scored separately on purpose: a publication
whose directory update fails is unannounced, not lost, and the design says an
idle ``repair_directory`` must be able to finish the job.

    python3 -m bench.cloud_contention --writers 8 --rounds 3
    POC16_LIVE_R2=1 ... python3 -m bench.cloud_contention --live-r2 --writers 6
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from peerlog.cloud import CloudCache, CloudQueue, MemoryCloud
from peerlog.fact import Fact
from peerlog.ingest import PeerState
from peerlog.log import WriterLog


THROTTLE_TOKENS = ("SlowDown", "TooManyRequests", "429", "503", "ServiceUnavailable")
REQUEST_METRICS = (
    "gets", "puts", "cas", "lists", "multipart_creates", "part_copies",
    "multipart_completes",
)


@dataclass
class Outcome:
    published: int = 0
    stale_slot: int = 0
    directory_exhausted: int = 0
    micro_fork: int = 0
    throttled: int = 0
    other: list = field(default_factory=list)
    seconds: float = 0.0


def _classify(error, outcome):
    text = f"{type(error).__name__}: {error}"
    if "stale cloud writer slot" in text or "stale cloud fold" in text:
        outcome.stale_slot += 1
    elif "cloud micro fork" in text:
        outcome.micro_fork += 1
    elif "cloud directory CAS contention" in text:
        outcome.directory_exhausted += 1
    elif any(token in text for token in THROTTLE_TOKENS):
        outcome.throttled += 1
    else:
        outcome.other.append(text[:160])


def _make_provider(factory):
    return factory()


def provider_request_report(providers):
    """Count logical adapter operations and estimate their request cost.

    These counters sit above the SDK.  A paginated list or an SDK read retry
    can issue more than one physical provider request, so this report must not
    be presented as billing-exact request telemetry.
    """
    providers = tuple({
        id(provider): provider for provider in providers
    }.values())
    operations = {
        name: sum(getattr(provider.metrics, name) for provider in providers)
        for name in REQUEST_METRICS
    }
    class_a = sum(operations[name] for name in (
        "puts", "cas", "lists", "multipart_creates", "part_copies",
        "multipart_completes",
    ))
    class_b = operations["gets"]
    return {
        "logical_operations": operations,
        "logical_class_a": class_a,
        "logical_class_b": class_b,
        "projected_logical_r2_usd": round(
            class_a * 4.50 / 1_000_000
            + class_b * 0.36 / 1_000_000,
            8,
        ),
    }


def probe_directory_contention(factory, workspace, writers, rounds, announce):
    """W distinct writers publish concurrently into one workspace."""
    logs = [WriterLog.owned() for _ in range(writers)]
    queues = [CloudQueue(_make_provider(factory), workspace) for _ in logs]
    outcome = Outcome()
    lock = threading.Lock()
    barrier = threading.Barrier(writers)

    def run(index):
        log, cloud = logs[index], queues[index]
        barrier.wait()
        for round_index in range(rounds):
            log.append(Fact("msg", 1000 + round_index,
                            (), f"w{index}r{round_index}".encode()))
            try:
                cloud.publish(log, announce=announce)
                with lock:
                    outcome.published += 1
            except Exception as error:  # noqa: BLE001 - probe classifies
                with lock:
                    _classify(error, outcome)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=writers) as pool:
        list(pool.map(run, range(writers)))
    outcome.seconds = time.perf_counter() - started

    # Durability is scored from owner-confined slots, announcement from the
    # derived directory: the design permits the second to lag the first.
    audit = CloudQueue(_make_provider(factory), workspace)
    if not announce:
        audit.repair_directory()
    announced = audit.visible_heads()
    durable = {}
    for log in logs:
        slot, _token = audit._slot_versioned(log.writer)
        durable[log.writer] = 0 if slot is None else slot.hi
    return outcome, durable, announced


def probe_same_writer_race(factory, workspace, clients):
    """One writer, N concurrent clients: exactly one CAS may win."""
    from nacl import signing

    secret = signing.SigningKey.generate()
    log = WriterLog.owned(secret)
    seed = CloudQueue(_make_provider(factory), workspace)
    log.append(Fact("msg", 1, (), b"seed"))
    seed.publish(log)
    base = len(log._facts)
    seeded = tuple(log._facts[seq] for seq in sorted(log._facts))

    queues = [CloudQueue(_make_provider(factory), workspace)
              for _ in range(clients)]
    barrier = threading.Barrier(clients)
    outcome = Outcome()
    lock = threading.Lock()

    def run(index):
        # Each client appends its own distinct fact at the same base sequence,
        # the exact shape of two devices racing one writer identity.
        rival = WriterLog.owned(secret)
        for fact in seeded:
            rival.append(fact)
        rival.append(Fact("msg", 2000 + index, (), f"race{index}".encode()))
        barrier.wait()
        try:
            queues[index].publish(rival, announce=False)
            with lock:
                outcome.published += 1
        except Exception as error:  # noqa: BLE001
            with lock:
                _classify(error, outcome)

    with ThreadPoolExecutor(max_workers=clients) as pool:
        list(pool.map(run, range(clients)))

    audit = CloudQueue(_make_provider(factory), workspace)
    slot, _token = audit._slot_versioned(log.writer)
    return outcome, (0 if slot is None else slot.hi), base


def probe_key_write_rate(factory, workspace, attempts):
    """Unpaced CAS bursts on one key: does the provider throttle, and how."""
    cloud = CloudQueue(_make_provider(factory), workspace)
    log = WriterLog.owned()
    log.append(Fact("msg", 1, (), b"rate"))
    cloud.publish(log, announce=False)
    outcome = Outcome()
    started = time.perf_counter()
    for _ in range(attempts):
        try:
            cloud.repair_directory()
            outcome.published += 1
        except Exception as error:  # noqa: BLE001
            _classify(error, outcome)
    outcome.seconds = time.perf_counter() - started
    return outcome


def _live_r2_factory():
    from adapters.r2.s3 import R2S3Config, R2S3Store
    from peerlog.cloud_s3 import S3Cloud

    prefix = "poc16-contention/run-" + secrets.token_hex(16)
    config = R2S3Config(
        account_id=os.environ["POC16_R2_ACCOUNT_ID"],
        bucket=os.environ["POC16_R2_BUCKET"],
        prefix=prefix,
    )

    def factory():
        return S3Cloud(R2S3Store(
            config,
            access_key_id=os.environ["POC16_R2_ACCESS_KEY_ID"],
            secret_access_key=os.environ["POC16_R2_SECRET_ACCESS_KEY"],
        ))

    return factory, prefix


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--writers", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--rate-attempts", type=int, default=8)
    parser.add_argument("--live-r2", action="store_true")
    args = parser.parse_args()

    prefix = None
    if args.live_r2:
        if os.environ.get("POC16_LIVE_R2") != "1":
            raise SystemExit("set POC16_LIVE_R2=1 for live evidence")
        factory, prefix = _live_r2_factory()
    else:
        shared = MemoryCloud()
        factory = lambda: shared  # noqa: E731 - one in-memory provider

    providers = []
    untracked_factory = factory

    def factory():
        result = untracked_factory()
        providers.append(result)
        return result

    report = {"target": "live-r2" if args.live_r2 else "memory",
              "prefix": prefix}

    for announce in (True, False):
        workspace = secrets.token_bytes(32)
        outcome, durable, announced = probe_directory_contention(
            factory, workspace, args.writers, args.rounds, announce)
        expected = args.writers * args.rounds
        report[f"directory_announce_{announce}"] = {
            "attempted": expected,
            "published_ok": outcome.published,
            "stale_slot": outcome.stale_slot,
            "directory_exhausted": outcome.directory_exhausted,
            "micro_fork": outcome.micro_fork,
            "throttled": outcome.throttled,
            "other": outcome.other,
            "seconds": round(outcome.seconds, 3),
            "facts_durable": sum(durable.values()),
            "facts_announced": sum(announced.values()),
            "writers_announced": len(announced),
            "durability_complete": sum(durable.values()) == expected,
            "announcement_complete": sum(announced.values()) == expected,
        }

    outcome, final_hi, base = probe_same_writer_race(
        factory, secrets.token_bytes(32), args.clients)
    report["same_writer_race"] = {
        "clients": args.clients,
        "won": outcome.published,
        "rejected_stale": outcome.stale_slot,
        "micro_fork": outcome.micro_fork,
        "throttled": outcome.throttled,
        "other": outcome.other,
        "base_seq": base,
        "final_seq": final_hi,
        "exactly_one_winner": outcome.published == 1,
        "no_lost_or_torn_append": final_hi == base + 1,
    }

    outcome = probe_key_write_rate(
        factory, secrets.token_bytes(32), args.rate_attempts)
    report["single_key_burst"] = {
        "attempts": args.rate_attempts,
        "ok": outcome.published,
        "throttled": outcome.throttled,
        "directory_exhausted": outcome.directory_exhausted,
        "other": outcome.other,
        "seconds": round(outcome.seconds, 3),
        "writes_per_second": round(
            outcome.published / outcome.seconds, 2) if outcome.seconds else None,
    }
    report["provider_logical_operations"] = provider_request_report(providers)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
