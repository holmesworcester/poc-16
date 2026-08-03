"""Measure writer-local physical packs over real signed-pile fixtures.

This is a storage-shape model, not a protocol implementation.  It generates
the same deterministic one-message closed piles as ``bench_writer_p2p_scale``
and then applies a simple physical policy independently to every writer:

* append pile bytes to one loose tail;
* seal at 256 piles or before the next pile would exceed the byte target;
* retain the final sub-target tail as ordinary individually addressed piles;
* store a canonical descriptor containing writer binding, body OID, and rows
  of ``[publication_sequence, pile_oid, offset, length]``.

The pack body is the raw pile concatenation.  Descriptor rows are locators,
never authority: every extracted pile retains its signed bytes and OID check.
Fetch accounting starts after authenticated tree discovery. A whole-pack GET
returns its offset table and concatenated body together. An exact-pile read
first range-fetches an uncached table, then range-fetches the pile. One loose
tail is one bounded writer-local response. Cold responses overlap across
writers at the requested 32- or 64-request bound; packs never cross writers.
"""
import argparse
from dataclasses import asdict, dataclass
import json
import math
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.bench_writer_p2p_scale import (
    LARGE_DURABLE_FACTS,
    base_forest,
    device_spec,
    large_distribution,
    message_pair,
)
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h
from core.fact import canon
from facts.auth.signature import signature as signature_fact


MIB = 1024 * 1024
DEFAULT_TARGETS_MIB = (4, 16, 64, 100)
DEFAULT_WRITERS = (100, 1_000)
MAX_PILES_PER_PACK = 256
FETCH_CONCURRENCIES = (32, 64)
PACK_FORMAT = "poc16-writer-pack-shape-v1"


@dataclass(frozen=True, slots=True)
class PileRef:
    sequence: int
    oid: str
    size: int


@dataclass(frozen=True, slots=True)
class WriterInventory:
    workspace: str
    writer: str
    piles: tuple[PileRef, ...]


@dataclass(frozen=True, slots=True)
class PhysicalPack:
    piles: tuple[PileRef, ...]
    body_bytes: int
    descriptor_bytes: int


@dataclass(frozen=True, slots=True)
class WriterShape:
    packs: tuple[PhysicalPack, ...]
    tail: tuple[PileRef, ...]


@dataclass(frozen=True, slots=True)
class ShapeReport:
    writers: int
    durable_facts: int
    target_mib: int
    policy: str
    piles: int
    pile_bytes: int
    pile_min_bytes: int
    pile_median_bytes: int
    pile_p95_bytes: int
    pile_max_bytes: int
    max_writer_bytes: int
    sealed_packs: int
    sealed_piles: int
    sealed_body_bytes: int
    average_pack_bytes: int
    max_pack_bytes: int
    descriptor_bytes: int
    descriptor_overhead_percent: float
    point_whole_pack_overfetch: float
    tail_piles: int
    tail_bytes: int
    tail_responses: int
    whole_pack_requests: int
    whole_pack_waves_32: int
    whole_pack_waves_64: int
    exact_range_requests: int
    exact_range_waves_32: int
    exact_range_waves_64: int
    point_read_cold_requests: int
    point_read_warm_requests: int


def _percentile(values, percentile):
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * percentile) - 1]


def build_inventory(writer_count, durable_facts=LARGE_DURABLE_FACTS):
    """Create genuine signed one-message piles without building a tree."""
    forest = base_forest()
    distribution, filler_count = large_distribution(
        writer_count, durable_facts)
    filler = signature_fact(
        forest.founder_secret,
        forest.founder,
        forest.root,
        9_999_999,
    ) if filler_count else None
    inventories = []
    for ordinal, message_count in enumerate(distribution):
        spec = device_spec(forest, ordinal)
        piles = []
        for index in range(message_count):
            facts = [*spec.authority]
            if ordinal == 0 and index == 0 and filler is not None:
                facts.append(filler)
            facts.extend(message_pair(
                forest, spec, index, label="catchup"))
            raw = encode_signed_pile(make_signed_pile(
                spec.secret,
                forest.root.fid,
                spec.public,
                facts,
            ))
            piles.append(PileRef(index + 1, h(raw), len(raw)))
        inventories.append(WriterInventory(
            forest.root.fid, spec.public, tuple(piles)))
    return tuple(inventories)


def _descriptor_size(inventory, piles):
    offset = 0
    rows = []
    for pile in piles:
        rows.append([pile.sequence, pile.oid, offset, pile.size])
        offset += pile.size
    # The actual concatenation hash is always 64 hexadecimal bytes, so a
    # placeholder of that exact wire width gives the exact descriptor length.
    return len(canon({
        "body": "0" * 64,
        "bytes": offset,
        "format": PACK_FORMAT,
        "piles": rows,
        "workspace": inventory.workspace,
        "writer": inventory.writer,
    }))


def writer_shape(inventory, target_bytes, *, force_seal_tail=False):
    """Greedily form bounded packs while leaving at most one loose tail."""
    if type(target_bytes) is not int or target_bytes < 1:
        raise ValueError("pack target")
    packs, pending, pending_bytes = [], [], 0

    def seal():
        nonlocal pending, pending_bytes
        if pending:
            values = tuple(pending)
            packs.append(PhysicalPack(
                values,
                pending_bytes,
                _descriptor_size(inventory, values),
            ))
            pending, pending_bytes = [], 0

    for pile in inventory.piles:
        if pile.size > target_bytes:
            raise ValueError("pile exceeds physical pack target")
        if pending and (
                len(pending) == MAX_PILES_PER_PACK
                or pending_bytes + pile.size > target_bytes):
            seal()
        pending.append(pile)
        pending_bytes += pile.size
        if len(pending) == MAX_PILES_PER_PACK \
                or pending_bytes == target_bytes:
            seal()
    if force_seal_tail:
        seal()
    return WriterShape(tuple(packs), tuple(pending))


def _waves(requests, concurrency):
    return math.ceil(requests / concurrency) if requests else 0


def report(
        inventories, target_mib, durable_facts=LARGE_DURABLE_FACTS, *,
        force_seal_tail=False):
    target_bytes = target_mib * MIB
    shapes = tuple(
        writer_shape(
            inventory, target_bytes,
            force_seal_tail=force_seal_tail)
        for inventory in inventories
    )
    piles = tuple(
        pile for inventory in inventories for pile in inventory.piles)
    packs = tuple(pack for shape in shapes for pack in shape.packs)
    tails = tuple(pile for shape in shapes for pile in shape.tail)
    descriptor_requests = len(packs)
    tail_requests = sum(bool(shape.tail) for shape in shapes)
    sealed_piles = sum(len(pack.piles) for pack in packs)
    whole_requests = len(packs) + tail_requests
    exact_requests = descriptor_requests + sealed_piles + tail_requests

    def exact_waves(concurrency):
        # Tail responses may overlap descriptor discovery. Every sealed-pile
        # range depends on its pack table, so the critical path has two phases.
        return max(
            _waves(tail_requests, concurrency),
            _waves(descriptor_requests, concurrency)
            + _waves(sealed_piles, concurrency),
        )

    first_has_pack = any(shape.packs for shape in shapes)
    first_has_tail = any(shape.tail for shape in shapes)
    return ShapeReport(
        len(inventories),
        durable_facts,
        target_mib,
        "idle-checkpoint" if force_seal_tail else "fixed-live-tail",
        len(piles),
        sum(pile.size for pile in piles),
        min(pile.size for pile in piles),
        round(statistics.median(pile.size for pile in piles)),
        _percentile([pile.size for pile in piles], .95),
        max(pile.size for pile in piles),
        max(sum(pile.size for pile in value.piles)
            for value in inventories),
        len(packs),
        sealed_piles,
        sum(pack.body_bytes for pack in packs),
        round(statistics.mean(
            pack.body_bytes for pack in packs)) if packs else 0,
        max((pack.body_bytes for pack in packs), default=0),
        sum(pack.descriptor_bytes for pack in packs),
        round(
            100 * sum(pack.descriptor_bytes for pack in packs)
            / sum(pack.body_bytes for pack in packs),
            4,
        ) if packs else 0.0,
        round(
            statistics.mean(pack.body_bytes for pack in packs)
            / statistics.median(pile.size for pile in piles),
            2,
        ) if packs else 0.0,
        len(tails),
        sum(pile.size for pile in tails),
        tail_requests,
        whole_requests,
        _waves(whole_requests, 32),
        _waves(whole_requests, 64),
        exact_requests,
        exact_waves(32),
        exact_waves(64),
        2 if first_has_pack else int(first_has_tail),
        int(first_has_pack or first_has_tail),
    )


def run(
        writers=DEFAULT_WRITERS, targets_mib=DEFAULT_TARGETS_MIB,
        durable_facts=LARGE_DURABLE_FACTS, include_forced=True):
    out = []
    for writer_count in writers:
        started = time.perf_counter()
        inventories = build_inventory(writer_count, durable_facts)
        generation_seconds = time.perf_counter() - started
        for target in targets_mib:
            value = asdict(report(
                inventories, target, durable_facts))
            value["fixture_generation_seconds"] = generation_seconds
            out.append(value)
            if include_forced:
                forced = asdict(report(
                    inventories, target, durable_facts,
                    force_seal_tail=True))
                forced["fixture_generation_seconds"] = generation_seconds
                out.append(forced)
    return tuple(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Measure writer-local sealed-pack storage shape")
    parser.add_argument(
        "--writers", type=int, nargs="+", default=DEFAULT_WRITERS)
    parser.add_argument(
        "--targets-mib", type=int, nargs="+", default=DEFAULT_TARGETS_MIB)
    parser.add_argument(
        "--durable-facts", type=int, default=LARGE_DURABLE_FACTS)
    parser.add_argument("--no-idle-checkpoint", action="store_true")
    args = parser.parse_args(argv)
    for value in run(
            tuple(args.writers), tuple(args.targets_mib),
            args.durable_facts,
            include_forced=not args.no_idle_checkpoint):
        print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
