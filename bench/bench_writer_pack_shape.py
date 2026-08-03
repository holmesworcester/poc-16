"""Measure writer-local physical packs over real signed-pile fixtures.

This is a storage-shape model, not a protocol implementation. It generates the
same deterministic one-message closed piles as ``bench_writer_p2p_scale``.
The logical RBSR pile tree remains independent of all physical choices below.

Every writer seals history at 256 piles or before the next pile would exceed
the byte target. Its final sub-target tail is then modeled four ways:

* individually addressed loose pile objects;
* loose piles followed by one idle/checkpoint pack;
* one content-addressed tail pack rewritten after every append;
* immutable power-of-two runs formed by binary carry, with optional idle seal.

Every physical run is two immutable objects, matching ``writer_bundle.py``:
writer-local raw pile concatenation, plus the canonical BundlePack locator with
``[offset, length]`` rows, the derived logical-bundle OID, and the body OID. The
table is untrusted; the logical RBSR rows supply expected pile OIDs, and every
extracted pile retains OID, signature, and closure checks.
A whole run therefore costs two cold GETs (locator then body). An exact pile is
also two cold GETs (locator then a body range), or one range with a cached
locator. Loose piles cost one portable object GET each. Current dependency-wave
accounting fetches locators before bodies; a future catalog containing both
OIDs could overlap those two GETs, but cannot turn them into one request.

The report also derives the proposed fixed-window LayoutPage shape separately.
One directly addressed page inlines every run locator for its 256-pile/byte
window, so a cold fetch reads that page once and then its body objects; exact
range hits reuse the page. Fields without an ``inline_`` prefix measure the
current BundlePack sidecar codec, including retained bytes and cumulative
uploads. The future page codec is not specified, so inline accounting covers
only object, request, and dependency-wave counts rather than inventing bytes.

RBSR tree and head objects are common to every policy and excluded from this
physical-layout comparison. The logical WriterBundle document is derived from
authenticated tree rows and is not fetched as a third physical object.
Responses overlap across writers at bounded concurrency 32 or 64; runs never
cross writers.
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
from core.limits import MAX_PILE_BYTES
from core.writer_bundle import (
    MAX_BUNDLE_PACK_BYTES,
    PACK_FORMAT,
)
from facts.auth.signature import signature as signature_fact


MIB = 1024 * 1024
DEFAULT_TARGETS_MIB = (4, 16, 64, 100)
DEFAULT_WRITERS = (100, 1_000)
MAX_PILES_PER_PACK = 256
MAX_PACK_BYTES = MAX_BUNDLE_PACK_BYTES
FETCH_CONCURRENCIES = (32, 64)


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
class PolicyState:
    packs: tuple[PhysicalPack, ...]
    loose: tuple[PileRef, ...]
    layout_pages: int
    upload_writes: int
    upload_bytes: int


@dataclass(frozen=True, slots=True)
class ShapeReport:
    writers: int
    durable_facts: int
    target_mib: int
    effective_target_mib: int
    policy: str
    piles: int
    pile_bytes: int
    pile_min_bytes: int
    pile_median_bytes: int
    pile_p95_bytes: int
    pile_max_bytes: int
    max_writer_bytes: int
    sealed_packs: int
    tail_piles: int
    pack_runs: int
    locator_objects: int
    pack_body_objects: int
    loose_objects: int
    retained_store_objects: int
    inline_layout_pages: int
    inline_retained_store_objects: int
    packed_piles: int
    packed_body_bytes: int
    average_pack_body_bytes: int
    max_pack_body_bytes: int
    max_pack_total_bytes: int
    descriptor_bytes: int
    descriptor_overhead_percent: float
    retained_bytes: int
    cumulative_upload_writes: int
    cumulative_upload_bytes: int
    upload_amplification: float
    whole_cold_requests: int
    whole_cold_waves_32: int
    whole_cold_waves_64: int
    inline_whole_cold_requests: int
    inline_whole_cold_waves_32: int
    inline_whole_cold_waves_64: int
    exact_range_requests: int
    exact_range_waves_32: int
    exact_range_waves_64: int
    inline_exact_range_requests: int
    inline_exact_range_waves_32: int
    inline_exact_range_waves_64: int
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


def _empty_descriptor_size(body_bytes):
    return len(canon({
        "bundle": "0" * 64,
        "format": PACK_FORMAT,
        "pack": {
            "bytes": body_bytes,
            "oid": "0" * 64,
        },
        "table": [],
    }))


def _descriptor_sizes(piles):
    """Exact canonical table bytes for every prefix in one physical run."""
    offset = row_bytes = 0
    out = []
    for pile in piles:
        row_bytes += len(canon([offset, pile.size]))
        offset += pile.size
        # Replacing the empty list's interior adds encoded rows and commas.
        out.append(
            _empty_descriptor_size(offset)
            + row_bytes + len(out))
    return tuple(out)


def _pack(piles):
    piles = tuple(piles)
    return PhysicalPack(
        piles,
        sum(pile.size for pile in piles),
        _descriptor_sizes(piles)[-1],
    )


def writer_shape(inventory, target_bytes, *, force_seal_tail=False):
    """Greedily form bounded packs while leaving at most one loose tail."""
    if type(target_bytes) is not int or target_bytes < 1:
        raise ValueError("pack target")
    target_bytes = min(target_bytes, MAX_PACK_BYTES)
    packs, pending, pending_bytes = [], [], 0

    def seal():
        nonlocal pending, pending_bytes
        if pending:
            values = tuple(pending)
            packs.append(_pack(values))
            pending, pending_bytes = [], 0

    for pile in inventory.piles:
        if pile.size > MAX_PILE_BYTES:
            raise ValueError("pile exceeds protocol limit")
        if pile.size > target_bytes:
            # A valid 4--5 MiB pile cannot fit the nominal 4 MiB target.
            # Preserve it whole as one writer-local run instead of rejecting
            # valid protocol input. The 95 MiB bound applies to the body;
            # BundlePack's small locator is a separate bounded object.
            seal()
            packs.append(_pack((pile,)))
            continue
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


def _loose_state(inventory, shape, *, checkpoint=False):
    packs = list(shape.packs)
    loose = shape.tail
    layout_pages = len(shape.packs)
    upload_bytes = sum(pile.size for pile in inventory.piles)
    upload_writes = len(inventory.piles)
    for pack in shape.packs:
        upload_bytes += pack.body_bytes + pack.descriptor_bytes
        upload_writes += 2
    if checkpoint and loose:
        pack = _pack(loose)
        packs.append(pack)
        upload_bytes += pack.body_bytes + pack.descriptor_bytes
        upload_writes += 2
        layout_pages += 1
        loose = ()
    return PolicyState(
        tuple(packs), tuple(loose), layout_pages,
        upload_writes, upload_bytes)


def _rewritten_state(shape):
    chunks = tuple(pack.piles for pack in shape.packs) + (
        (shape.tail,) if shape.tail else ())
    upload_bytes = upload_writes = 0
    for chunk in chunks:
        body = 0
        for pile, descriptor in zip(
                chunk, _descriptor_sizes(chunk)):
            body += pile.size
            upload_bytes += body + descriptor
            upload_writes += 2
    packs = tuple(shape.packs) + (
        (_pack(shape.tail),) if shape.tail else ())
    return PolicyState(
        packs, (), len(chunks), upload_writes, upload_bytes)


def _geometric_run(piles):
    levels = {}
    upload_bytes = upload_writes = 0
    for pile in piles:
        current = _pack((pile,))
        upload_bytes += current.body_bytes + current.descriptor_bytes
        upload_writes += 2
        level = 0
        while level in levels:
            current = _pack(levels.pop(level).piles + current.piles)
            upload_bytes += current.body_bytes + current.descriptor_bytes
            upload_writes += 2
            level += 1
        levels[level] = current
    runs = tuple(sorted(
        levels.values(), key=lambda pack: pack.piles[0].sequence))
    return runs, upload_writes, upload_bytes


def _geometric_state(shape, *, checkpoint=False):
    upload_bytes = upload_writes = 0
    for sealed in shape.packs:
        runs, writes, uploaded = _geometric_run(sealed.piles)
        upload_bytes += uploaded
        upload_writes += writes
        if len(runs) != 1 or runs[0].piles != sealed.piles:
            upload_bytes += sealed.body_bytes + sealed.descriptor_bytes
            upload_writes += 2
    tail_runs, writes, uploaded = _geometric_run(shape.tail)
    upload_bytes += uploaded
    upload_writes += writes
    if checkpoint and shape.tail:
        tail = _pack(shape.tail)
        if len(tail_runs) != 1 or tail_runs[0].piles != shape.tail:
            upload_bytes += tail.body_bytes + tail.descriptor_bytes
            upload_writes += 2
        tail_runs = (tail,)
    return PolicyState(
        tuple(shape.packs) + tail_runs,
        (),
        len(shape.packs) + int(bool(shape.tail)),
        upload_writes,
        upload_bytes,
    )


def _policy_states(inventory, shape):
    return (
        ("loose-piles", _loose_state(inventory, shape)),
        ("loose-idle-checkpoint", _loose_state(
            inventory, shape, checkpoint=True)),
        ("rewritten-tail-pack", _rewritten_state(shape)),
        ("geometric-runs", _geometric_state(shape)),
        ("geometric-idle-checkpoint", _geometric_state(
            shape, checkpoint=True)),
    )


def reports(
        inventories, target_mib, durable_facts=LARGE_DURABLE_FACTS):
    shapes = tuple(writer_shape(
        inventory, target_mib * MIB) for inventory in inventories)
    grouped = {}
    for inventory, shape in zip(inventories, shapes):
        for policy, state in _policy_states(inventory, shape):
            grouped.setdefault(policy, []).append(state)
    piles = tuple(
        pile for inventory in inventories for pile in inventory.piles)
    raw_bytes = sum(pile.size for pile in piles)
    sealed_packs = sum(len(shape.packs) for shape in shapes)
    tail_piles = sum(len(shape.tail) for shape in shapes)
    out = []
    for policy, states in grouped.items():
        packs = tuple(pack for state in states for pack in state.packs)
        loose = tuple(pile for state in states for pile in state.loose)
        layout_pages = sum(state.layout_pages for state in states)
        packed_piles = sum(len(pack.piles) for pack in packs)
        if packed_piles + len(loose) != len(piles):
            raise AssertionError("physical policy lost or duplicated a pile")
        # Each run is a locator object plus a concatenated body object.
        whole_requests = 2 * len(packs) + len(loose)
        exact_requests = len(packs) + packed_piles + len(loose)
        inline_whole_requests = layout_pages + len(packs) + len(loose)
        inline_exact_requests = layout_pages + packed_piles + len(loose)

        def dependent_waves(
                locator_requests, payload_requests, concurrency):
            # The current locator contains the body OID. Fetch all locators,
            # then overlap their body/range reads with direct loose GETs.
            return _waves(locator_requests, concurrency) + _waves(
                payload_requests + len(loose), concurrency)

        descriptor_bytes = sum(pack.descriptor_bytes for pack in packs)
        packed_bytes = sum(pack.body_bytes for pack in packs)
        uploaded = sum(state.upload_bytes for state in states)
        writes = sum(state.upload_writes for state in states)
        out.append(ShapeReport(
            writers=len(inventories),
            durable_facts=durable_facts,
            target_mib=target_mib,
            effective_target_mib=min(
                target_mib, MAX_PACK_BYTES // MIB),
            policy=policy,
            piles=len(piles),
            pile_bytes=raw_bytes,
            pile_min_bytes=min(pile.size for pile in piles),
            pile_median_bytes=round(statistics.median(
                pile.size for pile in piles)),
            pile_p95_bytes=_percentile(
                [pile.size for pile in piles], .95),
            pile_max_bytes=max(pile.size for pile in piles),
            max_writer_bytes=max(
                sum(pile.size for pile in value.piles)
                for value in inventories),
            sealed_packs=sealed_packs,
            tail_piles=tail_piles,
            pack_runs=len(packs),
            locator_objects=len(packs),
            pack_body_objects=len(packs),
            loose_objects=len(loose),
            retained_store_objects=2 * len(packs) + len(loose),
            inline_layout_pages=layout_pages,
            inline_retained_store_objects=(
                layout_pages + len(packs) + len(loose)),
            packed_piles=packed_piles,
            packed_body_bytes=packed_bytes,
            average_pack_body_bytes=round(statistics.mean(
                pack.body_bytes for pack in packs)) if packs else 0,
            max_pack_body_bytes=max(
                (pack.body_bytes for pack in packs), default=0),
            max_pack_total_bytes=max(
                (pack.body_bytes + pack.descriptor_bytes
                 for pack in packs), default=0),
            descriptor_bytes=descriptor_bytes,
            descriptor_overhead_percent=(
                round(100 * descriptor_bytes / packed_bytes, 4)
                if packed_bytes else 0.0),
            retained_bytes=raw_bytes + descriptor_bytes,
            cumulative_upload_writes=writes,
            cumulative_upload_bytes=uploaded,
            upload_amplification=round(uploaded / raw_bytes, 4),
            whole_cold_requests=whole_requests,
            whole_cold_waves_32=dependent_waves(
                len(packs), len(packs), 32),
            whole_cold_waves_64=dependent_waves(
                len(packs), len(packs), 64),
            inline_whole_cold_requests=inline_whole_requests,
            inline_whole_cold_waves_32=dependent_waves(
                layout_pages, len(packs), 32),
            inline_whole_cold_waves_64=dependent_waves(
                layout_pages, len(packs), 64),
            exact_range_requests=exact_requests,
            exact_range_waves_32=dependent_waves(
                len(packs), packed_piles, 32),
            exact_range_waves_64=dependent_waves(
                len(packs), packed_piles, 64),
            inline_exact_range_requests=inline_exact_requests,
            inline_exact_range_waves_32=dependent_waves(
                layout_pages, packed_piles, 32),
            inline_exact_range_waves_64=dependent_waves(
                layout_pages, packed_piles, 64),
            point_read_cold_requests=(
                2 if packs else int(bool(loose))),
            point_read_warm_requests=int(bool(packs or loose)),
        ))
    return tuple(out)


def report(
        inventories, target_mib, durable_facts=LARGE_DURABLE_FACTS, *,
        policy="loose-piles"):
    """Return one named policy for small tests and interactive accounting."""
    return next(value for value in reports(
        inventories, target_mib, durable_facts) if value.policy == policy)


def run(
        writers=DEFAULT_WRITERS, targets_mib=DEFAULT_TARGETS_MIB,
        durable_facts=LARGE_DURABLE_FACTS):
    out = []
    for writer_count in writers:
        started = time.perf_counter()
        inventories = build_inventory(writer_count, durable_facts)
        generation_seconds = time.perf_counter() - started
        for target in targets_mib:
            for result in reports(inventories, target, durable_facts):
                value = asdict(result)
                value["fixture_generation_seconds"] = generation_seconds
                out.append(value)
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
    args = parser.parse_args(argv)
    for value in run(
            tuple(args.writers), tuple(args.targets_mib),
            args.durable_facts):
        print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
