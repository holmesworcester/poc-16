"""Measure source-local writer layouts over real signed-pile fixtures.

This is a storage-shape model, not a second protocol. It generates the same
deterministic one-message closed piles as ``bench_writer_p2p_scale``. The
logical RBSR tree remains publication-sequence to signed-pile OID regardless
of the optional physical policy measured here.

Every writer-local pack is an immutable concatenation of complete piles. One
canonical :class:`core.writer_layout.LayoutPage` covers each deterministic
16,384-sequence window and inlines all of that window's ``PackPlacement``
tables. A cold reader derives and opens every occupied window key once, then
fetches each covered pack body once and each uncovered pile by its OID. Exact
range reads reuse the page. Missing pages mean that the whole window is loose.

The benchmark compares four policies:

* loose piles, sealing fixed history at 256 piles or the byte target;
* the same policy plus one asynchronous tail checkpoint;
* a current tail body and page rewritten after every append;
* immutable power-of-two tail runs formed by binary carry.

Retained bytes and cumulative uploads use the running LayoutPage codec. Page
CAS writes are charged whenever a policy changes its visible placements. RBSR
pages, writer heads, HTTP headers, and provider metadata are common or outside
this physical-layout comparison and are not counted.
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
from core.limits import MAX_SEMANTIC_PILE_BYTES, MIB
from core.writer_layout import (
    MAX_LAYOUT_PACK_BYTES,
    WINDOW_PILES,
    LayoutPage,
    PackPlacement,
    encode_layout_page,
    window_start,
)
from facts.auth.signature import signature as signature_fact


DEFAULT_TARGETS_MIB = (4, 16, 64, 100)
DEFAULT_WRITERS = (100, 1_000)
MAX_PILES_PER_PACK = 256
MAX_PACK_BYTES = MAX_LAYOUT_PACK_BYTES
FETCH_CONCURRENCIES = (32, 64)
PACK_OID_PLACEHOLDER = "0" * 64


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

    def __post_init__(self):
        if not self.piles \
                or any(
                    pile.sequence != self.piles[0].sequence + offset
                    for offset, pile in enumerate(self.piles)) \
                or window_start(self.piles[0].sequence) != window_start(
                    self.piles[-1].sequence) \
                or self.body_bytes > MAX_PACK_BYTES:
            raise ValueError("writer physical pack")

    @property
    def first(self):
        return self.piles[0].sequence

    @property
    def body_bytes(self):
        return sum(pile.size for pile in self.piles)

    @property
    def lengths(self):
        return tuple(pile.size for pile in self.piles)


@dataclass(frozen=True, slots=True)
class WriterShape:
    sealed: tuple[PhysicalPack, ...]
    tail: tuple[PileRef, ...]


@dataclass(frozen=True, slots=True)
class PolicyState:
    packs: tuple[PhysicalPack, ...]
    loose: tuple[PileRef, ...]
    body_writes: int
    body_bytes: int
    layout_writes: int
    layout_bytes: int


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
    pack_body_objects: int
    loose_objects: int
    layout_window_lookups: int
    layout_page_objects: int
    missing_layout_pages: int
    retained_store_objects: int
    packed_piles: int
    packed_body_bytes: int
    average_pack_body_bytes: int
    max_pack_body_bytes: int
    layout_page_bytes: int
    layout_overhead_percent: float
    retained_bytes: int
    cumulative_body_writes: int
    cumulative_layout_writes: int
    cumulative_upload_writes: int
    cumulative_body_bytes: int
    cumulative_layout_bytes: int
    cumulative_upload_bytes: int
    upload_amplification: float
    whole_cold_requests: int
    whole_cold_waves_32: int
    whole_cold_waves_64: int
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


def _pack(piles):
    return PhysicalPack(tuple(piles))


def _placement(pack):
    return PackPlacement(
        pack.first,
        PACK_OID_PLACEHOLDER,
        pack.body_bytes,
        pack.lengths,
    )


def _layout_page(inventory, packs, start):
    placements = tuple(
        _placement(pack)
        for pack in sorted(packs, key=lambda value: value.first)
        if window_start(pack.first) == start
    )
    return LayoutPage(
        inventory.workspace, inventory.writer, start, placements)


def _retained_pages(inventory, packs):
    starts = sorted({window_start(pack.first) for pack in packs})
    return tuple(_layout_page(inventory, packs, start) for start in starts)


def _page_write_bytes(inventory, visible_packs, changed_sequence):
    page = _layout_page(
        inventory, visible_packs, window_start(changed_sequence))
    return len(encode_layout_page(page))


def writer_shape(inventory, target_bytes, *, force_seal_tail=False):
    """Form fixed packs without crossing a deterministic layout window."""
    if type(target_bytes) is not int or target_bytes < 1:
        raise ValueError("pack target")
    target_bytes = min(target_bytes, MAX_PACK_BYTES)
    sealed, pending, pending_bytes = [], [], 0

    def seal():
        nonlocal pending, pending_bytes
        if pending:
            sealed.append(_pack(pending))
            pending, pending_bytes = [], 0

    for pile in inventory.piles:
        if pile.size > MAX_SEMANTIC_PILE_BYTES:
            raise ValueError("pile exceeds protocol limit")
        if pile.size > target_bytes:
            # A caller may benchmark a target below the shared semantic-
            # object ceiling. A complete pile remains indivisible.
            seal()
            sealed.append(_pack((pile,)))
            continue
        if pending and (
                window_start(pending[0].sequence)
                != window_start(pile.sequence)
                or len(pending) == MAX_PILES_PER_PACK
                or pending_bytes + pile.size > target_bytes):
            seal()
        pending.append(pile)
        pending_bytes += pile.size
        if len(pending) == MAX_PILES_PER_PACK \
                or pending_bytes == target_bytes:
            seal()
    if force_seal_tail:
        seal()
    return WriterShape(tuple(sealed), tuple(pending))


def _loose_state(inventory, shape, *, checkpoint=False):
    packs = list(shape.sealed)
    loose = shape.tail
    body_writes = len(inventory.piles)
    body_bytes = sum(pile.size for pile in inventory.piles)
    layout_writes = layout_bytes = 0
    visible = []
    for pack in shape.sealed:
        body_writes += 1
        body_bytes += pack.body_bytes
        visible.append(pack)
        layout_writes += 1
        layout_bytes += _page_write_bytes(
            inventory, visible, pack.first)
    if checkpoint and loose:
        pack = _pack(loose)
        packs.append(pack)
        body_writes += 1
        body_bytes += pack.body_bytes
        visible.append(pack)
        layout_writes += 1
        layout_bytes += _page_write_bytes(
            inventory, visible, pack.first)
        loose = ()
    return PolicyState(
        tuple(packs), tuple(loose), body_writes, body_bytes,
        layout_writes, layout_bytes)


def _rewritten_state(inventory, shape):
    chunks = tuple(pack.piles for pack in shape.sealed) + (
        (shape.tail,) if shape.tail else ())
    visible = []
    body_writes = body_bytes = layout_writes = layout_bytes = 0
    for chunk in chunks:
        current = None
        for size in range(1, len(chunk) + 1):
            current = _pack(chunk[:size])
            body_writes += 1
            body_bytes += current.body_bytes
            layout_writes += 1
            layout_bytes += _page_write_bytes(
                inventory, (*visible, current), current.first)
        visible.append(current)
    return PolicyState(
        tuple(visible), (), body_writes, body_bytes,
        layout_writes, layout_bytes)


def _geometric_state(inventory, shape):
    chunks = tuple((pack.piles, True) for pack in shape.sealed) + (
        ((shape.tail, False),) if shape.tail else ())
    visible = []
    body_writes = body_bytes = layout_writes = layout_bytes = 0
    for chunk, sealed in chunks:
        levels = {}
        runs = ()
        for pile in chunk:
            current = _pack((pile,))
            body_writes += 1
            body_bytes += current.body_bytes
            level = 0
            while level in levels:
                current = _pack(levels.pop(level).piles + current.piles)
                body_writes += 1
                body_bytes += current.body_bytes
                level += 1
            levels[level] = current
            runs = tuple(sorted(
                levels.values(), key=lambda value: value.first))
            layout_writes += 1
            layout_bytes += _page_write_bytes(
                inventory, (*visible, *runs), current.first)
        if sealed and len(runs) != 1:
            final = _pack(chunk)
            body_writes += 1
            body_bytes += final.body_bytes
            runs = (final,)
            layout_writes += 1
            layout_bytes += _page_write_bytes(
                inventory, (*visible, final), final.first)
        visible.extend(runs)
    return PolicyState(
        tuple(visible), (), body_writes, body_bytes,
        layout_writes, layout_bytes)


def _policy_states(inventory, shape):
    return (
        ("loose-piles", _loose_state(inventory, shape)),
        ("loose-idle-checkpoint", _loose_state(
            inventory, shape, checkpoint=True)),
        ("rewritten-tail-pack", _rewritten_state(inventory, shape)),
        ("geometric-runs", _geometric_state(inventory, shape)),
    )


def _waves(requests, concurrency):
    return math.ceil(requests / concurrency) if requests else 0


def reports(
        inventories, target_mib, durable_facts=LARGE_DURABLE_FACTS):
    inventories = tuple(inventories)
    shapes = tuple(writer_shape(
        inventory, target_mib * MIB) for inventory in inventories)
    grouped = {}
    for inventory, shape in zip(inventories, shapes):
        for policy, state in _policy_states(inventory, shape):
            grouped.setdefault(policy, []).append(state)
    piles = tuple(
        pile for inventory in inventories for pile in inventory.piles)
    raw_bytes = sum(pile.size for pile in piles)
    window_lookups = sum(
        len({window_start(pile.sequence) for pile in inventory.piles})
        for inventory in inventories)
    out = []
    for policy, states in grouped.items():
        packs = tuple(pack for state in states for pack in state.packs)
        loose = tuple(pile for state in states for pile in state.loose)
        packed_piles = sum(len(pack.piles) for pack in packs)
        if packed_piles + len(loose) != len(piles) \
                or sum(pack.body_bytes for pack in packs) \
                + sum(pile.size for pile in loose) != raw_bytes:
            raise AssertionError("physical policy lost or duplicated a pile")
        pages = tuple(
            page
            for inventory, state in zip(inventories, states)
            for page in _retained_pages(inventory, state.packs)
        )
        page_bytes = sum(len(encode_layout_page(page)) for page in pages)
        packed_bytes = sum(pack.body_bytes for pack in packs)
        body_writes = sum(state.body_writes for state in states)
        body_uploaded = sum(state.body_bytes for state in states)
        layout_writes = sum(state.layout_writes for state in states)
        layout_uploaded = sum(state.layout_bytes for state in states)
        whole_payloads = len(packs) + len(loose)
        exact_payloads = packed_piles + len(loose)

        def dependent_waves(payloads, concurrency):
            return _waves(window_lookups, concurrency) + _waves(
                payloads, concurrency)

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
                sum(pile.size for pile in inventory.piles)
                for inventory in inventories),
            sealed_packs=sum(len(shape.sealed) for shape in shapes),
            tail_piles=sum(len(shape.tail) for shape in shapes),
            pack_body_objects=len(packs),
            loose_objects=len(loose),
            layout_window_lookups=window_lookups,
            layout_page_objects=len(pages),
            missing_layout_pages=window_lookups - len(pages),
            retained_store_objects=(
                len(pages) + len(packs) + len(loose)),
            packed_piles=packed_piles,
            packed_body_bytes=packed_bytes,
            average_pack_body_bytes=round(statistics.mean(
                pack.body_bytes for pack in packs)) if packs else 0,
            max_pack_body_bytes=max(
                (pack.body_bytes for pack in packs), default=0),
            layout_page_bytes=page_bytes,
            layout_overhead_percent=(
                round(100 * page_bytes / raw_bytes, 4)
                if raw_bytes else 0.0),
            retained_bytes=raw_bytes + page_bytes,
            cumulative_body_writes=body_writes,
            cumulative_layout_writes=layout_writes,
            cumulative_upload_writes=body_writes + layout_writes,
            cumulative_body_bytes=body_uploaded,
            cumulative_layout_bytes=layout_uploaded,
            cumulative_upload_bytes=body_uploaded + layout_uploaded,
            upload_amplification=round(
                (body_uploaded + layout_uploaded) / raw_bytes, 4),
            whole_cold_requests=window_lookups + whole_payloads,
            whole_cold_waves_32=dependent_waves(whole_payloads, 32),
            whole_cold_waves_64=dependent_waves(whole_payloads, 64),
            exact_range_requests=window_lookups + exact_payloads,
            exact_range_waves_32=dependent_waves(exact_payloads, 32),
            exact_range_waves_64=dependent_waves(exact_payloads, 64),
            point_read_cold_requests=2,
            point_read_warm_requests=1,
        ))
    return tuple(out)


def report(
        inventories, target_mib, durable_facts=LARGE_DURABLE_FACTS, *,
        policy="loose-piles"):
    """Return one named policy for focused tests and interactive accounting."""
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
        description="Measure source-local writer layout shape")
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
