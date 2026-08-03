"""Ratchets for writer-local LayoutPage physical accounting."""
import pytest

from bench.bench_writer_pack_shape import (
    DEFAULT_TARGETS_MIB,
    FETCH_CONCURRENCIES,
    MAX_PACK_BYTES,
    MAX_PILES_PER_PACK,
    MIB,
    PileRef,
    WriterInventory,
    build_inventory,
    report,
    reports,
    writer_shape,
)
from core.limits import MAX_PILE_BYTES, MAX_REPOSITORY_OBJECT_BYTES
from core.writer_layout import (
    WINDOW_PILES,
    LayoutPage,
    PackPlacement,
    encode_layout_page,
)


def inventory(count, size=100, *, first=1):
    return WriterInventory(
        "a" * 64,
        "b" * 64,
        tuple(PileRef(
            first + offset,
            f"{first + offset:064x}",
            size,
        ) for offset in range(count)),
    )


def test_pack_defaults_share_the_running_layout_bounds():
    assert DEFAULT_TARGETS_MIB == (4, 16, 64, 100)
    assert MAX_PILES_PER_PACK == 256
    assert MAX_PACK_BYTES == 95 * MIB
    assert MAX_PILE_BYTES == MAX_REPOSITORY_OBJECT_BYTES == 4 * MIB
    assert WINDOW_PILES == 16_384
    assert FETCH_CONCURRENCIES == (32, 64)


def test_benchmark_prices_the_running_inline_layout_page_codec():
    source = inventory(3)
    measured = report(
        (source,), 4, durable_facts=3,
        policy="loose-idle-checkpoint")
    placement = PackPlacement(
        1, "0" * 64, 300, (100, 100, 100))
    page = LayoutPage(
        source.workspace, source.writer, 1, (placement,))

    assert measured.layout_page_objects == 1
    assert measured.layout_page_bytes == len(encode_layout_page(page))
    assert measured.cumulative_layout_writes == 1
    assert measured.cumulative_layout_bytes == len(encode_layout_page(page))


def test_real_signed_pile_distillation_counts_page_then_payloads():
    inventories = build_inventory(4, durable_facts=100)
    by_policy = {
        value.policy: value
        for value in reports(inventories, 4, durable_facts=100)
    }
    loose = by_policy["loose-piles"]

    assert (
        loose.piles,
        loose.pile_bytes,
        loose.pile_min_bytes,
        loose.pile_median_bytes,
        loose.pile_p95_bytes,
        loose.pile_max_bytes,
        loose.max_writer_bytes,
    ) == (45, 176_261, 2_886, 4_277, 4_278, 4_278, 47_048)
    assert (
        loose.sealed_packs,
        loose.tail_piles,
        loose.pack_body_objects,
        loose.loose_objects,
        loose.layout_window_lookups,
        loose.layout_page_objects,
        loose.missing_layout_pages,
        loose.whole_cold_requests,
        loose.whole_cold_waves_32,
        loose.whole_cold_waves_64,
    ) == (0, 45, 0, 45, 4, 0, 4, 49, 3, 2)
    assert loose.exact_range_requests == 49
    assert loose.upload_amplification == 1.0

    checkpoint = by_policy["loose-idle-checkpoint"]
    assert (
        checkpoint.pack_body_objects,
        checkpoint.loose_objects,
        checkpoint.layout_window_lookups,
        checkpoint.layout_page_objects,
        checkpoint.missing_layout_pages,
    ) == (4, 0, 4, 4, 0)
    assert checkpoint.whole_cold_requests == 8
    assert checkpoint.exact_range_requests == 49
    assert checkpoint.cumulative_body_writes == 49
    assert checkpoint.cumulative_layout_writes == 4
    assert checkpoint.point_read_cold_requests == 2
    assert checkpoint.point_read_warm_requests == 1


def test_live_tail_policies_expose_page_and_body_write_tradeoff():
    values = {
        value.policy: value
        for value in reports((inventory(6),), 4, durable_facts=6)
    }
    loose = values["loose-piles"]
    checkpoint = values["loose-idle-checkpoint"]
    rewritten = values["rewritten-tail-pack"]
    geometric = values["geometric-runs"]

    assert (
        loose.whole_cold_requests,
        loose.cumulative_body_writes,
        loose.cumulative_layout_writes,
    ) == (7, 6, 0)
    assert (
        checkpoint.whole_cold_requests,
        checkpoint.cumulative_body_writes,
        checkpoint.cumulative_layout_writes,
    ) == (2, 7, 1)
    # One current prefix body and one page CAS per append.
    assert (
        rewritten.whole_cold_requests,
        rewritten.cumulative_body_writes,
        rewritten.cumulative_layout_writes,
        rewritten.cumulative_body_bytes,
    ) == (2, 6, 6, 2_100)
    # Binary carry leaves 4-pile and 2-pile bodies but updates one page.
    assert (
        geometric.pack_body_objects,
        geometric.layout_page_objects,
        geometric.whole_cold_requests,
        geometric.cumulative_body_writes,
        geometric.cumulative_layout_writes,
        geometric.cumulative_body_bytes,
    ) == (2, 1, 3, 10, 6, 1_600)
    assert geometric.exact_range_requests == 7


def test_dual_trigger_and_layout_window_never_split_a_pile():
    count_shape = writer_shape(inventory(257), 4 * MIB)
    assert tuple(len(pack.piles) for pack in count_shape.sealed) == (256,)
    assert len(count_shape.tail) == 1

    byte_source = WriterInventory(
        "a" * 64,
        "b" * 64,
        (
            PileRef(1, "1" * 64, 3 * MIB),
            PileRef(2, "2" * 64, 2 * MIB),
        ),
    )
    byte_shape = writer_shape(byte_source, 4 * MIB)
    assert tuple(pack.body_bytes for pack in byte_shape.sealed) == (3 * MIB,)
    assert tuple(pile.sequence for pile in byte_shape.tail) == (2,)

    boundary = writer_shape(
        inventory(2, first=WINDOW_PILES), 4 * MIB)
    assert tuple(len(pack.piles) for pack in boundary.sealed) == (1,)
    assert tuple(pile.sequence for pile in boundary.tail) == (
        WINDOW_PILES + 1,)


def test_valid_pile_above_a_small_target_becomes_one_pile_pack():
    valid = WriterInventory(
        "a" * 64,
        "b" * 64,
        (PileRef(1, "1" * 64, 2 * MIB + 1),),
    )
    shape = writer_shape(valid, 2 * MIB)
    assert tuple(len(pack.piles) for pack in shape.sealed) == (1,)
    assert shape.sealed[0].body_bytes == 2 * MIB + 1
    assert shape.tail == ()

    maximum = WriterInventory(
        "a" * 64,
        "b" * 64,
        (PileRef(1, "1" * 64, MAX_PILE_BYTES),),
    )
    assert len(writer_shape(maximum, 4 * MIB).sealed) == 1


def test_protocol_oversize_pile_is_rejected_and_target_is_clamped():
    oversize = WriterInventory(
        "a" * 64,
        "b" * 64,
        (PileRef(1, "1" * 64, MAX_PILE_BYTES + 1),),
    )
    with pytest.raises(ValueError, match="protocol limit"):
        writer_shape(oversize, 100 * MIB)

    many = inventory(20, MAX_PILE_BYTES)
    shape = writer_shape(many, 100 * MIB, force_seal_tail=True)
    assert tuple(len(pack.piles) for pack in shape.sealed) == (20,)
    assert all(pack.body_bytes <= MAX_PACK_BYTES for pack in shape.sealed)
    assert report((many,), 100, durable_facts=20).effective_target_mib == 95


def test_many_pack_placements_share_one_deterministic_layout_page():
    values = {
        value.policy: value
        for value in reports((inventory(300),), 4, durable_facts=300)
    }
    checkpoint = values["loose-idle-checkpoint"]
    geometric = values["geometric-runs"]

    assert (
        checkpoint.pack_body_objects,
        checkpoint.layout_window_lookups,
        checkpoint.layout_page_objects,
        checkpoint.whole_cold_requests,
    ) == (2, 1, 1, 3)
    # One sealed 256-pile body plus popcount(44) == 3 tail bodies.
    assert (
        geometric.pack_body_objects,
        geometric.layout_window_lookups,
        geometric.layout_page_objects,
        geometric.whole_cold_requests,
        geometric.exact_range_requests,
    ) == (4, 1, 1, 5, 301)
