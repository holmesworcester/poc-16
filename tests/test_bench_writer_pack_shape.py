"""Ratchets for the writer-local physical pack accounting model."""
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
from core.crypto import h
from core.limits import MAX_PILE_BYTES
from core.writer_bundle import BundlePack, PackSlice, encode_bundle_pack


def inventory(count, size=100):
    return WriterInventory(
        "a" * 64,
        "b" * 64,
        tuple(PileRef(index, f"{index:064x}", size)
              for index in range(1, count + 1)),
    )


def test_pack_defaults_are_simple_fixed_bounds():
    assert DEFAULT_TARGETS_MIB == (4, 16, 64, 100)
    assert MAX_PILES_PER_PACK == 256
    assert MAX_PACK_BYTES == 95 * MIB
    assert MAX_PILE_BYTES == 5 * MIB
    assert FETCH_CONCURRENCIES == (32, 64)


def test_benchmark_prices_the_running_bundle_pack_sidecar_codec():
    source = inventory(3)
    measured = writer_shape(
        source, 4 * MIB, force_seal_tail=True).packs[0]
    locator = BundlePack(
        h(b"logical bundle"),
        h(b"concat body"),
        measured.body_bytes,
        tuple(PackSlice(index * 100, 100) for index in range(3)),
    )

    assert measured.descriptor_bytes == len(encode_bundle_pack(locator))


def test_real_signed_pile_distillation_charges_every_loose_get():
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
        loose.pack_runs,
        loose.loose_objects,
        loose.whole_cold_requests,
        loose.whole_cold_waves_32,
        loose.whole_cold_waves_64,
    ) == (0, 45, 0, 45, 45, 2, 1)
    assert loose.exact_range_requests == 45
    assert loose.upload_amplification == 1.0

    checkpoint = by_policy["loose-idle-checkpoint"]
    assert (
        checkpoint.pack_runs,
        checkpoint.loose_objects,
        checkpoint.packed_piles,
        checkpoint.descriptor_bytes,
        checkpoint.whole_cold_requests,
        checkpoint.exact_range_requests,
        checkpoint.exact_range_waves_32,
        checkpoint.exact_range_waves_64,
    ) == (4, 0, 45, 1_448, 8, 49, 3, 2)
    assert checkpoint.retained_store_objects == 8
    assert checkpoint.cumulative_upload_writes == 53
    assert checkpoint.cumulative_upload_bytes == 353_970
    assert checkpoint.point_read_cold_requests == 2
    assert checkpoint.point_read_warm_requests == 1


def test_live_tail_policies_expose_read_write_tradeoff():
    values = {
        value.policy: value
        for value in reports((inventory(6),), 4, durable_facts=6)
    }

    loose = values["loose-piles"]
    checkpoint = values["loose-idle-checkpoint"]
    rewritten = values["rewritten-tail-pack"]
    geometric = values["geometric-runs"]
    geometric_checkpoint = values["geometric-idle-checkpoint"]

    assert (loose.whole_cold_requests, loose.cumulative_upload_writes) == (6, 6)
    assert (checkpoint.whole_cold_requests,
            checkpoint.cumulative_upload_writes) == (2, 8)
    # Rewriting keeps one current run (two objects) but uploads all prefixes.
    assert (rewritten.whole_cold_requests,
            rewritten.cumulative_upload_writes) == (2, 12)
    assert rewritten.cumulative_upload_bytes == 3_618
    # Binary carry leaves the 4-pile and 2-pile runs: popcount(6) == 2.
    assert (geometric.whole_cold_requests,
            geometric.cumulative_upload_writes) == (4, 20)
    assert geometric.cumulative_upload_bytes == 3_940
    assert (
        geometric.inline_layout_pages,
        geometric.inline_whole_cold_requests,
        geometric.inline_exact_range_requests,
    ) == (1, 3, 7)
    assert (geometric_checkpoint.whole_cold_requests,
            geometric_checkpoint.cumulative_upload_writes) == (2, 22)


def test_dual_trigger_seals_at_count_or_before_byte_ceiling():
    count_shape = writer_shape(inventory(257), 4 * MIB)
    assert tuple(len(pack.piles) for pack in count_shape.packs) == (256,)
    assert len(count_shape.tail) == 1

    byte_inventory = WriterInventory(
        "a" * 64,
        "b" * 64,
        (
            PileRef(1, "1" * 64, 3 * MIB),
            PileRef(2, "2" * 64, 2 * MIB),
        ),
    )
    byte_shape = writer_shape(byte_inventory, 4 * MIB)
    assert tuple(pack.body_bytes for pack in byte_shape.packs) == (3 * MIB,)
    assert tuple(pile.sequence for pile in byte_shape.tail) == (2,)
    assert all(
        pack.body_bytes <= MAX_PACK_BYTES
        for pack in byte_shape.packs)


def test_valid_pile_above_nominal_target_becomes_one_pile_pack():
    valid = WriterInventory(
        "a" * 64,
        "b" * 64,
        (PileRef(1, "1" * 64, 4 * MIB + 1),),
    )
    shape = writer_shape(valid, 4 * MIB)
    assert tuple(len(pack.piles) for pack in shape.packs) == (1,)
    assert shape.packs[0].body_bytes == 4 * MIB + 1
    assert shape.tail == ()

    maximum = WriterInventory(
        "a" * 64,
        "b" * 64,
        (PileRef(1, "1" * 64, MAX_PILE_BYTES),),
    )
    assert len(writer_shape(maximum, 4 * MIB).packs) == 1


def test_protocol_oversize_pile_is_rejected_and_pack_target_is_clamped():
    oversize = WriterInventory(
        "a" * 64,
        "b" * 64,
        (PileRef(1, "1" * 64, MAX_PILE_BYTES + 1),),
    )
    with pytest.raises(ValueError, match="protocol limit"):
        writer_shape(oversize, 100 * MIB)

    many = inventory(20, MAX_PILE_BYTES)
    shape = writer_shape(many, 100 * MIB, force_seal_tail=True)
    assert tuple(len(pack.piles) for pack in shape.packs) == (19, 1)
    assert all(
        pack.body_bytes <= MAX_PACK_BYTES
        for pack in shape.packs)
    assert report((many,), 100, durable_facts=20).effective_target_mib == 95


def test_idle_checkpoint_seals_only_the_remaining_writer_local_tail():
    shape = writer_shape(
        inventory(257), 4 * MIB, force_seal_tail=True)
    assert tuple(len(pack.piles) for pack in shape.packs) == (256, 1)
    assert shape.tail == ()


def test_inline_layout_page_is_once_per_fixed_window_not_per_run():
    geometric = report(
        (inventory(300),), 4, durable_facts=300,
        policy="geometric-runs")

    # One sealed 256-pile body plus popcount(44) == 3 tail bodies.
    assert geometric.pack_runs == 4
    assert geometric.inline_layout_pages == 2
    assert geometric.whole_cold_requests == 8
    assert geometric.inline_whole_cold_requests == 6
    assert geometric.exact_range_requests == 304
    assert geometric.inline_exact_range_requests == 302
