"""Ratchets for the writer-local physical pack accounting model."""
from bench.bench_writer_pack_shape import (
    DEFAULT_TARGETS_MIB,
    FETCH_CONCURRENCIES,
    MAX_PILES_PER_PACK,
    MIB,
    PileRef,
    WriterInventory,
    build_inventory,
    report,
    writer_shape,
)


def test_pack_defaults_are_simple_fixed_bounds():
    assert DEFAULT_TARGETS_MIB == (4, 16, 64, 100)
    assert MAX_PILES_PER_PACK == 256
    assert FETCH_CONCURRENCIES == (32, 64)


def test_real_signed_pile_distillation_has_exact_storage_costs():
    inventories = build_inventory(4, durable_facts=100)
    live = report(inventories, 4, durable_facts=100)
    checkpoint = report(
        inventories, 4, durable_facts=100,
        force_seal_tail=True)

    assert (
        live.piles,
        live.pile_bytes,
        live.pile_min_bytes,
        live.pile_median_bytes,
        live.pile_p95_bytes,
        live.pile_max_bytes,
        live.max_writer_bytes,
    ) == (45, 176_261, 2_886, 4_277, 4_278, 4_278, 47_048)
    assert (
        live.sealed_packs,
        live.tail_piles,
        live.tail_responses,
        live.whole_pack_requests,
        live.whole_pack_waves_32,
        live.whole_pack_waves_64,
    ) == (0, 45, 4, 4, 1, 1)
    assert (
        checkpoint.sealed_packs,
        checkpoint.sealed_piles,
        checkpoint.descriptor_bytes,
        checkpoint.tail_piles,
        checkpoint.whole_pack_requests,
        checkpoint.exact_range_requests,
        checkpoint.exact_range_waves_32,
        checkpoint.exact_range_waves_64,
    ) == (4, 45, 4_842, 0, 4, 49, 3, 2)
    assert checkpoint.policy == "idle-checkpoint"
    assert checkpoint.point_read_cold_requests == 2
    assert checkpoint.point_read_warm_requests == 1


def test_dual_trigger_seals_at_count_or_before_byte_ceiling():
    inventory = WriterInventory(
        "a" * 64,
        "b" * 64,
        tuple(PileRef(index, f"{index:064x}", 100)
              for index in range(1, 258)),
    )
    count_shape = writer_shape(inventory, 4 * MIB)
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


def test_idle_checkpoint_seals_only_the_remaining_writer_local_tail():
    inventory = WriterInventory(
        "a" * 64,
        "b" * 64,
        tuple(PileRef(index, f"{index:064x}", 100)
              for index in range(1, 258)),
    )
    shape = writer_shape(
        inventory, 4 * MIB, force_seal_tail=True)
    assert tuple(len(pack.piles) for pack in shape.packs) == (256, 1)
    assert shape.tail == ()
