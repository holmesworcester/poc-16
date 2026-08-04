"""Accounting ratchets for the repeatable per-writer P2P benchmark."""
import asyncio

from bench.bench_writer_p2p_scale import (
    DEFAULT_RTTS_MS,
    DEFAULT_WRITERS,
    LARGE_DURABLE_FACTS,
    NORMAL_MESSAGES_PER_PILE,
    OFFLINE_PACKED_MESSAGES_PER_PILE,
    P2PMeasurement,
    large_distribution,
    measure_large_catchup,
    measure_small_scale,
)


def test_required_scale_and_rtt_matrix_is_the_benchmark_default():
    assert DEFAULT_WRITERS == (100, 1_000)
    assert DEFAULT_RTTS_MS == (25, 50, 75)
    assert LARGE_DURABLE_FACTS == 100_000
    assert NORMAL_MESSAGES_PER_PILE == 1
    assert OFFLINE_PACKED_MESSAGES_PER_PILE == 125


def test_required_writer_scales_ratchet_bundled_head_costs():
    async def scenario():
        return {
            writers: await measure_small_scale(writers)
            for writers in DEFAULT_WRITERS
        }

    measured = asyncio.run(scenario())
    expected = {
        100: (
            (100, 0, 0, 1, 1, 0, 71_425),
            (100, 2, 1, 4, 4, 0, 76_437),
            (101, 4, 1, 4, 4, 0, 77_047),
        ),
        1_000: (
            (1_000, 0, 0, 4, 4, 0, 714_499),
            (1_000, 2, 1, 7, 7, 0, 719_516),
            (1_001, 4, 1, 7, 7, 0, 720_126),
        ),
    }
    for writers, results in measured.items():
        assert tuple((
            result.writers,
            result.facts,
            result.piles,
            result.requests,
            result.parallel_request_waves,
            result.request_bytes,
            result.response_bytes,
        ) for result in results) == expected[writers]
        assert all(
            result.requests == result.parallel_request_waves
            for result in results
        )
        assert all(
            kind != "head"
            for result in results
            for kind, _count in result.request_breakdown
        )


def test_large_default_means_about_fifty_thousand_normal_piles():
    expected_messages = {100: 49_899, 1_000: 48_999}
    for writers, messages in expected_messages.items():
        distribution, filler = large_distribution(
            writers, LARGE_DURABLE_FACTS)
        assert sum(distribution) == messages
        assert filler == 1
        assert min(distribution) > 0
        assert 2 * writers + 1 + 2 * messages + filler \
            == LARGE_DURABLE_FACTS


def test_small_directory_change_and_new_writer_accounting():
    async def scenario():
        noop, changed, new_writer = await measure_small_scale(
            4, page_limit=2)

        assert isinstance(noop, P2PMeasurement)
        assert (
            noop.writers,
            noop.facts,
            noop.piles,
            noop.requests,
            noop.parallel_request_waves,
        ) == (4, 0, 0, 2, 2)
        assert (
            changed.writers,
            changed.facts,
            changed.piles,
            changed.requests,
            changed.parallel_request_waves,
        ) == (4, 2, 1, 5, 5)
        assert (
            new_writer.writers,
            new_writer.facts,
            new_writer.piles,
            new_writer.requests,
            new_writer.parallel_request_waves,
        ) == (5, 4, 1, 6, 6)

        assert noop.request_breakdown == (("heads", 2),)
        assert changed.request_breakdown == (
            ("heads", 2), ("object", 2), ("pile", 1))
        assert new_writer.request_breakdown == (
            ("heads", 3), ("object", 2), ("pile", 1))

        for result in (noop, changed, new_writer):
            assert result.measured_wall_seconds > 0
            assert result.measured_cpu_seconds > 0
            assert tuple(
                estimate.rtt_ms
                for estimate in result.latency_estimates
            ) == DEFAULT_RTTS_MS
            for estimate in result.latency_estimates:
                expected = result.measured_wall_seconds + (
                    result.parallel_request_waves
                    * estimate.rtt_ms / 1_000)
                assert abs(estimate.modeled_wall_seconds - expected) < 1e-12

        return noop, changed, new_writer

    noop, changed, new_writer = asyncio.run(scenario())
    assert (
        noop.request_bytes,
        noop.response_bytes,
        changed.request_bytes,
        changed.response_bytes,
        new_writer.request_bytes,
        new_writer.response_bytes,
    ) == (0, 3_039, 0, 8_046, 0, 8_813)


def test_exact_durable_fact_catchup_accounting():
    result = asyncio.run(measure_large_catchup(
        4, durable_facts=100, page_limit=2))
    assert (
        result.writers,
        result.facts,
        result.piles,
        result.requests,
        result.parallel_request_waves,
    ) == (4, 100, 45, 55, 55)
    assert (
        result.request_bytes,
        result.response_bytes,
    ) == (0, 178_004)
    assert result.messages_per_pile == 1
    assert result.scenario == "large-catchup-normal"
    assert result.request_breakdown == (
        ("heads", 2), ("object", 8), ("pile", 45))
    assert result.measured_facts_per_second > 0


def test_offline_packing_is_never_labeled_as_normal_history():
    result = asyncio.run(measure_large_catchup(
        4, durable_facts=100, page_limit=2, messages_per_pile=10))
    assert (result.facts, result.piles) == (100, 8)
    assert result.messages_per_pile == 10
    assert result.scenario == "large-catchup-offline-packed-10"
