import math

from bench.peerlog_cloud_scale import (
    measure_annex,
    measure_cold,
    measure_fanout,
    measure_interactive,
    measure_range,
    measure_skewed_interactive,
)
from peerlog.cloud import CLOUD_GET_CONCURRENCY


def test_100_and_1000_writer_fanout_has_bounded_waves_and_constant_warm_delta():
    for writers in (100, 1000):
        report = measure_fanout(writers)
        assert report.cold_gets == writers
        assert report.cold_rounds == 1 + math.ceil(
            writers / CLOUD_GET_CONCURRENCY)
        assert report.noop_gets == report.noop_rounds == 1
        assert report.warm_gets == 1
        assert report.warm_rounds == 2
        assert report.warm_facts == 1
        assert report.directory_bytes < writers * 1_500


def test_source_local_range_fetch_opens_only_intersecting_ladder_segment():
    report = measure_range()
    assert report.total_facts == 96
    assert (report.requested_lo, report.requested_hi) == (64, 96)
    assert report.received_facts == 32
    assert report.object_gets == 1
    assert report.rounds == 2


def test_100k_fact_cold_catchup_runs_exact_authenticated_path():
    report = measure_cold(writers=50, facts=100_000, body_bytes=80)
    assert report.facts == 100_000
    assert report.object_gets == 50
    assert report.rounds == 2
    assert report.received_bytes < 32 * 1024 * 1024
    assert report.pipelined_facts_per_s > 5_000
    assert report.pipelined_bytes_per_s > 1_000_000
    # At the decision-record 90 ms RTT and 2.5 MB/s useful bandwidth, bounded
    # request waves add less than 2% to the measured wire-byte floor.
    assert report.rtt_margin < 0.02


def test_recent_window_cost_is_independent_of_cold_history_size():
    small = measure_interactive(
        history_facts=1_000, recent_facts=100, writers=10)
    large = measure_interactive(
        history_facts=10_000, recent_facts=100, writers=10)
    for report in (small, large):
        assert report.recent_facts == 100
        assert report.initial_segment_gets == 10
        assert report.closure_segment_gets == report.closure_facts == 0
        assert report.annex_facts == report.closure_depth == 2
        assert report.object_gets == 10
        assert report.rounds == 2
        assert report.interactive_ready
        assert report.initial_bytes < 128 * 1024
        assert report.semantic_facts_per_s > 0
    # The recent micro carries the fixed two-fact annex. No old segment opens.
    assert abs(small.initial_bytes - large.initial_bytes) < 4 * 1024
    assert small.closure_bytes == large.closure_bytes == 0
    assert small.segment_overfetch_facts \
        == large.segment_overfetch_facts == 0


def test_skewed_recent_view_cost_tracks_writer_tails_not_hot_sequence():
    small = measure_skewed_interactive(history_facts=10_000)
    large = measure_skewed_interactive(history_facts=20_000)
    for report in (small, large):
        assert report.long_tail_writers == 1_000
        assert report.requested_writers == 1_006
        assert report.selected_facts == 1_262
        assert report.initial_segment_gets == 756
        assert report.closure_segment_gets == report.closure_facts == 0
        assert report.annex_facts == report.closure_depth == 2
        assert report.object_gets == 756
        assert report.closure_depth == 2
        assert report.hot_facts > report.selected_facts
        assert report.interactive_ready
        assert report.semantic_facts_per_s > 0
    assert small.initial_segment_gets == large.initial_segment_gets
    assert small.rounds == large.rounds
    assert abs(small.initial_bytes - large.initial_bytes) < 8 * 1024
    assert small.closure_bytes == large.closure_bytes == 0


def test_folded_annex_ratio_stays_near_the_store_model_prediction():
    for facts in (256, 2_048):
        report = measure_annex(facts=facts)
        assert report.refs == facts // 8
        assert report.annex_bytes > 0
        assert 1.05 < report.annex_ratio < 1.30
