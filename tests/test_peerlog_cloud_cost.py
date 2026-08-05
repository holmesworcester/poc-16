from bench.peerlog_cloud_cost import measure
from scratchpad.store_model import MIB, append_projection, sync_projection


def test_decision_record_model_reproduces_round_and_bandwidth_bounds():
    cold = sync_projection()
    assert cold.rounds == 3
    assert cold.bandwidth_floor_s == 32.0
    assert cold.margin < 0.02
    assert append_projection(4 * MIB).worst_amplification <= 11
    assert append_projection(64 * MIB).maximum_publish_upload_bytes == 8 * 1024


def test_measured_three_writer_queue_costs_match_recipe_model():
    report = measure(writers=3, facts_per_writer=40, body_bytes=90)
    assert report.cold_rounds - report.cold_directory_audit_rounds == 1
    assert report.cold_directory_audit_gets == report.writers + 2
    assert report.noop_rounds == report.noop_gets == 1
    assert report.warm_rounds == 2
    assert report.warm_bytes < report.cold_bytes
    # Physical codec/proof overhead dominates this deliberately tiny fixture,
    # but it remains bounded by the conservative 4 MiB ladder model and never
    # scales with an already-copied mono prefix.
    assert report.measured_upload_amplification \
        < report.model_upload_ceiling
    assert report.million_fact_floor_margin < 0.02
