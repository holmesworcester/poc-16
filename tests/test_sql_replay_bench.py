"""Executable evidence for the disposable SQL replay cost decision."""

from bench.bench_sql_replay import measure


def test_warm_and_one_head_replay_stay_incremental_but_delete_is_exact(
        tmp_path):
    result = measure(tmp_path / "peer", history_messages=24)

    assert result["warm_restart"]["piles"] == 0
    assert result["warm_restart"]["facts"] == 0
    assert result["one_head"]["piles"] == 1
    assert result["one_head"]["facts"] == 2
    assert result["cold"]["piles"] == 26
    assert result["cold"]["facts"] == result["projected_fact_rows"]
