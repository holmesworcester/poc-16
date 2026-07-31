from bench.bench_latency import measure_scale


def test_latency_benchmark_exercises_real_post_and_idle_paths(tmp_path):
    result = measure_scale(
        str(tmp_path / "node"), scale=80, posts=2, idle=3, members=4)

    assert result["facts"] >= result["seed_facts"] + 4
    assert result["post"]["samples"] == 2
    assert result["post"]["key_scans"] == 0
    assert 0 < result["post"]["object_touches_per_post"] \
        < result["authenticated_rows"]
    assert result["post"]["object_writes"] > 0
    assert result["post"]["object_kib_per_post"] > 0
    assert result["idle"]["samples"] == 3
    assert result["idle"]["p95_ms"] >= 0
