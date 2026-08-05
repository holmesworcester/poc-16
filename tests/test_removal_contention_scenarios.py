"""Deterministic gate evidence for live-R2 removal scenarios 8-11."""

from bench.removal_contention import run_removal_scenarios
from core.store import FsStore


def test_removal_scenarios_8_to_11_run_against_the_shared_gate(tmp_path):
    def factory(label):
        return FsStore(tmp_path / label)

    convergence, race, purge = run_removal_scenarios(
        factory, members=13)
    assert convergence["recipients"] == 3
    assert convergence["active_subjects"] == 2
    assert race["stale_removal_joined"] is True
    assert race["removal_commit"] == "applied"
    assert race["exact_replay"] == "noop"
    assert purge["members"] == 13
    assert purge["transitions"] == 3
    assert purge["offline_over_bound"] == "blocked:poc-16-6j4.26"
    for report in (convergence, race, purge):
        assert set(report["operations"]) == {
            "cas", "get", "list", "put_if_absent"}
        assert report["projected_r2_usd"] >= 0
