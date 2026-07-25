"""Behavioral tests for delegation-aware key-order measurement."""
import tinyp2p.layout as layout

from bench.bench_order import benchmark


def run_benchmark(tmp_path, shape):
    old_cold_cut = layout.COLD_CUT
    layout.COLD_CUT = None
    try:
        return benchmark(
            str(tmp_path / shape), 1023, shape=shape, n_members=32, seed=16)
    finally:
        layout.COLD_CUT = old_cold_cut


def test_reconstruction_uses_user_refs_not_ephemeral_invitee_keys(tmp_path):
    node, workspace, stats, topology, _ = run_benchmark(tmp_path, "random")
    member_keys = set(stats["depth_by_member"])
    invitee_keys = {
        fact.offers()[0][1]
        for (fid,) in node.idx(workspace).execute(
            "SELECT fid FROM facts WHERE t='user_invite'")
        for fact in (node.fact_of(workspace, fid),)
    }

    assert member_keys.isdisjoint(invitee_keys)
    assert topology["parent"] == {
        member: inviter
        for member, inviter in stats["parents"].items()
        if inviter is not None
    }
    assert topology["depth"] == stats["depth_by_member"]


def test_chain_dfs_tax_is_path_bounded_and_beats_scattered_orders(tmp_path):
    _, _, _, _, results = run_benchmark(tmp_path, "chain")
    rows = {
        order: {row["users"]: row for row in result["rows"]}
        for order, result in results.items()
    }
    singleton = rows["deleg"][1]
    small = rows["deleg"][3]

    for row in (singleton, small):
        depth = row["depth"]
        assert 3 * depth <= row["tax"] <= 4 * depth + 64
        assert row["tax"] < rows["author"][row["users"]]["tax"]
        assert row["tax"] < rows["ts"][row["users"]]["tax"]


def test_star_reproduces_the_auth_core_and_ordering_regression(tmp_path):
    _, _, stats, _, results = run_benchmark(tmp_path, "star")
    auth_facts = 1 + 4 * (stats["members"] - 1)

    assert results["ts"]["half"] == auth_facts
    assert results["deleg"]["half"] < results["author"]["half"] < auth_facts
    assert results["deleg"]["rho"] < results["author"]["rho"] \
        < results["ts"]["rho"]


def test_user_order_beats_device_author_order_with_plural_devices(tmp_path):
    old_cold_cut = layout.COLD_CUT
    layout.COLD_CUT = None
    try:
        _, _, stats, topology, results = benchmark(
            str(tmp_path / "devices"), 2047, shape="random", n_members=32,
            seed=16, devices_per_user=3)
    finally:
        layout.COLD_CUT = old_cold_cut

    assert len(topology["device_to_user"]) == 3 * stats["members"]
    assert results["user"]["rho"] < results["author"]["rho"]
    assert results["user"]["mean_tax"] < results["author"]["mean_tax"]
    author_rows = {
        row["member"]: row for row in results["author"]["rows"]
    }
    assert all(
        row["tax"] <= author_rows[row["member"]]["tax"]
        for row in results["user"]["rows"]
    )
