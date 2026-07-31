"""Realistic checks for the chained benchmark seed."""
import random

import pytest

from bench.seed_chain import build_seed
from bench.bench_sync import bidi, bulk_author, catchup, check_leaves
import facts

from core.close import close, decode_pile
from core.kernel import drain, resolve_deps
from core.limits import MAX_CLOSURE_FACTS

from .util import all_fids, closed_subset


@pytest.mark.parametrize(
    ("shape", "expected_max"),
    [("star", 1), ("wide", 2), ("chain", 23)],
)
def test_seed_shapes_have_the_claimed_depth(tmp_path, shape, expected_max):
    node, workspace, stats = build_seed(
        str(tmp_path / shape), 127, n_members=24, shape=shape,
        wide_inviters=4)

    assert stats["facts"] == 127
    assert stats["depth"]["max"] == expected_max
    assert sum(stats["depth"]["histogram"].values()) == 24
    assert len(node.by_type(workspace, "user")) == 23
    assert len(node.by_type(workspace, "user_invite")) == 23


def test_random_seed_is_deep_and_its_leaf_closes_over_the_real_path(tmp_path):
    node, workspace, stats = build_seed(
        str(tmp_path / "random"), 255, n_members=48, shape="random", seed=16)

    assert stats["depth"]["median"] > 1
    deepest_pk = max(stats["depth_by_member"],
                     key=stats["depth_by_member"].get)
    user_fid = stats["user_by_member"][deepest_pk]
    user_fact = node.fact_of(workspace, user_fid)
    invite_fid = user_fact.refs()[0][1]
    inviter_pk = stats["parents"][deepest_pk]
    inviter_user = stats["user_by_member"][inviter_pk]
    assert inviter_user in resolve_deps(
        node.fact_of(workspace, invite_fid), node.idx(workspace))

    stream = decode_pile(
        closed_subset(node, workspace, [user_fid]), workspace)
    assert drain(stream, workspace).ok


def test_seed_rejects_unknown_shapes(tmp_path):
    with pytest.raises(ValueError, match="shape must be one of"):
        build_seed(str(tmp_path / "bad"), 10, shape="broom")


def test_multi_device_seed_groups_equal_author_keys_by_user(tmp_path):
    node, workspace, stats = build_seed(
        str(tmp_path / "devices"), 255, n_members=12, shape="random",
        devices_per_user=3)

    assert stats["devices_per_user"] == 3
    assert all(len(group) == 3 for group in stats["devices_by_user"].values())
    assert len(stats["device_to_user"]) == 36
    assert set(stats["device_to_user"]) <= set(node.keyring["keys"])
    assert len(node.by_type(workspace, "device")) == 12
    assert len(node.by_type(workspace, "device_invite")) == 24
    assert check_leaves(node, workspace) > 1


def test_same_seed_reproduces_identities_fact_ids_and_layout(tmp_path):
    first, first_ws, first_stats = build_seed(
        str(tmp_path / "first"), 255, n_members=16, shape="random",
        seed=16, devices_per_user=2)
    second, second_ws, second_stats = build_seed(
        str(tmp_path / "second"), 255, n_members=16, shape="random",
        seed=16, devices_per_user=2)
    other, other_ws, _ = build_seed(
        str(tmp_path / "other"), 255, n_members=16, shape="random",
        seed=17, devices_per_user=2)

    assert first_ws == second_ws
    assert all_fids(first, first_ws) == all_fids(second, second_ws)
    assert first.store(first_ws).get("root") \
        == second.store(second_ws).get("root")
    assert first_stats["parents"] == second_stats["parents"]
    assert first_stats["devices_by_user"] == second_stats["devices_by_user"]
    assert other_ws != first_ws
    assert all_fids(other, other_ws) != all_fids(first, first_ws)


def test_topology_and_content_use_independent_rng_streams(tmp_path):
    star, star_ws, star_stats = build_seed(
        str(tmp_path / "star-content"), 255, n_members=24,
        shape="star", seed=16)
    random_tree, random_ws, random_stats = build_seed(
        str(tmp_path / "random-content"), 255, n_members=24,
        shape="random", seed=16)

    def messages(node, workspace):
        return sorted(
            (fact.body["text"], fact.body["pk"], fact.ts)
            for fact in node.by_type(workspace, "msg")
        )

    assert star_stats["parents"] != random_stats["parents"]
    assert messages(star, star_ws) == messages(random_tree, random_ws)


def test_bulk_author_closes_signatures_before_messages(tmp_path):
    node, workspace, _ = build_seed(
        str(tmp_path / "bulk-closure"), 127, n_members=12,
        shape="star", seed=16)
    before = set(all_fids(node, workspace))
    candidates = node.reader(workspace).validated()
    first_ts = max(
        candidates.fact(fid).ts for fid in candidates.fact_ids()
    ) + 1

    bulk_author(
        node, workspace, [(node.sk, node.pk)], 1,
        first_ts, 1, random.Random(99), "delta-")

    added = set(all_fids(node, workspace)) - before
    message_fid = next(
        fid for fid in added if node.fact_of(workspace, fid).t == "msg")
    message = node.fact_of(workspace, message_fid)
    deps = resolve_deps(message, node.idx(workspace))
    assert deps is not None
    assert {node.fact_of(workspace, fid).t for fid in deps} \
        == {"signature", "workspace"}
    pile = close(
        [message],
        lambda fid: resolve_deps(
            node.fact_of(workspace, fid), node.idx(workspace)) or (),
        lambda fid: node.fact_of(workspace, fid),
    )
    assert drain(pile, workspace).ok


def test_reader_rebuilds_a_deleted_projection_without_root_write(
        tmp_path):
    members = 64
    membership_facts = 1 + 4 * (members - 1)
    node, workspace, _ = build_seed(
        str(tmp_path / "projection-worklist"), membership_facts,
        n_members=members, shape="chain", seed=16)
    index = node.idx(workspace)
    root = node.store(workspace).get("root")
    index.execute("DELETE FROM fact_index")
    index.execute("DELETE FROM facts")
    index.commit()

    assert not node.sql(workspace).fact_ids()

    node.rebuild(workspace)

    assert node.store(workspace).get("root") == root
    assert index.execute(
        "SELECT COUNT(*) FROM facts",
    ).fetchone()[0] == membership_facts
    assert node.sql(workspace).fact_ids() == set(
        node.reader(workspace).validated().fact_ids())
    assert not {
        kind for (kind,) in index.execute(
            "SELECT DISTINCT kind FROM fact_index")
        if any(word in kind for word in ("edge", "eligible", "proof", "rank"))
    }


def test_ordinary_seed_append_aligns_projection_with_committed_reader(
        tmp_path):
    node, workspace, _ = build_seed(
        str(tmp_path / "ordinary-append"), 127,
        n_members=12, shape="random", seed=16)
    root = node.store(workspace).get("root")

    fid = facts.content.message.post(
        node, workspace, "general", "one conflict-free live append")

    assert node.store(workspace).get("root") != root
    assert node.reader(workspace).validated().fact(fid) \
        == node.fact_of(workspace, fid)
    assert node.idx(workspace).execute(
        "SELECT 1 FROM facts WHERE fid=?",
        (fid,),
    ).fetchone() == (1,)


def test_chained_seed_catches_up_and_every_committed_leaf_validates(tmp_path):
    node, workspace, _ = build_seed(
        str(tmp_path / "seed"), 511, n_members=24, shape="random")

    assert check_leaves(node, workspace) > 1
    result = catchup(node, workspace, str(tmp_path / "fresh"))
    assert result["match"]
    assert result["facts"] == 511


def test_chained_bidirectional_reconciliation_converges(tmp_path):
    result = bidi(
        511, str(tmp_path / "bidi"), n_members=24, shape="chain", seed=16)

    assert result["match"]
    assert result["shape"] == "chain"
    assert result["depth"]["max"] == 23
    assert result["facts"] > result["a_before"]
    assert result["pull_streamed"] > result["pull_useful"]
    assert result["push_streamed"] > result["push_useful"]


def test_chain_seed_rejects_a_pile_beyond_the_protocol_closure_bound(
        tmp_path):
    members = 2 + (MAX_CLOSURE_FACTS - 1) // 4
    membership_facts = 1 + 4 * (members - 1)
    with pytest.raises(ValueError, match="not admitted"):
        build_seed(
            str(tmp_path / "too-deep"), membership_facts,
            n_members=members, shape="chain", seed=16)
