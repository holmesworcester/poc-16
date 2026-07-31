"""Authenticated generic indexes are mechanical views of validated facts."""

import facts

from core import indexes
from core.fact_index import TYPE_INDEX
from full_peer.node import FullPeer
from core.repository_snapshot import compile_snapshot


def test_type_postings_include_suppressed_validated_facts(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    live = facts.content.message.post(
        node, workspace, "general", "live", ts=2)
    hidden = facts.content.message.post(
        node, workspace, "general", "hidden", ts=3)
    facts.content.delete.remove(node, workspace, hidden, ts=4)
    view = node.reader(workspace).worker()

    rows = view.postings(TYPE_INDEX, "msg").rows

    assert [row.fid for row in rows] == sorted((live, hidden))
    assert all(not hasattr(row, "rank") for row in rows)
    assert view.fact_active(live) is True
    assert view.fact_active(hidden) is False
    assert node.reader(workspace).validated().fact(hidden).fid == hidden


def test_fact_residence_is_only_an_object_id(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    view = node.reader(workspace)
    row = view.worker()._reader(indexes.FACT).get(
        indexes.fact_key(workspace))

    assert row == view.validated().fact_oid(workspace)
    assert isinstance(row, str)
    assert set(row) <= set("0123456789abcdef")


def test_worker_authenticates_provider_without_a_winner_projection(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    view = node.reader(workspace).worker()

    assert view.fact_known(workspace)
    assert view.fact(workspace).fid == workspace
    assert view.fact_active(workspace)
    assert set(view._validated.root.maps) == {
        "fact", "fact_order", "supp"}


def test_compile_is_history_independent_over_same_validated_set(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(
        node, workspace, "general", "one", ts=2)
    facts.content.message.post(
        node, workspace, "general", "two", ts=3)
    validated = node.reader(workspace).all_facts().facts

    forward = compile_snapshot(workspace, dict(validated))
    reverse = compile_snapshot(
        workspace, dict(reversed(tuple(validated.items()))))

    assert forward.root == reverse.root
    assert forward.objects == reverse.objects


def test_current_scopes_are_one_mechanical_definition(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fact = node.fact_of(workspace, workspace)

    assert facts.current_scopes(fact) == (
        facts.fact_scopes(fact)
        | facts.principal_sids(fact)
        | facts.authority_scopes(fact)
    )
    for sid in facts.current_scopes(fact):
        assert node.reader(workspace).worker().suppression(sid) == {
            "state": "clear"}
