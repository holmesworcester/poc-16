"""The current root/projection format is a strict cut, not a migration."""
import json

import pytest

import facts

from core import snapshot
from core.fact import canon
from full_peer.node import FullPeer


def test_root_atomically_names_the_four_current_bounded_maps(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "indexed", ts=10)

    raw = node.store(workspace).get("root")
    body = json.loads(raw)
    committed = snapshot.decode_root(raw)

    assert set(body) == {"anchor", "layout_seed", "maps", "stamp"}
    assert body["stamp"] == snapshot.LAYOUT
    assert set(committed.maps) == set(snapshot.MAP_NAMES)
    assert all(
        set(value) == {"root", "count", "depth"}
        for value in committed.maps.values()
    )
    assert "action_etag" not in body
    assert "manifest" not in body
    assert "trees" not in body


@pytest.mark.parametrize(
    "replacement",
    (
        b"",
        canon({"stamp": "retired-layout"}),
    ),
)
def test_unknown_or_empty_root_fails_closed_without_republication(
        tmp_path, replacement):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    store = node.store(workspace)
    store._replace("root", replacement)

    with pytest.raises(ValueError):
        node.rebuild(workspace)

    assert store.get("root") == replacement


def test_projection_rebuild_is_side_effect_free_and_republish_is_forbidden(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "stable", ts=10)
    store = node.store(workspace)
    root = store.get("root")

    node.idx(workspace).execute("DELETE FROM facts")
    node.idx(workspace).commit()
    node.rebuild(workspace)

    assert node.by_type(workspace, "msg")[0].body["text"] == "stable"
    assert store.get("root") == root
    with pytest.raises(ValueError, match="RepositoryApplier"):
        node.rebuild(workspace, republish=True)
    assert store.get("root") == root


def test_legacy_sql_authority_tables_are_discarded_not_migrated(
        tmp_path):
    directory = str(tmp_path / "node")
    node = FullPeer(directory)
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    root = node.store(workspace).get("root")
    db = node.idx(workspace)
    for table in (
            "admission_receipts",
            "staged",
            "offers",
            "log",
            "action_proposals"):
        db.execute(f"CREATE TABLE {table}(payload BLOB)")
        db.execute(f"INSERT INTO {table} VALUES(?)", (b"not-authority",))
    db.execute(
        "INSERT OR REPLACE INTO meta VALUES('root','stale-projection')")
    db.commit()
    db.close()

    reopened = FullPeer(directory)
    names = {
        name for (name,) in reopened.idx(workspace).execute(
            "SELECT name FROM sqlite_master WHERE type='table'")
    }

    assert not names.intersection({
        "admission_receipts",
        "staged",
        "offers",
        "log",
        "action_proposals",
    })
    assert reopened.store(workspace).get("root") == root
    assert reopened.fact_of(workspace, workspace) is not None
