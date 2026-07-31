"""The one disposable fact catalog and combined generic index."""
import json
import sqlite3

import pytest

import facts

from core import fact_index
from core.fact import Fact, canon, decode, encode
from full_peer import sql_store
from full_peer.node import FullPeer
from core.repository_snapshot import action_bindings


OBSOLETE_TABLES = {
    "action_proposals",
    "action_targets",
    "actions",
    "admission_receipts",
    "edges",
    "log",
    "offers",
    "proofs",
    "staged",
    "supp",
}


def _tables(db):
    return {
        name for (name,) in db.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    }


def _expected_projection(node, workspace):
    """Derive exact local rows from one authenticated validated set."""
    reader = node.reader(workspace)
    validated = reader.all_facts()
    facts_by_fid = {
        fid: encode(fact)
        for fid, fact in validated.facts.items()
    }
    rows = {
        row
        for fact in validated.facts.values()
        for row in fact_index.index_rows(fact)
    }
    rows.update(
        (fact_index.ACTION_INDEX, sid, "", fid)
        for sid, fid in action_bindings(validated.facts).items()
    )
    return facts_by_fid, rows


def _assert_exact_projection(node, workspace):
    expected_facts, expected_rows = _expected_projection(
        node, workspace)
    db = node.idx(workspace)
    actual_facts = dict(db.execute(
        "SELECT fid, blob FROM facts"))
    actual_rows = set(db.execute(
        "SELECT kind, k0, k1, src FROM fact_index"))

    assert actual_facts == expected_facts
    assert actual_rows == expected_rows
    assert _tables(db) == {"facts", "fact_index", "meta"}
    assert set(
        key for (key,) in db.execute("SELECT k FROM meta")
    ) == {"root"}
    for fid, raw in actual_facts.items():
        fact = decode(raw)
        assert fact.fid == fid
        assert encode(fact) == raw


def test_catalog_stores_one_blob_and_one_exact_combined_index(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    kept = facts.content.message.post(
        node, workspace, "general", "kept", ts=2)
    removed = facts.content.message.post(
        node, workspace, "general", "removed", ts=3)
    action = facts.content.delete.remove(node, workspace, removed, ts=4)
    db = node.idx(workspace)

    assert [
        (name, kind)
        for _, name, kind, *_ in db.execute("PRAGMA table_info(facts)")
    ] == [("fid", "TEXT"), ("blob", "BLOB")]
    assert [
        name for _, name, *_ in db.execute(
            "PRAGMA table_info(fact_index)")
    ] == ["kind", "k0", "k1", "src"]
    _assert_exact_projection(node, workspace)

    assert [fact.fid for fact in node.by_type(
        workspace, "msg")] == [kept]
    assert node.select(
        workspace, "member", node.identity_id(workspace)
    )[0].fid == workspace
    assert db.execute(
        "SELECT src FROM fact_index "
        "WHERE kind=? AND src=?",
        (fact_index.ACTION_INDEX, action),
    ).fetchone() == (action,)
    assert _tables(db).isdisjoint(OBSOLETE_TABLES)
    assert not (tmp_path / "node" / "app.db").exists()


def test_public_queries_restart_from_the_same_disposable_rows(tmp_path):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    keep = facts.content.message.post(node, workspace, "general", "keep", ts=2)
    remove = facts.content.message.post(node, workspace, "general", "remove", ts=3)
    facts.content.delete.remove(node, workspace, remove, ts=4)
    root = node.reader(workspace).root_bytes
    expected = {
        "members": facts.auth.user.members(node, workspace),
        "messages": facts.content.message.messages(node, workspace),
    }
    expected_facts, expected_rows = _expected_projection(
        node, workspace)
    assert [row["fid"] for row in expected["messages"]] == [keep]
    node.idx(workspace).close()

    reopened = FullPeer(str(directory))

    assert reopened.reader(workspace).root_bytes == root
    assert facts.auth.user.members(reopened, workspace) == expected["members"]
    assert facts.content.message.messages(reopened, workspace) == expected["messages"]
    assert dict(reopened.idx(workspace).execute(
        "SELECT fid, blob FROM facts")) == expected_facts
    assert set(reopened.idx(workspace).execute(
        "SELECT kind, k0, k1, src FROM fact_index"
    )) == expected_rows
    assert not (directory / "app.db").exists()


def test_legacy_authority_schema_is_discarded_then_root_refreshed(
        tmp_path):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    message_fid = facts.content.message.post(
        node, workspace, "general", "survives cut", ts=2)
    root = node.reader(workspace).root_bytes
    path = directory / "ws" / f"{workspace}.idx.db"
    node.idx(workspace).close()

    db = sqlite3.connect(path)
    db.executescript("""
        DROP TABLE facts;
        DROP TABLE fact_index;
        CREATE TABLE facts(
            fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT, admitted INT);
        CREATE TABLE fact_index(
            kind TEXT, k0 TEXT, k1 TEXT, src TEXT);
        CREATE TABLE action_proposals(value TEXT);
        CREATE TABLE action_targets(value TEXT);
        CREATE TABLE actions(value TEXT);
        CREATE TABLE admission_receipts(value TEXT);
        CREATE TABLE edges(value TEXT);
        CREATE TABLE log(value TEXT);
        CREATE TABLE offers(value TEXT);
        CREATE TABLE proofs(value TEXT);
        CREATE TABLE staged(value TEXT);
        CREATE TABLE supp(value TEXT);
        CREATE INDEX fact_keys ON fact_index(k0,src);
        CREATE INDEX fact_boundaries ON fact_index(k0,src);
        PRAGMA user_version=0;
    """)
    local_only = Fact(
        "legacy",
        3,
        [],
        {"value": "must be discarded"},
        workspace,
    )
    db.execute(
        "INSERT INTO facts VALUES(?,?,?,?,?)",
        (
            local_only.fid,
            local_only.ts,
            local_only.t,
            json.dumps(local_only.to_json()),
            1,
        ),
    )
    db.execute(
        "INSERT OR REPLACE INTO meta VALUES('obsolete',?)",
        ("admission-catalog-v27",),
    )
    db.commit()
    db.close()

    reopened = FullPeer(str(directory))
    upgraded = reopened.idx(workspace)

    assert reopened.reader(workspace).root_bytes == root
    assert reopened.fact_of(workspace, message_fid) is not None
    assert reopened.fact_of(
        workspace, local_only.fid) is None
    assert _tables(upgraded) == {"facts", "fact_index", "meta"}
    assert _tables(upgraded).isdisjoint(OBSOLETE_TABLES)
    assert upgraded.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type='index' AND name IN "
        "('fact_keys','fact_boundaries')"
    ).fetchone() is None
    _assert_exact_projection(reopened, workspace)


def test_root_refresh_replaces_stale_missing_and_extra_rows(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    message_fid = facts.content.message.post(
        node, workspace, "general", "kept", ts=2)
    root = node.reader(workspace).root_bytes
    db = node.idx(workspace)
    db.execute(
        "DELETE FROM fact_index WHERE src=?", (message_fid,))
    db.execute(
        "DELETE FROM facts WHERE fid=?", (message_fid,))
    db.execute(
        "INSERT INTO fact_index VALUES(?,?,?,?)",
        (fact_index.TYPE_INDEX, "forged", "", workspace),
    )
    db.commit()

    node.rebuild(workspace)

    assert node.reader(workspace).root_bytes == root
    _assert_exact_projection(node, workspace)
    assert [row["fid"] for row in facts.content.message.messages(
        node, workspace)] == [message_fid]


def test_foreign_root_format_fails_closed_without_local_republish(
        tmp_path):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "kept", ts=2)
    store = node.store(workspace)
    value = json.loads(store.get("root"))
    value["stamp"] = "obsolete-or-foreign-layout"
    foreign = canon(value)
    store._replace("root", foreign)
    node.idx(workspace).close()

    with pytest.raises(ValueError, match="root shape"):
        FullPeer(str(directory))

    assert store.get("root") == foreign


def test_index_lookup_decodes_only_selected_fact_bodies(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    for timestamp in range(2, 7):
        facts.content.message.post(
            node,
            workspace,
            "general",
            f"message-{timestamp}",
            ts=timestamp,
        )

    decoded = []
    strict_decode = sql_store.decode

    def observed(raw):
        fact = strict_decode(raw)
        decoded.append(fact.fid)
        return fact

    monkeypatch.setattr(sql_store, "decode", observed)
    selected = node.sql(workspace).indexed(
        "member", node.identity_id(workspace))

    assert [fact.fid for fact in selected] == [workspace]
    assert decoded == [workspace]
