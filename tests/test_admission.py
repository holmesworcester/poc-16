"""Successful whole-pile judgment is the repository's only admission."""

import sqlite3

import facts

from core import catalog
from core.fact import encode
from core.node import Node
from facts.content.message import message


def test_sql_projection_contains_no_admission_verdict_or_edges(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fid = facts.content.message.post(
        node, workspace, "general", "admitted once", ts=2)
    kinds = {
        kind for (kind,) in node.idx(workspace).execute(
            "SELECT DISTINCT kind FROM fact_index WHERE src=?", (fid,))
    }

    assert node.catalog(workspace).fact(fid).fid == fid
    assert kinds == {"fact.key", "fact.scope", "fact.type"}
    assert not any(
        marker in kind
        for kind in kinds
        for marker in ("admission", "edge", "eligible", "proof", "rank"))


def test_legacy_local_authority_rows_are_discarded_not_blessed(tmp_path):
    directory = tmp_path / "node"
    node = Node(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    root = node.reader(workspace).root_bytes
    forged = message(
        workspace,
        node.identity_id(workspace),
        "general",
        "legacy local-only row",
        2,
    )
    db = node.idx(workspace)
    db.execute(
        "INSERT INTO facts(fid, blob) VALUES(?,?)",
        (forged.fid, encode(forged)),
    )
    db.executemany(
        "INSERT INTO fact_index VALUES(?,?,?,?)",
        catalog.index_rows(forged),
    )
    db.executescript("""
        CREATE TABLE admission_receipts(value TEXT);
        CREATE TABLE proofs(value TEXT);
        INSERT INTO admission_receipts VALUES('invented authority');
        INSERT INTO proofs VALUES('invented rank');
    """)
    db.execute(
        "INSERT OR REPLACE INTO meta(k, v) VALUES('index-version', ?)",
        ("obsolete-admission-projection",),
    )
    db.commit()
    db.close()

    reopened = Node(str(directory))
    upgraded = reopened.idx(workspace)

    assert reopened.reader(workspace).root_bytes == root
    assert forged.fid not in reopened.reader(
        workspace).all_facts().facts
    assert reopened.fact_of(workspace, forged.fid) is None
    assert {
        name for (name,) in upgraded.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    } == {"facts", "fact_index", "meta"}
    assert upgraded.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE name IN ('admission_receipts','proofs')"
    ).fetchone() is None


def test_catalog_facade_is_read_only_over_a_disk_projection(tmp_path):
    database = sqlite3.connect(tmp_path / "disposable.db")
    database.executescript(catalog.SCHEMA)
    facade = catalog.Catalog(database, "0" * 64)

    assert facade.fact("1" * 64) is None
    assert not any(
        name in catalog.Catalog.__dict__
        for name in (
            "admit",
            "insert",
            "publish",
            "retire",
            "settle",
            "stage",
        )
    )
