"""Successful whole-pile judgment is the repository's only admission."""

import sqlite3

import facts

from full_peer import sql_store
from full_peer.node import FullPeer


def test_sql_projection_contains_no_admission_verdict_or_edges(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fid = facts.content.message.post(
        node, workspace, "general", "admitted once", ts=2)
    kinds = {
        kind for (kind,) in node.idx(workspace).execute(
            "SELECT DISTINCT kind FROM fact_index WHERE src=?", (fid,))
    }

    assert node.sql(workspace).fact_of(fid).fid == fid
    assert kinds == {"fact.key", "fact.scope", "fact.type"}
    assert not any(
        marker in kind
        for kind in kinds
        for marker in ("admission", "edge", "eligible", "proof", "rank"))


def test_sql_store_is_read_only_over_a_disposable_projection(tmp_path):
    database = sqlite3.connect(tmp_path / "disposable.db")
    database.executescript(sql_store.SCHEMA)
    facade = sql_store.SqlStore(database, "0" * 64)

    assert facade.fact_of("1" * 64) is None
    assert not any(
        name in sql_store.SqlStore.__dict__
        for name in (
            "admit",
            "insert",
            "publish",
            "retire",
            "settle",
            "stage",
        )
    )
