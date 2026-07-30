"""Admission semantics remain authenticated; SQLite only projects them."""
import sqlite3

import pytest

from core import catalog, cmds
from core.fact import encode
from core.node import Node
from facts.content.message import message


def _receipt_edges(reader, fid):
    verified = reader.candidates().verify(fid)
    receipt = next(
        receipt
        for receipt in verified.valids
        if receipt.fact.fid == fid
    )
    return tuple(sorted(
        receipt.edges, key=lambda edge: edge.role))


def test_combined_edge_rows_match_authenticated_admission_semantics(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    fid = cmds.post(
        node, workspace, "general", "admitted", ts=2)
    reader = node.reader(workspace)
    expected = _receipt_edges(reader, fid)
    projected = node.catalog(workspace).edges(fid)
    record = reader.candidates().fact_record(fid)

    assert projected == expected
    assert [
        [edge.role, edge.fid, edge.kind]
        for edge in projected
    ] == record["dependencies"]
    assert [edge.role for edge in projected] == sorted(
        edge.role for edge in projected)
    assert len({edge.role for edge in projected}) == len(projected)
    assert {edge.kind for edge in projected} == {"need"}
    assert set(node.idx(workspace).execute(
        "SELECT k0, k1 FROM fact_index "
        "WHERE kind=? AND src=?",
        (catalog.EDGE_INDEX, fid),
    )) == {
        (f"{edge.kind}:{edge.role}", edge.fid)
        for edge in expected
    }

    # Local rows are explicitly unauthenticated accelerators. A malformed
    # typed role fails closed locally, while the pinned repository proof
    # remains intact and a root refresh restores the exact combined rows.
    first = expected[0]
    node.idx(workspace).execute(
        "UPDATE fact_index SET k0=? "
        "WHERE kind=? AND src=? AND k0=? AND k1=?",
        (
            f"invented:{first.role}",
            catalog.EDGE_INDEX,
            fid,
            f"{first.kind}:{first.role}",
            first.fid,
        ),
    )
    node.idx(workspace).commit()
    with pytest.raises(ValueError, match="fact projection edge"):
        node.catalog(workspace).edges(fid)
    assert _receipt_edges(reader, fid) == expected

    node.rebuild(workspace)

    assert node.catalog(workspace).edges(fid) == expected


def test_legacy_local_authority_rows_are_discarded_not_blessed(
        tmp_path):
    directory = tmp_path / "node"
    node = Node(str(directory))
    workspace = cmds.create(node, "alice", ts=1)
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
    db.execute(
        "INSERT INTO fact_index VALUES(?,?,?,?)",
        (
            catalog.STATE_INDEX,
            "eligible",
            "999",
            forged.fid,
        ),
    )
    db.executescript("""
        CREATE TABLE admission_receipts(value TEXT);
        CREATE TABLE proofs(value TEXT);
        INSERT INTO admission_receipts VALUES('invented authority');
        INSERT INTO proofs VALUES('invented rank');
    """)
    db.execute(
        "INSERT OR REPLACE INTO meta(k, v) VALUES('index-version', ?)",
        ("admission-catalog-v27-generic-candidate-index",),
    )
    db.commit()
    db.close()

    reopened = Node(str(directory))
    upgraded = reopened.idx(workspace)

    assert reopened.reader(workspace).root_bytes == root
    assert forged.fid not in reopened.reader(
        workspace).archive().records
    assert reopened.candidate_of(workspace, forged.fid) is None
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

    assert facade.candidate("1" * 64) is None
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
