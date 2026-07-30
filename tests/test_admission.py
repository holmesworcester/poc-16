"""The durable catalog has one running-kernel admission membrane."""
import json

import pytest

from core import catalog, cmds
from core.fact import canon, encode
from core.node import Node
from facts.content.message import message


def test_admission_retains_the_kernels_exact_semantic_edges(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    fid = cmds.post(node, workspace, "general", "admitted", ts=2)

    edges = node.catalog(workspace).admission_edges(fid)
    assert edges == node.catalog(workspace).edges(fid)
    assert [edge.role for edge in edges] == sorted(
        edge.role for edge in edges)
    assert len({edge.role for edge in edges}) == len(edges)
    assert {edge.kind for edge in edges} == {"need"}

    # Canonical JSON is not enough: a semantically malformed local witness
    # fails closed when later proof-DAG work tries to consume it.
    index = node.idx(workspace)
    raw = index.execute(
        "SELECT receipt FROM admission_receipts WHERE fid=?",
        (fid,),
    ).fetchone()[0]
    damaged = json.loads(raw)
    damaged["edges"][0][2] = "invented"
    index.execute(
        "UPDATE admission_receipts SET receipt=? WHERE fid=?",
        (canon(damaged), fid),
    )
    with pytest.raises(ValueError, match="admission receipt integrity"):
        node.catalog(workspace).admission_edges(fid)


def test_v27_local_only_rows_remain_explicitly_proofless(tmp_path):
    """The membrane does not pretend to solve the pending legacy-cut bead."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    forged = message(
        workspace, node.identity_id(workspace),
        "general", "legacy local-only row", 2)
    index = node.idx(workspace)
    index.execute(
        "INSERT INTO facts(fid, blob) VALUES(?,?)",
        (forged.fid, encode(forged)),
    )
    index.execute("DELETE FROM admission_receipts")
    index.execute(
        "INSERT OR REPLACE INTO meta(k, v) VALUES('index-version', ?)",
        ("admission-catalog-v27-generic-candidate-index",),
    )
    index.commit()
    for connection in node._idx.values():
        connection.close()

    reopened = Node(node.dir)

    # The authenticated root is safely re-judged through the running kernel.
    assert reopened.catalog(workspace).admission_edges(workspace) == ()
    # The indistinguishable local-only legacy row is retained for the
    # explicit .17.11.3 cutover decision, but never receives a witness.
    assert reopened.candidate_of(workspace, forged.fid) == forged
    assert reopened.fact_of(workspace, forged.fid) is None
    assert reopened.catalog(workspace).admission_edges(forged.fid) is None


def test_raw_loader_is_memory_only(tmp_path):
    import sqlite3

    database = sqlite3.connect(tmp_path / "durable.db")
    database.executescript(catalog.SCHEMA)
    with pytest.raises(ValueError, match="in-memory"):
        catalog.ScratchCatalog(database, "0" * 64)
