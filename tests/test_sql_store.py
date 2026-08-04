"""The one disposable SQL projection and combined generic index."""
import asyncio
import sqlite3

import facts

from core import fact_index
from core.fact import CurrentFact, Fact, current_fact, decode, encode
from full_peer import sql_store
from full_peer.node import FullPeer
from core.repository_snapshot import action_bindings
from core.writer_repository import FactConsumer, RepositoryMirror
from facts.auth.signature import signature
from facts.content.message import legacy_message


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
    "meta",
}


def _tables(db):
    return {
        name for (name,) in db.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    }


def _expected_projection(node, workspace):
    """Replay accepted writer trees into an independent in-memory consumer."""
    consumer = FactConsumer(workspace)
    result = asyncio.run(RepositoryMirror(
        workspace,
        node.store(workspace),
        node.writer_binding,
        consumer,
    ).replay_local())
    assert result.errors == ()
    source_by_fid = {
        fid: consumer.fact_bytes(fid)
        for fid in consumer.fact_ids()
    }
    decoded = {
        fid: facts.hydrate(decode(raw))
        for fid, raw in source_by_fid.items()
    }
    rows = {
        row
        for fact in decoded.values()
        for row in fact_index.index_rows(fact)
    }
    rows.update(
        (fact_index.ACTION_INDEX, sid, "", fid)
        for sid, fid in action_bindings(decoded).items()
    )
    return {
        fid: sql_store._encode_current(decode(raw))
        for fid, raw in source_by_fid.items()
    }, rows


def _durable_heads(node, workspace):
    store = node.store(workspace)
    return {
        key: store.get(key)
        for key in store.list(f"heads/{workspace}/")
    }


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
    assert _tables(db) == {"facts", "fact_index", "projected_heads"}
    for fid, raw in actual_facts.items():
        _source, fact = sql_store._decode_current(raw)
        assert fact.fid == fid


def test_sql_store_has_one_blob_table_and_one_exact_combined_index(tmp_path):
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
    heads = _durable_heads(node, workspace)
    expected = {
        "members": facts.auth.user.members(node, workspace),
        "messages": facts.content.message.messages(node, workspace),
    }
    expected_facts, expected_rows = _expected_projection(
        node, workspace)
    assert [row["fid"] for row in expected["messages"]] == [keep]
    node.idx(workspace).close()

    reopened = FullPeer(str(directory))

    assert _durable_heads(reopened, workspace) == heads
    assert facts.auth.user.members(reopened, workspace) == expected["members"]
    assert facts.content.message.messages(reopened, workspace) == expected["messages"]
    assert dict(reopened.idx(workspace).execute(
        "SELECT fid, blob FROM facts")) == expected_facts
    assert set(reopened.idx(workspace).execute(
        "SELECT kind, k0, k1, src FROM fact_index"
    )) == expected_rows
    assert not (directory / "app.db").exists()


def test_app_version_replays_legacy_source_into_current_serialized_form(
        tmp_path):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    secret, writer = node.identity(workspace)
    root = node.fact_of(workspace, workspace)
    legacy = legacy_message(
        workspace, writer, "general", "survives cut", 2, writer)
    node.publish_closed(workspace, ((
        root,
        signature(secret, writer, legacy, 2),
        legacy,
    ),))
    message_fid = legacy.fid
    heads = _durable_heads(node, workspace)
    path = directory / "ws" / f"{workspace}.idx.db"
    node.idx(workspace).close()

    # This is the disposable projection an older application left behind.
    # Durable writer-pile bytes already contain the exact legacy source.
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version={facts.APP_VERSION - 1}")
    db.execute(
        "UPDATE facts SET blob=? WHERE fid=?",
        (encode(legacy), legacy.fid),
    )
    local_only = Fact(
        "obsolete_local",
        3,
        [],
        {"value": "must be discarded"},
        workspace,
    )
    db.execute(
        "INSERT INTO facts VALUES(?,?)",
        (local_only.fid, encode(local_only)),
    )
    db.commit()
    db.close()

    reopened = FullPeer(str(directory))
    upgraded = reopened.idx(workspace)
    stored = reopened.sql(workspace).stored_bytes(message_fid)
    source, form = sql_store._decode_current(stored)

    assert _durable_heads(reopened, workspace) == heads
    assert isinstance(form, CurrentFact)
    assert source == legacy
    assert current_fact(form).t == "msg"
    assert current_fact(form).body == {
        "pk": writer,
        "owner": writer,
        "chan": "general",
        "text": "survives cut",
    }
    assert form.fid == message_fid
    assert stored != encode(legacy)
    assert reopened.sql(workspace).fact_bytes(message_fid) == encode(legacy)
    assert reopened.sql(workspace).source_fact_of(message_fid) == legacy
    assert reopened.fact_of(
        workspace, local_only.fid) is None
    assert _tables(upgraded) == {
        "facts", "fact_index", "projected_heads"}
    assert upgraded.execute("PRAGMA user_version").fetchone()[0] \
        == facts.APP_VERSION
    assert upgraded.execute(
        "SELECT 1 FROM facts WHERE fid=?", (local_only.fid,)
    ).fetchone() is None
    assert upgraded.execute(
        "SELECT 1 FROM fact_index WHERE kind=? AND k0='msg' AND src=?",
        (fact_index.TYPE_INDEX, message_fid),
    ).fetchone() == (1,)
    assert upgraded.execute(
        "SELECT 1 FROM fact_index WHERE kind=? AND k0='msg.v0' AND src=?",
        (fact_index.TYPE_INDEX, message_fid),
    ).fetchone() is None
    assert facts.content.message.messages(reopened, workspace) == [{
        "chan": "general",
        "from": "alice",
        "text": "survives cut",
        "mentions": [],
        "ts": 2,
        "fid": message_fid,
    }]

    # A current dependent closes over and republishes the exact legacy source;
    # only the disposable semantic view is current.
    facts.content.delete.remove(reopened, workspace, message_fid, ts=3)
    assert facts.content.message.messages(reopened, workspace) == []
    current_blob = reopened.sql(workspace).stored_bytes(message_fid)
    reopened.rebuild(workspace)
    assert reopened.sql(workspace).stored_bytes(message_fid) == current_blob


def test_projection_rebuild_replaces_stale_missing_and_extra_rows(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    message_fid = facts.content.message.post(
        node, workspace, "general", "kept", ts=2)
    heads = _durable_heads(node, workspace)
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

    assert _durable_heads(node, workspace) == heads
    _assert_exact_projection(node, workspace)
    assert [row["fid"] for row in facts.content.message.messages(
        node, workspace)] == [message_fid]

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
