"""The single fact catalog and generic query-index contract."""
import json
import sqlite3

from core import catalog, cmds, suppression_state
from core.crypto import h
from core.fact import Fact, canon, decode, encode
from core.node import Node
from core.shape import boundary


def test_catalog_stores_one_blob_and_indexes_type_plus_every_offer(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    message_fid = cmds.post(
        node, workspace, "general", "indexed by type", ts=2)
    index = node.idx(workspace)

    assert [
        (name, kind)
        for _, name, kind, *_ in index.execute("PRAGMA table_info(facts)")
    ] == [("fid", "TEXT"), ("blob", "BLOB")]

    for fid, raw in index.execute("SELECT fid, blob FROM facts"):
        fact = decode(raw)
        assert fact.fid == fid
        assert encode(fact) == raw
        rows = set(index.execute(
            "SELECT kind, k0, k1 FROM fact_index WHERE src=?", (fid,)))
        assert rows == {
            (catalog.TYPE_INDEX, fact.t, ""),
            (catalog.KEY_INDEX, fact.key,
             "1" if boundary(fact.fid) else ""),
            *fact.offers(),
        }

    assert [fact.fid for fact in node.by_type(workspace, "msg")] \
        == [message_fid]
    assert node.select(
        workspace, "member", node.identity_id(workspace)
    )[0].fid == workspace
    assert index.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE name IN ('offers','log','projected','message_rows')"
    ).fetchone() is None
    assert not (tmp_path / "node" / "app.db").exists()


def test_public_queries_restart_directly_from_catalog(tmp_path):
    directory = tmp_path / "node"
    node = Node(str(directory))
    workspace = cmds.create(node, "alice", ts=1)
    keep = cmds.post(node, workspace, "general", "keep", ts=2)
    remove = cmds.post(node, workspace, "general", "remove", ts=3)
    cmds.remove(node, workspace, remove, ts=4)
    index = node.idx(workspace)

    assert [
        name for _, name, *_ in index.execute(
            "PRAGMA table_info(action_proposals)")
    ] == ["fid", "k"]
    assert [
        name for _, name, *_ in index.execute("PRAGMA table_info(actions)")
    ] == ["sid", "fid", "evidence"]
    assert index.execute(
        "SELECT COUNT(*) FROM facts WHERE fid IN "
        "(SELECT fid FROM action_proposals)"
    ).fetchone() == index.execute(
        "SELECT COUNT(*) FROM action_proposals"
    ).fetchone()

    expected = {
        "members": cmds.members(node, workspace),
        "messages": cmds.msgs(node, workspace),
    }
    assert [row["fid"] for row in expected["messages"]] == [keep]
    node.idx(workspace).close()

    reopened = Node(str(directory))
    assert cmds.members(reopened, workspace) == expected["members"]
    assert cmds.msgs(reopened, workspace) == expected["messages"]
    assert not (directory / "app.db").exists()


def test_legacy_rows_migrate_to_canonical_blobs_and_generic_index():
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE facts(
            fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT, admitted INT);
        CREATE TABLE offers(
            name TEXT, a0 TEXT, a1 TEXT, src TEXT,
            PRIMARY KEY(name, a0, a1, src));
    """)
    committed = Fact(
        "legacy", 1, [["offer", "legacy-key", "one"]], {"value": 1})
    pending = Fact("legacy", 2, [], {"value": 2})
    db.executemany(
        "INSERT INTO facts VALUES(?,?,?,?,?)",
        (
            (fact.fid, fact.ts, fact.t, json.dumps(fact.to_json()), admitted)
            for fact, admitted in ((committed, 1), (pending, 0))
        ),
    )
    db.commit()
    db.executescript(catalog.SCHEMA)

    catalog.upgrade_schema(db)

    assert {
        name for _, name, *_ in db.execute("PRAGMA table_info(facts)")
    } == {"fid", "blob"}
    assert decode(db.execute(
        "SELECT blob FROM facts WHERE fid=?", (committed.fid,)
    ).fetchone()[0]) == committed
    assert db.execute(
        "SELECT fid FROM staged").fetchall() == [(pending.fid,)]
    assert set(db.execute(
        "SELECT kind, k0, k1, src FROM fact_index"
    )) == {
        (catalog.TYPE_INDEX, "legacy", "", committed.fid),
        (catalog.TYPE_INDEX, "legacy", "", pending.fid),
        (catalog.KEY_INDEX, committed.key,
         "1" if boundary(committed.fid) else "", committed.fid),
        (catalog.KEY_INDEX, pending.key,
         "1" if boundary(pending.fid) else "", pending.fid),
        ("legacy-key", "one", "", committed.fid),
    }
    assert db.execute(
        "SELECT 1 FROM sqlite_master WHERE name='offers'"
    ).fetchone() is None


def test_legacy_action_tables_drop_copied_fact_json():
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE action_proposals(
            fid TEXT PRIMARY KEY, k TEXT NOT NULL, j TEXT NOT NULL);
        CREATE TABLE actions(
            sid TEXT PRIMARY KEY, fid TEXT NOT NULL,
            j TEXT NOT NULL, evidence TEXT NOT NULL);
        CREATE INDEX actions_by_fid ON actions(fid);
        INSERT INTO action_proposals VALUES('action','key','copied body');
        INSERT INTO actions VALUES('fact:target','action','copied body','proof');
    """)

    suppression_state.upgrade_schema(db)

    assert [
        name for _, name, *_ in db.execute(
            "PRAGMA table_info(action_proposals)")
    ] == ["fid", "k"]
    assert [
        name for _, name, *_ in db.execute("PRAGMA table_info(actions)")
    ] == ["sid", "fid", "evidence"]
    assert db.execute("SELECT * FROM action_proposals").fetchall() == [
        ("action", "key"),
    ]
    assert db.execute("SELECT * FROM actions").fetchall() == [
        ("fact:target", "action", "proof"),
    ]
    assert db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='index' AND name='actions_by_fid'"
    ).fetchone() == ("actions_by_fid",)


def test_rebuild_replaces_stale_and_missing_generic_index_rows(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    message = cmds.post(node, workspace, "general", "kept", ts=2)
    index = node.idx(workspace)
    index.execute("DELETE FROM fact_index WHERE src=?", (message,))
    index.execute(
        "INSERT INTO fact_index VALUES(?,?,?,?)",
        (catalog.TYPE_INDEX, "msg", "", workspace),
    )
    index.execute("DELETE FROM proofs WHERE fid=?", (message,))
    index.commit()

    node.rebuild(workspace)

    for fid, raw in index.execute("SELECT fid, blob FROM facts"):
        fact = decode(raw)
        assert set(index.execute(
            "SELECT kind, k0, k1 FROM fact_index WHERE src=?", (fid,)
        )) == {
            (catalog.TYPE_INDEX, fact.t, ""),
            (catalog.KEY_INDEX, fact.key,
             "1" if boundary(fact.fid) else ""),
            *fact.offers(),
        }
    assert [row["fid"] for row in cmds.msgs(node, workspace)] == [message]


def test_v23_blob_catalog_backfills_keys_before_foreign_root_republish(
        tmp_path):
    directory = tmp_path / "node"
    node = Node(str(directory))
    workspace = cmds.create(node, "alice", ts=1)
    message = cmds.post(node, workspace, "general", "survives", ts=2)
    store = node.store(workspace)
    current = store.get("root")
    foreign_value = json.loads(current)
    foreign_value["stamp"] = "composite-btreap-v4"
    foreign = canon(foreign_value)
    assert store.cas("root", h(current), foreign) == h(foreign)

    index = node.idx(workspace)
    index.execute(
        "DELETE FROM fact_index WHERE kind=?", (catalog.KEY_INDEX,))
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('root',?)", (h(foreign),))
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('root-bytes',?)", (foreign,))
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('index-version',?)",
        ("admission-catalog-v23",),
    )
    index.commit()
    index.close()

    reopened = Node(str(directory))

    assert reopened.store(workspace).get("root") != foreign
    assert reopened.fact_of(workspace, message) is not None
    assert [row["fid"] for row in cmds.msgs(reopened, workspace)] == [message]
    assert reopened.idx(workspace).execute(
        "SELECT COUNT(*) FROM fact_index WHERE kind=?",
        (catalog.KEY_INDEX,),
    ).fetchone() == reopened.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts"
    ).fetchone()


def test_index_lookup_decodes_only_selected_fact_bodies(tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    for timestamp in range(2, 22):
        cmds.post(
            node, workspace, "general", f"message-{timestamp}",
            ts=timestamp)

    decoded = []
    strict_decode = catalog.decode

    def observed(raw):
        fact = strict_decode(raw)
        decoded.append(fact.fid)
        return fact

    monkeypatch.setattr(catalog, "decode", observed)
    selected = node.catalog(workspace).indexed(
        "member", node.identity_id(workspace))

    assert [fact.fid for _, fact in selected] == [workspace]
    assert decoded == [workspace]
