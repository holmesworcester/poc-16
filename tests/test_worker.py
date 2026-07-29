"""Bounded Worker reads over the atomically committed composite root."""
import inspect
import json
import sqlite3

from core import btreap, cmds, indexes, manifest
from core.close import encode_pile
from core.crypto import h
from core.fact import canon
from core.node import Node, now_ms
from core.worker import WorkerView
from facts.auth import request

from .util import add_member


def putter(store):
    def emit(raw):
        oid = h(raw)
        store.put_if_absent("obj/" + oid, raw)
        return oid
    return emit


def test_exact_fid_and_principal_reads_never_fetch_the_fact_manifest(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    cmds.post(node, workspace, "general", "keeps another slot", ts=2)
    for ordinal in range(100):
        cmds.post(
            node, workspace, "general", f"message-{ordinal}",
            ts=10 + ordinal)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    root = store.get("root")
    manifest_oid = manifest.decode_root(root).manifest
    fetched = []

    def fetch(oid):
        fetched.append(oid)
        return store.get("obj/" + oid)

    view = WorkerView.from_root(root, fetch)
    assert view.mint(pile, now) == (node.identity_id(workspace), "sync")
    assert manifest_oid not in fetched
    assert len(set(fetched)) <= 6 * btreap.MAX_PAGE_DEPTH
    assert "sqlite" not in inspect.getsource(WorkerView).lower()


def test_worker_mint_uses_no_database(tmp_path, monkeypatch):
    """The deployed CF auth path remains usable when SQLite is unavailable."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    view = WorkerView.from_root(
        store.get("root"), lambda oid: store.get("obj/" + oid))

    def database_forbidden(*_args, **_kwargs):
        raise AssertionError("CF Worker authorization opened a database")

    monkeypatch.setattr(sqlite3, "connect", database_forbidden)
    assert view.mint(pile, now) == (node.identity_id(workspace), "sync")


def test_missing_suppression_slot_fails_closed_instead_of_meaning_clear(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    cmds.post(node, workspace, "general", "keeps another slot", ts=2)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    root = store.get("root")
    snapshot = manifest.decode_root(root)
    seed, trees = snapshot.layout_seed, snapshot.trees
    public = node.identity_id(workspace)
    removed = btreap.update(
        trees[indexes.SUPP]["root"], seed,
        [(indexes.principal_sid("member", public), None)],
        lambda oid: store.get("obj/" + oid), putter(store))
    body = json.loads(root)
    body["trees"][indexes.SUPP] = {
        "root": removed.root,
        "count": removed.count,
        "depth": removed.page_depth,
    }
    forged = canon(body)

    view = WorkerView.from_root(
        forged, lambda oid: store.get("obj/" + oid))
    assert view.mint(pile, now) is None


def test_eviction_is_one_exact_principal_read_and_covers_old_requests(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "Bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    before = WorkerView.from_root(
        store.get("root"), lambda oid: store.get("obj/" + oid))
    assert before.principal_active("member", bob)
    assert before.mint(pile, now) == (bob, "sync")

    node.bind_identity(workspace, founder)
    cmds.evict(node, workspace, bob)
    after = WorkerView.from_root(
        store.get("root"), lambda oid: store.get("obj/" + oid))
    assert not after.principal_active("member", bob)
    assert after.mint(pile, now) is None


def test_fact_and_suppression_action_slots_change_under_one_root(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    target = cmds.post(node, workspace, "general", "doomed", ts=10)
    store = node.store(workspace)
    old_root = store.get("root")
    old = WorkerView.from_root(
        old_root, lambda oid: store.get("obj/" + oid))
    sid = indexes.fact_key(target)
    assert old.suppression(sid) == {"state": "clear"}
    assert old._reader(indexes.FACT).get(
        indexes.action_key(sid)) == {"state": "clear"}

    action_fid = cmds.remove(node, workspace, target, ts=20)
    new_root = store.get("root")
    assert new_root != old_root
    new = WorkerView.from_root(
        new_root, lambda oid: store.get("obj/" + oid))
    active = {"state": "active", "action": action_fid}
    assert new.suppression(sid) == active
    assert new._reader(indexes.FACT).get(indexes.action_key(sid)) == active
    assert new.fact_record(action_fid)["evidence"]

    trees = manifest.decode_root(new_root).trees
    assert set(trees) == set(indexes.TREE_NAMES)
    assert "removal" not in trees
