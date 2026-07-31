"""Bounded Worker reads over the atomically committed composite root."""
import inspect
import json
import sqlite3

import pytest

import facts

from core import indexes, merkle_map, snapshot
from core.close import encode_pile
from core.crypto import h
from core.fact import canon
from full_peer.node import FullPeer, now_ms
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
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "keeps another slot", ts=2)
    for ordinal in range(100):
        facts.content.message.post(
            node, workspace, "general", f"message-{ordinal}",
            ts=10 + ordinal)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    root = store.get("root")
    fact_order_oid = snapshot.decode_root(
        root).maps[snapshot.FACT_ORDER]["root"]
    fetched = []

    def fetch(oid):
        fetched.append(oid)
        return store.get("obj/" + oid)

    view = WorkerView.from_root(root, fetch)
    assert view.mint(pile, now) == (node.identity_id(workspace), "sync")
    assert fact_order_oid not in fetched
    assert len(set(fetched)) <= 6 * merkle_map.MAX_PAGE_DEPTH
    assert "sqlite" not in inspect.getsource(WorkerView).lower()


def test_worker_mint_uses_no_database(tmp_path, monkeypatch):
    """The deployed CF auth path remains usable when SQLite is unavailable."""
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
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


def test_worker_shares_integrity_reads_without_gaining_validated_set_authority(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    reader = node.reader(workspace)
    worker, validated = reader.worker(), reader.validated()

    assert worker.fact(workspace) == validated.fact(workspace)
    assert not hasattr(worker, "closure")
    assert not hasattr(worker, "providers")
    assert not hasattr(validated, "mint")
    assert not hasattr(validated, "authority_provider")

    oid = validated.fact_oid(workspace)

    def corrupt(candidate):
        return b"corrupt" if candidate == oid \
            else node.store(workspace).get("obj/" + candidate)

    with pytest.raises(ValueError):
        WorkerView.from_root(reader.root_bytes, corrupt).fact(workspace)
    with pytest.raises(ValueError):
        type(validated)(reader.root_bytes, corrupt).fact(workspace)


@pytest.mark.parametrize("name", indexes.TREE_NAMES)
@pytest.mark.parametrize("field", ("count", "depth"))
def test_worker_mint_rejects_forged_outer_map_metadata(
        tmp_path, name, field):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    body = json.loads(store.get("root"))
    descriptor = body["maps"][name]
    target_root = descriptor["root"]
    descriptor[field] += 1
    fetched = []

    def fetch(oid):
        fetched.append(oid)
        return store.get("obj/" + oid)

    forged = canon(body)
    view = WorkerView.from_root(forged, fetch)
    with pytest.raises(ValueError, match="merkle map root metadata"):
        if name == indexes.FACT:
            view.fact(workspace)
        else:
            view.principal_active(
                "member", node.identity_id(workspace))
    assert target_root in fetched

    fetched.clear()
    assert WorkerView.from_root(forged, fetch).mint(pile, now) is None
    assert target_root in fetched


def test_missing_suppression_slot_fails_closed_instead_of_meaning_clear(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "keeps another slot", ts=2)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    root = store.get("root")
    committed = snapshot.decode_root(root)
    seed, maps = committed.layout_seed, committed.maps
    public = node.identity_id(workspace)
    removed = merkle_map.update(
        maps[indexes.SUPP]["root"], seed,
        [(indexes.principal_sid("member", public), None)],
        lambda oid: store.get("obj/" + oid), putter(store))
    body = json.loads(root)
    body["maps"][indexes.SUPP] = {
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
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
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
    facts.auth.removal.evict(node, workspace, bob)
    after = WorkerView.from_root(
        store.get("root"), lambda oid: store.get("obj/" + oid))
    assert not after.principal_active("member", bob)
    assert after.mint(pile, now) is None


def test_suppression_action_names_ordinary_fact_evidence(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    target = facts.content.message.post(node, workspace, "general", "doomed", ts=10)
    store = node.store(workspace)
    old_root = store.get("root")
    old = WorkerView.from_root(
        old_root, lambda oid: store.get("obj/" + oid))
    sid = indexes.fact_key(target)
    assert old.suppression(sid) == {"state": "clear"}

    action_fid = facts.content.delete.remove(node, workspace, target, ts=20)
    new_root = store.get("root")
    assert new_root != old_root
    new = WorkerView.from_root(
        new_root, lambda oid: store.get("obj/" + oid))
    active = {"state": "active", "action": action_fid}
    assert new.suppression(sid) == active
    assert new.fact(action_fid).fid == action_fid
    assert sid in facts.action_sids(new.fact(action_fid))
    assert new._reader(indexes.FACT).range_page(
        "action:", "action:\uffff").rows == ()

    maps = snapshot.decode_root(new_root).maps
    assert set(maps) == set(snapshot.MAP_NAMES)
    assert "removal" not in maps
