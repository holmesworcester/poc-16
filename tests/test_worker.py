"""Bounded Worker reads over the atomically committed composite root."""
import inspect
import json
import sqlite3

import pytest

import facts

from core import indexes, merkle_map, snapshot
from core.crypto import h
from core.fact import canon
from full_peer.node import FullPeer, now_ms
from core.repository_reader import RepositoryReader
from core.repository_snapshot import compile_snapshot
from core.worker import WorkerView
from facts.auth import request

from .util import add_member


def compiled(node, workspace):
    facts_by_fid = {
        fid: node.fact_of(workspace, fid)
        for fid in node.sql(workspace).fact_ids()
    }
    result = compile_snapshot(workspace, facts_by_fid)
    objects = dict(result.objects)
    return result.root, objects, RepositoryReader(
        workspace, result.root, objects.get)


def putter(objects):
    def emit(raw):
        oid = h(raw)
        objects.setdefault(oid, raw)
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
    pile = node.sender(workspace).pack(request.payload(
        node, workspace, "sync", now + 60_000, now))
    root, objects, _ = compiled(node, workspace)
    fact_order_oid = snapshot.decode_root(
        root).maps[snapshot.FACT_ORDER]["root"]
    fetched = []

    def fetch(oid):
        fetched.append(oid)
        return objects.get(oid)

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
    pile = node.sender(workspace).pack(request.payload(
        node, workspace, "sync", now + 60_000, now))
    root, objects, _ = compiled(node, workspace)
    view = WorkerView.from_root(
        root, objects.get)

    def database_forbidden(*_args, **_kwargs):
        raise AssertionError("CF Worker authorization opened a database")

    monkeypatch.setattr(sqlite3, "connect", database_forbidden)
    assert view.mint(pile, now) == (node.identity_id(workspace), "sync")


def test_worker_shares_integrity_reads_without_gaining_validated_set_authority(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    _root, objects, reader = compiled(node, workspace)
    worker, validated = reader.worker(), reader.validated()

    assert worker.fact_of(workspace) == validated.fact(workspace)
    assert not hasattr(worker, "closure")
    assert not hasattr(worker, "providers")
    assert not hasattr(validated, "mint")
    assert not hasattr(validated, "authority_provider")

    oid = validated.fact_oid(workspace)

    def corrupt(candidate):
        return b"corrupt" if candidate == oid \
            else objects.get(candidate)

    with pytest.raises(ValueError):
        WorkerView.from_root(reader.root_bytes, corrupt).fact_of(workspace)
    with pytest.raises(ValueError):
        type(validated)(reader.root_bytes, corrupt).fact(workspace)


@pytest.mark.parametrize("name", indexes.TREE_NAMES)
@pytest.mark.parametrize("field", ("count", "depth"))
def test_worker_mint_rejects_forged_outer_map_metadata(
        tmp_path, name, field):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    now = now_ms()
    pile = node.sender(workspace).pack(request.payload(
        node, workspace, "sync", now + 60_000, now))
    root, objects, _ = compiled(node, workspace)
    body = json.loads(root)
    descriptor = body["maps"][name]
    target_root = descriptor["root"]
    descriptor[field] += 1
    fetched = []

    def fetch(oid):
        fetched.append(oid)
        return objects.get(oid)

    forged = canon(body)
    view = WorkerView.from_root(forged, fetch)
    with pytest.raises(ValueError, match="merkle map root metadata"):
        if name == indexes.FACT:
            view.fact_of(workspace)
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
    pile = node.sender(workspace).pack(request.payload(
        node, workspace, "sync", now + 60_000, now))
    root, objects, _ = compiled(node, workspace)
    committed = snapshot.decode_root(root)
    seed, maps = committed.layout_seed, committed.maps
    public = node.identity_id(workspace)
    removed = merkle_map.update(
        maps[indexes.SUPP]["root"], seed,
        [(indexes.principal_sid("member", public), None)],
        objects.get, putter(objects))
    body = json.loads(root)
    body["maps"][indexes.SUPP] = {
        "root": removed.root,
        "count": removed.count,
        "depth": removed.page_depth,
    }
    forged = canon(body)

    view = WorkerView.from_root(
        forged, objects.get)
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
    pile = node.sender(workspace).pack(request.payload(
        node, workspace, "sync", now + 60_000, now))
    root, objects, _ = compiled(node, workspace)
    before = WorkerView.from_root(
        root, objects.get)
    assert before.principal_active("member", bob)
    assert before.mint(pile, now) == (bob, "sync")

    node.bind_identity(workspace, founder)
    facts.auth.removal.evict(node, workspace, bob)
    root, objects, _ = compiled(node, workspace)
    after = WorkerView.from_root(
        root, objects.get)
    assert not after.principal_active("member", bob)
    assert after.mint(pile, now) is None


def test_suppression_action_names_ordinary_fact_evidence(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    target = facts.content.message.post(node, workspace, "general", "doomed", ts=10)
    old_root, old_objects, _ = compiled(node, workspace)
    old = WorkerView.from_root(
        old_root, old_objects.get)
    sid = indexes.fact_key(target)
    assert old.suppression(sid) == {"state": "clear"}

    action_fid = facts.content.delete.remove(node, workspace, target, ts=20)
    new_root, new_objects, _ = compiled(node, workspace)
    assert new_root != old_root
    new = WorkerView.from_root(
        new_root, new_objects.get)
    active = {"state": "active", "action": action_fid}
    assert new.suppression(sid) == active
    assert new.fact_of(action_fid).fid == action_fid
    assert sid in facts.action_sids(new.fact_of(action_fid))
    assert new._reader(indexes.FACT).range_page(
        "action:", "action:\uffff").rows == ()

    maps = snapshot.decode_root(new_root).maps
    assert set(maps) == set(snapshot.MAP_NAMES)
    assert "removal" not in maps
