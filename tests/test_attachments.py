"""Bao attachment policy and query-time object verification."""
import json
import os
import random
import threading

import pytest

import facts
import core.catalog as catalog_module
import core.sync as sync_module
from core import bao, cmds, shape
from core.close import decode_pile, encode_pile
from core.crypto import h
from core.object_store import Applied, ensure_object
from core.fact import canon
from core.node import Node
from core.walk import _fetch_blobs, _push
from core.worker import WorkerView
from facts.content import chunk, file as file_family

from .util import (
    all_fids,
    closed_subset,
    deliver,
    member_src,
    send_bytes,
)


def close_node(node):
    for index in node._idx.values():
        index.close()


def progress(node, workspace):
    records = cmds.files(node, workspace)
    assert len(records) == 1
    return records[0]


def test_round_trip_survives_rebuild_and_index_wipe(tmp_path):
    path = tmp_path / "node"
    node = Node(str(path))
    workspace = cmds.create(node, "alice")
    data = random.Random(16).randbytes(bao.WIDTH * 2 + 17)
    fid = send_bytes(node, workspace, "three-slices.bin", data)

    record = progress(node, workspace)
    assert record["fid"] == fid
    assert record["have"] == 3
    assert record["complete"]
    node.rebuild(workspace)
    assert progress(node, workspace)["complete"]

    close_node(node)
    assert not (path / "app.db").exists()
    os.unlink(path / "ws" / f"{workspace}.idx.db")
    rebuilt = Node(str(path))
    output = tmp_path / "saved.bin"
    assert cmds.save_file(rebuilt, workspace, fid, output)["bytes"] == len(data)
    assert output.read_bytes() == data


def test_v24_catalog_prebackfills_refs_before_a_republish_crash(
        tmp_path, monkeypatch):
    directory = tmp_path / "node"
    node = Node(str(directory))
    workspace = cmds.create(node, "alice", ts=1)
    fid = send_bytes(node, workspace, "upgrade.bin", b"upgrade", ts=2)
    store = node.store(workspace)
    current = store.get("root")
    foreign_value = json.loads(current)
    foreign_value["stamp"] = "composite-btreap-v4"
    foreign = canon(foreign_value)
    assert isinstance(store.cas(
        "root", store.read_versioned("root").token, foreign), Applied)

    index = node.idx(workspace)
    index.execute(
        "DELETE FROM fact_index WHERE kind=?", (catalog_module.REF_INDEX,))
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('index-version', ?)",
        ("admission-catalog-v24",))
    index.commit()
    close_node(node)

    def crash_after_republish(_catalog):
        raise RuntimeError("crash after the early version stamp")

    monkeypatch.setattr(
        catalog_module.Catalog, "reindex", crash_after_republish)
    with pytest.raises(RuntimeError, match="early version stamp"):
        Node(str(directory))

    # The failed rebuild stamped v25 before reaching Catalog.reindex. Schema
    # opening must already have rebuilt ref rows, so a restart that now skips
    # the semantic rebuild still has a complete query index.
    upgraded = Node(str(directory))

    assert file_family.resolve(upgraded, workspace, fid)["complete"]
    assert upgraded.idx(workspace).execute(
        "SELECT COUNT(*) FROM fact_index WHERE kind=?",
        (catalog_module.REF_INDEX,)).fetchone()[0] > 0
    store = upgraded.store(workspace)
    view = WorkerView.from_root(
        store.get("root"), lambda oid: store.get("obj/" + oid))
    assert not view.authority_known(
        catalog_module.REF_INDEX, "file", fid)


def test_file_selector_compatibility_and_exact_suppression(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    first = send_bytes(node, workspace, "first.bin", b"first", ts=10)
    second = send_bytes(node, workspace, "second.bin", b"second", ts=20)
    root = node.fact_of(workspace, first).body["root"]
    unique_prefix = next(
        first[:width] for width in range(1, len(first) + 1)
        if not second.startswith(first[:width])
    )

    assert file_family.resolve(node, workspace, root)["fid"] == first
    assert file_family.resolve(node, workspace, unique_prefix)["fid"] == first
    assert file_family.resolve(node, workspace, "") is None

    cmds.remove(node, workspace, first, ts=30)
    assert file_family.resolve(node, workspace, first) is None


@pytest.mark.parametrize("operation", ("resolve", "bytes", "save"))
def test_single_file_queries_touch_only_selected_descriptor_and_chunks(
        tmp_path, monkeypatch, operation):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    wanted = random.Random(40).randbytes(bao.WIDTH + 17)
    unwanted = random.Random(41).randbytes(bao.WIDTH * 2 + 23)
    wanted_fid = send_bytes(
        node, workspace, "wanted.bin", wanted, ts=10)
    unwanted_fid = send_bytes(
        node, workspace, "unwanted.bin", unwanted, ts=20)

    descriptors = {
        fact.fid: fact for fact in node.by_type(workspace, file_family.TAG)
    }
    chunk_fids = {
        parent: {
            fact.fid for fact in node.by_type(workspace, chunk.TAG)
            if dict(fact.refs()).get("file") == parent
        }
        for parent in descriptors
    }
    wanted_root = descriptors[wanted_fid].body["root"]
    wanted_fids = {wanted_fid, *chunk_fids[wanted_fid]}
    unwanted_fids = {unwanted_fid, *chunk_fids[unwanted_fid]}

    decoded, verified_roots, synchronized = [], [], []
    strict_decode = catalog_module.decode
    strict_verify = bao.verify
    strict_sync = node._sync_index

    def observed_decode(raw):
        fact = strict_decode(raw)
        decoded.append(fact.fid)
        return fact

    def observed_verify(raw, root, index, size, width=bao.WIDTH):
        verified_roots.append(root)
        return strict_verify(raw, root, index, size, width)

    def observed_sync(ws):
        synchronized.append(ws)
        return strict_sync(ws)

    monkeypatch.setattr(catalog_module, "decode", observed_decode)
    monkeypatch.setattr(bao, "verify", observed_verify)
    monkeypatch.setattr(node, "_sync_index", observed_sync)

    if operation == "resolve":
        assert file_family.resolve(node, workspace, wanted_fid)["complete"]
    elif operation == "bytes":
        assert file_family.bytes_for(
            node, workspace, wanted_fid) == ("wanted.bin", wanted)
    else:
        output = tmp_path / "selected.bin"
        assert file_family.save(
            node, workspace, wanted_fid, output)["bytes"] == len(wanted)
        assert output.read_bytes() == wanted

    assert set(decoded) == wanted_fids
    assert unwanted_fids.isdisjoint(decoded)
    assert verified_roots
    assert set(verified_roots) == {wanted_root}
    assert synchronized == [workspace]


def test_file_read_pins_catalog_then_verifies_without_node_lock(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    payload = random.Random(42).randbytes(bao.WIDTH + 1)
    fid = send_bytes(node, workspace, "snapshot.bin", payload, ts=10)
    strict_verify = bao.verify
    started, release, removed = (
        threading.Event(), threading.Event(), threading.Event())
    pause_lock = threading.Lock()
    paused = False

    def paused_verify(raw, root, index, size, width=bao.WIDTH):
        nonlocal paused
        with pause_lock:
            first = not paused
            paused = True
        if first:
            started.set()
            assert release.wait(5)
        return strict_verify(raw, root, index, size, width)

    monkeypatch.setattr(bao, "verify", paused_verify)
    result, errors = {}, []

    def read():
        try:
            result["value"] = file_family.bytes_for(node, workspace, fid)
        except BaseException as error:
            errors.append(error)

    def remove():
        try:
            cmds.remove(node, workspace, fid, ts=20)
            removed.set()
        except BaseException as error:
            errors.append(error)

    reader = threading.Thread(target=read)
    reader.start()
    assert started.wait(5)
    deleter = threading.Thread(target=remove)
    deleter.start()
    removed_without_waiting_for_bao = removed.wait(2)
    release.set()
    reader.join(5)
    deleter.join(5)

    assert removed_without_waiting_for_bao
    assert not reader.is_alive() and not deleter.is_alive()
    assert errors == []
    assert result["value"] == ("snapshot.bin", payload)
    assert cmds.files(node, workspace) == []


def test_failed_manifest_publish_keeps_objects_and_retry_exposes_them(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    old_root = node.store(workspace).get("root")
    commit = node.commit

    def fail_commit(*args, **kwargs):
        raise RuntimeError("injected CAS failure")

    monkeypatch.setattr(node, "commit", fail_commit)

    with pytest.raises(RuntimeError, match="injected CAS failure"):
        send_bytes(node, workspace, "retry.bin", b"x" * (bao.WIDTH + 1))

    pile = node.store(workspace).list("pile/")[0]
    stream, _ = decode_pile(
        node.store(workspace).get(pile), workspace)
    descriptor = next(fact for fact in stream if fact.t == file_family.TAG)
    chunks = [fact for fact in stream if fact.t == "chunk"]
    assert node.store(workspace).get("root") == old_root
    assert node.fact_of(workspace, descriptor.fid) is None
    assert node.idx(workspace).execute(
        "SELECT 1 FROM sqlite_master WHERE name='log'").fetchone() is None
    assert all(node.store(workspace).has("obj/" + item.body["cid"])
               for item in chunks)

    monkeypatch.setattr(node, "commit", commit)
    node.turn(workspace)
    assert progress(node, workspace)["have"] == len(chunks)


def test_committed_blob_is_visible_without_an_arrival_cache(tmp_path):
    path = tmp_path / "node"
    node = Node(str(path))
    workspace = cmds.create(node, "alice")
    send_bytes(node, workspace, "restart.bin", b"restart")
    assert progress(node, workspace)["complete"]
    assert not (path / "app.db").exists()
    close_node(node)
    restarted = Node(str(path))
    assert progress(restarted, workspace)["complete"]


def test_sync_piles_carry_facts_while_blob_proofs_use_object_reads(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice")
    send_bytes(
        source, workspace, "separate-proof-path.bin",
        random.Random(31).randbytes(bao.WIDTH + 1))

    events = []

    class Capture:
        def put_obj(self, oid, raw):
            assert h(raw) == oid
            events.append(("object", oid, raw))

        def put_pile(self, raw):
            events.append(("pile", raw))
            self.raw = raw

    capture = Capture()
    _push(source, workspace, capture, all_fids(source, workspace))
    stream, embedded = decode_pile(capture.raw, workspace)
    assert embedded == {}
    object_events = [event for event in events if event[0] == "object"]
    assert {
        oid for _, oid, _ in object_events
    } == {
        oid for fact in stream for oid in facts.blob_refs(fact)
    }
    assert events[-1] == ("pile", capture.raw)

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "copy", [])
    for _, oid, raw in object_events:
        ensure_object(destination.store(workspace), oid, raw)
    deliver(destination, workspace, capture.raw)
    destination.turn(workspace)
    assert progress(destination, workspace)["complete"]

    class SourceObjects:
        def obj(self, oid):
            return source.store(workspace).get("obj/" + oid)

    landed, complete = _fetch_blobs(
        destination, workspace, SourceObjects())
    assert complete
    assert landed == []
    assert progress(destination, workspace)["complete"]


def test_blob_push_failure_precedes_the_fact_delivery(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice")
    send_bytes(
        source, workspace, "one-way.bin",
        random.Random(32).randbytes(bao.WIDTH + 1))

    class BrokenObjectDoor:
        @staticmethod
        def put_obj(oid, raw):
            raise ConnectionError(f"lost object {oid}")

        @staticmethod
        def put_pile(raw):
            pytest.fail("facts were delivered after an object upload failed")

    with pytest.raises(ConnectionError, match="lost object"):
        _push(source, workspace, BrokenObjectDoor(), all_fids(
            source, workspace))


def test_unchanged_root_retries_a_missing_proof(tmp_path, monkeypatch):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice")
    send_bytes(
        source, workspace, "retry.bin",
        random.Random(17).randbytes(bao.WIDTH * 2 + 1))
    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "copy", [])
    deliver(
        destination, workspace,
        closed_subset(source, workspace, all_fids(source, workspace)))
    destination.turn(workspace)
    assert progress(destination, workspace)["have"] == 0

    delayed = next(
        source.fact_of(workspace, fid).body["cid"]
        for fid in all_fids(source, workspace)
        if source.fact_of(workspace, fid).t == "chunk")
    attempts = set()
    url = "https://peer.invalid"
    destination.sync_cache[(workspace, url)] = {
        "etag": "unchanged",
        "local": h(destination.store(workspace).get("root")),
    }

    class CachedPeer:
        def __init__(self, node, ws, peer_url):
            self.cache = node.sync_cache[(ws, peer_url)]

        def root(self, etag=None):
            return None

        def obj(self, oid):
            if oid == delayed and oid not in attempts:
                attempts.add(oid)
                return b"wrong object"
            return source.store(workspace).get("obj/" + oid)

    monkeypatch.setattr(sync_module, "Peer", CachedPeer)
    assert sync_module.sync(destination, workspace, url) == (0, 0)
    assert progress(destination, workspace)["have"] == 2
    assert sync_module.sync(destination, workspace, url) == (0, 0)
    assert progress(destination, workspace)["have"] == 3


def test_invalid_proof_never_counts_as_progress(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice")
    fid = send_bytes(source, workspace, "proof.bin", b"good")
    descriptor = source.fact_of(workspace, fid)
    secret, public = source.identity(workspace)
    invalid = b"not a Bao proof"
    item, signed = chunk.author(
        workspace, secret, public, "general", descriptor.body["root"], 0, 1,
        h(invalid), descriptor.ts + 1, descriptor.fid,
        member_src(source, workspace, public))
    source.ingest_new(
        workspace, [signed, item],
        {
            signed.fid: [],
            item.fid: [
                signed.fid, member_src(source, workspace, public), fid],
        },
        blobs={h(invalid): invalid},
    )
    pile, _ = decode_pile(
        closed_subset(source, workspace, [item.fid]), workspace)

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "copy", [])
    deliver(
        destination, workspace,
        encode_pile(pile, {h(invalid): invalid}))
    destination.turn(workspace)
    assert progress(destination, workspace)["have"] == 0


def test_late_arrival_cannot_resurrect_a_retracted_chunk(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    send_bytes(node, workspace, "gone.bin", b"gone")
    chunk_fid = node.by_type(workspace, chunk.TAG)[0].fid
    cmds.remove(node, workspace, chunk_fid, ts=shape.FACT_TS_MAX)
    assert progress(node, workspace)["have"] == 0

    # The proof object remains present, but the query excludes its suppressed
    # fact before considering bytes.
    assert progress(node, workspace)["have"] == 0
    assert chunk_fid not in {
        fact.fid for fact in node.by_type(workspace, chunk.TAG)}

    node.rebuild(workspace)
    assert progress(node, workspace)["have"] == 0


def test_deleting_descriptor_retracts_chunks_and_stops_blob_demand(tmp_path):
    """SELF(file) and PARENT(file) resolve to one sid on every path."""
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice", ts=1)
    data = b"private-cascade-marker" * 40_000
    descriptor_fid = send_bytes(
        source, workspace, "cascade.bin", data, ts=10)
    chunk_fids = {
        fact.fid for fact in source.by_type(workspace, chunk.TAG)
    }
    assert len(chunk_fids) > 1

    cmds.remove(source, workspace, descriptor_fid, ts=20)
    assert cmds.files(source, workspace) == []
    assert chunk_fids.isdisjoint(
        fact.fid for fact in source.by_type(workspace, chunk.TAG))

    source.rebuild(workspace)
    assert cmds.files(source, workspace) == []

    class NoBlobPeer:
        def obj(self, oid):
            raise AssertionError(f"suppressed blob was demanded: {oid}")

    for fid in chunk_fids:
        for oid in facts.blob_refs(source.fact_of(workspace, fid)):
            source.store(workspace)._delete("obj/" + oid)
    assert _fetch_blobs(source, workspace, NoBlobPeer()) == ([], True)
