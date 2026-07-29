"""Bao attachment policy and arrival-log crash boundaries."""
import os
import random

import pytest

import facts
import core.sync as sync_module
from core import bao, cmds, shape
from core.close import decode_pile, encode_pile
from core.crypto import h
from core.node import Node
from core.pump import pump
from core.walk import _fetch_blobs
from facts.content import chunk, file as file_family

from .util import (
    all_fids,
    closed_subset,
    deliver,
    member_src,
    send_bytes,
)


def close_node(node):
    node.app.close()
    for index in node._idx.values():
        index.close()


def progress(node, workspace):
    records = cmds.files(node, workspace)
    assert len(records) == 1
    return records[0]


def test_round_trip_survives_rebuild_and_projection_wipe(tmp_path):
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
    os.unlink(path / "app.db")
    os.unlink(path / "ws" / f"{workspace}.idx.db")
    rebuilt = Node(str(path))
    output = tmp_path / "saved.bin"
    assert cmds.save_file(rebuilt, workspace, fid, output)["bytes"] == len(data)
    assert output.read_bytes() == data


def test_failed_manifest_publish_logs_no_arrival_and_retry_repairs_it(
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
    stream, _ = decode_pile(node.store(workspace).get(pile))
    descriptor = next(fact for fact in stream if fact.t == file_family.TAG)
    chunks = [fact for fact in stream if fact.t == "chunk"]
    assert node.store(workspace).get("root") == old_root
    assert node.fact_of(workspace, descriptor.fid) is None
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM log WHERE op='*'").fetchone()[0] == 0
    assert all(node.store(workspace).has("obj/" + item.body["cid"])
               for item in chunks)

    monkeypatch.setattr(node, "commit", commit)
    node.turn(workspace)
    assert progress(node, workspace)["have"] == len(chunks)


def test_restart_repairs_crash_between_manifest_and_arrival_log(
        tmp_path, monkeypatch):
    path = tmp_path / "node"
    node = Node(str(path))
    workspace = cmds.create(node, "alice")

    def fail_arrival_log(*args, **kwargs):
        raise RuntimeError("injected arrival-log crash")

    monkeypatch.setattr(node, "log_arrivals", fail_arrival_log)

    with pytest.raises(RuntimeError, match="arrival-log crash"):
        send_bytes(node, workspace, "restart.bin", b"restart")

    assert progress(node, workspace)["have"] == 0
    close_node(node)
    restarted = Node(str(path))
    assert progress(restarted, workspace)["complete"]


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
        "local": destination.store(workspace).etag("root"),
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
        secret, public, "general", descriptor.body["root"], 0, 1,
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
        closed_subset(source, workspace, [item.fid]))

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
    chunk_fid = node.idx(workspace).execute(
        "SELECT fid FROM facts WHERE t='chunk'").fetchone()[0]
    cmds.remove(node, workspace, chunk_fid, ts=shape.FACT_TS_MAX)
    assert progress(node, workspace)["have"] == 0

    node.log_arrivals(workspace, [chunk_fid], repeat=True)
    pump(node, workspace)
    assert progress(node, workspace)["have"] == 0
    assert node.app.execute(
        "SELECT 1 FROM file_chunk_rows WHERE ws=? AND src=?",
        (workspace, chunk_fid)).fetchone() is None

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
        fid for (fid,) in source.idx(workspace).execute(
            "SELECT fid FROM facts WHERE t='chunk'")
    }
    assert len(chunk_fids) > 1

    cmds.remove(source, workspace, descriptor_fid, ts=20)
    active = {
        src for (src,) in source.app.execute(
            "SELECT src FROM projected WHERE ws=?", (workspace,))
    }
    assert descriptor_fid not in active
    assert chunk_fids.isdisjoint(active)
    before = tuple(sorted(active))

    source.rebuild(workspace)
    rebuilt = tuple(sorted(
        src for (src,) in source.app.execute(
            "SELECT src FROM projected WHERE ws=?", (workspace,))))
    assert rebuilt == before

    class NoBlobPeer:
        def obj(self, oid):
            raise AssertionError(f"suppressed blob was demanded: {oid}")

    for fid in chunk_fids:
        for oid in facts.blob_refs(source.fact_of(workspace, fid)):
            source.store(workspace).delete("obj/" + oid)
    assert _fetch_blobs(source, workspace, NoBlobPeer()) == ([], True)
