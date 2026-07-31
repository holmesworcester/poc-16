"""Inline Bao slice authority, admission, querying, and reconstruction."""
import base64
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

import facts
from core.close import decode_pile
from core.kernel import drain, validate
from facts import _bao
from facts.content import file as files, file_slice as slices
from full_peer import bao_native
from full_peer.node import FullPeer
from full_peer import sql_store

from .util import deliver, send_bytes


ROOT = Path(__file__).resolve().parent.parent


def close_node(node):
    for projection in node._sql.values():
        projection.db.close()


def progress(node, workspace):
    records = files.files(node, workspace)
    assert len(records) == 1
    return records[0]


def slice_facts(node, workspace, descriptor=None):
    found = node.by_type(workspace, slices.TAG)
    if descriptor is None:
        return found
    return [
        fact for fact in found
        if fact.refs() == [("file", descriptor)]
    ]


def test_round_trip_survives_projection_rebuild_and_index_wipe(tmp_path):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    data = random.Random(16).randbytes(_bao.WIDTH * 2 + 17)
    fid = send_bytes(node, workspace, "three-slices.bin", data, ts=2)

    assert progress(node, workspace)["fid"] == fid
    assert progress(node, workspace)["have"] == 3
    node.rebuild(workspace)
    assert progress(node, workspace)["complete"]

    close_node(node)
    os.unlink(directory / "ws" / f"{workspace}.idx.db")
    rebuilt = FullPeer(str(directory))
    output = tmp_path / "saved.bin"
    assert files.save(rebuilt, workspace, fid, output)["bytes"] == len(data)
    assert output.read_bytes() == data


def test_send_emits_descriptor_then_one_independent_closed_pile_per_slice(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    raw_piles = []
    receive = node.receive_pile

    def observed(ws, member, raw):
        raw_piles.append(raw)
        return receive(ws, member, raw)

    monkeypatch.setattr(node, "receive_pile", observed)
    fid = send_bytes(
        node, workspace, "separate.bin",
        random.Random(1).randbytes(_bao.WIDTH + 9), ts=2)
    streams = [decode_pile(raw, workspace) for raw in raw_piles]

    assert len(streams) == 3
    assert all(validate(stream, workspace) for stream in streams)
    assert [sum(fact.t == slices.TAG for fact in stream)
            for stream in streams] == [0, 1, 1]
    assert all(any(fact.fid == fid for fact in stream) for stream in streams)
    for stream in streams[1:]:
        item = next(fact for fact in stream if fact.t == slices.TAG)
        assert item.refs() == [("file", fid)]
        judgment = drain(stream, workspace)
        admitted = next(
            valid for valid in judgment.valids
            if valid.fact.fid == item.fid)
        assert [(edge.role, edge.fid) for edge in admitted.edges] == [
            ("file", fid)]
        assert facts.fact_scopes(item) == {"fact:" + fid}
        assert not any(
            name == "author" and target == item.fid
            for fact in stream for name, target, _key in fact.offers())


def test_independent_slice_piles_make_partial_progress(tmp_path, monkeypatch):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    raw_piles = []
    receive = source.receive_pile

    def observed(ws, member, raw):
        raw_piles.append(raw)
        return receive(ws, member, raw)

    monkeypatch.setattr(source, "receive_pile", observed)
    send_bytes(
        source, workspace, "partial.bin", b"x" * (_bao.WIDTH + 1), ts=2)

    destination = FullPeer(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "copy", [])
    for raw in raw_piles[:2]:
        deliver(destination, workspace, raw)
        destination.turn(workspace)
    assert progress(destination, workspace)["have"] == 1
    assert not progress(destination, workspace)["complete"]
    assert files.bytes_for(
        destination, workspace, progress(destination, workspace)["fid"]
    )[1] is None

    deliver(destination, workspace, raw_piles[2])
    destination.turn(workspace)
    assert progress(destination, workspace)["complete"]


def test_family_rejects_tamper_wrong_range_and_wrong_descriptor_root(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    first = send_bytes(
        node, workspace, "first.bin",
        random.Random(2).randbytes(_bao.WIDTH + 7), ts=2)
    second = send_bytes(
        node, workspace, "second.bin",
        random.Random(3).randbytes(_bao.WIDTH + 7), ts=3)
    original = min(
        slice_facts(node, workspace, first), key=slices.index_of)
    proof = slices.proof_bytes(original)

    changed = bytearray(proof)
    changed[-1] ^= 1
    bad = (
        slices.file_slice(workspace, first, 0, bytes(changed), 2),
        slices.file_slice(workspace, first, 1, proof, 2),
        slices.file_slice(workspace, second, 0, proof, 3),
    )
    for item in bad:
        closed = node.sender(workspace).close(
            [item], {item.fid: [item.refs()[0][1]]})
        assert not validate(closed, workspace)

    # Even a valid proof cannot reach across the fact's workspace boundary to
    # borrow this descriptor. The family check is explicit as well as the
    # kernel's ambient-workspace check.
    foreign = slices.file_slice("f" * 64, first, 0, proof, 2)

    class Context:
        def fact_of(self, fid):
            return node.fact_of(workspace, fid)

    assert not slices.validate(foreign, Context())


def test_noncanonical_base64_and_trailing_proof_bytes_fail_closed(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fid = send_bytes(node, workspace, "canonical.bin", b"proof", ts=2)
    original = slice_facts(node, workspace, fid)[0]
    proof = slices.proof_bytes(original)

    trailing = slices.file_slice(workspace, fid, 0, proof + b"x", 2)
    closed = node.sender(workspace).close(
        [trailing], {trailing.fid: [fid]})
    assert not validate(closed, workspace)

    body = dict(original.body)
    body["proof"] = base64.b64encode(proof).decode() + "="
    malformed = original.__class__(
        original.t, original.ts, original.atoms, body, original.ws)
    closed = node.sender(workspace).close(
        [malformed], {malformed.fid: [fid]})
    assert not validate(closed, workspace)


def test_hosted_kernel_admits_slice_without_importing_native_bao(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    raw_piles = []
    receive = node.receive_pile

    def observed(ws, member, raw):
        raw_piles.append(raw)
        return receive(ws, member, raw)

    node.receive_pile = observed
    send_bytes(node, workspace, "hosted.bin", b"hosted proof", ts=2)
    pile = raw_piles[-1]
    script = f"""
import base64
import importlib.abc
import sys
class BlockBao(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'tinyp2p_bao':
            raise ModuleNotFoundError('blocked', name=fullname)
sys.meta_path.insert(0, BlockBao())
from core.close import decode_pile
from core.kernel import validate
raw = base64.b64decode({base64.b64encode(pile).decode()!r})
assert validate(decode_pile(raw, {workspace!r}), {workspace!r})
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT,
        text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_pure_verifier_matches_rust_authoring_binding(tmp_path):
    source = tmp_path / "cross.bin"
    data = random.Random(4).randbytes(_bao.WIDTH + 33)
    source.write_bytes(data)
    outboard = tmp_path / "cross.obao"
    root = bao_native.prepare(str(source), str(outboard))
    for index in range(_bao.geometry(len(data))):
        proof = bao_native.proof(
            str(source), str(outboard), index, len(data))
        assert _bao.verify(proof, root, index, len(data)) \
            == bao_native.verify(proof, root, index, len(data))


def test_file_list_counts_generic_ref_index_without_decoding_slice_bodies(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    send_bytes(
        node, workspace, "listed.bin", b"x" * (_bao.WIDTH + 1), ts=2)
    decoded = []
    strict = sql_store.decode

    def observed(raw):
        fact = strict(raw)
        decoded.append(fact.t)
        return fact

    monkeypatch.setattr(sql_store, "decode", observed)
    assert progress(node, workspace)["have"] == 2
    assert slices.TAG not in decoded


def test_selected_reads_touch_only_the_selected_descriptor_slices(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    wanted = send_bytes(node, workspace, "wanted.bin", b"wanted", ts=2)
    unwanted = send_bytes(node, workspace, "unwanted.bin", b"unwanted", ts=3)
    verified = []
    strict = _bao.verify

    def observed(proof, root, index, size, width=_bao.WIDTH):
        verified.append(root)
        return strict(proof, root, index, size, width)

    monkeypatch.setattr(_bao, "verify", observed)
    assert files.bytes_for(node, workspace, wanted) == ("wanted.bin", b"wanted")
    assert verified == [node.fact_of(workspace, wanted).body["root"]]
    assert node.fact_of(workspace, unwanted).body["root"] not in verified


def test_descriptor_deletion_cascades_to_slices(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fid = send_bytes(
        node, workspace, "gone.bin", b"x" * (_bao.WIDTH + 1), ts=2)
    children = {fact.fid for fact in slice_facts(node, workspace, fid)}
    assert len(children) == 2

    facts.content.delete.remove(node, workspace, fid, ts=3)
    assert files.files(node, workspace) == []
    assert children.isdisjoint(
        fact.fid for fact in node.by_type(workspace, slices.TAG))
    node.rebuild(workspace)
    assert files.files(node, workspace) == []


def test_256k_geometry_reduces_fact_and_cas_count_fourfold():
    """Both widths exceed one ordinary fact; 256 KiB does 1/4 the turns."""
    size = 64 * 1024 * 1024
    at_64k = _bao.geometry(size, 64 * 1024)
    at_256k = _bao.geometry(size, _bao.WIDTH)
    assert _bao.WIDTH == 256 * 1024
    assert at_64k == 4 * at_256k
    assert _bao.MAX_PROOF_BASE64_BYTES < 512 * 1024
