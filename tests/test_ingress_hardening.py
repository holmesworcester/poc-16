"""Exact pile bounds fail independently without destructive recovery."""
import asyncio
import json

import pytest
import facts

from core import (
    close,
    fact,
    http,
    http_stdlib,
    kernel,
    limits,
    merkle_map,
    snapshot,
)
from core.crypto import h, keypair
from core.fact import Fact, canon
from core.grants import make_token
from core.ingress import InvalidPile
from core.limits import (
    MAX_ATOM_NAME_BYTES,
    MAX_ATOM_VALUE_BYTES,
    MAX_FACT_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PayloadTooLarge,
)
from core.repository_applier import RepositoryApplier
from core.store import FsStore
from facts.auth.workspace import workspace as workspace_fact
from facts.content import message as message_family
from full_peer import status
from full_peer.node import FullPeer

from .util import (
    all_fids,
    apply_planted,
    closed_subset,
    plant_for,
)


def run(awaitable):
    return asyncio.run(awaitable)


def test_pile_codec_requires_one_canonical_json_spelling():
    workspace = "0" * 64
    canonical = close.encode_pile((), workspace=workspace)
    assert close.decode_pile(canonical, workspace) == []
    aliases = (
        b'{ "facts": [], "ws": "' + workspace.encode() + b'" }',
        b'{"ws":"' + workspace.encode() + b'","facts":[]}',
        b'{"facts":[],"ws":"' + workspace.encode()
        + b'","ws":"' + workspace.encode() + b'"}',
        b'{"facts":[],"ws":NaN}',
    )
    for raw in aliases:
        with pytest.raises(InvalidPile):
            close.decode_pile(raw, workspace)


def test_fact_count_is_bounded_before_store_or_kernel_work(
        monkeypatch):
    workspace = "0" * 64
    items = tuple(
        Fact("unknown", ts, [], {"text": str(ts)}, workspace)
        for ts in range(1, 4))
    monkeypatch.setattr(close, "MAX_PILE_FACTS", 2)
    monkeypatch.setattr(kernel, "MAX_PILE_FACTS", 2)
    over = canon({
        "facts": [item.to_json() for item in items],
        "ws": workspace,
    })
    with pytest.raises(InvalidPile, match="too many facts"):
        close.decode_pile(over, workspace)
    assert isinstance(kernel.drain(items, workspace).failure, PayloadTooLarge)

    class NeverMutated:
        def put_if_absent(self, *_args):
            raise AssertionError("oversized pile mutated store")

    applier = RepositoryApplier(workspace, NeverMutated())
    with pytest.raises(InvalidPile, match="too many facts"):
        run(applier.receive_pile("a" * 64, over))


def test_json_value_budget_precedes_staging_and_healthy_pile_recovers(
        tmp_path, monkeypatch):
    secret, public = keypair()
    root = workspace_fact(secret, public, "memory-bound", 1)
    healthy = close.encode_pile((root,), workspace=root.fid)
    exact = canon({"facts": [], "junk": list(range(16)), "ws": root.fid})
    over = canon({"facts": [], "junk": list(range(17)), "ws": root.fid})
    monkeypatch.setattr(
        close, "MAX_PILE_JSON_VALUES", close._scan_json_values(exact))
    store = FsStore(str(tmp_path / "store"))
    applier = RepositoryApplier(root.fid, store)
    with pytest.raises(InvalidPile, match="too many JSON values"):
        run(applier.receive_pile("a" * 64, over))
    monkeypatch.setattr(
        close, "MAX_PILE_JSON_VALUES", limits.MAX_PILE_JSON_VALUES)
    result = run(applier.receive_pile("a" * 64, healthy))
    assert result.status == "applied"
    assert store.get("root") is not None


def test_shared_pile_limits_fit_smallest_hosted_memory_ceiling():
    peak = limits.applier_peak_bound(
        limits.MAX_PILE_BYTES,
        limits.MAX_PILE_JSON_VALUES,
        limits.MAX_PILE_FACTS,
    )
    assert limits.MAX_FACT_BYTES == 4 * limits.MIB
    assert limits.MAX_PILE_FACTS == 256
    assert limits.MAX_PILE_BYTES == 5 * limits.MIB
    assert peak < limits.MIN_HOSTED_MEMORY_BYTES
    assert limits.MAX_APPLIER_SUBREQUESTS < limits.MAX_HOSTED_SUBREQUESTS


def test_generic_atom_grammar_enforces_text_and_fid_bounds():
    workspace = "0" * 64
    fid = "f" * 64
    valid = Fact(
        "unknown", 1,
        [["ref", "r" * MAX_ATOM_NAME_BYTES, fid], [
            "offer", "n" * MAX_ATOM_NAME_BYTES,
            "v" * MAX_ATOM_VALUE_BYTES,
        ]],
        {}, workspace)
    raw = close.encode_pile((valid,), workspace=workspace)
    assert close.decode_pile(raw, workspace) == [valid]
    for atom in (
            ["ref", "", fid],
            ["ref", "role", "not-a-fid"],
            ["offer", "name", ""],
            ["offer", "n" * (MAX_ATOM_NAME_BYTES + 1), "value"],
            ["offer", "name", "v" * (MAX_ATOM_VALUE_BYTES + 1)]):
        poison = Fact("unknown", 1, [atom], {}, workspace)
        with pytest.raises(InvalidPile):
            close.decode_pile(
                close.encode_pile((poison,), workspace=workspace),
                workspace,
            )


def test_rejected_exact_pile_does_not_block_independent_pile(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    healthy = closed_subset(source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    bad = run(plant_for(applier, "b" * 64, b"{}"))
    good = run(plant_for(applier, "c" * 64, healthy))

    assert run(apply_planted(applier, bad)).status == "rejected"
    assert run(apply_planted(applier, good)).status == "applied"
    assert store.get(bad) == b"{}"
    assert store.get(good) == healthy
    assert store.get("root") == source.store(workspace).get("root")


def test_program_failure_retains_source_and_independent_work_progresses(
        tmp_path, monkeypatch):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    first = facts.content.message.post(
        source, workspace, "general", "first", ts=10)
    first_raw = closed_subset(source, workspace, (first,))
    second = facts.content.message.post(
        source, workspace, "general", "second", ts=11)
    second_raw = closed_subset(source, workspace, (second,))
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    first_key = run(plant_for(applier, "d" * 64, first_raw))
    second_key = run(plant_for(applier, "e" * 64, second_raw))
    original = message_family.message
    monkeypatch.setattr(
        message_family,
        "message",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("family program failure")),
    )
    with pytest.raises(RuntimeError, match="family program failure"):
        run(apply_planted(applier, first_key))
    monkeypatch.setattr(message_family, "message", original)
    assert run(apply_planted(applier, second_key)).status == "applied"
    assert store.get(first_key) == first_raw


def test_failed_root_commit_retains_exact_source_for_named_retry(
        tmp_path, monkeypatch):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    key = run(plant_for(applier, "a" * 64, raw))
    original = store.cas
    monkeypatch.setattr(
        store,
        "cas",
        lambda *_args: (_ for _ in ()).throw(
            RuntimeError("root CAS failed")),
    )
    with pytest.raises(RuntimeError, match="root CAS failed"):
        run(apply_planted(applier, key))
    assert store.get(key) == raw
    assert store.get("root") is None
    monkeypatch.setattr(store, "cas", original)
    assert run(apply_planted(
        RepositoryApplier(workspace, store), key)).status == "applied"


def test_sync_failure_and_recovery_are_exposed_in_status(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "node", ts=1)
    peer = "https://peer.invalid"
    node.record_sync_failure(
        workspace, peer, ValueError("remote object integrity"))
    row = status.describe(node)["workspaces"][workspace]["sync_failures"]
    assert row[0]["error"] == "ValueError: remote object integrity"
    node.record_sync_success(workspace, peer)
    assert status.describe(node)["workspaces"][workspace][
        "sync_failures"] == []


def test_legacy_removal_field_is_rejected():
    root = {
        "anchor": "a" * 64,
        "layout_seed": "b" * 64,
        "maps": {},
        "stamp": snapshot.LAYOUT,
        "removals": {},
    }
    with pytest.raises(ValueError, match="root shape"):
        snapshot.decode_root(canon(root))


@pytest.mark.parametrize("decoder", (
    close.decode_pile,
    snapshot.decode_root,
    fact.decode,
))
def test_json_codec_doors_translate_recursion_to_value_error(decoder):
    nested = b"[" * 5_000 + b"0" + b"]" * 5_000
    with pytest.raises(ValueError):
        decoder(nested, "0" * 64) \
            if decoder is close.decode_pile else decoder(nested)


def test_merkle_page_recursion_is_a_value_error():
    nested = b"[" * 2_000 + b"0" + b"]" * 2_000
    with pytest.raises(ValueError, match="merkle map page shape"):
        merkle_map._decode(nested, h(nested), h(b"seed"))


def test_pile_and_root_reject_size_before_parsing(monkeypatch):
    workspace = "0" * 64
    cases = (
        (close, "MAX_PILE_BYTES",
         lambda raw: close.decode_pile(raw, workspace),
         canon({"ws": workspace, "facts": []})),
        (snapshot, "MAX_ROOT_BYTES", snapshot.decode_root, b'{"stamp":"x"}'),
    )
    for module, name, decoder, raw in cases:
        monkeypatch.setattr(module, name, len(raw) - 1)
        with pytest.raises(PayloadTooLarge):
            decoder(raw)


def test_exact_max_fact_round_trips_through_peer_and_http(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "source", ts=1)
    secret, public = source.identity(workspace)
    probe = message_family.message(workspace, public, "general", "", 2)
    padding = MAX_FACT_BYTES - len(canon(probe.to_json()))
    exact = message_family.message(
        workspace, public, "general", "x" * padding, 2)
    signed = facts.auth.signature.signature(secret, public, exact, 2)
    genesis = source.fact_of(workspace, workspace)
    raw = close.encode_pile((genesis, signed, exact), workspace=workspace)
    destination = FullPeer(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "destination", [])
    destination.receive_pile(workspace, "0123456789abcdef" * 4, raw)
    assert destination.fact_of(workspace, exact.fid) == exact

    secret_token = b"g" * 32
    gate = http.HttpGate(
        http.AsyncFromSyncReader(destination.store(workspace)),
        workspace,
        secret_token,
        lambda: 100,
        max_object_bytes=MAX_REPOSITORY_OBJECT_BYTES,
    )
    token = make_token(
        secret_token, "reader", workspace, issued_at=100)
    encoded = fact.encode(exact)
    response = run(gate.handle(
        "GET", "/page/" + h(encoded), {"ws": workspace},
        {"Authorization": "Bearer " + token}))
    assert response.status == 200
    assert response.body == encoded


def test_peer_adapter_rejects_claimed_oversize_without_reading(monkeypatch):
    class NeverRead:
        def read(self, _count):
            raise AssertionError("oversized body was read")

    handler = object.__new__(http_stdlib.StdlibPeerHandler)
    handler.headers = {"Content-Length": "9"}
    handler.rfile = NeverRead()
    monkeypatch.setattr(http_stdlib, "MAX_MINT_REQUEST_BYTES", 8)
    with pytest.raises(PayloadTooLarge):
        handler._body("POST", "/unknown")
