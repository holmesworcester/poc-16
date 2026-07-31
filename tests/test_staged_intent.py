"""Direct-upload keys name one exact pile; objects are a separate path."""
import asyncio
import json

import pytest

import facts
from core import staged_intent as staged_intent_module
from core.close import encode_pile
from core.crypto import h
from core.fact import Fact, canon
from core.ingress import InvalidStagedIntent
from core.repository_applier import RepositoryApplier
from core.staged_intent import (
    InvalidStagedObject,
    StagedObjectsPending,
    confirm_staged_object,
    decode_staged_pile,
    parse_staging_key,
    staging_key,
    staging_prefix,
)
from core.store import FsStore
from facts.content import chunk
from full_peer import bao_native as bao
from full_peer.node import FullPeer

from .util import closed_subset, send_bytes


SESSION = "c" * 32
MEMBER = "d" * 16


@pytest.fixture
def staged_file(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    send_bytes(
        node, workspace, "two-slices.bin",
        b"a" * (bao.WIDTH + 17), ts=10)
    chunks = tuple(
        fact.fid for fact in node.by_type(workspace, chunk.TAG))
    raw = closed_subset(node, workspace, chunks)
    key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))
    return node, workspace, raw, key


def test_upload_client_derives_exact_same_session_object_set(staged_file):
    node, workspace, raw, key = staged_file
    intent = decode_staged_pile(workspace, key, raw)
    expected = tuple(sorted(
        fact.body["cid"]
        for fact in node.by_type(workspace, chunk.TAG)))

    assert intent.workspace == workspace
    assert intent.member == MEMBER
    assert intent.session == SESSION
    assert intent.digest == h(raw)
    assert intent.blob_refs == expected
    assert intent.object_keys == tuple(
        staging_key(workspace, MEMBER, SESSION, "obj", digest)
        for digest in expected)
    assert key.startswith(staging_prefix(workspace, "pile"))
    for object_key, digest in zip(intent.object_keys, expected):
        raw_object = node.store(workspace).get("obj/" + digest)
        assert confirm_staged_object(
            intent, object_key, raw_object) == raw_object


def test_object_confirmation_distinguishes_delay_from_poison(staged_file):
    node, workspace, raw, key = staged_file
    intent = decode_staged_pile(workspace, key, raw)
    object_key = intent.object_keys[0]
    with pytest.raises(StagedObjectsPending):
        confirm_staged_object(intent, object_key, None)
    with pytest.raises(InvalidStagedObject):
        confirm_staged_object(intent, object_key, b"wrong")
    foreign = staging_key(
        workspace, MEMBER, "e" * 32, "obj", intent.blob_refs[0])
    with pytest.raises(InvalidStagedObject):
        confirm_staged_object(intent, foreign, b"wrong")


def test_repository_applier_reads_only_exact_pile_not_detached_objects(
        staged_file, tmp_path):
    _, workspace, raw, key = staged_file

    class Reads(FsStore):
        def __init__(self, root):
            super().__init__(root)
            self.reads = []

        def get_bounded(self, candidate, maximum):
            self.reads.append((candidate, maximum))
            return super().get_bounded(candidate, maximum)

    ingress = Reads(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    ingress.put_if_absent(key, raw)
    result = asyncio.run(RepositoryApplier(
        workspace, canonical).apply_exact(ingress, key, h(raw)))

    assert result.status == "applied"
    assert {candidate for candidate, _ in ingress.reads} == {key}
    assert ingress.get(key) == raw
    assert canonical.get("root") == result.root


def test_blob_reference_hook_is_not_part_of_repository_admission(
        staged_file, tmp_path, monkeypatch):
    _, workspace, raw, key = staged_file
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    ingress.put_if_absent(key, raw)
    monkeypatch.setattr(
        chunk,
        "blob_refs",
        lambda _fact: (_ for _ in ()).throw(
            RuntimeError("detached completion must not run")),
    )

    result = asyncio.run(RepositoryApplier(
        workspace, canonical).apply_exact(ingress, key, h(raw)))

    assert result.status == "applied"


@pytest.mark.parametrize("malformed", (None, [], ("not-a-fid",)))
def test_upload_client_rejects_malformed_blob_reference_results(
        staged_file, monkeypatch, malformed):
    _, workspace, raw, key = staged_file
    monkeypatch.setattr(chunk, "blob_refs", lambda _fact: malformed)
    with pytest.raises(InvalidStagedIntent, match="object reference"):
        decode_staged_pile(workspace, key, raw)


@pytest.mark.parametrize("mutate", (
    lambda key: key.upper(),
    lambda key: key.replace("/v1/", "/v2/"),
    lambda key: "/" + key,
    lambda key: key + "/extra",
    lambda key: key.replace("/piles/", "//piles/"),
    lambda key: key.replace("c" * 32, "c" * 31),
    lambda key: key.replace("d" * 16, "D" * 16),
    lambda key: key[:-1],
))
def test_pile_key_parser_rejects_noncanonical_paths(staged_file, mutate):
    _, _, _, key = staged_file
    with pytest.raises(InvalidStagedIntent, match="staging key"):
        parse_staging_key(mutate(key))


def test_staged_pile_binds_key_digest_and_workspace(staged_file):
    _, workspace, raw, key = staged_file
    foreign = "b" * 64
    with pytest.raises(InvalidStagedIntent, match="staging workspace"):
        decode_staged_pile(
            workspace,
            staging_key(foreign, MEMBER, SESSION, "pile", h(raw)),
            raw,
        )
    with pytest.raises(InvalidStagedIntent, match="staged pile digest"):
        decode_staged_pile(workspace, key, raw + b" ")
    with pytest.raises(InvalidStagedIntent, match="pile marker required"):
        decode_staged_pile(
            workspace,
            staging_key(workspace, MEMBER, SESSION, "obj", h(raw)),
            raw,
        )


def test_only_workspace_genesis_may_omit_workspace():
    ordinary = Fact("msg", 7, [], {}, None)
    workspace = ordinary.fid
    raw = encode_pile((ordinary,), workspace=workspace)
    key = staging_key(workspace, MEMBER, SESSION, "pile", h(raw))
    with pytest.raises(
            InvalidStagedIntent, match="only workspace genesis"):
        decode_staged_pile(workspace, key, raw)


def test_unknown_and_mixed_workspace_facts_fail_at_client_door():
    workspace = "a" * 64
    unknown = Fact("not-a-family", 1, [], {}, workspace)
    unknown_raw = encode_pile((unknown,), workspace=workspace)
    unknown_key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(unknown_raw))
    foreign = Fact("msg", 2, [], {}, "b" * 64)
    mixed_raw = canon({"ws": workspace, "facts": [foreign.to_json()]})
    mixed_key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(mixed_raw))
    with pytest.raises(InvalidStagedIntent, match="unknown fact family"):
        decode_staged_pile(workspace, unknown_key, unknown_raw)
    with pytest.raises(InvalidStagedIntent, match="invalid staged pile"):
        decode_staged_pile(workspace, mixed_key, mixed_raw)


def test_marker_rejects_noncanonical_extra_forms(staged_file):
    _, workspace, raw, _ = staged_file
    pretty = json.dumps(json.loads(raw), indent=2).encode()
    embedded = json.loads(raw)
    embedded["blobs"] = {h(b"embedded"): "ZW1iZWRkZWQ="}
    for candidate in (pretty, canon(embedded), b"{}"):
        key = staging_key(
            workspace, MEMBER, SESSION, "pile", h(candidate))
        with pytest.raises(InvalidStagedIntent, match="invalid staged pile"):
            decode_staged_pile(workspace, key, candidate)


def test_object_reference_count_is_bounded_without_large_fixture(
        staged_file, monkeypatch):
    _, workspace, raw, key = staged_file
    monkeypatch.setattr(staged_intent_module, "MAX_STAGED_OBJECTS", 1)
    with pytest.raises(InvalidStagedIntent, match="reference count"):
        decode_staged_pile(workspace, key, raw)
