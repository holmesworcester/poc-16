"""Direct-upload keys bind one exact fact-only pile."""
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
    decode_staged_pile,
    parse_staging_key,
    staging_key,
    staging_prefix,
)
from core.store import FsStore
from facts import _bao
from facts.content import file_slice
from full_peer.node import FullPeer

from .util import closed_subset, send_bytes


SESSION = "c" * 32
MEMBER = "d" * 16


@pytest.fixture
def staged_file(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    descriptor = send_bytes(
        node, workspace, "two-slices.bin",
        b"a" * (_bao.WIDTH + 17), ts=10)
    item = min(
        node.by_type(workspace, file_slice.TAG),
        key=file_slice.index_of,
    )
    raw = closed_subset(node, workspace, (item.fid,))
    key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))
    return node, workspace, descriptor, item, raw, key


def test_marker_decodes_one_inline_slice_pile(staged_file):
    _, workspace, descriptor, item, raw, key = staged_file

    intent = decode_staged_pile(workspace, key, raw)

    assert intent.workspace == workspace
    assert intent.member == MEMBER
    assert intent.session == SESSION
    assert intent.digest == h(raw)
    assert {fact.fid for fact in intent.stream} >= {
        workspace, descriptor, item.fid}
    assert not hasattr(intent, "blob_refs")
    assert not hasattr(intent, "object_keys")
    assert key.startswith(staging_prefix(workspace, "pile"))


def test_applier_reads_only_the_exact_inline_pile(staged_file, tmp_path):
    _, workspace, _, item, raw, key = staged_file

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
    assert item.fid in result.admitted
    assert ingress.get(key) == raw


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
    *_, key = staged_file
    with pytest.raises(InvalidStagedIntent, match="staging key"):
        parse_staging_key(mutate(key))


def test_staged_pile_binds_key_digest_workspace_and_class(staged_file):
    _, workspace, _, _, raw, key = staged_file
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
    _, workspace, _, _, raw, _ = staged_file
    pretty = json.dumps(json.loads(raw), indent=2).encode()
    embedded = json.loads(raw)
    embedded["objects"] = {h(b"embedded"): "ZW1iZWRkZWQ="}
    for candidate in (pretty, canon(embedded), b"{}"):
        key = staging_key(
            workspace, MEMBER, SESSION, "pile", h(candidate))
        with pytest.raises(InvalidStagedIntent, match="invalid staged pile"):
            decode_staged_pile(workspace, key, candidate)


def test_staged_intent_has_no_detached_completion_vocabulary():
    assert not any(hasattr(staged_intent_module, name) for name in (
        "confirm_staged_object",
        "InvalidStagedObject",
        "MAX_STAGED_OBJECTS",
        "StagedObjectsPending",
    ))
