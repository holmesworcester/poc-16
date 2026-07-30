"""The provider-neutral door from untrusted staging to publication."""
from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from core import bao, cmds
from core import ingress as ingress_module
from core import staged_intent as staged_intent_module
from core.close import decode_pile, encode_pile
from core.crypto import h
from core.fact import Fact, canon
from core.ingress import InvalidStagedIntent, PermanentIngressRejection
from core.ingress import check_source
from core.node import Node
from core.staged_intent import (
    InvalidStagedObject,
    StagedObjectsPending,
    confirm_staged_object,
    decode_staged_pile,
    parse_staging_key,
    promote_staged_pile,
    staging_key,
    staging_prefix,
)
from facts.content import chunk
from tests.util import closed_subset, send_bytes


SESSION = "c" * 32
MEMBER = "d" * 16


@pytest.fixture
def staged_file(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    send_bytes(
        node,
        workspace,
        "two-slices.bin",
        b"a" * (bao.WIDTH + 17),
        ts=10,
    )
    chunks = tuple(
        fact.fid for fact in node.by_type(workspace, chunk.TAG))
    assert len(chunks) == 2
    raw = closed_subset(node, workspace, chunks)
    key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))
    return node, workspace, raw, key


def test_real_multi_chunk_pile_derives_exact_same_session_object_set(
        staged_file):
    node, workspace, raw, key = staged_file

    first = decode_staged_pile(workspace, key, raw)
    replay = decode_staged_pile(workspace, key, raw)
    expected_refs = tuple(sorted(
        fact.body["cid"]
        for fact in node.by_type(workspace, chunk.TAG)
    ))

    assert first == replay
    assert first.workspace == workspace
    assert first.member == MEMBER
    assert first.session == SESSION
    assert first.digest == h(raw)
    assert first.blob_refs == expected_refs
    assert first.object_keys == tuple(
        staging_key(workspace, MEMBER, SESSION, "obj", digest)
        for digest in expected_refs
    )
    assert first.key.startswith(staging_prefix(workspace, "pile"))
    assert all(
        key.startswith(staging_prefix(workspace, "obj"))
        for key in first.object_keys)
    assert not staging_prefix(workspace, "pile").startswith(
        staging_prefix(workspace, "obj"))
    for object_key, digest in zip(first.object_keys, expected_refs):
        blob = node.store(workspace).get("obj/" + digest)
        assert blob is not None and h(blob) == digest
        assert confirm_staged_object(first, object_key, blob) == blob


def test_verified_session_promotes_to_fresh_internal_generation(
        staged_file, monkeypatch):
    node, workspace, raw, key = staged_file
    intent = decode_staged_pile(workspace, key, raw)
    generation = "e" * 32
    monkeypatch.setattr(
        ingress_module.secrets, "token_hex", lambda size: generation)

    source = promote_staged_pile(node.store(workspace), intent)

    assert source == f"pile/{MEMBER}/{generation}/{h(raw)}"
    assert source != intent.key
    assert check_source(source, raw).generation == generation
    assert node.store(workspace).get(source) == raw


def test_staging_replay_and_concurrent_promotions_cannot_recreate_generation(
        staged_file):
    node, workspace, raw, key = staged_file
    intent = decode_staged_pile(workspace, key, raw)
    store = node.store(workspace)

    first = promote_staged_pile(store, intent)
    old_receipt = node.admission(workspace).commit_ingress(
        node.admission(workspace).admit_ingress(first, raw))
    # Another worker wins retirement while this process still holds its
    # genuine historical receipt.
    store.delete(first)

    # Even a replay of the exact client-writable session object crosses the
    # trusted copy door into a new internal key. Two concurrent notification
    # handlers likewise cannot collide or recreate ``first``.
    with ThreadPoolExecutor(max_workers=2) as pool:
        promoted = tuple(pool.map(
            lambda _: promote_staged_pile(store, intent), range(2)))
    assert len(set(promoted)) == 2
    assert first not in promoted
    assert all(store.get(source) == raw for source in promoted)

    for source in promoted:
        with pytest.raises(
                ValueError, match="published ingress capability"):
            node.admission(workspace).retire(
                source, raw, old_receipt)
        assert store.get(source) == raw

    node.turn(workspace)
    assert all(store.get(source) is None for source in promoted)


def test_object_confirmation_separates_retryable_delay_from_poison(
        staged_file):
    _, workspace, raw, key = staged_file
    intent = decode_staged_pile(workspace, key, raw)

    with pytest.raises(StagedObjectsPending):
        confirm_staged_object(intent, intent.object_keys[0], None)

    surplus = staging_key(
        workspace, MEMBER, SESSION, "obj", "e" * 64)
    foreign = staging_key(
        workspace, MEMBER, "f" * 32, "obj", intent.blob_refs[0])
    for observed in (surplus, foreign):
        with pytest.raises(InvalidStagedObject, match="surplus"):
            confirm_staged_object(intent, observed, b"")
    with pytest.raises(InvalidStagedObject, match="object key"):
        confirm_staged_object(intent, "not/a/staging/key", b"")
    with pytest.raises(InvalidStagedObject, match="integrity"):
        confirm_staged_object(
            intent, intent.object_keys[0], b"not the named bytes")

    assert issubclass(InvalidStagedIntent, PermanentIngressRejection)
    assert not issubclass(InvalidStagedObject, PermanentIngressRejection)
    assert not issubclass(StagedObjectsPending, PermanentIngressRejection)


@pytest.mark.parametrize("mutate", (
    lambda key: key.upper(),
    lambda key: key.replace("/v1/", "/v2/"),
    lambda key: "/" + key,
    lambda key: key + "/extra",
    lambda key: key.replace("/piles/", "//piles/"),
    lambda key: key.replace("c" * 32, "c" * 31),
    lambda key: key.replace("c" * 32, "C" * 32),
    lambda key: key.replace("d" * 16, "d" * 15),
    lambda key: key.replace("d" * 16, "D" * 16),
    lambda key: key[:-1],
))
def test_pile_key_parser_rejects_noncanonical_or_free_form_paths(
        staged_file, mutate):
    _, _, _, key = staged_file
    with pytest.raises(InvalidStagedIntent, match="staging key"):
        parse_staging_key(mutate(key))


def test_staged_pile_binds_configured_key_and_envelope_workspace(
        staged_file):
    _, workspace, raw, key = staged_file
    foreign = "b" * 64
    foreign_key = staging_key(
        foreign, MEMBER, SESSION, "pile", h(raw))
    wrong_envelope = canon({"ws": foreign, "facts": []})
    wrong_envelope_key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(wrong_envelope))

    with pytest.raises(InvalidStagedIntent, match="staging workspace"):
        decode_staged_pile(workspace, foreign_key, raw)
    with pytest.raises(InvalidStagedIntent, match="staged pile"):
        decode_staged_pile(
            workspace, wrong_envelope_key, wrong_envelope)
    with pytest.raises(
            InvalidStagedIntent, match="configured workspace"):
        decode_staged_pile("B" * 64, key, raw)


def test_only_workspace_genesis_may_omit_workspace():
    ordinary = Fact("msg", 7, [], {}, None)
    workspace = ordinary.fid
    raw = encode_pile([ordinary], workspace=workspace)
    key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))

    with pytest.raises(
            InvalidStagedIntent, match="only workspace genesis"):
        decode_staged_pile(workspace, key, raw)


def test_unknown_and_mixed_workspace_facts_fail_at_staging_door():
    workspace = "a" * 64
    unknown = Fact("not-a-family", 1, [], {}, workspace)
    unknown_raw = encode_pile([unknown], workspace=workspace)
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


def test_marker_rejects_noncanonical_embedded_and_forged_forms(
        staged_file):
    _, workspace, raw, _ = staged_file
    stream, _ = decode_pile(raw, workspace)
    pretty = json.dumps(json.loads(raw), indent=2).encode()
    embedded = encode_pile(
        stream, {h(b"embedded"): b"embedded"}, workspace=workspace)
    forged = json.loads(raw)
    forged["uploader"] = MEMBER
    forged = canon(forged)

    candidates = (
        (
            pretty,
            "non-canonical staged pile",
        ),
        (
            embedded,
            "cannot embed objects",
        ),
        (
            forged,
            "invalid staged pile",
        ),
        (
            b"{}",
            "invalid staged pile",
        ),
    )
    for candidate, message in candidates:
        key = staging_key(
            workspace, MEMBER, SESSION, "pile", h(candidate))
        with pytest.raises(InvalidStagedIntent, match=message):
            decode_staged_pile(workspace, key, candidate)


def test_digest_and_object_notification_cannot_become_pile_authority(
        staged_file):
    _, workspace, raw, key = staged_file
    changed = raw + b" "
    with pytest.raises(InvalidStagedIntent, match="staged pile digest"):
        decode_staged_pile(workspace, key, changed)

    object_key = staging_key(
        workspace, MEMBER, SESSION, "obj", h(raw))
    with pytest.raises(InvalidStagedIntent, match="pile marker required"):
        decode_staged_pile(workspace, object_key, raw)


def test_pile_without_object_references_is_a_valid_ready_marker(
        staged_file):
    node, workspace, _, _ = staged_file
    raw = closed_subset(node, workspace, [workspace])
    key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))

    intent = decode_staged_pile(workspace, key, raw)

    assert intent.blob_refs == ()
    assert intent.object_keys == ()


def test_staged_object_reference_count_is_bounded_without_large_fixture(
        staged_file, monkeypatch):
    _, workspace, raw, key = staged_file
    monkeypatch.setattr(staged_intent_module, "MAX_STAGED_OBJECTS", 1)

    with pytest.raises(InvalidStagedIntent, match="reference count"):
        decode_staged_pile(workspace, key, raw)
