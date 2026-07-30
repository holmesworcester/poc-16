"""The provider-neutral door from untrusted staging to publication."""
from concurrent.futures import ThreadPoolExecutor
import asyncio
import json

import pytest

import facts

from core import bao
from core import repository_applier as applier_module
from core import staged_intent as staged_intent_module
from core.close import decode_pile, encode_pile
from core.crypto import h
from core.fact import Fact, canon
from core.ingress import InvalidStagedIntent, PermanentIngressRejection
from core.node import Node
from core.repository_applier import RepositoryApplier
from core.object_store import STALE
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
from tests.util import closed_subset, send_bytes


SESSION = "c" * 32
MEMBER = "d" * 16


@pytest.fixture
def staged_file(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
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


def _put_staged_file(ingress, node, workspace, raw, key):
    ingress.put_if_absent(key, raw)
    intent = decode_staged_pile(workspace, key, raw)
    for object_key, digest in zip(intent.object_keys, intent.blob_refs):
        ingress.put_if_absent(
            object_key, node.store(workspace).get("obj/" + digest))
    return intent


def test_verified_session_enters_the_applier_through_a_fresh_generation(
        staged_file, monkeypatch, tmp_path):
    node, workspace, raw, key = staged_file
    ingress = FsStore(str(tmp_path / "ingress"))
    intent = _put_staged_file(
        ingress, node, workspace, raw, key)
    canonical = FsStore(str(tmp_path / "canonical"))
    generation = "e" * 32
    monkeypatch.setattr(
        applier_module.secrets, "token_hex", lambda size: generation)

    applied = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))

    assert applied.source == f"pile/{MEMBER}/{generation}/{h(raw)}"
    assert applied.source != intent.key
    assert applied.result.status == "applied"
    assert applied.result.retired is True
    assert canonical.get(applied.source) is None
    assert canonical.get("root") == applied.result.root
    assert ingress.get(key) == raw
    assert set(applied.promoted) == set(intent.blob_refs)
    assert applied.unavailable == ()


def test_staging_replay_and_concurrent_appliers_cannot_recreate_generation(
        staged_file, tmp_path):
    node, workspace, raw, key = staged_file
    ingress = FsStore(str(tmp_path / "ingress"))
    _put_staged_file(ingress, node, workspace, raw, key)
    canonical = FsStore(str(tmp_path / "canonical"))
    first = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))
    first_root = canonical.get("root")

    # Even a replay of the exact client-writable session object crosses the
    # trusted copy door into a new internal key. Two concurrent notification
    # handlers likewise cannot collide or recreate the first generation.
    with ThreadPoolExecutor(max_workers=2) as pool:
        replayed = tuple(pool.map(
            lambda _: asyncio.run(
                RepositoryApplier(workspace, canonical).apply_staged(
                    ingress, key)),
            range(2),
        ))
    sources = {result.source for result in replayed}
    assert sources == {None}
    assert all(
        result.result.status == "admitted"
        for result in replayed)
    assert not canonical.list("pile/")
    assert canonical.get("root") == first_root
    assert ingress.get(key) == raw


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


def test_missing_staged_blob_does_not_block_valid_fact_admission(
        staged_file, tmp_path):
    node, workspace, raw, key = staged_file
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    intent = decode_staged_pile(workspace, key, raw)
    ingress.put_if_absent(key, raw)

    applied = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))

    assert applied.result.status == "applied"
    assert applied.result.retired is True
    assert applied.promoted == ()
    assert applied.unavailable == intent.object_keys
    assert canonical.get("root") == applied.result.root
    assert all(
        canonical.get("obj/" + oid) is None
        for oid in intent.blob_refs)


def test_attachment_failure_is_observed_only_after_root_commit(
        staged_file, tmp_path):
    node, workspace, raw, key = staged_file
    underlying = FsStore(str(tmp_path / "ingress"))
    intent = _put_staged_file(
        underlying, node, workspace, raw, key)
    canonical = FsStore(str(tmp_path / "canonical"))

    class FailingObjects:
        def get_bounded(self, object_key, maximum):
            if object_key.startswith(staging_prefix(workspace, "obj")):
                assert canonical.get("root") is not None
                raise OSError("simulated detached-object outage")
            value = underlying.get(object_key)
            assert value is None or len(value) <= maximum
            return value

    applied = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            FailingObjects(), key))

    assert applied.result.status == "applied"
    assert applied.result.retired is True
    assert applied.promoted == ()
    assert applied.unavailable == intent.object_keys
    assert canonical.get("root") is not None
    assert canonical.list("staged/admitted/")
    assert not canonical.list("staged/done/")


def test_detached_completion_is_bounded_to_one_page_per_turn(
        staged_file, monkeypatch, tmp_path):
    node, workspace, raw, key = staged_file
    ingress = FsStore(str(tmp_path / "ingress"))
    intent = _put_staged_file(
        ingress, node, workspace, raw, key)
    canonical = FsStore(str(tmp_path / "canonical"))
    monkeypatch.setattr(applier_module, "_STAGED_OBJECT_BATCH", 1)

    first = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))
    second = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))

    assert len(intent.blob_refs) == 2
    assert len(first.promoted) == len(second.promoted) == 1
    assert set(first.promoted + second.promoted) == set(intent.blob_refs)
    assert not first.unavailable and not second.unavailable
    assert len(canonical.list("staged/object-page/")) == 2
    assert canonical.list("staged/done/")
    assert ingress.get(key) == raw


def test_detached_completion_round_robin_does_not_wedge_behind_a_gap(
        staged_file, monkeypatch, tmp_path):
    node, workspace, raw, key = staged_file
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    intent = decode_staged_pile(workspace, key, raw)
    assert len(intent.blob_refs) == 2
    ingress.put_if_absent(key, raw)
    available_key, available_oid = (
        intent.object_keys[1], intent.blob_refs[1])
    ingress.put_if_absent(
        available_key,
        node.store(workspace).get("obj/" + available_oid),
    )
    monkeypatch.setattr(applier_module, "_STAGED_OBJECT_BATCH", 1)

    blocked = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))
    progressed = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))

    assert blocked.unavailable == (intent.object_keys[0],)
    assert progressed.promoted == (available_oid,)
    assert not canonical.list("staged/done/")
    missing_oid = intent.blob_refs[0]
    ingress.put_if_absent(
        intent.object_keys[0],
        node.store(workspace).get("obj/" + missing_oid),
    )

    completed = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))

    assert completed.promoted == (missing_oid,)
    assert canonical.list("staged/done/")
    assert canonical.get("obj/" + missing_oid) == \
        node.store(workspace).get("obj/" + missing_oid)


def test_poisoned_detached_object_is_evidenced_and_does_not_repeat(
        staged_file, tmp_path):
    _, workspace, raw, key = staged_file
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    intent = decode_staged_pile(workspace, key, raw)
    ingress.put_if_absent(key, raw)
    for object_key in intent.object_keys:
        ingress.put_if_absent(object_key, b"wrong same-session bytes")

    first = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))
    second = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))

    assert first.result.status == "applied"
    assert first.unavailable == ()
    assert first.poisoned == intent.object_keys
    assert canonical.list("staged/object-poisoned/")
    assert canonical.list("staged/done/")
    assert second.result.status == "admitted"
    assert second.poisoned == ()
    assert canonical.get("root") == first.result.root


def test_stale_marker_replay_reuses_one_claimed_internal_generation(
        staged_file, tmp_path):
    node, workspace, raw, key = staged_file
    ingress = FsStore(str(tmp_path / "ingress"))
    _put_staged_file(ingress, node, workspace, raw, key)
    underlying = FsStore(str(tmp_path / "canonical"))

    class AlwaysStale:
        def __getattr__(self, name):
            return getattr(underlying, name)

        def cas(self, _key, _token, _value):
            return STALE

    first = asyncio.run(
        RepositoryApplier(workspace, AlwaysStale()).apply_staged(
            ingress, key))
    sources = underlying.list("pile/")
    replay = asyncio.run(
        RepositoryApplier(workspace, AlwaysStale()).apply_staged(
            ingress, key))

    assert first.result.status == replay.result.status == "stale"
    assert replay.source == first.source
    assert underlying.list("pile/") == sources == [first.source]
    assert len(underlying.list("staged/claim/")) == 1


def test_invalid_marker_gets_one_deterministic_staged_rejection(
        tmp_path):
    workspace = "a" * 64
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    raw = b"{}"
    key = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))
    ingress.put_if_absent(key, raw)

    first = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))
    before = canonical.list("staged/rejected/")
    replay = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, key))

    assert first.result.status == replay.result.status == "rejected-staging"
    assert first.source is replay.source is None
    assert canonical.list("staged/rejected/") == before
    assert len(before) == 1
    assert not canonical.list("pile/")
    assert canonical.get("root") is None


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


def test_marker_rejects_noncanonical_extra_and_forged_forms(
        staged_file):
    _, workspace, raw, _ = staged_file
    decode_pile(raw, workspace)
    pretty = json.dumps(json.loads(raw), indent=2).encode()
    embedded_form = json.loads(raw)
    embedded_form["blobs"] = {h(b"embedded"): "ZW1iZWRkZWQ="}
    embedded = canon(embedded_form)
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
            "invalid staged pile",
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
