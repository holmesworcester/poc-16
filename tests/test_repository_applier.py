"""The two actor compositions share one database-free receiving engine."""
import asyncio
import base64
import inspect
import json
import sqlite3

import facts
import pytest

from core import crypto
from core.validated_set import reconstruct
from core.close import decode_pile, encode_pile
from core.crypto import h, keypair
from core.fact import Fact, canon
from full_peer.node import FullPeer
from core.limits import (
    MAX_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    PayloadTooLarge,
)
from core.repository_applier import RepositoryApplier, SyncStoreAdapter
from core.repository_reader import RepositoryReader
from core.store import FsStore

from .util import all_fids, closed_subset, suppression_world


def run(awaitable):
    return asyncio.run(awaitable)


def test_stage_rejects_bad_type_and_one_over_before_store_mutation(
        tmp_path):
    class MutationSpy(FsStore):
        def __init__(self, root):
            super().__init__(root)
            self.mutations = []

        def put_if_absent(self, key, value):
            self.mutations.append((key, value))
            return super().put_if_absent(key, value)

    store = MutationSpy(str(tmp_path / "hosted"))
    applier = RepositoryApplier("0" * 64, store)

    with pytest.raises(TypeError, match="exact ingress bytes"):
        run(applier.stage("member", "not bytes"))
    with pytest.raises(PayloadTooLarge, match="pile exceeds"):
        run(applier.stage("member", b"x" * (MAX_PILE_BYTES + 1)))

    assert store.mutations == []
    assert store.list("") == []


def test_applier_adapter_has_no_unbounded_read_or_list_fallback():
    class UnboundedOnly:
        def get(self, _key):
            raise AssertionError("whole-object fallback was used")

        def list(self, _prefix):
            raise AssertionError("unbounded LIST fallback was used")

    adapter = SyncStoreAdapter(UnboundedOnly())

    assert not hasattr(adapter, "list")
    with pytest.raises(AttributeError, match="get_bounded"):
        run(adapter.get_bounded("pile/member/generation/hash", 1))
    with pytest.raises(AttributeError, match="list_page"):
        run(adapter.list_page("pile/", None, 1))


def test_strict_async_store_needs_no_whole_get_or_list_surface(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    pile = closed_subset(source, workspace, all_fids(source, workspace))

    class StrictAsyncStore:
        def __init__(self, root):
            self.inner = FsStore(root)

        async def get_bounded(self, key, maximum):
            return self.inner.get_bounded(key, maximum)

        async def read_versioned(self, key):
            return self.inner.read_versioned(key)

        async def put(self, key, value):
            return self.inner.put(key, value)

        async def put_if_absent(self, key, value):
            return self.inner.put_if_absent(key, value)

        async def cas(self, key, token, value):
            return self.inner.cas(key, token, value)

        async def list_page(self, prefix, cursor, limit):
            return self.inner.list_page(prefix, cursor, limit)

        async def delete(self, key):
            return self.inner.delete(key)

    store = StrictAsyncStore(str(tmp_path / "hosted"))
    assert not hasattr(store, "get")
    assert not hasattr(store, "list")
    applier = RepositoryApplier(workspace, store)

    key = run(applier.stage("feed7feed7feed7f", pile))
    result = run(applier.apply(key))

    assert result.status == "applied"
    assert result.retired is True
    assert store.inner.get_bounded(key, MAX_PILE_BYTES) is None
    assert store.inner.get_bounded("root", MAX_ROOT_BYTES) == \
        source.reader(workspace).root_bytes


def test_apply_fetches_internal_pile_through_bounded_contract(
        tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    pile = closed_subset(source, workspace, all_fids(source, workspace))

    class BoundedSourceStore(FsStore):
        bounded_source = None

        def __init__(self, root):
            super().__init__(root)
            self.bounded_reads = []

        def get(self, key):
            if key == self.bounded_source:
                raise AssertionError("internal pile used whole-object get")
            return super().get(key)

        def get_bounded(self, key, maximum):
            self.bounded_reads.append((key, maximum))
            return super().get_bounded(key, maximum)

    store = BoundedSourceStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(applier.stage("member", pile))
    store.bounded_source = key

    result = run(applier.apply(key, retire=False))

    assert result.status == "applied"
    assert (key, MAX_PILE_BYTES) in store.bounded_reads


def test_apply_has_no_unstaged_raw_commit_door(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    pile = closed_subset(source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    unstaged = (
        "pile/feed7feed7feed7f/"
        "0123456789abcdef0123456789abcdef/"
        + h(pile)
    )

    assert "raw" not in inspect.signature(applier.apply).parameters
    with pytest.raises(TypeError):
        run(applier.apply(unstaged, pile))

    missing = run(applier.apply(unstaged))
    assert missing.status == "missing"
    proposal = run(applier.propose(pile))
    with pytest.raises(ValueError, match="present exact generation"):
        run(applier.commit(unstaged, pile, proposal))
    assert not hasattr(applier, "reject")
    assert store.get_bounded("root", MAX_ROOT_BYTES) is None
    assert store.list("obj/") == []
    assert store.list("failed/") == []


def test_cold_applier_reproduces_full_p2p_root_without_sql(
        tmp_path, monkeypatch):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    pile = closed_subset(source, workspace, all_fids(source, workspace))
    expected = source.store(workspace).get("root")

    def sql_is_forbidden(*_args, **_kwargs):
        raise AssertionError("RepositoryApplier touched SQLite")

    monkeypatch.setattr(sqlite3, "connect", sql_is_forbidden)
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(applier.stage("feed7feed7feed7f", pile))
    result = run(applier.apply(key))

    assert result.status == "applied"
    assert result.retired is True
    assert store.get(key) is None
    assert store.get("root") == expected
    validated = reconstruct(
        expected, lambda oid: store.get("obj/" + oid))
    assert set(result.admitted) <= set(validated.facts)


def test_cold_rebase_bounds_authenticated_repository_objects(tmp_path):
    class RecordingStore(FsStore):
        def __init__(self, root):
            super().__init__(root)
            self.object_reads = []

        def get_bounded(self, key, maximum):
            if key.startswith("obj/"):
                self.object_reads.append((key, maximum))
            return super().get_bounded(key, maximum)

    source, workspace, _, _ = suppression_world(tmp_path / "source")
    initial = closed_subset(
        source, workspace, all_fids(source, workspace))
    store = RecordingStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    first = run(applier.stage("0123456789abcdef", initial))
    assert run(applier.apply(first)).status == "applied"

    new_fid = facts.content.message.post(
        source, workspace, "general", "after the pinned root", ts=100)
    update = closed_subset(source, workspace, [new_fid])
    store.object_reads.clear()
    second = run(applier.stage("fedcba9876543210", update))
    assert run(applier.apply(second)).status == "applied"

    assert store.object_reads
    assert all(
        maximum <= MAX_REPOSITORY_OBJECT_BYTES
        for _key, maximum in store.object_reads
    )
    assert any(
        maximum == MAX_REPOSITORY_OBJECT_BYTES
        for _key, maximum in store.object_reads
    )


def test_crash_after_cas_replays_as_token_checked_noop_and_retires(
        tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    pile = closed_subset(source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "hosted"))
    first = RepositoryApplier(workspace, store)
    key = run(first.stage("feed7feed7feed7f", pile))
    applied = run(first.apply(key, retire=False))
    assert applied.status == "applied"
    assert store.get(key) == pile

    cold = RepositoryApplier(workspace, store)
    replay = run(cold.apply(key))
    assert replay.status == "noop"
    assert replay.retired is True
    assert store.get(key) is None
    assert replay.root == applied.root


def test_concurrent_cold_appliers_rebase_retained_loser(
        tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    base_pile = closed_subset(
        source, workspace, all_fids(source, workspace))

    first_fid = facts.content.message.post(
        source, workspace, "general", "first", ts=10)
    first_pile = closed_subset(source, workspace, [first_fid])
    second_fid = facts.content.message.post(
        source, workspace, "general", "second", ts=11)
    second_pile = closed_subset(source, workspace, [second_fid])
    expected = source.store(workspace).get("root")

    store = FsStore(str(tmp_path / "shared"))
    first = RepositoryApplier(workspace, store)
    second = RepositoryApplier(workspace, store)
    bootstrap = run(first.stage("feed7feed7feed7f", base_pile))
    run(first.apply(bootstrap))
    first_key = run(first.stage("feed7feed7feed7f", first_pile))
    second_key = run(second.stage("feed7feed7feed7f", second_pile))

    first_proposal = run(first.propose(first_pile))
    second_proposal = run(second.propose(second_pile))
    won = run(first.commit(first_key, first_pile, first_proposal))
    lost = run(second.commit(second_key, second_pile, second_proposal))

    assert won.status == "applied"
    assert lost.status == "stale"
    assert store.get(second_key) == second_pile
    retried = run(RepositoryApplier(
        workspace, store).apply(second_key))
    assert retried.status == "applied"
    assert retried.retired is True
    assert store.get("root") == expected

    # The winners simulated crash left its exact obligation live.  A cold
    # Replay observes the already-committed fact through the new root.
    discharged = run(RepositoryApplier(
        workspace, store).apply(first_key))
    assert discharged.status == "noop"
    assert discharged.retired is True
    assert store.get("root") == expected


def test_proposal_for_one_pile_cannot_commit_or_retire_another(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    first_fid = facts.content.message.post(
        source, workspace, "general", "first", ts=10)
    first_raw = closed_subset(source, workspace, [first_fid])
    second_fid = facts.content.message.post(
        source, workspace, "general", "second", ts=11)
    second_raw = closed_subset(source, workspace, [second_fid])

    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    first_key = run(applier.stage("first", first_raw))
    second_key = run(applier.stage("second", second_raw))
    proposal = run(applier.propose(first_raw))

    with pytest.raises(ValueError, match="proposal binding"):
        run(applier.commit(second_key, second_raw, proposal))

    assert store.get("root") is None
    assert store.list("obj/") == []
    assert store.get(first_key) == first_raw
    assert store.get(second_key) == second_raw
    assert applier._receipts == {}


def test_proposal_is_an_ephemeral_capability_of_its_minting_applier(
        tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "hosted"))
    first = RepositoryApplier(workspace, store)
    key = run(first.stage("member", raw))
    proposal = run(first.propose(raw))

    with pytest.raises(ValueError, match="proposal binding"):
        run(RepositoryApplier(
            workspace, store).commit(key, raw, proposal))

    assert store.get("root") is None
    assert store.list("obj/") == []
    assert store.get(key) == raw


def test_permanent_rejection_preserves_exact_evidence_before_delete(
        tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    store = FsStore(str(tmp_path / "hosted"))
    malformed = b"{}"
    applier = RepositoryApplier(workspace, store)
    key = run(applier.stage("feed7feed7feed7f", malformed))
    result = run(applier.apply(key))

    assert result.status == "rejected"
    assert result.retired is True
    assert result.rejection is not None
    assert store.get(key) is None
    assert store.get(
        "failed/pile/" + result.rejection.payload) == malformed
    assert store.get(
        "failed/meta/" + h(result.rejection.record)
    ) == result.rejection.record


def test_removal_of_a_never_member_is_rejected_before_root_mutation(
        tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    secret, public = author.identity(workspace)
    _, never_member = keypair()
    item = facts.auth.removal.removal(
        workspace, public, never_member, 10)
    signed = facts.auth.signature.signature(
        secret, public, item, item.ts)
    base = decode_pile(
        closed_subset(author, workspace, all_fids(author, workspace)),
        workspace,
    )
    raw = encode_pile(
        (*base, signed, item), workspace=workspace)

    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("feed7feed7feed7f", raw))
    result = run(applier.apply(source))

    assert result.status == "rejected"
    assert result.retired is True
    assert store.get("root") is None
    assert store.get(source) is None
    assert store.get("failed/pile/" + h(raw)) == raw


def test_family_program_failure_retains_source_without_rejection_evidence(
        tmp_path, monkeypatch):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    facts.content.message.post(
        author, workspace, "general", "valid before failure", ts=10)
    raw = closed_subset(
        author, workspace, all_fids(author, workspace))

    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("feed7feed7feed7f", raw))

    def broken_constructor(*_args, **_kwargs):
        raise RuntimeError("message family program failure")

    monkeypatch.setattr(
        facts.content.message, "message", broken_constructor)
    with pytest.raises(
            RuntimeError, match="message family program failure"):
        run(applier.apply(source))

    assert store.get(source) == raw
    assert store.get("root") is None
    assert store.list("failed/") == []
    assert applier._receipts == {}


def test_crypto_program_failure_retains_source_without_rejection_evidence(
        tmp_path, monkeypatch):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    raw = closed_subset(
        author, workspace, all_fids(author, workspace))
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("feed7feed7feed7f", raw))

    def program_failure(*_args, **_kwargs):
        raise RuntimeError("crypto program failure")

    monkeypatch.setattr(crypto.signing, "VerifyKey", program_failure)
    with pytest.raises(RuntimeError, match="crypto program failure"):
        run(applier.apply(source))

    assert store.get(source) == raw
    assert store.get("root") is None
    assert store.list("failed/") == []
    assert applier._receipts == {}


@pytest.mark.parametrize(
    "attack",
    ("whitespace", "key-order", "duplicate-key", "non-finite", "bad-ref"),
)
def test_noncanonical_pile_retires_exact_source_then_healthy_work_applies(
        tmp_path, attack):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    good = closed_subset(
        author, workspace, all_fids(author, workspace))
    encoded_workspace = workspace.encode()
    if attack == "whitespace":
        bad = b'{ "facts": [], "ws": \"' + encoded_workspace + b'\" }'
    elif attack == "key-order":
        bad = b'{\"ws\":\"' + encoded_workspace + b'\",\"facts\":[]}'
    elif attack == "duplicate-key":
        bad = b'{\"facts\":[],\"ws\":\"' + encoded_workspace \
            + b'\",\"ws\":\"' + encoded_workspace + b'\"}'
    elif attack == "non-finite":
        bad = b'{\"facts\":[],\"ws\":NaN}'
    else:
        poison = Fact(
            "msg",
            2,
            [["ref", "member", []]],
            {"pk": author.pk, "chan": "general", "text": "poison"},
            workspace,
        )
        bad = encode_pile((poison,), workspace=workspace)

    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    bad_source = run(applier.stage("bad", bad))
    rejected = run(applier.apply(bad_source))

    assert rejected.status == "rejected"
    assert rejected.retired is True
    assert store.get(bad_source) is None
    assert store.get("root") is None
    assert store.get("failed/pile/" + h(bad)) == bad

    good_source = run(applier.stage("good", good))
    applied = run(applier.apply(good_source))
    assert applied.status == "applied"
    assert applied.retired is True
    assert store.get("root") == author.reader(workspace).root_bytes


def test_apply_does_not_readjudicate_previously_validated_facts(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(
        node, workspace, "general", "retained fact", ts=10)
    request = facts.auth.request.payload(
        node, workspace, "sync", 200, 100)
    raw = encode_pile(request, workspace=workspace)
    store = node.store(workspace)
    root = store.get("root")
    applier = node.applier(workspace)
    source = run(applier.stage("feed7feed7feed7f", raw))

    def broken_constructor(*_args, **_kwargs):
        raise AssertionError("previous fact was re-adjudicated")

    monkeypatch.setattr(
        facts.content.message, "message", broken_constructor)
    result = run(applier.apply(source))

    assert result.status == "applied"
    assert result.retired is True
    assert store.get(source) is None
    assert store.get("root") != root
    assert any(
        fact.body.get("text") == "retained fact"
        for fact in node.reader(workspace).all_facts().facts.values()
    )
    assert store.list("failed/") == []
    assert applier._receipts == {}


def test_malformed_pile_is_rejected_before_root_or_validated_set_reads(
        tmp_path, monkeypatch):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    raw = b"{}"
    key = run(applier.stage("member", raw))

    monkeypatch.setattr(
        store,
        "read_versioned",
        lambda _key: pytest.fail(
            "malformed pile forced repository root/validated-set reads"),
    )

    result = run(applier.apply(key))

    assert result.status == "rejected"
    assert result.retired is True
    assert store.get("failed/pile/" + h(raw)) == raw


def test_embedded_object_member_is_rejected_without_establishing_bytes(
        tmp_path):
    """An ordinary pile cannot bypass detached immutable-object ingress."""
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    ordinary = closed_subset(
        source, workspace, all_fids(source, workspace))
    object_bytes = b"unreferenced object must not cross the pile door"
    oid = h(object_bytes)
    envelope = json.loads(ordinary)
    envelope["blobs"] = {
        oid: base64.b64encode(object_bytes).decode("ascii"),
    }
    hostile = canon(envelope)

    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(applier.stage("member", hostile))
    result = run(applier.apply(key))

    assert result.status == "rejected"
    assert result.retired is True
    assert store.get("obj/" + oid) is None
    assert store.get("root") is None
    assert store.get("failed/pile/" + h(hostile)) == hostile
    rejection = json.loads(result.rejection.record)
    assert (
        rejection["classification"],
        rejection["diagnostic"],
    ) == ("InvalidPile", "pile shape")


def test_repository_reader_is_pinned_and_has_no_store_authority(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    store = source.store(workspace)
    root = store.get("root")
    reads = []

    def fetch(oid):
        reads.append(oid)
        return store.get("obj/" + oid)

    reader = RepositoryReader(workspace, root, fetch)
    validated = reader.validated()
    assert validated.fact(workspace).fid == workspace
    assert reader.worker().fact_active(workspace)
    assert reader.root_bytes == root
    assert reads
    assert not any(
        name in RepositoryReader.__dict__
        for name in ("apply", "cas", "delete", "list", "put", "turn"))


def test_turn_reports_one_failed_generation_without_wedging_the_next(
        tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    pile = closed_subset(source, workspace, all_fids(source, workspace))

    class OneReadFails(FsStore):
        blocked = None

        def get_bounded(self, key, maximum):
            if key == self.blocked:
                raise OSError("injected exact-source read failure")
            return super().get_bounded(key, maximum)

    store = OneReadFails(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    blocked = run(applier.stage("blocked", pile))
    live = run(applier.stage("live", pile))
    store.blocked = blocked

    report = run(applier.turn())

    by_source = {item.source: item for item in report}
    assert isinstance(by_source[blocked].error, OSError)
    assert by_source[blocked].result is None
    assert by_source[live].error is None
    assert by_source[live].result.status == "applied"
    assert store.has(blocked)
    assert not store.has(live)
