"""One exact immutable pile is the complete repository-apply unit."""
import asyncio
import inspect
import sqlite3

import facts
import pytest

from core import crypto
from core.close import encode_pile
from core.crypto import h, keypair
from core.limits import (
    MAX_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    PayloadTooLarge,
)
from core.object_store import Applied, OutcomeUnknown
from core.repository_applier import RepositoryApplier, SyncStoreAdapter
from core.repository_reader import RepositoryReader
from core.store import FsStore
from core.validated_set import reconstruct
from full_peer.node import FullPeer

from .util import all_fids, closed_subset, suppression_world


def run(awaitable):
    return asyncio.run(awaitable)


def test_stage_rejects_bad_type_and_one_over_before_mutation(tmp_path):
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
    with pytest.raises(PayloadTooLarge, match="pile too large"):
        run(applier.stage("member", b"x" * (MAX_PILE_BYTES + 1)))
    assert store.mutations == []


def test_adapter_requires_no_unbounded_read_list_or_delete():
    class ExactOnly:
        def get_bounded(self, _key, _maximum):
            return None

    adapter = SyncStoreAdapter(ExactOnly())
    assert not any(
        hasattr(adapter, name) for name in ("get", "list", "list_page", "delete")
    )
    assert run(adapter.get_bounded("exact", 1)) is None


def test_exact_async_store_applies_without_sql_list_or_delete(
        tmp_path, monkeypatch):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))

    class ExactAsyncStore:
        def __init__(self, root):
            self.inner = FsStore(root)

        async def get_bounded(self, key, maximum):
            return self.inner.get_bounded(key, maximum)

        async def read_versioned(self, key):
            return self.inner.read_versioned(key)

        async def put_if_absent(self, key, value):
            return self.inner.put_if_absent(key, value)

        async def cas(self, key, token, value):
            return self.inner.cas(key, token, value)

    store = ExactAsyncStore(str(tmp_path / "hosted"))
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *_args, **_kwargs: pytest.fail("applier opened SQLite"),
    )
    applier = RepositoryApplier(workspace, store)
    key = run(applier.stage("feed7feed7feed7f", raw))
    result = run(applier.apply(key))
    assert result.status == "applied"
    assert store.inner.get_bounded(key, MAX_PILE_BYTES) == raw
    assert store.inner.get_bounded("root", MAX_ROOT_BYTES) == \
        source.reader(workspace).root_bytes


def test_apply_exact_needs_caller_key_and_digest(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    key = "provider/exact/pile"
    ingress.put_if_absent(key, raw)
    applier = RepositoryApplier(workspace, canonical)

    assert list(inspect.signature(applier.apply_exact).parameters) == [
        "source_store", "source", "payload",
    ]
    rejected = run(applier.apply_exact(ingress, key, "0" * 64))
    assert rejected.status == "rejected"
    assert canonical.get("root") is None
    assert canonical.list("obj/") == []
    assert ingress.get(key) == raw

    applied = run(applier.apply_exact(ingress, key, h(raw)))
    assert applied.status == "applied"
    assert ingress.get(key) == raw


def test_missing_and_oversize_exact_sources_are_typed_without_mutation(
        tmp_path):
    workspace = "a" * 64
    canonical = FsStore(str(tmp_path / "canonical"))
    ingress = FsStore(str(tmp_path / "ingress"))
    applier = RepositoryApplier(workspace, canonical)

    missing = run(applier.apply_exact(ingress, "missing", "b" * 64))
    assert missing.status == "retryable"

    raw = b"x" * (MAX_PILE_BYTES + 1)
    ingress.put_if_absent("oversize", raw)
    oversize = run(applier.apply_exact(ingress, "oversize", h(raw)))
    assert oversize.status == "rejected"
    assert canonical.list("") == []
    assert ingress.get("oversize") == raw


def test_whole_pile_rejection_precedes_repository_reads(tmp_path):
    workspace = "a" * 64
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(applier.stage("member", b"{}"))
    store.read_versioned = lambda _key: pytest.fail(
        "invalid pile read repository state")

    result = run(applier.apply(key))
    assert result.status == "rejected"
    assert store.get(key) == b"{}"
    assert store.list("obj/") == []


def test_cold_applier_reproduces_full_peer_root(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    expected = source.store(workspace).get("root")
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(applier.stage("feed7feed7feed7f", raw))

    result = run(applier.apply(key))

    assert result.status == "applied"
    assert store.get(key) == raw
    assert store.get("root") == expected
    validated = reconstruct(expected, lambda oid: store.get("obj/" + oid))
    assert set(result.admitted) <= set(validated.facts)


def test_repository_page_reads_remain_bounded(tmp_path):
    class RecordingStore(FsStore):
        def __init__(self, root):
            super().__init__(root)
            self.object_reads = []

        def get_bounded(self, key, maximum):
            if key.startswith("obj/"):
                self.object_reads.append((key, maximum))
            return super().get_bounded(key, maximum)

    source, workspace, _, _ = suppression_world(tmp_path / "source")
    initial = closed_subset(source, workspace, all_fids(source, workspace))
    store = RecordingStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    assert run(applier.receive_pile("0123456789abcdef", initial)).status \
        == "applied"

    fid = facts.content.message.post(
        source, workspace, "general", "next", ts=100)
    update = closed_subset(source, workspace, (fid,))
    store.object_reads.clear()
    assert run(applier.receive_pile("fedcba9876543210", update)).status \
        == "applied"
    assert store.object_reads
    assert all(
        maximum <= MAX_REPOSITORY_OBJECT_BYTES
        for _, maximum in store.object_reads
    )


def test_lost_cas_response_replays_from_retained_source(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))

    class LoseFirstCasReply(FsStore):
        lose = True

        def cas(self, key, token, value):
            result = super().cas(key, token, value)
            if self.lose and isinstance(result, Applied):
                self.lose = False
                raise OutcomeUnknown("lost CAS response")
            return result

    store = LoseFirstCasReply(str(tmp_path / "hosted"))
    first = RepositoryApplier(workspace, store)
    key = run(first.stage("feed7feed7feed7f", raw))
    confirmed = run(first.apply(key))
    assert confirmed.status == "confirmed"
    assert store.get(key) == raw

    replay = run(RepositoryApplier(workspace, store).apply(key))
    assert replay.status == "noop"
    assert replay.root == confirmed.root
    assert store.get(key) == raw


def test_concurrent_exact_sources_rebase_after_one_root_cas(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    base = closed_subset(source, workspace, all_fids(source, workspace))
    first_fid = facts.content.message.post(
        source, workspace, "general", "first", ts=10)
    first_raw = closed_subset(source, workspace, (first_fid,))
    second_fid = facts.content.message.post(
        source, workspace, "general", "second", ts=11)
    second_raw = closed_subset(source, workspace, (second_fid,))
    expected = source.store(workspace).get("root")

    store = FsStore(str(tmp_path / "shared"))
    left = RepositoryApplier(workspace, store)
    right = RepositoryApplier(workspace, store)
    assert run(left.receive_pile("base", base)).status == "applied"
    left_key = run(left.stage("left", first_raw))
    right_key = run(right.stage("right", second_raw))
    left_proposal = run(left.propose(left_key, h(first_raw), first_raw))
    right_proposal = run(right.propose(right_key, h(second_raw), second_raw))

    assert run(left.commit(
        left_key, h(first_raw), left_proposal)).status == "applied"
    assert run(right.commit(
        right_key, h(second_raw), right_proposal)).status == "retryable"
    assert store.get(left_key) == first_raw
    assert store.get(right_key) == second_raw
    assert run(RepositoryApplier(
        workspace, store).apply(right_key)).status == "applied"
    assert store.get("root") == expected


def test_proposal_is_bound_to_source_digest_and_applier(tmp_path):
    secret, public = keypair()
    root = facts.auth.workspace.workspace(secret, public, "root", 1)
    raw = encode_pile((root,), workspace=root.fid)
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(root.fid, store)
    key = run(applier.stage("member", raw))
    proposal = run(applier.propose(key, h(raw), raw))

    with pytest.raises(ValueError, match="proposal binding"):
        run(applier.commit("another", h(raw), proposal))
    with pytest.raises(ValueError, match="proposal binding"):
        run(RepositoryApplier(root.fid, store).commit(
            key, h(raw), proposal))
    assert store.get("root") is None
    assert store.get(key) == raw


def test_program_failure_retains_source_and_does_not_mutate_root(
        tmp_path, monkeypatch):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(applier.stage("member", raw))

    def failure(*_args, **_kwargs):
        raise RuntimeError("crypto program failure")

    monkeypatch.setattr(crypto.signing, "VerifyKey", failure)
    with pytest.raises(RuntimeError, match="crypto program failure"):
        run(applier.apply(key))
    assert store.get(key) == raw
    assert store.get("root") is None


def test_repository_reader_is_pinned_and_has_no_store_authority(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    store = source.store(workspace)
    root = store.get("root")
    reader = RepositoryReader(
        workspace, root, lambda oid: store.get("obj/" + oid))
    assert reader.validated().fact(workspace).fid == workspace
    assert reader.worker().fact_active(workspace)
    assert not any(
        name in RepositoryReader.__dict__
        for name in ("apply", "cas", "delete", "list", "put", "turn")
    )
