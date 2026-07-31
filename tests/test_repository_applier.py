"""One exact immutable pile is the complete repository-apply unit."""
import asyncio
import inspect
import sqlite3

import facts
import pytest

from core import crypto
from core.crypto import h
from core.ingress import InvalidPile, ingress_key
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

from .util import all_fids, closed_subset, plant_exact, suppression_world


def run(awaitable):
    return asyncio.run(awaitable)


def test_receive_rejects_bad_type_and_one_over_before_mutation(tmp_path):
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
        run(applier.receive_pile("a" * 64, "not bytes"))
    with pytest.raises(InvalidPile, match="pile too large"):
        run(applier.receive_pile(
            "a" * 64, b"x" * (MAX_PILE_BYTES + 1)))
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
    key = run(plant_exact(store, workspace, "f" * 64, raw))
    result = run(applier.apply_exact(store, key, h(raw)))
    assert result.status == "applied"
    assert store.inner.get_bounded(key, MAX_PILE_BYTES) == raw
    assert store.inner.get_bounded("root", MAX_ROOT_BYTES) == \
        source.reader(workspace).root_bytes


def test_apply_exact_needs_caller_key_and_digest(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    key = ingress_key(workspace, "b" * 32, "c" * 64, h(raw))
    ingress.put_if_absent(key, raw)
    applier = RepositoryApplier(workspace, canonical)

    assert list(inspect.signature(applier.apply_exact).parameters) == [
        "source_store", "source", "payload",
    ]
    with pytest.raises(ValueError, match="exact ingress address"):
        run(applier.apply_exact(ingress, key, "0" * 64))
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

    missing_key = ingress_key(
        workspace, "c" * 32, "d" * 64, "b" * 64)
    missing = run(applier.apply_exact(ingress, missing_key, "b" * 64))
    assert missing.status == "retryable"

    raw = b"x" * (MAX_PILE_BYTES + 1)
    oversize_key = ingress_key(
        workspace, "e" * 32, "f" * 64, h(raw))
    ingress.put_if_absent(oversize_key, raw)
    oversize = run(applier.apply_exact(ingress, oversize_key, h(raw)))
    assert oversize.status == "rejected"
    assert canonical.list("") == []
    assert ingress.get(oversize_key) == raw


def test_whole_pile_rejection_precedes_repository_reads(tmp_path):
    workspace = "a" * 64
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(plant_exact(store, workspace, "a" * 64, b"{}"))
    store.read_versioned = lambda _key: pytest.fail(
        "invalid pile read repository state")

    result = run(applier.apply_exact(store, key, h(b"{}")))
    assert result.status == "rejected"
    assert store.get(key) == b"{}"
    assert store.list("obj/") == []


def test_cold_applier_reproduces_full_peer_root(tmp_path):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    expected = source.store(workspace).get("root")
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(plant_exact(store, workspace, "f" * 64, raw))

    result = run(applier.apply_exact(store, key, h(raw)))

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
    assert run(applier.receive_pile("0" * 64, initial)).status \
        == "applied"

    fid = facts.content.message.post(
        source, workspace, "general", "next", ts=100)
    update = closed_subset(source, workspace, (fid,))
    store.object_reads.clear()
    assert run(applier.receive_pile("f" * 64, update)).status \
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
    key = run(plant_exact(store, workspace, "f" * 64, raw))
    confirmed = run(first.apply_exact(store, key, h(raw)))
    assert confirmed.status == "applied"
    assert store.get(key) == raw

    replay = run(RepositoryApplier(workspace, store).apply_exact(
        store, key, h(raw)))
    assert replay.status == "noop"
    assert replay.root == confirmed.root
    assert store.get(key) == raw


def test_concurrent_cold_apply_exact_reconciles_lost_winner_and_rebases_loser(
        tmp_path):
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

    class Interleaved:
        def __init__(self, path):
            self.inner = FsStore(path)
            self.race = False
            self.reads = 0
            self.barrier = asyncio.Barrier(2)
            self.lost_reply = False

        async def get_bounded(self, key, maximum):
            await asyncio.sleep(0)
            return self.inner.get_bounded(key, maximum)

        async def read_versioned(self, key):
            result = self.inner.read_versioned(key)
            if self.race and key == "root" and self.reads < 2:
                self.reads += 1
                await self.barrier.wait()
            return result

        async def put_if_absent(self, key, value):
            await asyncio.sleep(0)
            return self.inner.put_if_absent(key, value)

        async def cas(self, key, token, value):
            result = self.inner.cas(key, token, value)
            if isinstance(result, Applied) and not self.lost_reply:
                self.lost_reply = True
                raise OutcomeUnknown("winner committed; response was lost")
            return result

    async def scenario():
        store = Interleaved(str(tmp_path / "shared"))
        bootstrap = RepositoryApplier(workspace, store)
        assert (await bootstrap.receive_pile(
            "a" * 64, base)).status == "applied"
        left_key = await plant_exact(
            store, workspace, "b" * 64, first_raw)
        right_key = await plant_exact(
            store, workspace, "c" * 64, second_raw)
        store.race = True
        workers = (
            RepositoryApplier(workspace, store),
            RepositoryApplier(workspace, store),
        )
        collision = await asyncio.gather(
            workers[0].apply_exact(
                store, left_key, h(first_raw)),
            workers[1].apply_exact(
                store, right_key, h(second_raw)),
        )
        assert sorted(result.status for result in collision) == [
            "applied", "retryable"]
        loser = next(
            (key, raw) for key, raw, result in (
                (left_key, first_raw, collision[0]),
                (right_key, second_raw, collision[1]),
            ) if result.status == "retryable"
        )
        retried = await RepositoryApplier(
            workspace, store).apply_exact(store, loser[0], h(loser[1]))
        assert retried.status == "applied"
        return store, left_key, right_key

    store, left_key, right_key = run(scenario())
    assert store.inner.get(left_key) == first_raw
    assert store.inner.get(right_key) == second_raw
    assert store.inner.get("root") == expected
    reader = RepositoryReader(
        workspace,
        store.inner.get("root"),
        lambda oid: store.inner.get("obj/" + oid),
    )
    validated = reader.validated()
    assert {first_fid, second_fid} <= set(validated.fact_ids())
    # Reading every fact also authenticates all three map roots and postings.
    assert validated.fact(first_fid).body["text"] == "first"
    assert validated.fact(second_fid).body["text"] == "second"


def test_bad_exact_addresses_fail_before_any_source_read(tmp_path):
    class SourceSpy:
        reads = 0

        async def get_bounded(self, _key, _maximum):
            self.reads += 1
            raise AssertionError("bad address reached source storage")

    workspace = "a" * 64
    source = SourceSpy()
    applier = RepositoryApplier(
        workspace, FsStore(str(tmp_path / "canonical")))
    digest = "d" * 64
    bad = (
        ("not/an/ingress/key", digest),
        (ingress_key(
            "b" * 64, "c" * 32, "e" * 64, digest), digest),
        (ingress_key(
            workspace, "c" * 32, "e" * 64, digest), "f" * 64),
    )
    for key, claimed in bad:
        with pytest.raises(ValueError, match="exact ingress address"):
            run(applier.apply_exact(source, key, claimed))
    assert source.reads == 0


def test_program_failure_retains_source_and_does_not_mutate_root(
        tmp_path, monkeypatch):
    source, workspace, _, _ = suppression_world(tmp_path / "source")
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "hosted"))
    applier = RepositoryApplier(workspace, store)
    key = run(plant_exact(store, workspace, "a" * 64, raw))

    def failure(*_args, **_kwargs):
        raise RuntimeError("crypto program failure")

    monkeypatch.setattr(crypto.signing, "VerifyKey", failure)
    with pytest.raises(RuntimeError, match="crypto program failure"):
        run(applier.apply_exact(store, key, h(raw)))
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
