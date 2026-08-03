"""Cold-worker convergence through only the public exact-source boundary."""
import asyncio
import random
import sqlite3

import facts
import pytest

from core.crypto import h
from core.limits import MAX_ROOT_BYTES
from core.object_store import async_store
from core.repository_applier import RepositoryApplier
from core.repository_snapshot import compile_snapshot
from full_peer.node import FullPeer

from .provider_fakes import provider_store
from .util import all_fids, closed_subset, plant_exact


pytestmark = pytest.mark.unit


def _database_forbidden(*_args, **_kwargs):
    raise AssertionError("database-free RepositoryApplier opened SQLite")


def _corpus(directory, count):
    author = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    bootstrap = closed_subset(
        author, workspace, all_fids(author, workspace))
    work = []
    for ordinal in range(count):
        fid = facts.content.message.post(
            author, workspace, "general", f"concurrent-{ordinal}",
            ts=10 + ordinal)
        work.append((fid, closed_subset(author, workspace, (fid,))))
    return (
        workspace,
        bootstrap,
        tuple(work),
        compile_snapshot(
            workspace,
            {
                fid: author.fact_of(workspace, fid)
                for fid in author.sql(workspace).fact_ids()
            },
        ).root,
    )


class _SharedRootRead:
    """Make all cold workers pin one root before any of them may CAS."""

    def __init__(self, store, parties):
        self.store = async_store(store)
        self.barrier = asyncio.Barrier(parties)
        self.waits = parties

    async def get_bounded(self, key, maximum):
        return await self.store.get_bounded(key, maximum)

    async def read_versioned(self, key):
        value = await self.store.read_versioned(key)
        if key == "root" and self.waits:
            self.waits -= 1
            await self.barrier.wait()
        return value

    async def put_if_absent(self, key, value):
        return await self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        return await self.store.cas(key, token, value)


async def _exercise(store, workspace, bootstrap, work, seed):
    exact = async_store(store)
    bootstrap_key = await plant_exact(
        exact, workspace, "a" * 64, bootstrap)
    bootstrapped = await RepositoryApplier(
        workspace, exact).apply_exact(
            exact, bootstrap_key, h(bootstrap))
    assert bootstrapped.status == "applied"

    sources = [
        await plant_exact(
            exact, workspace, f"{ordinal + 2:064x}", raw)
        for ordinal, (_fid, raw) in enumerate(work)
    ]
    shared = _SharedRootRead(exact, len(work))
    collision = await asyncio.gather(*(
        RepositoryApplier(workspace, shared).apply_exact(
            shared, source, h(raw))
        for source, (_fid, raw) in zip(sources, work)
    ))
    assert [result.status for result in collision].count("applied") == 1
    assert [result.status for result in collision].count("retryable") \
        == len(work) - 1

    order = list(range(len(work)))
    random.Random(seed).shuffle(order)
    replayed = []
    for index in order:
        replayed.append(await RepositoryApplier(
            workspace, exact).apply_exact(
                exact, sources[index], h(work[index][1])))
    assert {result.status for result in replayed} <= {"applied", "noop"}

    cold = [
        await RepositoryApplier(workspace, exact).apply_exact(
            exact, source, h(raw))
        for source, (_fid, raw) in zip(reversed(sources), reversed(work))
    ]
    assert {result.status for result in cold} == {"noop"}
    for source, (_fid, raw) in zip(sources, work):
        assert await exact.get_bounded(source, len(raw)) == raw
    return await exact.get_bounded("root", MAX_ROOT_BYTES)


def _assert_no_discovery_or_deletion(kind, store):
    if kind == "s3":
        operations = [
            event[1] for event in store._read_client.bucket.history]
    elif kind == "r2":
        operations = [event[0] for event in store.bucket.history]
    else:
        return
    assert "list" not in operations
    assert "delete" not in operations


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
@pytest.mark.parametrize("workers", range(2, 7))
def test_cold_workers_converge_without_sql_discovery_or_delete(
        kind, workers, tmp_path, monkeypatch):
    workspace, bootstrap, work, expected_root = _corpus(
        tmp_path / f"author-{kind}-{workers}", workers)
    store = provider_store(
        kind, tmp_path / f"recipient-{kind}-{workers}")
    monkeypatch.setattr(sqlite3, "connect", _database_forbidden)

    root = asyncio.run(_exercise(
        store, workspace, bootstrap, work, 0xF20000 + workers))

    assert root == expected_root
    _assert_no_discovery_or_deletion(kind, store)
