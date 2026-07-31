"""Seeded multi-worker convergence over the running exact-pile applier.

Atomic object stores linearize simultaneous root replacements in some order.
These tests construct the important collision directly: every worker prepares
from the same opaque root version, exactly one proposal wins, and the retained
losers retry against that winner.  No discovery queue or cleanup protocol is
part of the schedule.
"""
import asyncio
import random
import sqlite3

import facts
import pytest

from core.crypto import h
from core.limits import MAX_ROOT_BYTES
from core.repository_applier import RepositoryApplier, async_store
from full_peer.node import FullPeer

from .provider_fakes import provider_store
from .util import all_fids, closed_subset


pytestmark = pytest.mark.unit

FIXED_CASES = tuple(
    (workers, 0xF20000 + workers) for workers in range(2, 7))


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
            author,
            workspace,
            "general",
            f"concurrent-{ordinal}",
            ts=10 + ordinal,
        )
        work.append((
            fid,
            closed_subset(author, workspace, (fid,)),
        ))
    return (
        workspace,
        bootstrap,
        tuple(work),
        author.store(workspace).get_bounded("root", MAX_ROOT_BYTES),
    )


async def _exercise(store, workspace, bootstrap, work, seed):
    bootstrapper = RepositoryApplier(workspace, store)
    bootstrap_source = await bootstrapper.stage("bootstrap", bootstrap)
    bootstrapped = await bootstrapper.apply(bootstrap_source)
    assert bootstrapped.status == "applied"

    workers = [
        RepositoryApplier(workspace, store)
        for _ in work
    ]
    sources = await asyncio.gather(*(
        worker.stage(f"worker-{ordinal}", raw)
        for ordinal, (worker, (_fid, raw))
        in enumerate(zip(workers, work))
    ))

    # Preparing before any commit gives every worker the exact same opaque
    # root token.  Their immutable page writes may overlap safely.
    proposals = await asyncio.gather(*(
        worker.propose(source, h(raw), raw)
        for worker, source, (_fid, raw)
        in zip(workers, sources, work)
    ))
    assert len({proposal.base_token for proposal in proposals}) == 1

    order = list(range(len(work)))
    random.Random(seed).shuffle(order)
    collision = [
        await workers[index].commit(
            sources[index], h(work[index][1]), proposals[index])
        for index in order
    ]
    assert [result.status for result in collision].count("applied") == 1
    assert [result.status for result in collision].count("retryable") \
        == len(work) - 1

    # Work identity is the retained exact source.  Any cold worker may retry
    # it; no worker needs a local queue, cursor, receipt, or database.
    retry_order = list(range(len(work)))
    random.Random(seed ^ 0xA11CE).shuffle(retry_order)
    first_replay = [
        await RepositoryApplier(workspace, store).apply(sources[index])
        for index in retry_order
    ]
    assert {result.status for result in first_replay} <= {"applied", "noop"}

    cold_replay = [
        await RepositoryApplier(workspace, store).apply(source)
        for source in reversed(sources)
    ]
    assert {result.status for result in cold_replay} == {"noop"}

    exact_store = async_store(store)
    for source, (_fid, raw) in zip(sources, work):
        assert await exact_store.get_bounded(source, len(raw)) == raw
    return await exact_store.get_bounded("root", MAX_ROOT_BYTES)


def _assert_no_discovery_or_deletion(kind, store):
    if kind == "s3":
        history = store._read_client.bucket.history
        operations = [event[1] for event in history]
    elif kind == "r2":
        history = store.bucket.history
        operations = [event[0] for event in history]
    else:
        return
    assert "list" not in operations
    assert "delete" not in operations


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
@pytest.mark.parametrize(("workers", "seed"), FIXED_CASES)
def test_fixed_multi_worker_schedules_converge_without_discovery_or_delete(
        kind, workers, seed, tmp_path, monkeypatch):
    workspace, bootstrap, work, expected_root = _corpus(
        tmp_path / f"author-{kind}-{workers}", workers)
    store = provider_store(
        kind, tmp_path / f"recipient-{kind}-{workers}")
    monkeypatch.setattr(sqlite3, "connect", _database_forbidden)

    root = asyncio.run(_exercise(
        store, workspace, bootstrap, work, seed))

    assert root == expected_root
    _assert_no_discovery_or_deletion(kind, store)
