"""Exact immutable ingress needs no queue, spend record, or DELETE."""
import asyncio
from concurrent.futures import ThreadPoolExecutor

import facts
import pytest

from core.object_store import ABSENT
from core.ingress import ingress_key
from core.repository_applier import RepositoryApplier
from core.store import FsStore
from full_peer.node import FullPeer

from .provider_fakes import provider_store
from .util import apply_planted, closed_subset, plant_exact


def run(awaitable):
    return asyncio.run(awaitable)


def _message_pile(directory, text="message", ts=10):
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fid = facts.content.message.post(
        node, workspace, "general", text, ts=ts)
    return workspace, closed_subset(node, workspace, (fid,)), fid


def _concurrently(call, actors):
    with ThreadPoolExecutor(max_workers=len(actors)) as pool:
        return tuple(pool.map(lambda actor: run(call(actor)), actors))


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_concurrent_workers_apply_one_exact_source_without_deleting(
        kind, tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / f"source-{kind}", f"same-{kind}")
    store = provider_store(kind, tmp_path / f"recipient-{kind}")
    first = RepositoryApplier(workspace, store)
    second = RepositoryApplier(workspace, store)
    source = run(plant_exact(store, workspace, "a" * 64, raw))

    results = _concurrently(
        lambda actor: apply_planted(actor, source, store), (first, second))
    assert {result.status for result in results} <= {
        "applied", "noop", "retryable",
    }
    cold = RepositoryApplier(workspace, store)
    replay = run(apply_planted(cold, source, store))
    assert replay.status == "noop"
    assert run(cold.store.get_bounded(source, len(raw))) == raw


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_concurrent_rejection_is_repeatable_and_non_destructive(
        kind, tmp_path):
    workspace, _, _ = _message_pile(
        tmp_path / f"source-reject-{kind}")
    raw = b"{}"
    store = provider_store(kind, tmp_path / f"recipient-reject-{kind}")
    workers = (
        RepositoryApplier(workspace, store),
        RepositoryApplier(workspace, store),
    )
    source = run(plant_exact(store, workspace, "a" * 64, raw))
    results = _concurrently(
        lambda worker: apply_planted(worker, source, store), workers)

    assert {result.status for result in results} == {"rejected"}
    cold = RepositoryApplier(workspace, store)
    assert run(apply_planted(cold, source, store)).status == "rejected"
    assert run(cold.store.get_bounded(source, len(raw))) == raw
    assert run(cold.store.read_versioned("root")) is ABSENT


def test_applier_never_calls_list_or_delete(tmp_path):
    workspace, raw, _ = _message_pile(tmp_path / "source")
    inner = FsStore(str(tmp_path / "recipient"))

    class ExactStore:
        def __getattr__(self, name):
            if name in {"list", "list_page", "delete"}:
                raise AssertionError(f"forbidden store operation: {name}")
            return getattr(inner, name)

    applier = RepositoryApplier(workspace, ExactStore())
    source = run(plant_exact(
        applier.store, workspace, "a" * 64, raw))
    assert run(apply_planted(applier, source)).status == "applied"
    assert inner.get(source) == raw


def test_missing_source_is_retryable_not_destructive(tmp_path):
    workspace, _, _ = _message_pile(tmp_path / "source")
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))

    source = ingress_key(
        workspace, "a" * 32, "b" * 64, "c" * 64)
    result = run(RepositoryApplier(workspace, canonical).apply_exact(
        ingress, source, "c" * 64))

    assert result.status == "retryable"
    assert canonical.list("") == []
