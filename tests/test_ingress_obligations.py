"""Exact immutable ingress needs no queue, spend record, or DELETE."""
import asyncio
from concurrent.futures import ThreadPoolExecutor

import facts
import pytest

from core.crypto import h
from core.object_store import ABSENT
from core.repository_applier import RepositoryApplier
from core.store import FsStore
from full_peer.node import FullPeer

from .provider_fakes import provider_store
from .shared_bucket import ScriptedBucket
from .util import closed_subset


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
    sources = _concurrently(
        lambda actor: actor.stage("member", raw), (first, second))
    assert sources[0] == sources[1]

    results = _concurrently(
        lambda actor: actor.apply(sources[0]), (first, second))
    assert {result.status for result in results} <= {
        "applied", "confirmed", "noop", "retryable",
    }
    cold = RepositoryApplier(workspace, store)
    replay = run(cold.apply(sources[0]))
    assert replay.status == "noop"
    assert run(cold.store.get_bounded(sources[0], len(raw))) == raw


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
    source = _concurrently(
        lambda worker: worker.stage("member", raw), workers)[0]
    results = _concurrently(lambda worker: worker.apply(source), workers)

    assert {result.status for result in results} == {"rejected"}
    cold = RepositoryApplier(workspace, store)
    assert run(cold.apply(source)).status == "rejected"
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
    source = run(applier.stage("member", raw))
    assert run(applier.apply(source)).status == "applied"
    assert inner.get(source) == raw


def test_stale_worker_retains_source_then_rebases(tmp_path):
    node = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    first_fid = facts.content.message.post(
        node, workspace, "general", "first", ts=10)
    first_raw = closed_subset(node, workspace, (first_fid,))
    second_fid = facts.content.message.post(
        node, workspace, "general", "second", ts=11)
    second_raw = closed_subset(node, workspace, (second_fid,))
    expected = node.store(workspace).get("root")
    bucket = ScriptedBucket(seed=0xE1AC7)
    left = RepositoryApplier(workspace, bucket.handle("left"))
    right = RepositoryApplier(workspace, bucket.handle("right"))
    left_key = run(left.stage("left", first_raw))
    right_key = run(right.stage("right", second_raw))
    left_proposal = run(left.propose(left_key, h(first_raw), first_raw))
    right_proposal = run(right.propose(
        right_key, h(second_raw), second_raw))

    assert run(left.commit(
        left_key, h(first_raw), left_proposal)).status == "applied"
    assert run(right.commit(
        right_key, h(second_raw), right_proposal)).status == "retryable"
    assert bucket.handle("probe").get(right_key) == second_raw
    assert run(RepositoryApplier(
        workspace, bucket.handle("retry")).apply(right_key)).status \
        == "applied"
    assert bucket.handle("probe").get("root") == expected
    assert bucket.assert_valid_history()


def test_source_digest_mismatch_cannot_establish_objects_or_root(tmp_path):
    workspace, raw, _ = _message_pile(tmp_path / "source")
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))
    ingress.put_if_absent("exact", raw)

    result = run(RepositoryApplier(workspace, canonical).apply_exact(
        ingress, "exact", "0" * 64))

    assert result.status == "rejected"
    assert canonical.list("") == []
    assert ingress.get("exact") == raw


def test_missing_source_is_retryable_not_destructive(tmp_path):
    workspace, _, _ = _message_pile(tmp_path / "source")
    ingress = FsStore(str(tmp_path / "ingress"))
    canonical = FsStore(str(tmp_path / "canonical"))

    result = run(RepositoryApplier(workspace, canonical).apply_exact(
        ingress, "not-visible-yet", "0" * 64))

    assert result.status == "retryable"
    assert canonical.list("") == []
