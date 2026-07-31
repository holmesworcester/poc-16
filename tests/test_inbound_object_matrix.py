"""Provider-neutral repository-root CAS concurrency."""
import asyncio

import facts
import pytest

from adapters.r2 import R2BindingStore
from adapters.s3 import S3Config, S3Store
from core.repository_applier import RepositoryApplier
from core.store import FsStore
from full_peer.node import FullPeer

from .provider_fakes import FakeR2Bucket, FakeS3Bucket
from .util import all_fids, closed_subset


def run(awaitable):
    return asyncio.run(awaitable)


def _provider(kind, directory):
    if kind == "fs":
        return FsStore(str(directory))

    if kind == "s3":
        bucket = FakeS3Bucket()
        return S3Store(S3Config(
            "canonical-bucket",
            "tenant",
            read_total_max_attempts=1,
        ), client=bucket.client("applier"))

    if kind == "r2":
        return R2BindingStore(FakeR2Bucket(), "tenant")

    raise AssertionError(kind)


def _concurrent_piles(directory):
    author = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    bootstrap = closed_subset(
        author, workspace, all_fids(author, workspace))
    first = facts.content.message.post(
        author, workspace, "general", "first", ts=10)
    first_raw = closed_subset(author, workspace, [first])
    second = facts.content.message.post(
        author, workspace, "general", "second", ts=11)
    second_raw = closed_subset(author, workspace, [second])
    return workspace, bootstrap, first_raw, second_raw


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_stale_token_is_only_a_repository_root_commit_outcome(
        kind, tmp_path):
    workspace, bootstrap, first_raw, second_raw = _concurrent_piles(
        tmp_path / f"author-{kind}")
    store = _provider(kind, tmp_path / f"recipient-{kind}")
    first = RepositoryApplier(workspace, store)
    second = RepositoryApplier(workspace, store)

    base_source = run(first.stage("bootstrap", bootstrap))
    assert run(first.apply(base_source)).status == "applied"
    first_source = run(first.stage("first", first_raw))
    second_source = run(second.stage("second", second_raw))
    first_proposal = run(first.propose(
        first_source, h(first_raw), first_raw))
    second_proposal = run(second.propose(
        second_source, h(second_raw), second_raw))
    assert first_proposal.base_token == second_proposal.base_token

    assert run(first.commit(
        first_source, h(first_raw), first_proposal)).status == "applied"
    stale = run(second.commit(
        second_source, h(second_raw), second_proposal))

    assert stale.status == "retryable"
    assert run(second.store.get_bounded(
        second_source, len(second_raw))) == second_raw
