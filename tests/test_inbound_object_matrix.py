"""One provider-neutral matrix for inbound canonical object outcomes."""
import asyncio
from dataclasses import dataclass

import facts
import pytest

from adapters.r2 import R2BindingStore
from adapters.s3 import S3Config, S3Store
from core.crypto import h
from core.object_store import (
    CREATED,
    EXISTS,
    OutcomeUnknown,
    RetryableStoreError,
)
from core.repository_applier import RepositoryApplier
from core.store import FsStore
from full_peer.node import FullPeer

from .provider_fakes import FakeR2Bucket, FakeS3Bucket, ProviderError
from .util import all_fids, closed_subset


WORKSPACE = "0" * 64


def run(awaitable):
    return asyncio.run(awaitable)


@dataclass
class _Provider:
    store: object
    corrupt: object
    fault: object


class _FsCreateFault:
    def __init__(self, store, fault):
        self.store, self.fault, self.attempts = store, fault, 0

    def __getattr__(self, name):
        return getattr(self.store, name)

    def put_if_absent(self, key, raw):
        self.attempts += 1
        if self.fault == "missing":
            return EXISTS
        if self.fault == "definite":
            raise RetryableStoreError("definite failure before create")
        if self.fault == "unknown-before":
            raise OutcomeUnknown("transport timeout before create")
        result = self.store.put_if_absent(key, raw)
        raise OutcomeUnknown(f"response lost after {result.value}")


class _S3CreateFault:
    def __init__(self, client, fault):
        self.client, self.fault, self.attempts = client, fault, 0

    def __getattr__(self, name):
        return getattr(self.client, name)

    def put_object(self, **request):
        self.attempts += 1
        if self.fault == "missing":
            raise ProviderError(412, "PreconditionFailed")
        if self.fault == "definite":
            raise ProviderError(429, "TooManyRequests")
        if self.fault == "unknown-before":
            raise ConnectionError("transport timeout before create")
        result = self.client.put_object(**request)
        raise ConnectionError("transport response lost after create")


class _R2Failure(Exception):
    status = 429


class _R2CreateFault:
    def __init__(self, bucket, fault):
        self.bucket, self.fault, self.attempts = bucket, fault, 0

    def __getattr__(self, name):
        return getattr(self.bucket, name)

    async def put(self, key, raw, **options):
        self.attempts += 1
        if self.fault == "missing":
            return None
        if self.fault == "definite":
            raise _R2Failure("definite failure before create")
        if self.fault == "unknown-before":
            raise ConnectionError("transport timeout before create")
        await self.bucket.put(key, raw, **options)
        raise ConnectionError("transport response lost after create")


def _provider(kind, directory):
    if kind == "fs":
        store = FsStore(str(directory))

        def corrupt(oid, raw):
            store._replace("obj/" + oid, raw)

        def fault(outcome):
            probe = _FsCreateFault(store, outcome)
            return probe, probe

        return _Provider(store, corrupt, fault)

    if kind == "s3":
        bucket = FakeS3Bucket()
        prefix = "tenant"
        config = S3Config(
            "canonical-bucket",
            prefix,
            read_total_max_attempts=1,
        )
        store = S3Store(config, client=bucket.client("applier"))

        def corrupt(oid, raw):
            key = f"{prefix}/obj/{oid}"
            with bucket.lock:
                bucket.data[key] = raw
                bucket.tokens[key] = bucket._etag(raw)

        def fault(outcome):
            probe = _S3CreateFault(bucket.client("applier"), outcome)
            return S3Store(config, client=probe), probe

        return _Provider(store, corrupt, fault)

    if kind == "r2":
        bucket = FakeR2Bucket()
        prefix = "tenant"
        store = R2BindingStore(bucket, prefix)

        def corrupt(oid, raw):
            key = f"{prefix}/obj/{oid}"
            bucket.data[key] = raw
            bucket.tokens[key] = bucket._etag(raw)

        def fault(outcome):
            probe = _R2CreateFault(bucket, outcome)
            return R2BindingStore(probe, prefix), probe

        return _Provider(store, corrupt, fault)

    raise AssertionError(kind)


_OBJECT_CASES = (
    "valid",
    "address-mismatch",
    "duplicate",
    "collision",
    "missing-after-exists",
    "definite-failure",
    "unknown-before-create",
    "unknown-after-create",
)


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
@pytest.mark.parametrize("case", _OBJECT_CASES)
def test_inbound_canonical_object_outcome_matrix(
        kind, case, tmp_path):
    provider = _provider(kind, tmp_path / kind)
    raw = b"one canonical inbound object"
    oid = h(raw)
    key = "obj/" + oid
    direct = RepositoryApplier(WORKSPACE, provider.store)

    if case == "valid":
        assert run(direct.admit_object(oid, raw)) is CREATED
    elif case == "address-mismatch":
        attempted = h(b"another object")
        with pytest.raises(ValueError, match="address"):
            run(direct.admit_object(attempted, raw))
        assert run(direct.store.get_bounded(
            "obj/" + attempted, len(raw))) is None
        assert run(direct.store.get_bounded(key, len(raw))) is None
        return
    elif case == "duplicate":
        assert run(direct.admit_object(oid, raw)) is CREATED
        assert run(direct.admit_object(oid, raw)) is EXISTS
    elif case == "collision":
        provider.corrupt(oid, b"wrong incumbent bytes")
        with pytest.raises(ValueError, match="conflict"):
            run(direct.admit_object(oid, raw))
        assert run(direct.store.get_bounded(key, len(raw))) != raw
        return
    else:
        fault = {
            "missing-after-exists": "missing",
            "definite-failure": "definite",
            "unknown-before-create": "unknown-before",
            "unknown-after-create": "unknown-after",
        }[case]
        fault_store, probe = provider.fault(fault)
        applier = RepositoryApplier(WORKSPACE, fault_store)
        if case == "missing-after-exists":
            with pytest.raises(ValueError, match="conflict"):
                run(applier.admit_object(oid, raw))
            assert probe.attempts == 1
        elif case == "definite-failure":
            with pytest.raises(RetryableStoreError):
                run(applier.admit_object(oid, raw))
            assert probe.attempts == 1
        elif case == "unknown-before-create":
            with pytest.raises(OutcomeUnknown):
                run(applier.admit_object(oid, raw))
            assert probe.attempts == 2
        else:
            assert run(applier.admit_object(oid, raw)) is EXISTS
            assert probe.attempts == 1

    expected = raw if case in {
        "valid", "duplicate", "unknown-after-create"} else None
    assert run(direct.store.get_bounded(key, len(raw))) == expected


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
    provider = _provider(kind, tmp_path / f"recipient-{kind}")
    first = RepositoryApplier(workspace, provider.store)
    second = RepositoryApplier(workspace, provider.store)

    base_source = run(first.stage("bootstrap", bootstrap))
    assert run(first.apply(base_source)).status == "applied"
    first_source = run(first.stage("first", first_raw))
    second_source = run(second.stage("second", second_raw))
    first_proposal = run(first.propose(first_source, first_raw))
    second_proposal = run(second.propose(second_source, second_raw))
    assert first_proposal.base_token == second_proposal.base_token

    assert run(first.commit(
        first_source, first_raw, first_proposal)).status == "applied"
    stale = run(second.commit(
        second_source, second_raw, second_proposal))

    assert stale.status == "stale"
    assert run(second.store.get_bounded(
        second_source, len(second_raw))) == second_raw
