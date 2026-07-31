"""AWS invokes the shared applier with exact immutable S3 addresses."""
import asyncio
from pathlib import Path
import sqlite3

import facts
import pytest

from adapters.s3 import S3Config, S3Store
from core.crypto import h
from core.object_store import ensure_object_async
from core.repository_applier import RepositoryApplier, async_store
from core.repository_reader import RepositoryReader
from core.staged_intent import staging_key
from core.store import FsStore
from deploy.aws_repository_applier import app, manage
from deploy.aws_repository_applier.app import apply_request
from deploy.repository_apply_wire import (
    APPLY_REQUEST_SCHEMA,
    APPLY_RESULT_SCHEMA,
    MAX_APPLY_KEY_BYTES,
    decode_apply_result,
    encode_apply_request,
)
from full_peer.node import FullPeer

from .provider_fakes import FakeS3Bucket, ProviderError
from .util import all_fids, closed_subset


SESSION = "a" * 32
MEMBER = "b" * 16
BUCKET = "isolated-ingress"


def _stage(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    facts.content.message.post(
        source, workspace, "general", "provider applier", ts=10)
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    ingress = FsStore(str(tmp_path / "ingress"))
    key = staging_key(workspace, MEMBER, SESSION, "pile", h(raw))
    ingress.put_if_absent(key, raw)
    return source, workspace, ingress, key, raw


def _request(workspace, key, *, digest=None):
    return encode_apply_request(
        workspace,
        key,
        key.rsplit("/", 1)[-1] if digest is None else digest,
    )


def test_exact_lambda_event_is_database_free_reader_visible_and_retained(
        tmp_path, monkeypatch):
    source, workspace, ingress, key, raw = _stage(tmp_path)
    canonical = FsStore(str(tmp_path / "canonical"))
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *_args, **_kwargs: pytest.fail("Lambda opened SQLite"),
    )

    result = asyncio.run(apply_request(
        _request(workspace, key),
        canonical=canonical,
        ingress=ingress,
        workspace=workspace,
    ))

    assert result.status == "applied"
    assert ingress.get(key) == raw
    reader = RepositoryReader(
        workspace,
        canonical.get("root"),
        lambda oid: canonical.get("obj/" + oid),
    )
    assert reader.root_bytes == source.reader(workspace).root_bytes


def test_exact_private_invocation_replays_as_noop(tmp_path):
    _, workspace, ingress, key, _ = _stage(tmp_path)
    canonical = FsStore(str(tmp_path / "canonical"))
    request = _request(workspace, key)
    first = asyncio.run(apply_request(
        request, canonical=canonical, ingress=ingress,
        workspace=workspace))
    root = canonical.get("root")
    replay = asyncio.run(apply_request(
        request, canonical=canonical, ingress=ingress,
        workspace=workspace))

    assert first.status == "applied"
    assert replay.status == "noop"
    assert canonical.get("root") == root


@pytest.mark.parametrize("bad", (
    {},
    {"Records": []},
    {"workspace": "wrong", "key": "key", "digest": "0" * 64},
    {"workspace": "WORKSPACE", "key": "KEY", "digest": "f" * 64},
))
def test_malformed_or_misbound_private_invocation_fails_closed(
        bad, tmp_path):
    _, workspace, ingress, key, _ = _stage(tmp_path)
    canonical = FsStore(str(tmp_path / "canonical"))
    request = {
        name: workspace if value == "WORKSPACE" else key
        if value == "KEY" else value
        for name, value in bad.items()
    }

    with pytest.raises(ValueError, match="request|binding"):
        asyncio.run(apply_request(
            request, canonical=canonical, ingress=ingress,
            workspace=workspace))
    assert canonical.list("") == []


def test_private_invocation_cannot_fall_back_to_list(tmp_path):
    _, workspace, ingress, _, _ = _stage(tmp_path)
    canonical = FsStore(str(tmp_path / "canonical"))
    with pytest.raises(ValueError, match="request"):
        asyncio.run(apply_request(
            {}, canonical=canonical, ingress=ingress,
            workspace=workspace))
    assert canonical.list("") == []


def test_lambda_stage_contains_only_db_free_applier_authority(tmp_path):
    staged = manage.stage(tmp_path / "stage")
    for relative in (
            "core/repository_applier.py",
            "core/repository_snapshot.py",
            "deploy/repository_apply_wire.py",
            "deploy/aws_repository_applier/app.py",
            "adapters/s3/store.py",
            "facts/auth/workspace.py"):
        assert (staged / relative).is_file()
    for forbidden in (
            "core/admission.py",
            "core/catalog.py",
            "core/client_projection.py",
            "core/node.py",
            "core/pile_sender.py",
            "core/publication.py",
            "core/runtime.py"):
        assert not (staged / forbidden).exists()


def test_sam_role_has_exact_get_conditional_put_and_no_discovery_or_delete():
    raw = (
        Path(__file__).parents[1]
        / "deploy/aws_repository_applier/template.yaml"
    ).read_text()
    assert "deploy.aws_repository_applier.app.handler" in raw
    assert "s3:GetObject" in raw
    assert "s3:PutObject" in raw
    assert "${CanonicalPrefix}/root" in raw
    assert "${CanonicalPrefix}/obj/*" in raw
    assert (
        "ingress/v1/workspaces/${WorkspaceId}/piles/*" in raw)
    for forbidden in (
            "s3:ListBucket", "s3:DeleteObject", "ScheduleV2",
            "AWS::SQS", "/objects/*", "/failed/*", "/staged/*",
            "/applier/*", "${CanonicalPrefix}/pile/*"):
        assert forbidden not in raw


def _s3_store(bucket, name, prefix=""):
    return S3Store(
        S3Config(
            name,
            prefix,
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
            access_denied_is_absent=True,
        ),
        client=bucket.client("applier"),
    )


def test_real_s3_adapters_keep_exact_ingress_and_canonical_disjoint(
        tmp_path):
    _, workspace, _, key, raw = _stage(tmp_path)
    canonical_bucket, ingress_bucket = FakeS3Bucket(), FakeS3Bucket()
    canonical = _s3_store(
        canonical_bucket, "canonical-bucket", f"workspaces/{workspace}")
    ingress = _s3_store(ingress_bucket, BUCKET)
    ingress.put_if_absent(key, raw)

    result = asyncio.run(apply_request(
        _request(workspace, key), canonical=canonical, ingress=ingress,
        workspace=workspace))

    assert result.status == "applied"
    assert f"workspaces/{workspace}/root" in canonical_bucket.data
    assert key in ingress_bucket.data
    assert not any(
        operation in {"list", "delete"}
        for _, operation, _, _ in (
            canonical_bucket.history + ingress_bucket.history))


def test_missing_403_bootstraps_without_list(tmp_path):
    _, workspace, _, key, raw = _stage(tmp_path)
    canonical_bucket, ingress_bucket = FakeS3Bucket(), FakeS3Bucket()
    canonical_bucket.deny_missing_get = True
    canonical = _s3_store(
        canonical_bucket, "canonical-bucket", f"workspaces/{workspace}")
    ingress = _s3_store(ingress_bucket, BUCKET)
    ingress.put_if_absent(key, raw)

    result = asyncio.run(apply_request(
        _request(workspace, key), canonical=canonical, ingress=ingress,
        workspace=workspace))

    assert result.status == "applied"
    assert not any(
        operation == "list"
        for _, operation, _, _ in canonical_bucket.history)


def test_existing_but_unreadable_root_cannot_be_overwritten(tmp_path):
    _, workspace, _, key, raw = _stage(tmp_path)
    bucket = FakeS3Bucket()
    prefix = f"workspaces/{workspace}"
    incumbent = b"an existing opaque root"
    base = bucket.client("seed")
    base.put_object(
        Bucket="canonical-bucket",
        Key=prefix + "/root",
        Body=incumbent,
        IfNoneMatch="*",
    )

    class DenyRootRead:
        def __getattr__(self, name):
            return getattr(base, name)

        def get_object(self, **request):
            if request["Key"] == prefix + "/root":
                raise ProviderError(403, "AccessDenied")
            return base.get_object(**request)

    canonical = S3Store(
        S3Config(
            "canonical-bucket", prefix,
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
            access_denied_is_absent=True,
        ),
        client=DenyRootRead(),
    )
    ingress = FsStore(str(tmp_path / "ingress"))
    ingress.put_if_absent(key, raw)

    result = asyncio.run(RepositoryApplier(
        workspace, canonical).apply_exact(ingress, key, h(raw)))

    assert result.status == "retryable"
    assert bucket.data[prefix + "/root"] == incumbent


def test_existing_but_unreadable_immutable_never_confirms_equality():
    workspace = "a" * 64
    raw, oid = b"incumbent", h(b"incumbent")
    bucket = FakeS3Bucket()
    base = bucket.client("seed")
    base.put_object(
        Bucket="canonical-bucket",
        Key=f"workspaces/{workspace}/obj/{oid}",
        Body=raw,
        IfNoneMatch="*",
    )

    class DenyReads:
        def __getattr__(self, name):
            return getattr(base, name)

        @staticmethod
        def get_object(**_request):
            raise ProviderError(403, "AccessDenied")

    store = S3Store(
        S3Config(
            "canonical-bucket", f"workspaces/{workspace}",
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
            access_denied_is_absent=True,
        ),
        client=DenyReads(),
    )
    with pytest.raises(ValueError, match="conflict"):
        asyncio.run(ensure_object_async(async_store(store), oid, raw))


def test_lambda_handler_returns_retryable_exact_result(monkeypatch):
    async def retryable(_event):
        return type("Result", (), {
            "admitted": (),
            "root": None,
            "status": "retryable",
        })()

    monkeypatch.setattr(app, "apply_request", retryable)
    assert app.handler({}, None) == {
        "schema": APPLY_RESULT_SCHEMA, "status": "retryable"}


@pytest.mark.parametrize(("internal", "public"), (
    ("applied", "applied"),
    ("confirmed", "applied"),
    ("admitted", "applied"),
    ("noop", "noop"),
    ("rootless", "noop"),
    ("rejected", "rejected"),
    ("retryable", "retryable"),
))
def test_private_apply_result_has_one_small_provider_shape(
        internal, public, monkeypatch):
    async def outcome(_event):
        return type("Result", (), {"status": internal})()

    monkeypatch.setattr(app, "apply_request", outcome)
    document = app.handler({}, None)
    assert document == {
        "schema": "poc16-repository-apply-result-v1",
        "status": public,
    }
    assert decode_apply_result(document) == public
    assert set(document) == {"schema", "status"}
    assert APPLY_REQUEST_SCHEMA == "poc16-repository-apply-v1"


@pytest.mark.parametrize("value", (
    None,
    {},
    {"schema": APPLY_RESULT_SCHEMA, "status": "confirmed"},
    {"schema": "wrong", "status": "applied"},
    {"schema": APPLY_RESULT_SCHEMA, "status": "applied", "extra": 1},
))
def test_private_apply_result_decoder_rejects_every_noncanonical_shape(value):
    with pytest.raises(ValueError, match="apply result"):
        decode_apply_result(value)


def test_private_apply_request_has_an_explicit_provider_key_bound():
    workspace, digest = "a" * 64, "b" * 64
    assert encode_apply_request(
        workspace, "k" * MAX_APPLY_KEY_BYTES, digest)["key"] \
        == "k" * MAX_APPLY_KEY_BYTES
    for key in ("k" * (MAX_APPLY_KEY_BYTES + 1), "snowman-☃"):
        with pytest.raises(ValueError, match="apply request"):
            encode_apply_request(workspace, key, digest)
