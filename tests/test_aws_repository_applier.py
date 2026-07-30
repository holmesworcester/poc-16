"""AWS events are hints into the one provider-neutral repository applier."""
import asyncio
from pathlib import Path
import sqlite3

import facts

from adapters.s3 import S3Config, S3Store
from core import bao
from core.close import decode_pile
from core.crypto import h
from core.node import Node
from core.repository_applier import RepositoryApplier
from core.repository_reader import RepositoryReader
from core.staged_intent import staging_key
from core.store import FsStore
from deploy.aws_repository_applier.app import drain
from deploy.aws_repository_applier import manage
from facts.content import chunk

from .util import closed_subset, send_bytes
from .provider_fakes import FakeS3Bucket


SESSION = "a" * 32
MEMBER = "b" * 16


def _stage_file(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    send_bytes(
        source,
        workspace,
        "provider.bin",
        b"provider-applier" * (bao.WIDTH // 8),
        ts=10,
    )
    fids = tuple(
        fact.fid for fact in source.by_type(workspace, chunk.TAG))
    raw = closed_subset(source, workspace, fids)
    stream = decode_pile(raw, workspace)
    ingress = FsStore(str(tmp_path / "ingress"))
    marker = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))
    ingress.put_if_absent(marker, raw)
    refs = sorted({
        oid for fact in stream
        for oid in facts.blob_refs(fact)
    })
    for oid in refs:
        ingress.put_if_absent(
            staging_key(workspace, MEMBER, SESSION, "obj", oid),
            source.store(workspace).get("obj/" + oid),
        )
    return source, workspace, ingress, marker, refs


def test_scheduled_lambda_drain_is_database_free_and_reader_visible(
        tmp_path, monkeypatch):
    _, workspace, ingress, marker, refs = _stage_file(tmp_path)
    canonical = FsStore(str(tmp_path / "canonical"))

    monkeypatch.setattr(
        sqlite3, "connect",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("hosted applier touched SQLite")),
    )
    outcomes = asyncio.run(drain(
        {}, canonical=canonical, ingress=ingress,
        workspace=workspace,
    ))

    assert outcomes.internal == ()
    assert [key for key, _ in outcomes.staged] == [marker]
    staged = outcomes.staged[0][1]
    assert staged.result.status == "applied"
    assert staged.result.retired is True
    assert set(staged.promoted) == set(refs)
    reader = RepositoryReader(
        workspace,
        canonical.get("root"),
        lambda oid: canonical.get("obj/" + oid),
    )
    assert reader.worker().fact_active(workspace)
    assert ingress.get(marker) is not None


def test_duplicate_s3_notifications_replay_as_safe_noops(
        tmp_path, monkeypatch):
    _, workspace, ingress, marker, _ = _stage_file(tmp_path)
    canonical = FsStore(str(tmp_path / "canonical"))
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_INGRESS_BUCKET", "isolated-ingress")
    event = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "isolated-ingress"},
                    "object": {"key": marker},
                },
            },
            {
                "s3": {
                    "bucket": {"name": "isolated-ingress"},
                    "object": {"key": marker},
                },
            },
        ],
    }

    first = asyncio.run(drain(
        event, canonical=canonical, ingress=ingress,
        workspace=workspace,
    ))
    root = canonical.get("root")
    replay = asyncio.run(drain(
        event, canonical=canonical, ingress=ingress,
        workspace=workspace,
    ))

    assert len(first.staged) == 1
    assert first.staged[0][1].result.status == "applied"
    assert len(replay.staged) == 1
    assert replay.staged[0][1].result.status == "admitted"
    assert canonical.get("root") == root
    assert not canonical.list("pile/")


def test_internal_retry_precedes_staging_and_bad_hint_does_not_wedge_batch(
        tmp_path, monkeypatch):
    _, workspace, ingress, marker, _ = _stage_file(tmp_path)
    canonical = FsStore(str(tmp_path / "canonical"))
    raw = ingress.get(marker)
    internal = asyncio.run(
        RepositoryApplier(workspace, canonical).stage(MEMBER, raw))
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_INGRESS_BUCKET", "isolated-ingress")
    event = {
        "Records": [
            {"not": "an s3 notification"},
            {
                "s3": {
                    "bucket": {"name": "isolated-ingress"},
                    "object": {"key": marker},
                },
            },
        ],
    }

    result = asyncio.run(drain(
        event, canonical=canonical, ingress=ingress,
        workspace=workspace,
    ))

    assert result.rejected_hints == 1
    assert [item.result.status for item in result.internal] == ["applied"]
    assert result.staged[0][1].result.status == "noop"
    assert canonical.get(internal) is None
    assert not canonical.list("pile/")


def test_lambda_stage_contains_only_db_free_applier_authority(
        tmp_path):
    staged = manage.stage(tmp_path / "stage")

    for relative in (
            "core/repository_applier.py",
            "core/repository_snapshot.py",
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


def test_sam_role_can_retire_only_internal_piles():
    raw = (
        Path(__file__).parents[1]
        / "deploy/aws_repository_applier/template.yaml"
    ).read_text()

    assert "deploy.aws_repository_applier.app.handler" in raw
    assert 'ScheduleExpression: "rate(1 minute)"' in raw
    assert "RetireOnlyInternalPileGenerations" in raw
    delete_section = raw.split(
        "RetireOnlyInternalPileGenerations", 1)[1].split(
        "- !If", 1)[0]
    assert "CanonicalPrefix}/pile/*" in delete_section
    assert "IngressBucketName" not in delete_section
    assert "CanonicalPrefix}/root" not in delete_section


def test_real_s3_adapters_keep_ingress_and_canonical_prefixes_disjoint(
        tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    facts.content.message.post(source, workspace, "general", "S3 adapter", ts=2)
    raw = closed_subset(
        source,
        workspace,
        [fact.fid for fact in source.by_type(workspace, "msg")],
    )
    marker = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))
    canonical_bucket, ingress_bucket = FakeS3Bucket(), FakeS3Bucket()
    canonical = S3Store(
        S3Config(
            "canonical-bucket",
            f"workspaces/{workspace}",
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
        ),
        client=canonical_bucket.client("applier"),
    )
    ingress = S3Store(
        S3Config(
            "isolated-ingress",
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
        ),
        client=ingress_bucket.client("applier"),
    )
    ingress.put_if_absent(marker, raw)

    result = asyncio.run(drain(
        {}, canonical=canonical, ingress=ingress,
        workspace=workspace,
    ))

    assert result.staged[0][1].result.status == "applied"
    assert f"workspaces/{workspace}/root" in canonical_bucket.data
    assert marker in ingress_bucket.data
    assert not any(
        key.startswith("ingress/")
        for key in canonical_bucket.data)
    assert not any(
        key.startswith(f"workspaces/{workspace}/")
        for key in ingress_bucket.data)
