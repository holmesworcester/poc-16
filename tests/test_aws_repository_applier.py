"""AWS events are hints into the one provider-neutral repository applier."""
import asyncio
from pathlib import Path
import re
import sqlite3

import facts
import pytest

from adapters.s3 import S3Config, S3Store
from core import indexes, snapshot
from full_peer import bao_native as bao
from core.close import decode_pile
from core.crypto import h
from full_peer.node import FullPeer
from core.repository_applier import RepositoryApplier
from core.repository_reader import RepositoryReader
from core.staged_intent import staging_key
from core.store import FsStore
from deploy.aws_repository_applier.app import drain
from deploy.aws_repository_applier import manage
from facts.content import chunk

from .util import closed_subset, send_bytes
from .provider_fakes import FakeS3Bucket, ProviderError


SESSION = "a" * 32
MEMBER = "b" * 16


def _stage_file(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
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


def test_sam_role_limits_canonical_missing_key_probes():
    raw = (
        Path(__file__).parents[1]
        / "deploy/aws_repository_applier/template.yaml"
    ).read_text()
    probe = raw.split(
        "- Sid: DistinguishMissingCanonicalKeys", 1)[1].split(
        "- Sid: DiscoverStagedPileMarkers", 1)[0]

    assert "Action: s3:ListBucket" in probe
    assert "CanonicalBucketName" in probe
    assert "ExpectedBucketOwner" in probe
    assert "CanonicalPrefix}/root" in probe
    assert "CanonicalPrefix}/obj/*" in probe
    assert "CanonicalPrefix}/applier/*" in probe
    assert "CanonicalPrefix}/staged/*" in probe
    assert "s3:max-keys: 1" in probe
    for forbidden in (
            "CanonicalPrefix}/pile",
            "CanonicalPrefix}/failed",
            "IngressBucketName",
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject"):
        assert forbidden not in probe


def test_sam_role_grants_only_required_operational_cursor_authority():
    raw = (
        Path(__file__).parents[1]
        / "deploy/aws_repository_applier/template.yaml"
    ).read_text()
    read = raw.split(
        "- Sid: ReadCanonicalRepository", 1)[1].split(
        "- Sid: ReadIsolatedIngress", 1)[0]
    write = raw.split(
        "- Sid: ConditionallyWriteCanonicalRepository", 1)[1].split(
        "- Sid: RetireOnlyInternalPileGenerations", 1)[0]
    delete = raw.split(
        "- Sid: RetireOnlyInternalPileGenerations", 1)[1].split(
        "- !If", 1)[0]

    assert "Action:\n                  - s3:GetObject" in read
    assert "CanonicalPrefix}/applier/*" in read
    assert "Action: s3:PutObject" in write
    assert "CanonicalPrefix}/applier/*" in write
    assert "CanonicalPrefix}/applier/*" not in delete


def test_sam_role_limits_ingress_missing_probe_to_detached_objects():
    raw = (
        Path(__file__).parents[1]
        / "deploy/aws_repository_applier/template.yaml"
    ).read_text()
    probe = raw.split(
        "- Sid: DistinguishMissingIngressObjects", 1)[1].split(
        "- Sid: ReadCanonicalRepository", 1)[0]

    assert "Action: s3:ListBucket" in probe
    assert "IngressBucketName" in probe
    assert "ExpectedBucketOwner" in probe
    assert "ingress/v1/workspaces/${WorkspaceId}/objects/*" in probe
    assert "s3:max-keys: 1" in probe
    for forbidden in (
            "CanonicalBucketName",
            "/piles/*",
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject"):
        assert forbidden not in probe


def test_real_s3_adapters_keep_ingress_and_canonical_prefixes_disjoint(
        tmp_path):
    source = FullPeer(str(tmp_path / "source"))
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


def test_403_missing_root_probe_bootstraps_repository_genesis(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    raw = closed_subset(
        source, workspace,
        [fact.fid for fact in source.by_type(workspace, "workspace")],
    )
    bucket = FakeS3Bucket()
    bucket.deny_missing_get = True
    prefix = f"workspaces/{workspace}"
    canonical = S3Store(
        S3Config(
            "canonical-bucket",
            prefix,
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
            probe_access_denied_missing=True,
        ),
        client=bucket.client("applier"),
    )

    applier = RepositoryApplier(workspace, canonical)
    internal = asyncio.run(applier.stage(MEMBER, raw))
    result = asyncio.run(applier.apply(internal))

    assert result.status == "applied"
    assert bucket.data[prefix + "/root"] == result.root
    assert (
        "applier", "list", prefix + "/root", ()
    ) in bucket.history


def test_403_missing_validated_map_page_uses_exact_probe_not_access_denied(
        tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    raw = closed_subset(
        source, workspace,
        [fact.fid for fact in source.by_type(workspace, "workspace")],
    )
    bucket = FakeS3Bucket()
    bucket.deny_missing_get = True
    prefix = f"workspaces/{workspace}"
    canonical = S3Store(
        S3Config(
            "canonical-bucket",
            prefix,
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
            probe_access_denied_missing=True,
        ),
        client=bucket.client("applier"),
    )
    applier = RepositoryApplier(workspace, canonical)
    internal = asyncio.run(applier.stage(MEMBER, raw))
    assert asyncio.run(applier.apply(internal)).status == "applied"
    root = snapshot.decode_root(bucket.data[prefix + "/root"])
    missing = prefix + "/obj/" + root.maps[indexes.FACT]["root"]
    bucket.data.pop(missing)
    bucket.tokens.pop(missing)
    bucket.history.clear()
    probe = asyncio.run(
        RepositoryApplier(workspace, canonical).stage("probe", raw))
    bucket.history.clear()

    with pytest.raises(ValueError, match="integrity"):
        asyncio.run(
            RepositoryApplier(
                workspace, canonical).propose(probe, raw))

    probes = [
        key for _, operation, key, result in bucket.history
        if operation == "list" and result == ()
        and "/obj/" in key
    ]
    assert probes == [missing]


def test_403_missing_operational_cursors_do_not_wedge_cold_discovery(
        tmp_path):
    workspace = "c" * 64
    bucket = FakeS3Bucket()
    bucket.deny_missing_get = True
    prefix = f"workspaces/{workspace}"
    canonical = S3Store(
        S3Config(
            "canonical-bucket",
            prefix,
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
            probe_access_denied_missing=True,
        ),
        client=bucket.client("applier"),
    )
    applier = RepositoryApplier(workspace, canonical)

    assert asyncio.run(applier.turn()) == ()
    assert asyncio.run(applier.drain_staged(
        FsStore(str(tmp_path / "empty-ingress")))) == ()

    cursor_keys = {
        prefix + "/applier/cursor/internal",
        prefix + "/applier/cursor/staged",
    }
    assert cursor_keys <= set(bucket.data)
    probes = {
        key for _, operation, key, result in bucket.history
        if operation == "list" and result == () and key in cursor_keys
    }
    assert probes == cursor_keys
    assert {
        key for _, operation, key, _ in bucket.history
        if operation == "put" and key in cursor_keys
    } == cursor_keys


def test_403_missing_ingress_object_is_bounded_unavailable_work(
        tmp_path):
    _, workspace, staged, marker, refs = _stage_file(tmp_path)
    bucket = FakeS3Bucket()
    raw = staged.get(marker)
    ingress = S3Store(
        S3Config(
            "isolated-ingress",
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
            probe_access_denied_missing=True,
        ),
        client=bucket.client("applier"),
    )
    ingress.put_if_absent(marker, raw)
    bucket.deny_missing_get = True
    canonical = FsStore(str(tmp_path / "canonical-missing-object"))

    outcomes = asyncio.run(
        RepositoryApplier(workspace, canonical).drain_staged(ingress))

    result = outcomes[0][1]
    expected = {
        staging_key(workspace, MEMBER, SESSION, "obj", oid)
        for oid in refs
    }
    assert result.result.status == "applied"
    assert set(result.unavailable) == expected
    probes = {
        key for _, operation, key, values in bucket.history
        if operation == "list" and values == ()
        and key.startswith(
            f"ingress/v1/workspaces/{workspace}/objects/")
    }
    assert probes == expected


def test_cold_staged_apply_obeys_probe_prefixes_from_sam_policy(
        tmp_path):
    _, workspace, ingress, marker, _ = _stage_file(tmp_path)
    raw_template = (
        Path(__file__).parents[1]
        / "deploy/aws_repository_applier/template.yaml"
    ).read_text()
    probe = raw_template.split(
        "- Sid: DistinguishMissingCanonicalKeys", 1)[1].split(
        "- Sid: DiscoverStagedPileMarkers", 1)[0]
    suffixes = re.findall(
        r'\$\{CanonicalPrefix\}(/[^"]+)"', probe)
    prefix = f"workspaces/{workspace}"

    bucket = FakeS3Bucket()
    bucket.deny_missing_get = True
    inner = bucket.client("applier")

    def allowed(physical):
        return physical.startswith(prefix + "/pile/") or any(
            re.fullmatch(
                re.escape(prefix + suffix).replace(r"\*", ".*"),
                physical,
            )
            for suffix in suffixes)

    class PolicyClient:
        def __getattr__(self, name):
            return getattr(inner, name)

        def list_objects_v2(self, **request):
            physical = request["Prefix"]
            if request.get("MaxKeys") != 1 or not allowed(physical):
                raise ProviderError(403, "AccessDenied")
            return inner.list_objects_v2(**request)

    canonical = S3Store(
        S3Config(
            "canonical-bucket",
            prefix,
            expected_bucket_owner="123456789012",
            read_total_max_attempts=1,
            probe_access_denied_missing=True,
        ),
        client=PolicyClient(),
    )

    result = asyncio.run(
        RepositoryApplier(workspace, canonical).apply_staged(
            ingress, marker))

    assert result.result.status == "applied"
    probes = [
        key for _, operation, key, values in bucket.history
        if operation == "list" and values == ()
    ]
    assert any(key.startswith(prefix + "/staged/") for key in probes)
    assert all(allowed(key) for key in probes)
