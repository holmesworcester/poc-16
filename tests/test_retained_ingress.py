"""Provider-enforced retention around the real hosted Applier entrypoints."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import threading

import facts
import pytest

from adapters.s3 import S3Config, S3Store
from core.crypto import h
from core.staged_intent import staging_key
from deploy.aws_repository_applier.app import apply_request
from deploy.aws_upload_broker.policy import presigner_policy
from deploy.aws_upload_broker.signer import S3UploadConfig
from deploy.cloudflare_upload.boundary import (
    Deployment,
    access_policies,
    ingress_lock,
)
from deploy.cloudflare_upload.worker.applier_runtime import apply as apply_r2
from deploy.repository_apply_wire import encode_apply_request
from full_peer.node import FullPeer

from .provider_fakes import (
    FakeR2Bucket,
    FakeS3Bucket,
    FakeS3Client,
    ProviderError,
)
from .util import all_fids, closed_subset


MEMBER = "b" * 16
SESSION = "c" * 32
AWS_BUCKET = "ingress"


def _pile(tmp_path):
    peer = FullPeer(str(tmp_path / "sender"))
    workspace = facts.auth.workspace.create(peer, "alice", ts=1)
    facts.content.message.post(
        peer, workspace, "general", "retained ingress", ts=2)
    raw = closed_subset(
        peer, workspace, all_fids(peer, workspace))
    marker = staging_key(
        workspace, MEMBER, SESSION, "pile", h(raw))
    return workspace, marker, raw


def _request(workspace, marker):
    return encode_apply_request(
        workspace, marker, marker.rsplit("/", 1)[-1])


class _RetainedS3Client(FakeS3Client):
    """The exact broker role: conditional PUT, never replace or DELETE."""

    def put_object(self, **request):
        if self.actor == "broker-parent" \
                and request.get("IfNoneMatch") != "*":
            raise ProviderError(403, "AccessDenied")
        return super().put_object(**request)

    def delete_object(self, **request):
        if self.actor == "broker-parent":
            raise ProviderError(403, "AccessDenied")
        return super().delete_object(**request)


class _RetainedS3Bucket(FakeS3Bucket):
    def client(self, actor):
        return _RetainedS3Client(self, actor)

    def lifecycle_delete(self, key):
        # The AWS deployment creates no ingress lifecycle rule.
        self._record("lifecycle", "retain", key, "not-configured")
        return False


def test_aws_parent_race_restart_and_teardown_preserve_acknowledged_marker(
        tmp_path):
    workspace, marker, raw = _pile(tmp_path)
    ingress_bucket = _RetainedS3Bucket()
    canonical_bucket = FakeS3Bucket()
    parent = ingress_bucket.client("broker-parent")
    expires_at, clock = 1_000, [1_000]
    began, finish = threading.Event(), threading.Event()
    began_at, completed_at = [], []

    def upload():
        began_at.append(clock[0])
        began.set()
        if not finish.wait(5):
            raise TimeoutError("delayed S3 upload was not released")
        parent.put_object(Key=marker, Body=raw, IfNoneMatch="*")
        completed_at.append(clock[0])

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(upload)
        assert began.wait(5)
        clock[0] = expires_at + 1
        finish.set()
        pending.result(5)
    assert began_at == [expires_at]
    assert completed_at == [expires_at + 1]
    canonical = S3Store(
        S3Config("canonical", f"workspaces/{workspace}"),
        client=canonical_bucket.client("applier"),
    )
    ingress = S3Store(
        S3Config("ingress"),
        client=ingress_bucket.client("applier"),
    )
    start = threading.Barrier(2)

    def attack():
        start.wait(5)
        denied = []
        for operation in (
                lambda: parent.put_object(
                    Key=marker, Body=b"replacement"),
                lambda: parent.delete_object(Key=marker)):
            with pytest.raises(ProviderError) as caught:
                operation()
            denied.append(
                caught.value.response["ResponseMetadata"]["HTTPStatusCode"])
        return tuple(denied)

    def apply():
        start.wait(5)
        return asyncio.run(apply_request(
            _request(workspace, marker),
            canonical=canonical, ingress=ingress,
            workspace=workspace,
        ))

    with ThreadPoolExecutor(max_workers=2) as pool:
        attacked = pool.submit(attack)
        applied = pool.submit(apply)
        assert attacked.result(10) == (403, 403)
        first = applied.result(10)

    assert first.status == "applied"
    assert ingress_bucket.data[marker] == raw
    assert not ingress_bucket.lifecycle_delete(marker)

    # Cold restart and stack teardown both leave the externally owned bucket.
    root = canonical.get("root")
    replay = asyncio.run(apply_request(
        _request(workspace, marker),
        canonical=canonical, ingress=ingress,
        workspace=workspace,
    ))
    assert replay.status == "noop"
    assert canonical.get("root") == root
    assert ingress_bucket.data[marker] == raw
    assert not any(
        event[1] == "delete" for event in ingress_bucket.history)

    policy = presigner_policy(
        S3UploadConfig(
            bucket="ingress",
            region_name="us-west-2",
            expected_bucket_owner=None,
            ttl_seconds=60,
        ),
        workspace,
    )
    statement = policy["Statement"][0]
    assert statement["Action"] == "s3:PutObject"
    assert statement["Condition"]["Null"] == {
        "s3:if-none-match": "false"}


class _LockedR2Bucket(FakeR2Bucket):
    """R2's broad parent behind one provider-enforced prefix lock."""

    def __init__(self, prefix):
        super().__init__()
        self.locked_prefix = prefix

    def _locked(self, key):
        return key.startswith(self.locked_prefix)

    async def put(self, key, value, **options):
        if self._locked(key) and key in self.data:
            self.history.append(("lock-deny-put", key))
            raise ProviderError(403, "ObjectLocked")
        return await super().put(key, value, **options)

    async def delete(self, key):
        if self._locked(key):
            self.history.append(("lock-deny-delete", key))
            raise ProviderError(403, "ObjectLocked")
        await super().delete(key)

    async def lifecycle_delete(self, key):
        try:
            await self.delete(key)
        except ProviderError:
            return False
        return True


def _r2_deployment(workspace):
    return Deployment(
        account_id="a" * 32,
        workspace=workspace,
        canonical_bucket="canonical",
        ingress_bucket="ingress",
        owner="retained-ingress-test",
        broker_name="upload-broker",
        applier_name="repository-applier",
        read_permission_group_id="c" * 32,
        write_permission_group_id="d" * 32,
    )


def test_r2_lock_defeats_broad_parent_race_lifecycle_and_cold_restart(
        tmp_path):
    workspace, marker, raw = _pile(tmp_path)
    deployment = _r2_deployment(workspace)
    rule = ingress_lock(deployment)["rules"][0]
    ingress_bucket = _LockedR2Bucket(rule["prefix"])
    canonical_bucket = FakeR2Bucket()

    async def history():
        expires_at, clock = 1_000, [1_000]
        began, finish = asyncio.Event(), asyncio.Event()
        began_at, completed_at = [], []

        async def upload():
            began_at.append(clock[0])
            began.set()
            await finish.wait()
            await ingress_bucket.put(
                marker, raw, onlyIf={"If-None-Match": "*"})
            completed_at.append(clock[0])

        pending = asyncio.create_task(upload())
        await began.wait()
        clock[0] = expires_at + 1
        finish.set()
        await pending
        assert began_at == [expires_at]
        assert completed_at == [expires_at + 1]
        env = SimpleNamespace(
            POC16_DEPLOYMENT_ROLE="applier",
            WORKSPACE=workspace,
            CANONICAL_PREFIX=f"workspaces/{workspace}",
            INGRESS_PREFIX=deployment.ingress_prefix,
            CANONICAL=canonical_bucket,
            INGRESS=ingress_bucket,
        )
        start = asyncio.Event()

        async def attack():
            await start.wait()
            denied = []
            for operation in (
                    ingress_bucket.put(marker, b"replacement"),
                    ingress_bucket.delete(marker)):
                with pytest.raises(ProviderError) as caught:
                    await operation
                denied.append(
                    caught.value.response[
                        "ResponseMetadata"]["HTTPStatusCode"])
            return tuple(denied)

        async def apply():
            start.set()
            return await apply_r2(env, marker, h(raw))

        denied, result = await asyncio.gather(
            attack(), apply())
        assert denied == (403, 403)
        assert result.status == "applied"
        assert ingress_bucket.data[marker] == raw
        assert not await ingress_bucket.lifecycle_delete(marker)

        root = canonical_bucket.data[
            f"workspaces/{workspace}/root"]
        replay = await apply_r2(env, marker, h(raw))
        assert replay.status == "noop"
        assert canonical_bucket.data[
            f"workspaces/{workspace}/root"] == root
        assert ingress_bucket.data[marker] == raw

    asyncio.run(history())

    # The parent remains broad; the independent lock is the enforcement.
    parent = access_policies(deployment)["broker_ingress_parent"]
    assert parent["policies"][0]["permission_groups"][0]["name"].endswith(
        "Item Write")
    assert rule["condition"] == {"type": "Indefinite"}
    assert not any(
        event[0] == "delete" for event in ingress_bucket.history)
