"""Cloudflare invokes the shared applier with one exact R2 address."""
import asyncio
import ast
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import facts
import pytest

from core.close import encode_pile
from core.crypto import h, load_sk
from core.limits import MAX_HOSTED_SUBREQUESTS
from core.object_store import MAX_STORE_PREFIX_BYTES
from core.repository_reader import RepositoryReader
from core.ingress import ingress_key
from deploy.cloudflare_upload.worker import applier_runtime
from deploy.cloudflare_upload.worker.applier_runtime import apply
from facts.auth.signature import signature
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message
from full_peer.node import FullPeer

from .test_r2_worker_store import Bucket
from .util import all_fids, closed_subset


def _env(workspace, canonical, ingress):
    return SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="applier",
        WORKSPACE=workspace,
        CANONICAL_PREFIX=f"workspaces/{workspace}",
        INGRESS_PREFIX=f"ingress/v1/workspaces/{workspace}",
        CANONICAL=canonical,
        INGRESS=ingress,
    )


def _put(bucket, key, raw):
    bucket.data[key] = raw
    bucket.etags[key] = bucket._token()


def test_runtime_rejects_canonical_prefix_one_byte_over_provider_budget():
    workspace = "a" * 64
    canonical, ingress = Bucket(), Bucket()
    exact = _env(workspace, canonical, ingress)
    exact.CANONICAL_PREFIX = "a" * MAX_STORE_PREFIX_BYTES
    assert applier_runtime.Settings.from_env(exact).canonical_prefix \
        == exact.CANONICAL_PREFIX

    oversized = _env(workspace, canonical, ingress)
    oversized.CANONICAL_PREFIX = "a" * (MAX_STORE_PREFIX_BYTES + 1)
    with pytest.raises(ValueError, match="CANONICAL_PREFIX"):
        applier_runtime.Settings.from_env(oversized)


def test_exact_r2_rpc_applies_and_replays_without_sql_list_or_delete(
        tmp_path, monkeypatch):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    facts.content.message.post(
        source, workspace, "general", "through R2", ts=10)
    raw = closed_subset(source, workspace, all_fids(source, workspace))
    key = ingress_key(
        workspace, "c" * 32, "b" * 64, h(raw))
    canonical, ingress = Bucket(), Bucket()
    _put(ingress, key, raw)
    env = _env(workspace, canonical, ingress)

    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *_args, **_kwargs: pytest.fail("R2 applier opened SQLite"),
    )
    first = asyncio.run(apply(env, key, h(raw)))
    assert first.status == "applied"
    assert ingress.data[key] == raw
    assert not any(call[0] in {"list", "delete"} for call in ingress.calls)
    assert not any(call[0] in {"list", "delete"} for call in canonical.calls)

    root = canonical.data[f"workspaces/{workspace}/root"]
    reader = RepositoryReader(
        workspace,
        root,
        lambda oid: canonical.data.get(
            f"workspaces/{workspace}/obj/{oid}"),
    )
    assert reader.worker().fact_active(workspace)
    replay = asyncio.run(apply(env, key, h(raw)))
    assert replay.status == "noop"
    assert canonical.data[f"workspaces/{workspace}/root"] == root


@pytest.mark.parametrize("fault", ("foreign", "nonpile", "digest"))
def test_rpc_rejects_unbound_address_before_r2_read(fault):
    workspace = "a" * 64
    raw = b"pile"
    key = ingress_key(
        workspace, "c" * 32, "b" * 64, h(raw))
    digest = h(raw)
    if fault == "foreign":
        key = ingress_key(
            "d" * 64, "c" * 32, "b" * 64, digest)
    elif fault == "nonpile":
        key = key.replace("/piles/", "/objects/")
    else:
        digest = "e" * 64
    canonical, ingress = Bucket(), Bucket()

    with pytest.raises(ValueError, match="exact ingress|ingress key"):
        asyncio.run(apply(
            _env(workspace, canonical, ingress), key, digest))
    assert canonical.calls == []
    assert ingress.calls == []


def test_same_isolate_overlap_is_not_hidden_by_singleflight(monkeypatch):
    entered = 0
    release = asyncio.Event()

    class Delayed:
        def __init__(self, _workspace, _store):
            pass

        async def apply_exact(self, _ingress, key, digest):
            nonlocal entered
            entered += 1
            await release.wait()
            return SimpleNamespace(
                status="retryable", root=None, admitted=(key, digest))

    workspace = "a" * 64
    raw = b"pile"
    key = ingress_key(
        workspace, "c" * 32, "b" * 64, h(raw))
    env = _env(workspace, Bucket(), Bucket())
    monkeypatch.setattr(applier_runtime, "RepositoryApplier", Delayed)

    async def overlap():
        first = asyncio.create_task(apply(env, key, h(raw)))
        second = asyncio.create_task(apply(env, key, h(raw)))
        while entered < 2:
            await asyncio.sleep(0)
        release.set()
        return await asyncio.gather(first, second)

    results = asyncio.run(overlap())
    assert entered == 2
    assert [result.status for result in results] == [
        "retryable", "retryable",
    ]


def test_applier_entrypoint_has_private_rpc_and_no_scheduler():
    path = Path(__file__).parents[1] / (
        "deploy/cloudflare_upload/worker/applier.py")
    module = ast.parse(path.read_text())
    default = next(
        item for item in module.body
        if isinstance(item, ast.ClassDef) and item.name == "Default"
    )
    methods = {
        item.name for item in default.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert methods == {"fetch", "apply"}


def test_realistic_nonempty_turn_stays_below_configured_calls():
    secret = load_sk("01" * 32)
    public = secret.verify_key.encode().hex()
    root = workspace_fact(secret, public, "hosted-call-bound", 1)
    stream = [root]
    for ordinal in range(124):
        timestamp = 2 + ordinal
        item = message(
            root.fid, public, "general", f"hosted-{timestamp}", timestamp)
        stream.extend((signature(
            secret, public, item, timestamp), item))
    raw = encode_pile(stream, workspace=root.fid)
    canonical, ingress = Bucket(), Bucket()
    key = ingress_key(
        root.fid, "c" * 32, "b" * 64, h(raw))
    _put(ingress, key, raw)

    result = asyncio.run(apply(
        _env(root.fid, canonical, ingress), key, h(raw)))
    assert result.status == "applied"
    assert len(canonical.calls) + len(ingress.calls) < 25_000
    assert len(canonical.calls) + len(ingress.calls) \
        < MAX_HOSTED_SUBREQUESTS
