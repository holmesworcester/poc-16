"""Cloudflare scheduled runtime composes the exact shared Applier."""
import asyncio
import sqlite3
from types import SimpleNamespace

import facts

from core.crypto import h
from core.node import Node
from core.repository_reader import RepositoryReader
from core.staged_intent import staging_key
from deploy.cloudflare_upload.worker.applier_runtime import drain

from .test_r2_worker_store import Bucket
from .util import all_fids, closed_subset


def test_scheduled_r2_actor_applies_and_reads_without_sql(
        tmp_path, monkeypatch):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    facts.content.message.post(source, workspace, "general", "through R2", ts=10)
    raw = closed_subset(
        source, workspace, all_fids(source, workspace))
    marker = staging_key(
        workspace, "b" * 16, "c" * 32, "pile", h(raw))
    canonical, ingress = Bucket(), Bucket()
    ingress.data[marker] = raw
    ingress.etags[marker] = ingress._token()
    env = SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="applier",
        WORKSPACE=workspace,
        CANONICAL_PREFIX=f"workspaces/{workspace}",
        INGRESS_PREFIX=f"ingress/v1/workspaces/{workspace}",
        CANONICAL=canonical,
        INGRESS=ingress,
    )

    monkeypatch.setattr(
        sqlite3, "connect",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("R2 applier touched SQLite")),
    )
    internal, staged = asyncio.run(drain(env))

    assert internal == ()
    assert staged[0][0] == marker
    assert staged[0][1].result.status == "applied"
    physical = f"workspaces/{workspace}/root"
    root = canonical.data[physical]
    reader = RepositoryReader(
        workspace,
        root,
        lambda oid: canonical.data.get(
            f"workspaces/{workspace}/obj/{oid}"),
    )
    assert reader.worker().fact_active(workspace)
    assert ingress.data[marker] == raw

    _, replay = asyncio.run(drain(env))
    assert replay[0][1].result.status == "admitted"
    assert canonical.data[physical] == root
    assert not any(
        key.startswith(f"workspaces/{workspace}/pile/")
        for key in canonical.data)
