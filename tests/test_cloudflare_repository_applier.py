"""Cloudflare scheduled runtime composes the exact shared Applier."""
import asyncio
import sqlite3
from types import SimpleNamespace

import facts
import pytest

from core.close import encode_pile
from core.crypto import h, load_sk
from core.limits import MAX_HOSTED_SUBREQUESTS
from facts.auth.signature import signature
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message
from full_peer.node import FullPeer
from core.repository_reader import RepositoryReader
from core.staged_intent import staging_key
from deploy.cloudflare_upload.worker import applier_runtime
from deploy.cloudflare_upload.worker.applier_runtime import drain

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


def test_scheduled_r2_actor_applies_and_reads_without_sql(
        tmp_path, monkeypatch):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    facts.content.message.post(source, workspace, "general", "through R2", ts=10)
    raw = closed_subset(
        source, workspace, all_fids(source, workspace))
    marker = staging_key(
        workspace, "b" * 16, "c" * 32, "pile", h(raw))
    canonical, ingress = Bucket(), Bucket()
    ingress.data[marker] = raw
    ingress.etags[marker] = ingress._token()
    env = _env(workspace, canonical, ingress)

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

    latest = facts.content.message.post(
        source, workspace, "general", "incremental R2", ts=20)
    next_raw = closed_subset(source, workspace, (latest,))
    next_marker = staging_key(
        workspace, "b" * 16, "d" * 32, "pile", h(next_raw))
    ingress.data[next_marker] = next_raw
    ingress.etags[next_marker] = ingress._token()

    _, first_page = asyncio.run(drain(env))
    assert len(first_page) == 1
    _, outcomes = asyncio.run(drain(env))
    applied = dict(outcomes)[next_marker]
    assert applied.result.status == "applied"
    assert canonical.data[physical] \
        == source.store(workspace).get("root")


def test_same_isolate_scheduled_calls_are_one_cancellation_safe_flight(
        monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()

    class Delayed:
        calls = 0

        def __init__(self, _workspace, _store):
            pass

        async def turn(self, *, limit):
            assert limit == 1
            type(self).calls += 1
            entered.set()
            await release.wait()
            return ("one",)

        async def drain_staged(self, _ingress, *, limit):
            assert limit == 1
            return ()

    async def scenario():
        first = asyncio.create_task(drain(env))
        second = asyncio.create_task(drain(env))
        await entered.wait()
        assert Delayed.calls == 1
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        third = asyncio.create_task(drain(env))
        await asyncio.sleep(0)
        assert Delayed.calls == 1
        release.set()
        expected = (("one",), ())
        assert await second == await third == expected
        assert await drain(env) == expected
        assert Delayed.calls == 2

    workspace = "a" * 64
    env = _env(workspace, object(), object())
    monkeypatch.setattr(applier_runtime, "RepositoryApplier", Delayed)
    monkeypatch.setattr(applier_runtime, "_inflight", None)
    monkeypatch.setattr(applier_runtime, "_next_kind", "internal")
    asyncio.run(scenario())


def test_one_pile_turns_alternate_backlogs_without_batch_retention(
        monkeypatch):
    events = []

    class Fair:
        internal = ["i1", "i2"]
        staged = ["s1", "s2"]

        def __init__(self, _workspace, _store):
            pass

        async def turn(self, *, limit):
            assert limit == 1
            events.append("internal")
            return tuple(self.internal[:1])

        async def drain_staged(self, _ingress, *, limit):
            assert limit == 1
            events.append("staged")
            return tuple(self.staged[:1])

    workspace = "b" * 64
    env = _env(workspace, object(), object())
    monkeypatch.setattr(applier_runtime, "RepositoryApplier", Fair)
    monkeypatch.setattr(applier_runtime, "_inflight", None)
    monkeypatch.setattr(applier_runtime, "_next_kind", "internal")

    assert asyncio.run(drain(env)) == (("i1",), ())
    Fair.internal.pop(0)
    assert asyncio.run(drain(env)) == ((), ("s1",))
    Fair.staged.pop(0)
    assert asyncio.run(drain(env)) == (("i2",), ())
    assert events == ["internal", "staged", "internal"]


def test_realistic_nonempty_256_fact_turn_stays_below_configured_calls():
    """Exact R2 calls ratchet the effect machine, not a pure compiler."""
    secret = load_sk("01" * 32)
    public = secret.verify_key.encode().hex()
    root = workspace_fact(secret, public, "hosted-call-bound", 1)

    def pile(start):
        stream = [root]
        for ordinal in range(124):
            timestamp = start + ordinal
            item = message(
                root.fid, public, "general",
                f"hosted-{timestamp}", timestamp)
            stream.extend((
                signature(
                    secret, public, item, timestamp),
                item,
            ))
        assert len(stream) == 249
        return encode_pile(stream, workspace=root.fid)

    canonical, ingress = Bucket(), Bucket()
    env = _env(root.fid, canonical, ingress)
    applier_runtime._next_kind = "internal"
    applier_runtime._inflight = None
    call_counts = []
    for session, raw in (("c" * 32, pile(2)), ("d" * 32, pile(1000))):
        marker = staging_key(
            root.fid, "b" * 16, session, "pile", h(raw))
        ingress.data[marker] = raw
        ingress.etags[marker] = ingress._token()
        canonical.calls.clear()
        ingress.calls.clear()

        _, staged = asyncio.run(drain(env))
        assert staged[0][1].result.status == "applied"
        call_counts.append(len(canonical.calls) + len(ingress.calls))

        # Isolate the next nonempty append from LIST cursor/replay effects.
        ingress.data.pop(marker)
        ingress.etags.pop(marker)
    assert max(call_counts) < 25_000
    assert max(call_counts) < MAX_HOSTED_SUBREQUESTS
