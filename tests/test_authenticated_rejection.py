"""Permanent rejection is a repeatable verdict over retained exact bytes."""
import asyncio

import facts
import pytest

from core.crypto import keypair
from core.object_store import ABSENT
from core.repository_applier import RepositoryApplier
from full_peer.node import FullPeer

from .provider_fakes import provider_store
from .util import apply_planted, closed_subset, plant_for


def run(awaitable):
    return asyncio.run(awaitable)


def _workspace(tmp_path):
    node = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    return node, workspace


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_malformed_exact_pile_is_repeatably_rejected_and_retained(
        kind, tmp_path):
    _, workspace = _workspace(tmp_path)
    store = provider_store(kind, tmp_path / f"recipient-{kind}")
    first = RepositoryApplier(workspace, store)
    source = run(plant_for(first, "a" * 64, b"{}"))

    assert run(apply_planted(first, source)).status == "rejected"
    assert run(apply_planted(
        RepositoryApplier(workspace, store), source)).status == "rejected"
    assert run(first.store.get_bounded(source, 2)) == b"{}"
    assert run(first.store.read_versioned("root")) is ABSENT


def test_digest_mismatch_rejects_before_decoding(tmp_path, monkeypatch):
    _, workspace = _workspace(tmp_path)
    store = provider_store("fs", tmp_path / "recipient")
    applier = RepositoryApplier(workspace, store)
    source = run(plant_for(applier, "a" * 64, b"{}"))
    monkeypatch.setattr(
        applier,
        "_validated_facts",
        lambda *_args: pytest.fail("digest mismatch reached decoder"),
    )

    with pytest.raises(ValueError, match="exact ingress address"):
        run(applier.apply_exact(store, source, "0" * 64))
    assert store.get(source) == b"{}"
    assert store.get("root") is None


def test_kernel_rejection_does_not_establish_objects_or_root(tmp_path):
    node, workspace = _workspace(tmp_path)
    _, foreign_public = keypair()
    item = facts.content.message.message(
        workspace, foreign_public, "general", "unsigned", 10)
    raw = node.sender(workspace).pack((item,))
    store = provider_store("fs", tmp_path / "recipient")
    applier = RepositoryApplier(workspace, store)
    source = run(plant_for(applier, "a" * 64, raw))

    result = run(apply_planted(applier, source))

    assert result.status == "rejected"
    assert store.get(source) == raw
    assert store.get("root") is None
    assert store.list("obj/") == []


def test_program_failure_is_not_misclassified_as_rejection(
        tmp_path, monkeypatch):
    node, workspace = _workspace(tmp_path)
    fid = facts.content.message.post(
        node, workspace, "general", "valid", ts=10)
    raw = closed_subset(node, workspace, (fid,))
    store = provider_store("fs", tmp_path / "recipient")
    applier = RepositoryApplier(workspace, store)
    source = run(plant_for(applier, "a" * 64, raw))

    def broken(*_args, **_kwargs):
        raise RuntimeError("program failure")

    monkeypatch.setattr(facts.content.message, "message", broken)
    with pytest.raises(RuntimeError, match="program failure"):
        run(apply_planted(applier, source))
    assert store.get(source) == raw
    assert store.get("root") is None


def test_rejection_creates_no_operational_evidence_namespace(tmp_path):
    _, workspace = _workspace(tmp_path)
    store = provider_store("fs", tmp_path / "recipient")
    applier = RepositoryApplier(workspace, store)
    source = run(plant_for(applier, "a" * 64, b"{}"))
    assert run(apply_planted(applier, source)).status == "rejected"
    keys = store.list("")
    assert keys == [source]
    assert not any(
        marker in key
        for key in keys
        for marker in ("failed/", "applier/", "spent/", "receipt/")
    )
