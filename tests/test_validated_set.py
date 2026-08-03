"""The authenticated repository is a monotone set of validated fact bytes."""

import asyncio

import facts

from .util import signed_pile_facts, signed_pile_bytes
from core.crypto import h
from core.fact import encode
from full_peer.node import FullPeer
from core.repository_applier import RepositoryApplier
from core.repository_snapshot import compile_snapshot
from core.store import FsStore
from core.validated_set import ValidatedView, reconstruct

from .util import (
    all_fids,
    apply_planted,
    closed_subset,
    plant_for,
    suppression_world,
)


def run(awaitable):
    return asyncio.run(awaitable)


def apply(applier, member, raw):
    source = run(plant_for(applier, member, raw))
    return run(apply_planted(applier, source))


def compiled_view(node, workspace):
    facts_by_fid = {
        fid: node.fact_of(workspace, fid)
        for fid in node.sql(workspace).fact_ids()
    }
    compiled = compile_snapshot(workspace, facts_by_fid)
    objects = dict(compiled.objects)
    return compiled, objects, ValidatedView(compiled.root, objects.get)


def test_unclosed_pile_is_rejected_atomically(tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    message = facts.content.message.message(
        workspace, author.identity(workspace)[1], "general", "orphan", 2)
    raw = signed_pile_bytes((message,), workspace=workspace)
    store = FsStore(str(tmp_path / "recipient"))

    result = apply(RepositoryApplier(workspace, store), "a" * 64, raw)

    assert result.status == "rejected"
    assert store.get("root") is None
    assert store.list("obj/") == []


def test_valid_prefix_of_invalid_pile_publishes_nothing(tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    genesis = closed_subset(author, workspace, (workspace,))
    assert apply(applier, "a" * 64, genesis).status == "applied"
    before_root = store.get("root")
    before = reconstruct(
        before_root, lambda oid: store.get("obj/" + oid))

    secret, public = author.identity(workspace)
    message = facts.content.message.message(
        workspace, public, "general", "missing membership closure", 2)
    signed = facts.auth.signature.signature(
        secret, public, message, message.ts)
    mixed = signed_pile_bytes((signed, message), workspace=workspace)

    result = apply(applier, "a" * 64, mixed)

    assert result.status == "rejected"
    assert store.get("root") == before_root
    after = reconstruct(
        before_root, lambda oid: store.get("obj/" + oid))
    assert set(after.facts) == set(before.facts) == {workspace}
    assert store.get("obj/" + h(encode(signed))) is None


def test_successful_closed_pile_publishes_every_durable_fact(tmp_path):
    author, workspace, _, _ = suppression_world(tmp_path / "author")
    raw = closed_subset(
        author, workspace, all_fids(author, workspace))
    stream = signed_pile_facts(raw, workspace)
    expected = {
        fact.fid
        for fact in stream
        if facts.family_for(fact.t).DURABLE
    }
    store = FsStore(str(tmp_path / "recipient"))

    result = apply(RepositoryApplier(workspace, store), "a" * 64, raw)
    validated = reconstruct(
        result.root, lambda oid: store.get("obj/" + oid))

    assert result.status == "applied"
    assert set(result.admitted) == expected
    assert set(validated.facts) == expected
    assert all(
        validated.facts[fid].fid == fid
        for fid in expected
    )


def test_suppression_changes_visibility_not_validated_residence(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    target = facts.content.message.post(
        node, workspace, "general", "keep the validated bytes", ts=2)
    before = set(node.sql(workspace).fact_ids())

    action = facts.content.delete.remove(
        node, workspace, target, ts=3)
    view = node.sql(workspace)

    assert view.fact_active(target) is False
    assert target in view.fact_ids()
    assert view.fact_of(target).fid == target
    assert before <= view.fact_ids()
    assert action in view.fact_ids()


def test_reconstruction_rejects_forged_fact_bytes(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    compiled, objects, view = compiled_view(node, workspace)
    oid = view.fact_oid(workspace)

    def fetch(candidate):
        if candidate == oid:
            return b"forged"
        return objects.get(candidate)

    try:
        reconstruct(compiled.root, fetch)
    except ValueError:
        pass
    else:
        raise AssertionError("forged canonical fact bytes were accepted")


def test_fact_oid_is_canonical_bytes_not_an_admission_witness(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    _compiled, _objects, view = compiled_view(node, workspace)
    fact = view.fact(workspace)

    assert view.fact_oid(workspace) == h(
        __import__("core.fact", fromlist=["encode"]).encode(fact))
    assert set(view.fact_ids()) == {workspace}
