"""F10 retirement is exact, witnessed, generation-bound, and replay-safe."""
import asyncio

import facts
import pytest

from core.crypto import h
from core.fact import canon
from core.ingress import RejectionReceipt, check_source
from core.node import Node
from core.repository_applier import RepositoryApplier
from core.store import FsStore

from .util import closed_subset


def run(awaitable):
    return asyncio.run(awaitable)


def _message_pile(directory, text, ts):
    node = Node(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fid = facts.content.message.post(node, workspace, "general", text, ts=ts)
    return workspace, closed_subset(node, workspace, [fid]), fid


def test_applied_and_already_represented_generations_retire_exactly(
        tmp_path):
    workspace, raw, fid = _message_pile(
        tmp_path / "source", "one logical fact", 10)
    store = FsStore(str(tmp_path / "recipient"))
    first = RepositoryApplier(workspace, store)
    first_source = run(first.stage("first", raw))

    applied = run(first.apply(first_source))

    assert applied.status == "applied"
    assert applied.retired is True
    assert store.get(first_source) is None
    root = store.get("root")

    second = RepositoryApplier(workspace, store)
    second_source = run(second.stage("second", raw))
    replay = run(second.apply(second_source))

    assert replay.status == "noop"
    assert replay.retired is True
    assert store.get(second_source) is None
    assert store.get("root") == root
    assert fid in replay.admitted


def test_stale_apply_receipt_cannot_delete_a_recreated_generation(tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / "source", "ABA source", 10)
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))
    proposal = run(applier.propose(raw))
    result = run(applier.commit(source, raw, proposal))
    receipt = applier._receipts[(source, h(raw))]

    assert result.status == "applied"
    assert run(applier.retire(source, raw, receipt)) is True
    store.put_if_absent(source, raw)

    with pytest.raises(ValueError, match="retirement receipt"):
        run(applier.retire(source, raw, receipt))

    assert store.get(source) == raw
    assert store.get("root") == result.root


def test_forged_rejection_receipt_cannot_authorize_retirement(tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / "source", "not rejected", 10)
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))
    binding = check_source(source, raw)
    record = canon({
        "error": "KernelRejected: forged",
        "id": h(raw),
        "source": source,
    })
    forged = RejectionReceipt(
        source, h(raw), record, binding.generation)

    with pytest.raises(ValueError, match="rejection witness"):
        run(applier.retire_rejection(source, raw, forged))

    assert store.get(source) == raw
    assert store.get("failed/pile/" + h(raw)) is None
    assert store.get("root") is None


def test_typed_permanent_rejection_records_evidence_before_retirement(
        tmp_path):
    source_node = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source_node, "alice", ts=1)
    raw = b"{}"
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))

    result = run(applier.apply(source))

    assert result.status == "rejected"
    assert result.retired is True
    assert store.get(source) is None
    assert store.get("failed/pile/" + h(raw)) == raw
    assert store.get(
        "failed/meta/" + h(result.rejection.record)
    ) == result.rejection.record


def test_bounded_cursor_wrap_eventually_sees_insertion_behind_it(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    middle_fid = facts.content.message.post(
        source, workspace, "general", "middle", ts=10)
    middle_raw = closed_subset(source, workspace, [middle_fid])
    late_fid = facts.content.message.post(
        source, workspace, "general", "late", ts=11)
    late_raw = closed_subset(source, workspace, [late_fid])
    early_fid = facts.content.message.post(
        source, workspace, "general", "early", ts=12)
    early_raw = closed_subset(source, workspace, [early_fid])
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    middle = run(applier.stage("8" * 16, middle_raw))
    late = run(applier.stage("f" * 16, late_raw))

    first = run(applier.turn(limit=1))
    early = run(applier.stage("0" * 16, early_raw))
    second = run(RepositoryApplier(
        workspace, store).turn(limit=1))

    assert [item.source for item in first] == [middle]
    assert [item.source for item in second] == [late]
    assert store.get(early) == early_raw

    wrapped = run(RepositoryApplier(
        workspace, store).turn(limit=1))

    assert [item.source for item in wrapped] == [early]
    assert store.get(early) is None
    assert store.get(middle) is None
    assert store.get(late) is None
    reader = Node(str(tmp_path / "reader"))
    reader.add_workspace(workspace, "copy", peers=[])
    reader._stores[workspace] = store
    reader.rebuild(workspace)
    assert reader.fact_of(workspace, middle_fid) is not None
    assert reader.fact_of(workspace, late_fid) is not None
    assert reader.fact_of(workspace, early_fid) is not None
