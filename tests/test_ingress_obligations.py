"""F10 retirement is exact, witnessed, generation-bound, and replay-safe."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import threading

import facts
import pytest

from adapters.r2 import R2BindingStore
from adapters.s3 import S3Config, S3Store
from core.crypto import h
from core.fact import canon
from core.ingress import check_source, decode_rejection_record
from core.object_store import OutcomeUnknown
from full_peer.node import FullPeer
from core.repository_applier import (
    RejectionReceipt,
    RepositoryApplier,
)
from core.store import FsStore

from .ingress_obligations import ObligationTrace, ObligationViolation
from .provider_fakes import provider_store
from .shared_bucket import ScriptedBucket
from .util import closed_subset


def run(awaitable):
    return asyncio.run(awaitable)


def _message_pile(directory, text, ts):
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fid = facts.content.message.post(node, workspace, "general", text, ts=ts)
    return workspace, closed_subset(node, workspace, [fid]), fid


def _two_message_piles(directory):
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    first = facts.content.message.post(
        node, workspace, "general", "first", ts=10)
    second = facts.content.message.post(
        node, workspace, "general", "second", ts=11)
    return (
        workspace,
        closed_subset(node, workspace, [first]),
        closed_subset(node, workspace, [second]),
    )


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


def test_publication_root_without_exact_spend_cannot_authorize_delete(
        tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / "source-without-spend", "unspent publication", 10)
    bucket = ScriptedBucket(seed=0xF10C)
    store = bucket.handle("worker")
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))
    result = run(applier.commit(
        source, raw, run(applier.propose(raw))))
    trace = ObligationTrace(bucket, workspace)
    trace.observe_publication(source, raw, applier._receipts[source])

    store.delete(source)

    assert result.status == "applied"
    with pytest.raises(
            ObligationViolation,
            match="definite fresh publication spend"):
        trace.check()


def test_publication_observation_derives_every_durable_fact_from_pile(
        tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / "source-omitted-admission", "omitted admission", 10)
    bucket = ScriptedBucket(seed=0xF10D)
    applier = RepositoryApplier(workspace, bucket.handle("worker"))
    source = run(applier.stage("member", raw))
    run(applier.commit(source, raw, run(applier.propose(raw))))
    receipt = applier._receipts[source]
    assert receipt.admitted

    with pytest.raises(
            AssertionError, match="invalid publication observation"):
        ObligationTrace(bucket, workspace).observe_publication(
            source, raw, replace(receipt, admitted=()))


def test_stale_apply_receipt_cannot_delete_a_recreated_generation(tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / "source", "ABA source", 10)
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))
    proposal = run(applier.propose(raw))
    result = run(applier.commit(source, raw, proposal))
    receipt = applier._receipts[source]

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
        workspace=workspace,
        source=source,
        payload=h(raw),
        generation=binding.generation,
        outcome="rejected",
        issuer=object(),
        record=record,
    )

    with pytest.raises(ValueError, match="rejection witness"):
        run(applier.retire_rejection(source, raw, forged))

    assert store.get(source) == raw
    assert store.get("failed/pile/" + h(raw)) is None
    assert store.get("root") is None


@pytest.mark.parametrize("rejected", (False, True))
def test_live_receipt_cannot_retarget_source_bytes_or_applier(
        rejected, tmp_path, monkeypatch):
    if rejected:
        workspace, _, _ = _message_pile(
            tmp_path / "authority-rejected", "workspace anchor", 10)
        first_raw, second_raw = b"{}", b"[]"
    else:
        workspace, first_raw, second_raw = _two_message_piles(
            tmp_path / "authority-applied")
    store = FsStore(str(tmp_path / f"authority-recipient-{rejected}"))
    deletes = []
    delete = store.delete

    def recorded_delete(key):
        deletes.append(key)
        return delete(key)

    monkeypatch.setattr(store, "delete", recorded_delete)
    owner = RepositoryApplier(workspace, store)
    first_source = run(owner.stage("first-member", first_raw))
    second_source = run(owner.stage("second-member", second_raw))
    if rejected:
        result = run(owner.apply(first_source, retire=False))
        assert result.status == "rejected"
        receipt = result.rejection
        retire = owner.retire_rejection
    else:
        proposal = run(owner.propose(first_raw))
        run(owner.commit(first_source, first_raw, proposal))
        receipt = owner._receipts[first_source]
        retire = owner.retire

    bindings = (
        check_source(first_source, first_raw),
        check_source(second_source, second_raw),
    )

    # A live authority for A grants nothing over a distinct present B.
    with pytest.raises(ValueError):
        run(retire(second_source, second_raw, receipt))

    # Nor can its exact source be paired with different pile bytes.
    with pytest.raises(ValueError):
        run(retire(first_source, second_raw, receipt))

    # Copying the object into another Applier's local receipt slot does not
    # cross the issuer boundary.
    foreign = RepositoryApplier(workspace, store)
    foreign._receipts[first_source] = receipt
    foreign_retire = foreign.retire_rejection if rejected else foreign.retire
    with pytest.raises(ValueError):
        run(foreign_retire(first_source, first_raw, receipt))

    assert deletes == []
    assert store.get(first_source) == first_raw
    assert store.get(second_source) == second_raw
    for binding in bindings:
        assert store.get("applier/spent/" + binding.generation) is None


def test_typed_permanent_rejection_records_evidence_before_retirement(
        tmp_path):
    source_node = FullPeer(str(tmp_path / "source"))
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

    # Recreating identical provider bytes cannot revive the consumed receipt.
    store.put_if_absent(source, raw)
    with pytest.raises(ValueError, match="rejection witness"):
        run(applier.retire_rejection(source, raw, result.rejection))
    assert store.get(source) == raw


def test_deferred_rejection_replay_dispatches_its_typed_receipt(tmp_path):
    workspace, _, _ = _message_pile(
        tmp_path / "deferred-rejection", "workspace anchor", 10)
    store = FsStore(str(tmp_path / "deferred-rejection-recipient"))
    applier = RepositoryApplier(workspace, store)
    raw = b"{}"
    source = run(applier.stage("member", raw))

    first = run(applier.apply(source, retire=False))
    replay = run(applier.apply(source))

    assert first.status == replay.status == "rejected"
    assert first.retired is False
    assert replay.retired is True
    assert replay.rejection is first.rejection
    assert store.get(source) is None


def _concurrently(call, actors):
    with ThreadPoolExecutor(max_workers=len(actors)) as pool:
        return tuple(pool.map(lambda actor: run(call(actor)), actors))


class _LoseFirstSpend:
    """Commit one spend marker but hide its response from the Applier."""

    def __init__(self, store):
        self.store = store
        self.lost = False
        self.deletes = 0

    def __getattr__(self, name):
        return getattr(self.store, name)

    def put_if_absent(self, key, value):
        result = self.store.put_if_absent(key, value)
        if key.startswith("applier/spent/") and not self.lost:
            self.lost = True
            raise OutcomeUnknown("lost spend response")
        return result

    def delete(self, key):
        self.deletes += 1
        return self.store.delete(key)


class _CreateAfterSpend:
    """Pause stable-source recovery until its first copy was spent."""

    def __init__(self, store, source, ready, spent):
        self.store = store
        self.source = source
        self.ready = ready
        self.spent = spent

    def __getattr__(self, name):
        return getattr(self.store, name)

    def put_if_absent(self, key, value):
        if key == self.source:
            self.ready.set()
            if not self.spent.wait(5):
                raise TimeoutError("spend did not finish")
        return self.store.put_if_absent(key, value)


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_identical_success_is_one_reserved_generation_and_one_delete(
        kind, tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / f"source-{kind}", f"same success {kind}", 10)
    store = provider_store(kind, tmp_path / f"recipient-{kind}")
    first = RepositoryApplier(workspace, store)
    second = RepositoryApplier(workspace, store)

    sources = _concurrently(
        lambda actor: actor.stage("member", raw), (first, second))
    assert sources[0] == sources[1]
    source = sources[0]
    results = _concurrently(
        lambda actor: actor.apply(source), (first, second))

    assert {result.status for result in results} <= {
        "applied", "confirmed", "noop", "missing", "stale"}
    cold = RepositoryApplier(workspace, store)
    assert run(cold.store.get_bounded(source, len(raw))) is None
    assert len(run(cold.store.list_page(
        "applier/generation/", None, 8)).keys) == 1
    assert len(run(cold.store.list_page(
        "applier/spent/", None, 8)).keys) == 1

    # A duplicate delivery is the same logical generation, not a fresh event.
    assert run(cold.stage("member", raw)) == source
    terminal = run(cold.apply(source))
    assert terminal.status in {"applied", "confirmed", "noop"}
    assert terminal.retired is True

    # Even a raw-store ABA injection cannot make a cold legitimate applier
    # spend this generation twice. Provider ETags deliberately repeat by value.
    assert run(cold.store.put_if_absent(source, raw)).value in {
        "created", "exists"}
    recreated = run(RepositoryApplier(workspace, store).apply(source))
    assert recreated.status in {"applied", "confirmed", "noop"}
    assert recreated.retired is False
    assert run(cold.store.get_bounded(source, len(raw))) == raw


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_identical_rejection_is_one_reserved_generation_and_one_delete(
        kind, tmp_path):
    workspace, _, _ = _message_pile(
        tmp_path / f"source-reject-{kind}", f"reject {kind}", 10)
    raw = b"{}"
    store = provider_store(kind, tmp_path / f"rejected-{kind}")
    first = RepositoryApplier(workspace, store)
    second = RepositoryApplier(workspace, store)
    sources = _concurrently(
        lambda actor: actor.stage("member", raw), (first, second))
    assert sources[0] == sources[1]
    source = sources[0]
    results = _concurrently(
        lambda actor: actor.apply(source), (first, second))

    assert {result.status for result in results} <= {
        "rejected", "missing"}
    cold = RepositoryApplier(workspace, store)
    assert run(cold.store.get_bounded(source, len(raw))) is None
    assert run(cold.stage("member", raw)) == source
    terminal = run(cold.apply(source))
    assert terminal.status == "rejected"
    assert terminal.retired is True
    binding = check_source(source, raw)
    metadata = run(cold.store.list_page(
        "failed/meta/", None, 8)).keys
    assert len(metadata) == 1
    record = run(cold.store.get_bounded(metadata[0], 4 * 1024))
    decode_rejection_record(
        record,
        workspace=workspace,
        source=source,
        payload=h(raw),
        generation=binding.generation,
    )
    spend = run(cold.store.get_bounded(
        "applier/spent/" + binding.generation, 4 * 1024))
    assert json.loads(spend) == {
        "kind": "internal-generation-spend-v1",
        "outcome": "rejected",
        "proof": h(record),
    }

    run(cold.store.put_if_absent(source, raw))
    recreated = run(RepositoryApplier(workspace, store).apply(source))
    assert recreated.status == "rejected"
    assert recreated.retired is False
    assert run(cold.store.get_bounded(source, len(raw))) == raw


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_generation_and_spend_evidence_cannot_be_erased_or_replaced(
        kind, tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / f"source-tombstone-{kind}", f"tombstone {kind}", 10)
    store = provider_store(
        kind, tmp_path / f"recipient-tombstone-{kind}")
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))
    result = run(applier.apply(source))
    assert result.status in {"applied", "confirmed", "noop"}
    binding = check_source(source, raw)
    keys = (
        "applier/generation/" + binding.generation,
        "applier/spent/" + binding.generation,
    )

    for key in keys:
        exact = run(applier.store.get_bounded(key, 4 * 1024))
        assert exact is not None
        with pytest.raises(ValueError, match="authoritative"):
            run(applier.store.delete(key))
        with pytest.raises(ValueError, match="authoritative"):
            run(applier.store.put(key, b"replacement"))
        assert run(applier.store.get_bounded(key, 4 * 1024)) == exact

    # Even a raw source-value ABA remains terminal because neither safety
    # record can be erased through the provider-neutral store contract.
    run(applier.store.put_if_absent(source, raw))
    replay = run(RepositoryApplier(workspace, store).apply(source))
    assert replay.status in {"applied", "confirmed", "noop"}
    assert replay.retired is False
    assert run(applier.store.get_bounded(source, len(raw))) == raw


@pytest.mark.parametrize("rejected", (False, True))
def test_ambiguous_spend_never_grants_a_delete_and_restart_is_terminal(
        rejected, tmp_path):
    workspace, valid, _ = _message_pile(
        tmp_path / f"ambiguous-{rejected}", "ambiguous spend", 10)
    raw = b"{}" if rejected else valid
    underlying = FsStore(str(tmp_path / f"recipient-{rejected}"))
    fault = _LoseFirstSpend(underlying)
    applier = RepositoryApplier(workspace, fault)
    source = run(applier.stage("member", raw))

    result = run(applier.apply(source, retire=False))
    receipt = result.rejection if rejected else \
        applier._receipts[source]
    retired = run(
        applier.retire_rejection(source, raw, receipt)
        if rejected else applier.retire(source, raw, receipt)
    )

    assert retired is False
    assert fault.lost is True
    assert fault.deletes == 0
    assert underlying.get(source) == raw
    assert len(underlying.list("applier/spent/")) == 1

    terminal = run(RepositoryApplier(
        workspace, underlying).apply(source))
    assert terminal.status == ("rejected" if rejected else result.status)
    assert terminal.retired is False
    assert underlying.get(source) == raw


def test_stage_racing_spend_leaves_one_terminal_source_without_amplifying(
        tmp_path):
    workspace, raw, _ = _message_pile(
        tmp_path / "stage-spend", "stage versus spend", 10)
    store = FsStore(str(tmp_path / "stage-spend-recipient"))
    winner = RepositoryApplier(workspace, store)
    source = run(winner.stage("member", raw))
    result = run(winner.commit(source, raw, run(winner.propose(raw))))
    receipt = winner._receipts[source]
    ready = threading.Event()
    spent = threading.Event()
    racing = RepositoryApplier(
        workspace, _CreateAfterSpend(store, source, ready, spent))

    with ThreadPoolExecutor(max_workers=1) as pool:
        recovery = pool.submit(lambda: run(racing.stage("member", raw)))
        assert ready.wait(5)
        assert run(winner.retire(source, raw, receipt)) is True
        spent.set()
    assert recovery.result(5) == source

    assert store.get(source) == raw
    cold = RepositoryApplier(workspace, store)
    for ordinal in range(5):
        turn = run(cold.turn(limit=1))
        assert len(turn) == 1
        assert turn[0].result.status == result.status
        assert turn[0].result.retired is False
        keys = tuple(store.list(""))
        if ordinal == 0:
            settled = keys
        else:
            assert keys == settled
    assert store.list("pile/") == [source]
    assert len(store.list("applier/generation/")) == 1
    assert len(store.list("applier/spent/")) == 1


def test_bounded_cursor_wrap_eventually_sees_insertion_behind_it(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
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
    reader = FullPeer(str(tmp_path / "reader"))
    reader.add_workspace(workspace, "copy", peers=[])
    reader._stores[workspace] = store
    reader.rebuild(workspace)
    assert reader.fact_of(workspace, middle_fid) is not None
    assert reader.fact_of(workspace, late_fid) is not None
    assert reader.fact_of(workspace, early_fid) is not None
