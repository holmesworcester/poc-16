"""Permanent rejection is exact durable evidence, not an error-shaped string."""
import asyncio
import json

import facts
import pytest

from core.crypto import h
from core.fact import canon
from core.ingress import (
    InvalidPile,
    check_source,
    decode_rejection_record,
)
from core.limits import (
    MAX_REJECTION_DIAGNOSTIC_BYTES,
    MAX_REJECTION_RECORD_BYTES,
)
from core.object_store import (
    CREATED,
    EXISTS,
    OutcomeUnknown,
)
from core.repository_applier import (
    RepositoryApplier,
    async_store,
)
from core.store import FsStore
from full_peer.node import FullPeer

from .adversarial_bucket import AdversarialBucket, Fault
from .ingress_obligations import ObligationTrace, ObligationViolation
from .shared_bucket import ScriptedBucket
from .provider_fakes import provider_store
from .util import closed_subset


def run(awaitable):
    return asyncio.run(awaitable)


def test_rejection_record_binds_every_retirement_identity_before_delete(
        tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    raw = b"{}"
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))
    binding = check_source(source, raw)

    result = run(applier.apply(source))

    assert result.status == "rejected"
    assert json.loads(result.rejection.record) == {
        "classification": "InvalidPile",
        "diagnostic": "pile shape",
        "generation": binding.generation,
        "kind": "permanent-rejection-v1",
        "payload": h(raw),
        "pile": "failed/pile/" + h(raw),
        "source": source,
        "workspace": workspace,
    }
    assert store.get(source) is None


def _world(directory):
    author = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    fid = facts.content.message.post(
        author, workspace, "general", "healthy", ts=2)
    return workspace, b"{}", closed_subset(author, workspace, [fid])


def _rejection_record(
        expected_workspace, source, raw, *, omit=(), **changes):
    binding = check_source(source, raw)
    payload = h(raw)
    value = {
        "classification": "InvalidPile",
        "diagnostic": "pile shape",
        "generation": binding.generation,
        "kind": "permanent-rejection-v1",
        "payload": payload,
        "pile": "failed/pile/" + payload,
        "source": source,
        "workspace": expected_workspace,
    }
    value.update(changes)
    for field in omit:
        value.pop(field)
    return canon(value)


def _forge_trace(case):
    workspace = "a" * 64
    raw = b"{}"
    bucket = ScriptedBucket(seed=0xF108)
    store = bucket.handle("forger")
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))
    binding = check_source(source, raw)
    # F10 requires a post-obligation read of the stable reservation.
    store.get("applier/generation/" + binding.generation)
    record_changes = {}
    if case == "forged-classification":
        record_changes["classification"] = "KernelRejected"
    elif case == "cross-workspace":
        record_changes["workspace"] = "b" * 64
    elif case == "stale-generation":
        record_changes["generation"] = "0" * 64
    elif case == "excessive":
        record_changes["diagnostic"] = "x" * (
            MAX_REJECTION_DIAGNOSTIC_BYTES + 1)
    record = _rejection_record(
        workspace,
        source,
        raw,
        omit=("kind",) if case == "partial" else (),
        **record_changes,
    )
    payload_key = "failed/pile/" + h(raw)
    store.put_if_absent(payload_key, raw)
    store.get(payload_key)
    meta_key = "failed/meta/" + h(record)
    store.put_if_absent(meta_key, record)
    store.get(meta_key)
    spend = canon({
        "kind": "internal-generation-spend-v1",
        "outcome": "rejected",
        "proof": h(record),
    })
    spend_key = "applier/spent/" + binding.generation
    if case != "no-spend":
        store.put_if_absent(spend_key, spend)
        store.get(spend_key)
    store.delete(source)
    return ObligationTrace(bucket, workspace)


@pytest.mark.parametrize(
    "case",
    (
        "no-spend",
        "forged-classification",
        "cross-workspace",
        "stale-generation",
        "partial",
        "excessive",
    ),
)
def test_f10_rejects_partial_forged_or_unspent_rejection_evidence(case):
    with pytest.raises(ObligationViolation):
        _forge_trace(case).check()


def test_running_rejection_satisfies_the_exact_f10_witness():
    workspace = "a" * 64
    bucket = ScriptedBucket(seed=0xF10)
    applier = RepositoryApplier(workspace, bucket.handle("worker"))
    source = run(applier.stage("member", b"{}"))

    result = run(applier.apply(source))
    report = ObligationTrace(bucket, workspace).check()

    assert result.status == "rejected"
    assert [(item.key, item.witness) for item in report.discharges] == [
        (source, "rejection")]
    assert report.live == ()


def test_f10_rejects_a_spend_whose_create_result_was_ambiguous():
    workspace = "a" * 64
    raw = b"{}"
    bucket = AdversarialBucket(seed=0xF10A)
    store = bucket.handle("worker")
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", raw))
    binding = check_source(source, raw)
    store.get("applier/generation/" + binding.generation)
    record = _rejection_record(workspace, source, raw)
    pile_key = "failed/pile/" + h(raw)
    store.put_if_absent(pile_key, raw)
    store.get(pile_key)
    meta_key = "failed/meta/" + h(record)
    store.put_if_absent(meta_key, record)
    store.get(meta_key)
    spend = canon({
        "kind": "internal-generation-spend-v1",
        "outcome": "rejected",
        "proof": h(record),
    })
    spend_key = "applier/spent/" + binding.generation
    bucket.fail(
        "worker",
        "put_if_absent",
        spend_key,
        Fault.RESPONSE_LOST,
        when="after",
    )

    with pytest.raises(OutcomeUnknown):
        store.put_if_absent(spend_key, spend)
    store.get(spend_key)
    store.delete(source)

    with pytest.raises(
            ObligationViolation, match="definite fresh rejection spend"):
        ObligationTrace(bucket, workspace).check()


def test_rejection_diagnostic_is_bounded_without_becoming_authority(
        tmp_path, monkeypatch):
    workspace, _, healthy = _world(tmp_path / "diagnostic-author")
    store = FsStore(str(tmp_path / "diagnostic-recipient"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", healthy))

    def excessive(_raw, _workspace):
        raise InvalidPile("é" * MAX_REJECTION_DIAGNOSTIC_BYTES)

    monkeypatch.setattr(
        "core.repository_applier.decode_pile", excessive)
    result = run(applier.apply(source))
    value = decode_rejection_record(
        result.rejection.record, workspace=workspace)

    assert value["classification"] == "InvalidPile"
    assert len(value["diagnostic"].encode()) \
        <= MAX_REJECTION_DIAGNOSTIC_BYTES
    assert value["diagnostic"].endswith("...")
    assert len(result.rejection.record) <= MAX_REJECTION_RECORD_BYTES


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_retryable_failure_has_no_terminal_evidence_and_later_progresses(
        kind, tmp_path, monkeypatch):
    workspace, _, healthy = _world(tmp_path / f"retry-author-{kind}")
    store = provider_store(kind, tmp_path / f"retry-recipient-{kind}")
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", healthy))
    propose = applier.propose
    attempts = 0

    async def fail_once(raw):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OutcomeUnknown("temporary repository read outage")
        return await propose(raw)

    monkeypatch.setattr(applier, "propose", fail_once)

    with pytest.raises(OutcomeUnknown):
        run(applier.apply(source))
    assert run(applier.store.get_bounded(source, len(healthy))) == healthy
    assert run(applier.store.list_page("failed/", None, 1)).keys == ()
    assert run(applier.store.list_page(
        "applier/spent/", None, 1)).keys == ()

    result = run(applier.apply(source))
    assert result.status in {"applied", "confirmed", "noop"}
    assert result.retired is True


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_failed_evidence_is_content_addressed_and_never_mutable(
        kind, tmp_path):
    workspace, rejected, _ = _world(tmp_path / f"immutable-author-{kind}")
    store = provider_store(kind, tmp_path / f"immutable-recipient-{kind}")
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", rejected))
    result = run(applier.apply(source))
    evidence = {
        "failed/pile/" + h(rejected): rejected,
        "failed/meta/" + h(result.rejection.record):
            result.rejection.record,
    }

    for key, exact in evidence.items():
        assert run(applier.store.get_bounded(key, max(1, len(exact)))) == exact
        with pytest.raises(ValueError, match="authoritative"):
            run(applier.store.put(key, b"replacement"))
        with pytest.raises(ValueError, match="authoritative"):
            run(applier.store.delete(key))
        with pytest.raises(ValueError, match="immutable object address"):
            run(applier.store.put_if_absent(key, b"wrong address"))
        assert run(applier.store.get_bounded(
            key, max(1, len(exact)))) == exact


@pytest.mark.parametrize("damage", ("missing", "corrupt"))
def test_cold_rejected_spend_requires_its_linked_metadata(
        damage, tmp_path):
    workspace, rejected, _ = _world(tmp_path / f"cold-author-{damage}")
    store = FsStore(str(tmp_path / f"cold-recipient-{damage}"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage("member", rejected))
    result = run(applier.apply(source))
    metadata = "failed/meta/" + h(result.rejection.record)
    payload = "failed/pile/" + h(rejected)
    assert store.get(payload) == rejected

    if damage == "missing":
        store._delete(metadata)
    else:
        changed = json.loads(result.rejection.record)
        changed["diagnostic"] = "different but still valid metadata"
        store._replace(metadata, canon(changed))

    cold = RepositoryApplier(workspace, store)
    assert run(cold.apply(source)).status == "missing"
    assert store.put_if_absent(source, rejected) is CREATED
    with pytest.raises(ValueError, match="internal generation spend"):
        run(cold.apply(source))
    assert store.get(source) == rejected
    assert store.get(payload) == rejected


class _MetadataCollision:
    """Expose a different incumbent at the exact metadata address."""

    def __init__(self, store):
        self.store = async_store(store)
        self.key = None

    async def get_bounded(self, key, maximum):
        if key == self.key:
            return b"{}"
        return await self.store.get_bounded(key, maximum)

    async def read_versioned(self, key):
        return await self.store.read_versioned(key)

    async def put(self, key, value):
        return await self.store.put(key, value)

    async def put_if_absent(self, key, value):
        if key.startswith("failed/meta/"):
            self.key = key
            return EXISTS
        return await self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        return await self.store.cas(key, token, value)

    async def list_page(self, prefix, cursor, limit):
        return await self.store.list_page(prefix, cursor, limit)

    async def delete(self, key):
        return await self.store.delete(key)


@pytest.mark.parametrize("kind", ("fs", "s3", "r2"))
def test_metadata_collision_retains_work_then_provider_recovers(
        kind, tmp_path):
    workspace, rejected, healthy = _world(tmp_path / f"author-{kind}")
    store = provider_store(kind, tmp_path / f"recipient-{kind}")
    fault = RepositoryApplier(workspace, _MetadataCollision(store))
    source = run(fault.stage("member", rejected))

    with pytest.raises(ValueError, match="evidence conflict"):
        run(fault.apply(source))

    cold = RepositoryApplier(workspace, store)
    assert run(cold.store.get_bounded(source, len(rejected))) == rejected
    assert run(cold.store.get_bounded(
        "failed/pile/" + h(rejected), len(rejected))) == rejected
    assert run(cold.store.list_page(
        "failed/meta/", None, 1)).keys == ()
    assert run(cold.store.list_page(
        "applier/spent/", None, 1)).keys == ()

    rejected_result = run(cold.apply(source))
    healthy_result = run(cold.receive_pile("member", healthy)).result

    assert rejected_result.status == "rejected"
    assert rejected_result.retired is True
    assert healthy_result.status in {"applied", "confirmed", "noop"}
    assert healthy_result.retired is True
