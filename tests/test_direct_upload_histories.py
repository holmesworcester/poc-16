"""Direct staging histories refined through running publication and F10.

Unlike the symbolic promotion events in ``direct_upload_method``, every root
witness here is produced by the production ``Publisher`` over opaque version
tokens and decoded by ``ObligationTrace`` through the running manifest and
WorkerView readers before a pile DELETE can discharge.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import random
import shutil
import threading

import pytest

from core import cmds
from core.crypto import h
from core.node import Node
from core.object_store import (
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    ensure_object,
    retire_exact,
)
from core.walk import _push

from .adversarial_bucket import AdversarialBucket, Fault
from .direct_upload_method import (
    MAX_DURABLE_HISTORY_CASES,
    StageCleanupViolation,
    check_stage_cleanup,
    durable_history_corpus,
)
from .ingress_obligations import ObligationTrace, ObligationViolation
from .util import all_fids, send_bytes


FIXED_IDENTITY = "01" * 32
HISTORY_SEED = 0xCA5DE1E7E


def _snapshot(store):
    return {key: store.get(key) for key in store.list("")}


def _close(node):
    for index in node._idx.values():
        index.close()


class _Capture:
    """Capture the real objects-first/fact-pile-last peer representation."""

    def __init__(self):
        self.objects = {}
        self.pile = None
        self.operations = []

    def put_obj(self, oid, raw):
        assert h(raw) == oid
        self.objects[oid] = raw
        self.operations.append(("object", oid))

    def put_pile(self, raw):
        self.pile = raw
        self.operations.append(("pile", h(raw)))


class _History:
    """One isolated realistic attachment and shared canonical bucket."""

    def __init__(self, path, seed):
        self.path = Path(path)
        self.seed = seed
        origin = Node(
            str(self.path / "origin"),
            initial_secret=FIXED_IDENTITY)
        self.workspace = cmds.create(origin, "alice", ts=1)
        before_fids = set(all_fids(origin, self.workspace))
        initial = _snapshot(origin.store(self.workspace))
        _close(origin)
        shutil.copytree(self.path / "origin", self.path / "template")

        source = Node(str(self.path / "origin"))
        payload = random.Random(seed ^ 0xF11E).randbytes(4_097)
        self.payload = payload
        self.file_fid = send_bytes(
            source, self.workspace, "history.bin", payload, ts=10)
        new_fids = set(all_fids(source, self.workspace)) - before_fids
        capture = _Capture()
        pushed = _push(source, self.workspace, capture, new_fids)
        self.member = source.member_for(self.workspace)
        _close(source)

        assert self.file_fid in pushed
        assert capture.objects
        assert capture.operations[-1][0] == "pile"
        self.pile_raw = capture.pile
        self.pile_key = (
            f"pile/{self.member}/{h(self.pile_raw)}")
        session = f"{seed & ((1 << 64) - 1):016x}"
        self.stage_objects = {
            f"stage/{session}/obj/{oid}": (oid, raw)
            for oid, raw in sorted(capture.objects.items())
        }

        self.bucket = AdversarialBucket(initial, seed=seed)
        uploader = self.bucket.handle("uploader")
        for key, (_oid, raw) in self.stage_objects.items():
            uploader.put_if_absent(key, raw)
        # The durable work item is last. It uses the production pile codec and
        # address; physical ingress-bucket/session scoping stays adapter work.
        uploader.put_if_absent(self.pile_key, self.pile_raw)

        promoter = self.bucket.handle("promoter")
        for stage_key, (oid, raw) in self.stage_objects.items():
            assert promoter.get(stage_key) == raw
            ensure_object(promoter, oid, raw)

        self.trace = ObligationTrace(self.bucket, self.workspace)
        self._actors = {}

    def actor(self, name, before_retire=None):
        if name in self._actors:
            raise ValueError(f"duplicate actor {name}")
        target = self.path / name
        shutil.copytree(self.path / "template", target)
        node = Node(str(target))
        node._stores[self.workspace] = self.bucket.handle(name)
        retire = node._retire_ingress_exact

        def observed(workspace, key, raw):
            self.trace.observe_node_retirement(
                node, workspace, key, raw)
            if before_retire is not None:
                before_retire()
            return retire(workspace, key, raw)

        node._retire_ingress_exact = observed
        self._actors[name] = node
        return node

    def close(self):
        for node in self._actors.values():
            _close(node)


def _run_competing(history):
    alice_before_cas = history.bucket.pause(
        "alice", "cas", "root", when="before")
    bob_at_retirement = threading.Event()
    release_bob = threading.Event()

    def hold_bob():
        bob_at_retirement.set()
        if not release_bob.wait(timeout=5):
            raise AssertionError("Bob was not released")

    alice = history.actor("alice")
    bob = history.actor("bob", hold_bob)
    listed = threading.Barrier(2)
    for node in (alice, bob):
        store = node.store(history.workspace)
        list_keys = store.list

        def synchronized_list(prefix, list_keys=list_keys):
            keys = list_keys(prefix)
            if prefix == "pile/":
                listed.wait(timeout=5)
            return keys

        store.list = synchronized_list

    bob_cas = bob.store(history.workspace).cas

    def bob_waits_for_alice(key, expected, value):
        alice_before_cas.wait()
        return bob_cas(key, expected, value)

    bob.store(history.workspace).cas = bob_waits_for_alice
    with ThreadPoolExecutor(max_workers=2) as pool:
        alice_turn = pool.submit(alice.turn, history.workspace)
        bob_turn = pool.submit(bob.turn, history.workspace)
        assert bob_at_retirement.wait(timeout=10)
        alice_before_cas.release.set()
        alice_turn.result(timeout=10)
        release_bob.set()
        bob_turn.result(timeout=10)


def _run_serial(history, case):
    first = history.actor("first")
    if case.cas == "unapplied":
        history.bucket.fail(
            "first", "cas", "root", Fault.TRANSPORT,
            when="before", nth=1)
        history.bucket.fail(
            "first", "cas", "root", Fault.TRANSPORT,
            when="before", nth=2)
    elif case.cas == "applied-response-lost":
        history.bucket.fail(
            "first", "cas", "root", Fault.RESPONSE_LOST,
            when="after", nth=1)
        # Two root reads precede CAS. Deny both same-process reconciliation
        # reads so only a cold actor can establish what happened.
        history.bucket.fail(
            "first", "read_versioned", "root", Fault.TRANSPORT,
            when="before", nth=3)
        history.bucket.fail(
            "first", "read_versioned", "root", Fault.TRANSPORT,
            when="before", nth=4)
    if case.pile_delete == "unapplied":
        history.bucket.fail(
            "first", "delete", history.pile_key, Fault.TRANSPORT,
            when="before")
    elif case.pile_delete == "applied-response-lost":
        history.bucket.fail(
            "first", "delete", history.pile_key, Fault.RESPONSE_LOST,
            when="after")

    if case.cas == "applied-response-lost":
        with pytest.raises(RetryableStoreError):
            first.turn(history.workspace)
    else:
        first.turn(history.workspace)

    if first.store(history.workspace).get(history.pile_key) is not None:
        history.actor("fresh").turn(history.workspace)


def _clean_stage_objects(history, case):
    first = history.bucket.handle("cleanup")
    fresh = history.bucket.handle("fresh-cleanup")
    fault_key = next(iter(history.stage_objects))
    if case.object_delete == "unapplied":
        history.bucket.fail(
            "cleanup", "delete", fault_key, Fault.TRANSPORT,
            when="before")
    elif case.object_delete == "applied-response-lost":
        history.bucket.fail(
            "cleanup", "delete", fault_key, Fault.RESPONSE_LOST,
            when="after")

    for key, (oid, raw) in history.stage_objects.items():
        if key == fault_key and case.object_delete == "unapplied":
            with pytest.raises(OutcomeUnknown):
                retire_exact(first, key, raw)
            assert retire_exact(fresh, key, raw) is True
        else:
            assert retire_exact(first, key, raw) is True
        assert retire_exact(fresh, key, raw) is False
        assert fresh.get("obj/" + oid) == raw


def _execute_case(path, case, seed):
    history = _History(path, seed)
    try:
        with history.bucket.capture():
            if case.cas == "competing":
                _run_competing(history)
            else:
                _run_serial(history, case)

            publication = history.trace.check()
            assert publication.live == ()
            assert len(publication.discharges) == 1
            assert publication.discharges[0].witness == "publication"
            readers = [
                node for node in history._actors.values()
                if node.fact_of(
                    history.workspace, history.file_fid) is not None
            ]
            assert readers
            assert cmds.file_bytes(
                readers[-1], history.workspace, history.file_fid
            ) == ("history.bin", history.payload)
            _clean_stage_objects(history, case)
            cleanup = check_stage_cleanup(history.bucket)
            assert cleanup.live == ()
            assert {
                row.key for row in cleanup.discharges
            } == set(history.stage_objects)
            assert history.bucket.assert_valid_history()
            return history, publication, cleanup
    except BaseException:
        history.close()
        raise


def test_durable_history_corpus_is_bounded_seeded_and_complete():
    first = durable_history_corpus(seed=31)
    replay = durable_history_corpus(seed=31)
    alternate = durable_history_corpus(seed=32)

    assert first == replay
    assert [case.name for case in first] != [
        case.name for case in alternate]
    assert len(first) == MAX_DURABLE_HISTORY_CASES
    assert {case.name for case in first} == {
        "cas-win",
        "cas-unapplied-fresh-retry",
        "cas-applied-response-lost-fresh-reconcile",
        "competing-publishers-stale",
        "pile-delete-unapplied",
        "pile-delete-applied-response-lost",
        "object-delete-unapplied",
        "object-delete-applied-response-lost",
    }


def test_seeded_histories_refine_staging_through_authenticated_roots(tmp_path):
    reports = {}
    for ordinal, case in enumerate(durable_history_corpus(HISTORY_SEED)):
        case_seed = HISTORY_SEED ^ ordinal
        history, publication, cleanup = _execute_case(
            tmp_path / case.name, case, case_seed)
        try:
            reports[case.name] = history
            assert publication.discharges[0].raw == history.pile_raw
            assert len(cleanup.discharges) == len(history.stage_objects)
        finally:
            history.close()

    competing = reports["competing-publishers-stale"].bucket.history
    assert len([
        event for event in competing
        if event.op == "cas" and isinstance(event.result, Applied)
    ]) == 1
    assert len([
        event for event in competing
        if event.op == "cas" and event.result is STALE
    ]) == 1

    lost = reports[
        "cas-applied-response-lost-fresh-reconcile"].bucket.history
    applied = next(
        event for event in lost
        if event.op == "cas" and isinstance(event.result, Applied))
    deleted = next(
        event for event in lost
        if event.op == "delete"
        and event.key.startswith("pile/"))
    fresh_reads = [
        event for event in lost
        if event.actor == "fresh"
        and event.op == "read_versioned"
        and applied.seq < event.seq < deleted.seq
    ]
    assert fresh_reads
    assert deleted.actor == "fresh"

    unapplied = reports["cas-unapplied-fresh-retry"].bucket
    assert [
        event.actor for event in unapplied.history
        if event.op == "cas" and isinstance(event.result, Applied)
    ] == ["fresh"]
    assert [
        rule.fault for rule in unapplied.fault_script
        if rule.op == "cas"
    ] == [Fault.TRANSPORT, Fault.TRANSPORT]

    pile_before = reports["pile-delete-unapplied"].bucket
    assert [
        event.actor for event in pile_before.history
        if event.op == "delete" and event.key.startswith("pile/")
    ] == ["fresh"]
    pile_after = reports["pile-delete-applied-response-lost"].bucket
    assert [
        event.actor for event in pile_after.history
        if event.op == "delete" and event.key.startswith("pile/")
    ] == ["first"]

    object_before = reports["object-delete-unapplied"].bucket
    assert [
        event.actor for event in object_before.history
        if event.op == "delete" and event.key.startswith("stage/")
    ] == ["fresh-cleanup"]
    object_after = reports[
        "object-delete-applied-response-lost"].bucket
    assert [
        event.actor for event in object_after.history
        if event.op == "delete" and event.key.startswith("stage/")
    ] == ["cleanup"]


def _weak_attempt_is_not_a_witness(path, seed):
    history = _History(path, seed)
    first = history.actor("weak")
    history.bucket.fail(
        "weak", "cas", "root", Fault.TRANSPORT,
        when="before", nth=1)
    history.bucket.fail(
        "weak", "cas", "root", Fault.TRANSPORT,
        when="before", nth=2)
    first.turn(history.workspace)
    assert first.store(history.workspace).get(history.pile_key) \
        == history.pile_raw
    # Planted weak policy: retry count/CAS attempt is treated as authority.
    first.store(history.workspace).delete(history.pile_key)
    try:
        history.trace.check()
    except ObligationViolation as error:
        history.close()
        return error
    history.close()
    raise AssertionError("weak CAS-attempt retirement unexpectedly passed")


def test_weak_cas_attempt_retirement_has_a_replayable_first_failure(tmp_path):
    first = _weak_attempt_is_not_a_witness(
        tmp_path / "first", HISTORY_SEED)
    replay = _weak_attempt_is_not_a_witness(
        tmp_path / "replay", HISTORY_SEED)

    assert "no post-create runtime publication classification" in first.reason
    assert first.event.seq == replay.event.seq
    assert first.event.op == replay.event.op == "delete"
    assert first.event.key == replay.event.key
    assert first.prefix == replay.prefix


def _weak_delete_response_is_not_cleanup(path, seed):
    history = _History(path, seed)
    key, (_oid, raw) = next(iter(history.stage_objects.items()))
    store = history.bucket.handle("weak-cleanup")
    history.bucket.fail(
        "weak-cleanup", "delete", key, Fault.TRANSPORT,
        when="before")
    try:
        store.delete(key)
    except OutcomeUnknown:
        pass  # planted weak policy: unknown is called successful cleanup
    try:
        check_stage_cleanup(history.bucket)
    except StageCleanupViolation as error:
        history.close()
        return error
    history.close()
    raise AssertionError("weak ambiguous cleanup unexpectedly passed")


def test_weak_ambiguous_delete_has_a_replayable_first_failure(tmp_path):
    first = _weak_delete_response_is_not_cleanup(
        tmp_path / "first", HISTORY_SEED)
    replay = _weak_delete_response_is_not_cleanup(
        tmp_path / "replay", HISTORY_SEED)

    assert first.event is replay.event is None
    assert "left acknowledged staging values live" in first.reason
    assert first.prefix == replay.prefix


def test_exact_retirement_refuses_a_changed_staging_value(tmp_path):
    history = _History(tmp_path, HISTORY_SEED)
    try:
        key, (_oid, raw) = next(iter(history.stage_objects.items()))
        attacker = history.bucket.handle("broker-parent")
        attacker.put(key, raw + b"changed")

        with pytest.raises(OSError, match="retirement source changed"):
            retire_exact(
                history.bucket.handle("publisher"), key, raw)
        assert attacker.get(key) == raw + b"changed"
        assert not [
            event for event in history.bucket.history
            if event.op == "delete" and event.key == key
        ]
        with pytest.raises(
                StageCleanupViolation,
                match="staging bytes were overwritten"):
            check_stage_cleanup(
                history.bucket, require_drained=False)
    finally:
        history.close()


def _replacement_race_failure(path, seed):
    """Violate replace-proof addressing after exact GET, before DELETE."""
    history = _History(path, seed)
    key, (_oid, raw) = next(iter(history.stage_objects.items()))
    publisher = history.bucket.handle("publisher")
    parent = history.bucket.handle("broker-parent")
    before_delete = history.bucket.pause(
        "publisher", "delete", key, when="before")
    replacement = raw + b"changed-after-exact-read"
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            retirement = pool.submit(
                retire_exact, publisher, key, raw)
            before_delete.wait()
            parent.put(key, replacement)
            before_delete.release.set()
            # This is deliberately *not* a safe-history assertion. It exposes
            # what an unconditional DELETE does when the documented stable-
            # address precondition is violated.
            assert retirement.result(timeout=5) is True
        assert parent.get(key) is None
        try:
            check_stage_cleanup(history.bucket)
        except StageCleanupViolation as error:
            history.close()
            return error
    except BaseException:
        before_delete.release.set()
        history.close()
        raise
    history.close()
    raise AssertionError("replacement race unexpectedly passed")


def test_parent_replacement_between_exact_get_and_delete_is_rejected(
        tmp_path):
    first = _replacement_race_failure(
        tmp_path / "first", HISTORY_SEED)
    replay = _replacement_race_failure(
        tmp_path / "replay", HISTORY_SEED)

    assert first.event.op == replay.event.op == "put"
    assert first.event.actor == replay.event.actor == "broker-parent"
    assert "staging bytes were overwritten" in first.reason
    assert first.prefix == replay.prefix


def test_node_retirement_call_boundary_requires_hash_bound_pile(tmp_path):
    history = _History(tmp_path, HISTORY_SEED)
    try:
        node = history.actor("publisher")
        wrong = f"pile/{history.member}/{'0' * 64}"

        with pytest.raises(
                ValueError,
                match="ingress source is not bound to exact bytes"):
            node._retire_ingress_exact(
                history.workspace, wrong, history.pile_raw)
        assert not [
            event for event in history.bucket.history
            if event.op == "delete" and event.key == wrong
        ]
    finally:
        history.close()
