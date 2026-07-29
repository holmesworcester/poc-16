"""Destructive ingress retirement is justified by durable trace evidence."""
from concurrent.futures import ThreadPoolExecutor
import shutil
import threading

import pytest

from core import cmds
from core.close import encode_pile
from core.crypto import h
from core.fact import Fact, canon
from core.node import Node
from core.object_store import Applied
from facts.content import message as message_family

from .adversarial_bucket import AdversarialBucket, Fault
from .ingress_obligations import (
    ObligationTrace,
    ObligationViolation,
    production_call_sites,
)
from .shared_bucket import ScriptedBucket
from .test_ingress_hardening import poisoned_timestamp_pile
from .test_shared_bucket_node import _message_pile


def _snapshot(store):
    return {key: store.get(key) for key in store.list("")}


def _shared_nodes(
        seed, workspace, path, actors, *,
        bucket_type=ScriptedBucket, **bucket_options):
    initial = _snapshot(seed.store(workspace))
    for index in seed._idx.values():
        index.close()
    bucket = bucket_type(initial, **bucket_options)
    nodes = []
    for actor in actors:
        target = path / actor
        shutil.copytree(seed.dir, target)
        node = Node(str(target))
        node._stores[workspace] = bucket.handle(actor)
        nodes.append(node)
    return bucket, tuple(nodes)


def _observe_retirements(
        monkeypatch, trace, node, before_retire=None):
    retire = node._retire_ingress_exact

    def observed(workspace, key, raw):
        trace.observe_node_retirement(
            node, workspace, key, raw)
        if before_retire is not None:
            before_retire()
        return retire(workspace, key, raw)

    monkeypatch.setattr(node, "_retire_ingress_exact", observed)


def _put_pile(store, raw, member="shared"):
    key = f"pile/{member}/{h(raw)}"
    store.put_if_absent(key, raw)
    return key


def _forge_rejection(store, source, raw, error_type):
    payload = "failed/pile/" + h(raw)
    store.put_if_absent(payload, raw)
    assert store.get(payload) == raw
    record = canon({
        "error": f"{error_type}: forged",
        "id": h(raw),
        "source": source,
    })
    metadata = "failed/meta/" + h(record)
    store.put_if_absent(metadata, record)
    assert store.get(metadata) == record
    store.delete(source)


def test_winning_worker_delete_has_authenticated_publication_witness(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw, item = _message_pile(
        seed, workspace, "winner publishes", 10)
    bucket, (winner, _other) = _shared_nodes(
        seed, workspace, tmp_path, ("winner", "other"))
    trace = ObligationTrace(bucket, workspace)
    _observe_retirements(monkeypatch, trace, winner)
    source = _put_pile(winner.store(workspace), raw)

    winner.turn(workspace)

    report = trace.check()
    assert report.live == ()
    assert [(row.key, row.witness) for row in report.discharges] == [
        (source, "publication")]
    assert winner.fact_of(workspace, item.fid) == item


def test_already_represented_pile_retires_without_republishing(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw, item = _message_pile(
        seed, workspace, "already represented", 10)
    source = _put_pile(seed.store(workspace), raw)
    seed.turn(workspace)
    assert seed.store(workspace).get(source) is None
    bucket, (worker,) = _shared_nodes(
        seed, workspace, tmp_path, ("worker",))
    trace = ObligationTrace(bucket, workspace)
    _observe_retirements(monkeypatch, trace, worker)
    source = _put_pile(worker.store(workspace), raw)

    worker.turn(workspace)

    report = trace.check()
    assert report.live == ()
    assert bucket.commits == []
    assert [(row.key, row.witness_seq) for row in report.discharges] == [
        (source, 0)]
    assert worker.fact_of(workspace, item.fid) == item


def test_cas_loser_may_retire_only_after_reconciling_identical_winner_root(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw, item = _message_pile(
        seed, workspace, "same candidate", 10)
    bucket, (alice, bob) = _shared_nodes(
        seed, workspace, tmp_path, ("alice", "bob"))
    source = _put_pile(alice.store(workspace), raw)
    trace = ObligationTrace(bucket, workspace)

    listed = threading.Barrier(2)
    for node in (alice, bob):
        store = node.store(workspace)
        list_keys = store.list

        def synchronized_list(prefix, list_keys=list_keys):
            keys = list_keys(prefix)
            if prefix == "pile/":
                listed.wait(timeout=5)
            return keys

        monkeypatch.setattr(store, "list", synchronized_list)

    alice_before_cas = bucket.pause(
        "alice", "cas", "root", when="before")
    bob_cas = bob.store(workspace).cas

    def bob_waits_for_alice(key, expected, value):
        alice_before_cas.wait()
        return bob_cas(key, expected, value)

    monkeypatch.setattr(bob.store(workspace), "cas", bob_waits_for_alice)

    bob_at_retirement = threading.Event()
    release_bob = threading.Event()

    def hold_bob_after_commit():
        bob_at_retirement.set()
        if not release_bob.wait(timeout=5):
            raise AssertionError("Bob was not released")

    _observe_retirements(monkeypatch, trace, alice)
    _observe_retirements(
        monkeypatch, trace, bob, hold_bob_after_commit)

    with ThreadPoolExecutor(max_workers=2) as pool:
        alice_turn = pool.submit(alice.turn, workspace)
        bob_turn = pool.submit(bob.turn, workspace)
        assert bob_at_retirement.wait(timeout=10)
        alice_before_cas.release.set()
        alice_turn.result(timeout=10)
        release_bob.set()
        bob_turn.result(timeout=10)

    report = trace.check()
    assert report.live == ()
    assert [(row.key, row.witness) for row in report.discharges] == [
        (source, "publication")]
    applied = [
        event for event in bucket.history
        if event.op == "cas" and isinstance(event.result, Applied)]
    deletes = [
        event for event in bucket.history
        if event.op == "delete" and event.key == source]
    assert [event.actor for event in applied] == ["bob"]
    assert [event.actor for event in deletes] == ["alice"]
    assert alice.fact_of(workspace, item.fid) == item


def test_lost_applied_cas_response_reconciles_before_retirement(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw, item = _message_pile(
        seed, workspace, "response was lost", 10)
    bucket, (worker,) = _shared_nodes(
        seed, workspace, tmp_path, ("worker",),
        bucket_type=AdversarialBucket)
    trace = ObligationTrace(bucket, workspace)
    _observe_retirements(monkeypatch, trace, worker)
    source = _put_pile(worker.store(workspace), raw)
    bucket.fail(
        "worker", "cas", "root", Fault.RESPONSE_LOST,
        when="after", nth=1)

    with bucket.capture():
        worker.turn(workspace)
        report = trace.check()

    assert report.live == ()
    assert [(row.key, row.witness) for row in report.discharges] == [
        (source, "publication")]
    assert worker.fact_of(workspace, item.fid) == item
    assert any(
        event.op == "cas" and isinstance(event.result, Applied)
        for event in bucket.history)


def test_unknown_unapplied_cas_and_retry_count_never_support_delete(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw, _item = _message_pile(
        seed, workspace, "not committed", 10)
    bucket, (worker,) = _shared_nodes(
        seed, workspace, tmp_path, ("worker",),
        bucket_type=AdversarialBucket)
    trace = ObligationTrace(bucket, workspace)
    _observe_retirements(monkeypatch, trace, worker)
    source = _put_pile(worker.store(workspace), raw)
    bucket.fail(
        "worker", "cas", "root", Fault.TRANSPORT,
        when="before", nth=1)
    bucket.fail(
        "worker", "cas", "root", Fault.TRANSPORT,
        when="before", nth=2)

    worker.turn(workspace)
    assert worker.store(workspace).get(source) == raw
    assert worker.ingress_attempt_failures(workspace)

    # Mutation control: a retry counter or local error record is not proof.
    worker.store(workspace).delete(source)
    with pytest.raises(
            ObligationViolation,
            match=r"unsupported DELETE.*no post-create runtime"):
        trace.check()


def test_paginated_insertion_is_delayed_then_a_restarted_worker_drains_it(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    middle_raw, middle = _message_pile(
        seed, workspace, "first page", 10)
    late_raw, late = _message_pile(
        seed, workspace, "second page", 11)
    early_raw, early = _message_pile(
        seed, workspace, "inserted behind cursor", 12)
    bucket, (worker, stale) = _shared_nodes(
        seed, workspace, tmp_path, ("worker", "stale"),
        bucket_type=AdversarialBucket, list_page_size=1)
    uploader = bucket.handle("uploader")
    middle_key = _put_pile(
        uploader, middle_raw, member="8000000000000000")
    late_key = _put_pile(
        uploader, late_raw, member="ffffffffffffffff")
    trace = ObligationTrace(bucket, workspace)
    _observe_retirements(monkeypatch, trace, worker)
    first_page = bucket.pause(
        "worker", "list_page", "pile/", when="after", nth=1)

    with ThreadPoolExecutor(max_workers=1) as pool:
        first_turn = pool.submit(worker.turn, workspace)
        first_page.wait()
        early_key = _put_pile(
            uploader, early_raw, member="0000000000000000")
        first_page.release.set()
        first_turn.result(timeout=10)

    delayed = trace.check()
    assert [row.key for row in delayed.live] == [early_key]
    assert [row.key for row in delayed.discharges] == [
        middle_key, late_key]
    assert worker.fact_of(workspace, middle.fid) == middle
    assert worker.fact_of(workspace, late.fid) == late
    assert worker.fact_of(workspace, early.fid) is None

    # This process held the initial catalog while another Worker published.
    # Reopening forces it to understand the written root before its next turn.
    for index in stale._idx.values():
        index.close()
    restarted = Node(
        stale.dir,
        store_factory=lambda _workspace: bucket.handle("restarted"))
    _observe_retirements(monkeypatch, trace, restarted)
    restarted.turn(workspace)

    final = trace.check()
    assert final.live == ()
    assert [(row.key, row.witness) for row in final.discharges] == [
        (middle_key, "publication"),
        (late_key, "publication"),
        (early_key, "publication"),
    ]
    assert restarted.fact_of(workspace, middle.fid) == middle
    assert restarted.fact_of(workspace, late.fid) == late
    assert restarted.fact_of(workspace, early.fid) == early


def test_typed_exact_rejection_evidence_supports_the_other_delete_path(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    bucket, (worker, _other) = _shared_nodes(
        seed, workspace, tmp_path, ("worker", "other"))
    bad = poisoned_timestamp_pile(workspace)
    source = _put_pile(
        worker.store(workspace), bad,
        member="0000000000000000")
    trace = ObligationTrace(bucket, workspace)
    _observe_retirements(monkeypatch, trace, worker)

    worker.turn(workspace)

    report = trace.check()
    assert report.live == ()
    assert [(row.key, row.witness) for row in report.discharges] == [
        (source, "rejection")]


def test_real_kernel_rejection_supports_typed_exact_retirement(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    bucket, (worker,) = _shared_nodes(
        seed, workspace, tmp_path, ("worker",))
    rejected = encode_pile(
        [
            Fact(
                "signature", 3,
                [["offer", "author", "not-a-fact", seed.pk]], {},
                workspace),
        ],
        workspace=workspace,
    )
    source = _put_pile(worker.store(workspace), rejected)
    trace = ObligationTrace(bucket, workspace)
    _observe_retirements(monkeypatch, trace, worker)

    worker.turn(workspace)

    report = trace.check()
    assert report.live == ()
    assert [(row.key, row.witness) for row in report.discharges] == [
        (source, "rejection")]


def test_valid_pile_with_forged_invalid_pile_record_is_not_rejection(
        tmp_path):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw, _item = _message_pile(seed, workspace, "valid", 10)
    bucket, (worker,) = _shared_nodes(
        seed, workspace, tmp_path, ("worker",))
    store = worker.store(workspace)
    source = _put_pile(store, raw)
    _forge_rejection(store, source, raw, "InvalidPile")

    with pytest.raises(
            ObligationViolation,
            match=r"exact bytes pass.*rejection is forged"):
        ObligationTrace(bucket, workspace).check()


def test_program_failure_with_forged_kernel_rejection_is_not_input_local(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw, item = _message_pile(
        seed, workspace, "family failure", 10)
    bucket, (worker,) = _shared_nodes(
        seed, workspace, tmp_path, ("worker",))
    needs = message_family.needs

    def program_failure(fact):
        if fact.fid == item.fid:
            raise RuntimeError("family bug")
        return needs(fact)

    monkeypatch.setattr(message_family, "needs", program_failure)
    store = worker.store(workspace)
    source = _put_pile(store, raw)
    _forge_rejection(store, source, raw, "KernelRejected")

    with pytest.raises(
            ObligationViolation,
            match=r"family/program failure.*RuntimeError: family bug"):
        ObligationTrace(bucket, workspace).check()


def test_recreated_key_needs_a_new_post_create_witness(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw, _item = _message_pile(
        seed, workspace, "recreated obligation", 10)
    bucket, (worker,) = _shared_nodes(
        seed, workspace, tmp_path, ("worker",))
    trace = ObligationTrace(bucket, workspace)
    _observe_retirements(monkeypatch, trace, worker)
    source = _put_pile(worker.store(workspace), raw)
    worker.turn(workspace)
    assert trace.check().live == ()

    # Same address and bytes are safe to republish as intent, but this is a
    # new acknowledged lifetime. Stale cleanup from the first must not erase
    # it without observing the new obligation.
    worker.store(workspace).put_if_absent(source, raw)
    worker.store(workspace).delete(source)

    with pytest.raises(
            ObligationViolation,
            match=r"unsupported DELETE.*no post-create runtime"):
        trace.check()


def test_obsolete_good_root_cannot_mask_bad_current_authority(tmp_path):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    bucket = ScriptedBucket(_snapshot(seed.store(workspace)))
    store = bucket.handle("mutation")
    raw = b"classification supplied explicitly"
    source = _put_pile(store, raw)
    current = store.read_versioned("root")
    assert isinstance(store.cas(
        "root", current.token, b"malformed-current-root"), Applied)
    trace = ObligationTrace(bucket, workspace)
    trace.observe_publication(source, raw, {workspace})
    store.delete(source)

    with pytest.raises(
            ObligationViolation,
            match=r"current root.*is not authenticated"):
        trace.check()


def test_failure_reports_first_unsupported_delete_and_replay_prefix():
    bucket = ScriptedBucket(seed=0xF10)
    store = bucket.handle("mutation")
    first = _put_pile(store, b"first", member="0000000000000000")
    store.delete(first)
    second = _put_pile(store, b"second", member="ffffffffffffffff")
    store.delete(second)

    with pytest.raises(ObligationViolation) as caught:
        ObligationTrace(bucket, "f" * 64).check()

    error = caught.value
    assert error.event.key == first
    assert error.event.seq < next(
        event.seq for event in bucket.history
        if event.op == "delete" and event.key == second)
    assert error.prefix[-1] == error.event
    assert len(error.prefix) == error.event.seq


def test_production_delete_inventory_and_both_proof_callers_are_ratchets():
    root = __file__.rsplit("/tests/", 1)[0]
    deletes = production_call_sites(root, "delete")
    retirements = production_call_sites(
        root, "_retire_ingress_exact")

    assert [
        (
            site.path, site.function, site.line,
            site.receiver, site.use,
        )
        for site in deletes
    ] == [(
        "core/node.py", "_retire_ingress_exact", 209, "st", "direct")]
    assert [
        (
            site.path, site.function, site.line,
            site.receiver, site.use,
        )
        for site in retirements
    ] == [
        (
            "core/node.py", "_quarantine_ingress", 196,
            "self", "direct"),
        ("core/runtime.py", "turn", 97, "node", "direct"),
    ]


def test_delete_inventory_reports_alias_and_dynamic_capability(tmp_path):
    core = tmp_path / "core"
    core.mkdir()
    (core / "probe.py").write_text(
        "def alias(store, source):\n"
        "    deleter = store.delete\n"
        "    deleter(source)\n"
        "\n"
        "def dynamic(store, source):\n"
        "    deleter = getattr(store, 'delete')\n"
        "    deleter(source)\n")

    sites = production_call_sites(tmp_path, "delete")

    assert [
        (site.function, site.receiver, site.use)
        for site in sites
    ] == [
        ("alias", "store", "alias"),
        ("dynamic", "store", "getattr"),
    ]
