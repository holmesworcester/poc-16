"""Real ingress failures are isolated, durable and visible."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from core import (
    close, cmds, daemon, fact, manifest, merkle_map, node as node_module,
    object_store, runtime, sync,
)
from core.crypto import h
from core.fact import Fact, canon
from core.ingress import stage_pile
from core.limits import PayloadTooLarge
from core.node import Node
from core.object_store import OutcomeUnknown
from core.store import FsStore
from facts.content import message as message_family
from tests.util import closed_subset, deliver


def poisoned_timestamp_pile(workspace):
    body = {}
    envelope = {
        "a": [],
        "bh": h(canon(body)),
        "t": "msg",
        "ts": -1,
    }
    return canon({
        "ws": workspace,
        "facts": [{"b": body, "e": envelope}],
    })


def test_poisoned_pile_is_quarantined_and_unrelated_pile_continues(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "source", ts=1)
    survivor = cmds.post(source, workspace, "general", "survives", ts=2)

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "source", [])
    good = closed_subset(source, workspace, [survivor])
    bad = poisoned_timestamp_pile(workspace)
    deliver(destination, workspace, bad, member="0000000000000000")
    deliver(destination, workspace, good, member="ffffffffffffffff")

    destination.turn(workspace)

    assert destination.fact_of(workspace, survivor) is not None
    assert destination.store(workspace).list("pile/") == []
    failures = cmds.status(destination)["workspaces"][workspace][
        "ingress_failures"]
    assert len(failures) == 1
    assert failures[0]["error"] == "InvalidPile: fact shape"
    assert destination.store(workspace).get(
        "failed/pile/" + h(bad)) == bad

    restarted = Node(str(tmp_path / "destination"))
    assert restarted.fact_of(workspace, survivor) is not None
    assert restarted.store(workspace).list("pile/") == []
    assert cmds.status(restarted)["workspaces"][workspace][
        "ingress_failures"] == failures


def queued_messages(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "source", ts=1)
    first = cmds.post(source, workspace, "general", "first", ts=2)
    second = cmds.post(source, workspace, "general", "second", ts=3)
    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "source", [])
    first_raw = closed_subset(source, workspace, [first])
    second_raw = closed_subset(source, workspace, [second])
    first_key = deliver(
        destination, workspace, first_raw, member="0000000000000000")
    second_key = deliver(
        destination, workspace, second_raw, member="ffffffffffffffff")
    return (
        destination, workspace,
        (first, first_raw, first_key),
        (second, second_raw, second_key),
    )


def test_untyped_decoder_failure_retains_exact_pile_and_does_not_wedge(
        tmp_path, monkeypatch):
    node, workspace, first, second = queued_messages(tmp_path)
    first_fid, first_raw, first_key = first
    second_fid, _, second_key = second
    decode = node_module.decode_pile

    def program_failure(raw, expected_workspace):
        if raw == first_raw:
            raise ValueError("simulated decoder programming failure")
        return decode(raw, expected_workspace)

    monkeypatch.setattr(node_module, "decode_pile", program_failure)
    node.turn(workspace)

    assert node.store(workspace).get(first_key) == first_raw
    assert node.store(workspace).get(second_key) is None
    assert node.store(workspace).list("failed/pile/") == []
    assert node.fact_of(workspace, first_fid) is None
    assert node.fact_of(workspace, second_fid) is not None
    assert node.ingress_attempt_failures(workspace)[0]["error"] == \
        "ValueError: simulated decoder programming failure"


def test_untyped_fact_decoder_value_error_is_not_a_quarantine_verdict(
        monkeypatch):
    def program_failure(_value):
        raise ValueError("simulated fact decoder programming failure")

    monkeypatch.setattr(close, "from_json", program_failure)
    workspace = "0" * 64
    raw = canon({"ws": workspace, "facts": [{}]})

    with pytest.raises(
            ValueError, match="simulated fact decoder programming failure"):
        close.decode_pile(raw, workspace)


def test_family_program_failure_retains_exact_pile_and_does_not_wedge(
        tmp_path, monkeypatch):
    node, workspace, first, second = queued_messages(tmp_path)
    first_fid, first_raw, first_key = first
    second_fid, _, second_key = second
    needs = message_family.needs

    def program_failure(item):
        if item.fid == first_fid:
            raise RuntimeError("simulated family programming failure")
        return needs(item)

    monkeypatch.setattr(message_family, "needs", program_failure)
    node.turn(workspace)

    assert node.store(workspace).get(first_key) == first_raw
    assert node.store(workspace).get(second_key) is None
    assert node.store(workspace).list("failed/pile/") == []
    assert node.fact_of(workspace, first_fid) is None
    assert node.fact_of(workspace, second_fid) is not None
    assert node.ingress_attempt_failures(workspace)[0]["error"] == \
        "RuntimeError: simulated family programming failure"


@pytest.mark.parametrize("boundary", ["program", "provider"])
def test_failed_publication_is_isolated_from_the_next_pile_and_retries(
        tmp_path, monkeypatch, boundary):
    node, workspace, first, second = queued_messages(tmp_path)
    first_fid, first_raw, first_key = first
    second_fid, _, second_key = second
    store = node.store(workspace)
    if boundary == "program":
        original = node.commit_ingress
        calls = 0

        def fail_first(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("simulated publication program failure")
            return original(*args, **kwargs)

        monkeypatch.setattr(node, "commit_ingress", fail_first)
    else:
        original = store.cas
        calls = 0

        def fail_first(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls <= 2:
                raise OutcomeUnknown("simulated provider CAS outage")
            return original(*args, **kwargs)

        monkeypatch.setattr(store, "cas", fail_first)

    node.turn(workspace)

    assert store.get(first_key) == first_raw
    assert store.get(second_key) is None
    assert node.candidate_of(workspace, first_fid) is not None
    assert node.fact_of(workspace, first_fid) is None
    assert node.fact_of(workspace, second_fid) is not None
    assert node.idx(workspace).execute(
        "SELECT 1 FROM staged WHERE fid=?", (first_fid,)).fetchone() == (1,)
    assert node.ingress_attempt_failures(workspace)

    for index in node._idx.values():
        index.close()
    reopened = Node(node.dir)
    reopened.turn(workspace)

    assert reopened.fact_of(workspace, first_fid) is not None
    assert reopened.store(workspace).list("pile/") == []
    assert reopened.ingress_attempt_failures(workspace) == []


def test_retryable_failure_never_ages_into_destructive_quarantine(
        tmp_path, monkeypatch):
    node, workspace, first, second = queued_messages(tmp_path)
    first_fid, first_raw, first_key = first
    second_fid, _, second_key = second
    commit = node.commit_ingress

    def fail_first_pile(admission, *args, **kwargs):
        if admission.source == first_key:
            raise OutcomeUnknown("persistent provider outage for this pile")
        return commit(admission, *args, **kwargs)

    monkeypatch.setattr(node, "commit_ingress", fail_first_pile)

    for _ in range(12):
        node.turn(workspace)

    assert node.store(workspace).get(first_key) == first_raw
    assert node.store(workspace).get(second_key) is None
    assert node.store(workspace).list("failed/") == []
    assert node.fact_of(workspace, first_fid) is None
    assert node.fact_of(workspace, second_fid) is not None
    failure = node.ingress_attempt_failures(workspace)[0]
    assert failure["error"] == \
        "OutcomeUnknown: persistent provider outage for this pile"


def test_failed_authoritative_restore_stops_before_the_next_pile(
        tmp_path, monkeypatch):
    node, workspace, first, second = queued_messages(tmp_path)
    first_fid, first_raw, first_key = first
    second_fid, second_raw, second_key = second

    def fail_commit(*_args, **_kwargs):
        raise RuntimeError("simulated publication failure")

    def fail_restore(_workspace):
        raise OutcomeUnknown("authoritative root unavailable")

    monkeypatch.setattr(node, "commit_ingress", fail_commit)
    monkeypatch.setattr(node, "_restore_authoritative_state", fail_restore)

    with pytest.raises(
            OutcomeUnknown, match="authoritative root unavailable"):
        node.turn(workspace)

    assert node.store(workspace).get(first_key) == first_raw
    assert node.store(workspace).get(second_key) == second_raw
    assert node.store(workspace).list("failed/") == []
    assert node.fact_of(workspace, first_fid) is not None
    assert node.fact_of(workspace, second_fid) is None
    failure = node.ingress_attempt_failures(workspace)[0]
    assert "publication failure" in failure["error"]
    assert "authoritative restore failed" in failure["error"]


@pytest.mark.parametrize(
    ("boundary", "source_survives", "payload_exact"),
    [
        ("payload", True, False),
        ("metadata", True, True),
        ("delete-before", True, True),
        ("delete-after", False, True),
    ],
)
def test_rejection_retirement_requires_exact_durable_evidence(
        tmp_path, monkeypatch, boundary, source_survives, payload_exact):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "source", ts=1)
    survivor = cmds.post(source, workspace, "general", "survives", ts=2)
    node = Node(str(tmp_path / "destination"))
    node.add_workspace(workspace, "source", [])
    bad = poisoned_timestamp_pile(workspace)
    good = closed_subset(source, workspace, [survivor])
    bad_key = deliver(
        node, workspace, bad, member="0000000000000000")
    deliver(node, workspace, good, member="ffffffffffffffff")
    store = node.store(workspace)

    if boundary == "payload":
        put_if_absent = store.put_if_absent

        def corrupt_payload(key, value):
            if key.startswith("failed/pile/"):
                return put_if_absent(key, b"wrong rejection bytes")
            return put_if_absent(key, value)

        monkeypatch.setattr(store, "put_if_absent", corrupt_payload)
    elif boundary == "metadata":
        put_if_absent = store.put_if_absent

        def corrupt_metadata(key, value):
            if key.startswith("failed/meta/"):
                return put_if_absent(key, b"wrong metadata bytes")
            return put_if_absent(key, value)

        monkeypatch.setattr(store, "put_if_absent", corrupt_metadata)
    else:
        delete = store.delete

        def ambiguous_delete(key):
            if key == bad_key:
                if boundary == "delete-after":
                    delete(key)
                raise OutcomeUnknown("simulated lost delete response")
            return delete(key)

        monkeypatch.setattr(store, "delete", ambiguous_delete)

    node.turn(workspace)

    assert node.fact_of(workspace, survivor) is not None
    assert (store.get(bad_key) is not None) is source_survives
    payload = store.get("failed/pile/" + h(bad))
    assert (payload == bad) is payload_exact
    if source_survives:
        assert node.ingress_attempt_failures(workspace)
    else:
        assert node.ingress_attempt_failures(workspace) == []
    if boundary == "delete-before":
        for _ in range(4):
            node.turn(workspace)
        assert store.get(bad_key) == bad
        assert len(store.list("failed/meta/")) == 1


def test_decoded_kernel_rejection_is_the_only_other_quarantine_verdict(
        tmp_path, monkeypatch):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "source", ts=1)
    survivor = cmds.post(source, workspace, "general", "survives", ts=2)
    node = Node(str(tmp_path / "destination"))
    node.add_workspace(workspace, "source", [])
    rejected = close.encode_pile([
        Fact(
            "signature", 3,
            [["offer", "author", "not-a-fact", source.pk]], {}, workspace),
    ], workspace=workspace)
    deliver(node, workspace, rejected, member="0000000000000000")
    deliver(
        node, workspace,
        closed_subset(source, workspace, [survivor]),
        member="ffffffffffffffff")

    listed = []
    list_keys = node.store(workspace).list

    def observe_list(prefix):
        listed.append(prefix)
        return list_keys(prefix)

    monkeypatch.setattr(node.store(workspace), "list", observe_list)
    node.turn(workspace)

    assert node.fact_of(workspace, survivor) is not None
    assert not any(prefix.startswith("failed/") for prefix in listed)
    failure = node.ingress_failures(workspace)[0]
    assert failure["error"] == "KernelRejected: ingress rejected"
    assert node.store(workspace).get(
        "failed/pile/" + h(rejected)) == rejected


def test_two_workers_share_immutable_rejection_evidence_without_clobber(
        tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    factory = lambda workspace: FsStore(str(shared / workspace))
    first = Node(str(tmp_path / "first"), store_factory=factory)
    workspace = cmds.create(first, "shared", ts=1)
    second = Node(str(tmp_path / "second"), store_factory=factory)
    second.add_workspace(workspace, "shared", [])
    second.rebuild(workspace)
    bad = poisoned_timestamp_pile(workspace)
    source = stage_pile(
        first.store(workspace), "0000000000000000", bad)

    listed = threading.Barrier(2)
    retiring = threading.Barrier(2)
    for node in (first, second):
        store = node.store(workspace)
        list_keys = store.list
        retire = node._retire_rejected_ingress

        def synchronized_list(prefix, list_keys=list_keys):
            keys = list_keys(prefix)
            if prefix == "pile/":
                listed.wait(timeout=5)
            return keys

        def synchronized_retire(
                ws, key, raw, receipt, retire=retire):
            retiring.wait(timeout=5)
            return retire(ws, key, raw, receipt)

        monkeypatch.setattr(store, "list", synchronized_list)
        monkeypatch.setattr(node, "_retire_rejected_ingress",
                            synchronized_retire)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            pool.submit(node.turn, workspace)
            for node in (first, second)
        ]
        assert [future.result(timeout=10) for future in results] == [[], []]

    store = first.store(workspace)
    assert store.get(source) is None
    assert store.get("failed/pile/" + h(bad)) == bad
    meta_keys = store.list("failed/meta/")
    assert len(meta_keys) == 1
    records = [json.loads(store.get(key)) for key in meta_keys]
    assert all(record["id"] == h(bad) for record in records)
    assert all(record["source"] == source for record in records)
    assert all(
        record["error"] == "InvalidPile: fact shape"
        for record in records)
    assert first.ingress_attempt_failures(workspace) == []
    assert second.ingress_attempt_failures(workspace) == []
    assert first.ingress_failures(workspace) \
        == second.ingress_failures(workspace)


def test_sync_failure_and_recovery_are_exposed_in_status(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "node", ts=1)
    peer = "https://peer.invalid"

    node.record_sync_failure(
        workspace, peer, ValueError("remote object integrity"))
    row = cmds.status(node)["workspaces"][workspace]["sync_failures"]
    assert len(row) == 1
    assert row[0]["peer"] == peer
    assert row[0]["error"] == "ValueError: remote object integrity"

    node.record_sync_success(workspace, peer)
    assert cmds.status(node)["workspaces"][workspace][
        "sync_failures"] == []


def test_legacy_removal_field_is_rejected_instead_of_partly_decoded(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "node", ts=1)
    store = node.store(workspace)
    root = json.loads(store.get("root"))
    root["removals"] = {"oid": "", "fp": ""}

    with pytest.raises(ValueError, match="root shape"):
        manifest.decode_root(canon(root))


@pytest.mark.parametrize("decoder", [
    close.decode_pile,
    manifest.decode_root,
    sync._sibling_keys,
    fact.decode,
])
def test_json_codec_doors_translate_parser_recursion_to_value_error(decoder):
    nested = b"[" * 5_000 + b"0" + b"]" * 5_000

    with pytest.raises(ValueError):
        if decoder is close.decode_pile:
            decoder(nested, "0" * 64)
        else:
            decoder(nested)


def test_merkle_map_parser_recursion_is_also_a_value_error():
    nested = b"[" * 2_000 + b"0" + b"]" * 2_000

    with pytest.raises(ValueError, match="merkle map page shape"):
        merkle_map._decode(nested, h(nested), h(b"seed"))


def test_pile_root_and_sibling_codecs_reject_size_before_parsing(monkeypatch):
    workspace = "0" * 64
    cases = (
        (
            close, "MAX_PILE_BYTES",
            lambda raw: close.decode_pile(raw, workspace),
            canon({"ws": workspace, "facts": []}),
        ),
        (manifest, "MAX_ROOT_BYTES", manifest.decode_root, b'{"stamp":"x"}'),
        (sync, "MAX_OBJECT_BYTES", sync._sibling_keys, b'{"keys":[]}'),
    )
    for module, limit, decoder, raw in cases:
        monkeypatch.setattr(module, limit, len(raw) - 1)
        with pytest.raises(PayloadTooLarge):
            decoder(raw)


def test_pile_encoder_and_object_publisher_enforce_the_reader_bounds(
        monkeypatch):
    workspace = "0" * 64
    empty = close.encode_pile((), workspace=workspace)
    monkeypatch.setattr(close, "MAX_PILE_BYTES", len(empty) - 1)
    with pytest.raises(PayloadTooLarge):
        close.encode_pile((), workspace=workspace)

    class NeverWritten:
        def put_if_absent(self, *_args):
            raise AssertionError("oversized object was written")

    raw = b"too large"
    monkeypatch.setattr(object_store, "MAX_OBJECT_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="address"):
        object_store.ensure_object(NeverWritten(), h(raw), raw)


def test_daemon_body_rejects_claimed_oversize_without_reading():
    class NeverRead:
        def read(self, _count):
            raise AssertionError("oversized body was read")

    handler = object.__new__(daemon.Handler)
    handler.headers = {"Content-Length": "9"}
    handler.rfile = NeverRead()

    with pytest.raises(PayloadTooLarge):
        handler._body(8)


def test_repeated_retirement_failures_reuse_one_publication_capability(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    raw = close.encode_pile((), workspace=workspace)
    source = stage_pile(
        node.store(workspace), node.member_for(workspace), raw)
    store = node.store(workspace)
    real_delete = store.delete
    real_admit = node.admit_ingress
    admits = {"count": 0}

    def observed_admit(*args, **kwargs):
        admits["count"] += 1
        return real_admit(*args, **kwargs)

    def failed_delete(_key):
        raise OSError("injected retirement outage")

    monkeypatch.setattr(node, "admit_ingress", observed_admit)
    monkeypatch.setattr(store, "delete", failed_delete)

    for _ in range(5):
        node.turn(workspace)

    assert store.get(source) == raw
    assert admits["count"] == 1
    assert len(node._publication_receipts) == 1

    monkeypatch.setattr(store, "delete", real_delete)
    node.turn(workspace)
    assert store.get(source) is None
    assert node._publication_receipts == {}
