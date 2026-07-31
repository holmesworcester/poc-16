"""Real ingress failures are isolated, durable and visible."""
import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
import facts

from core import (
    close, daemon, fact, merkle_map, object_store,
    repository_applier as repository_applier_module, snapshot, status,
)
from core.crypto import h
from core.fact import Fact, canon
from core.ingress import InvalidPile
from core.limits import (
    MAX_ATOM_NAME_BYTES,
    MAX_ATOM_VALUE_BYTES,
    PayloadTooLarge,
)
from core.node import Node
from core.object_store import OutcomeUnknown
from core.store import FsStore
from facts.content import message as message_family
from tests.util import all_fids, closed_subset, deliver


def run(awaitable):
    return asyncio.run(awaitable)


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


def test_pile_codec_requires_one_canonical_json_spelling():
    workspace = "0" * 64
    canonical = close.encode_pile((), workspace=workspace)
    assert close.decode_pile(canonical, workspace) == []

    aliases = (
        b'{ "facts": [], "ws": "' + workspace.encode() + b'" }',
        b'{"ws":"' + workspace.encode() + b'","facts":[]}',
        b'{"facts":[],"ws":"' + workspace.encode()
        + b'","ws":"' + workspace.encode() + b'"}',
        b'{"facts":[],"ws":NaN}',
        b'{"facts":[],"ws":Infinity}',
    )
    for raw in aliases:
        with pytest.raises(InvalidPile):
            close.decode_pile(raw, workspace)


def test_generic_atom_grammar_enforces_exact_text_and_fid_bounds():
    workspace = "0" * 64
    fid = "f" * 64
    valid = Fact(
        "unknown",
        1,
        [
            ["ref", "r" * MAX_ATOM_NAME_BYTES, fid],
            [
                "offer",
                "n" * MAX_ATOM_NAME_BYTES,
                "v" * MAX_ATOM_VALUE_BYTES,
                "w" * MAX_ATOM_VALUE_BYTES,
            ],
        ],
        {},
        workspace,
    )
    raw = close.encode_pile((valid,), workspace=workspace)
    assert close.decode_pile(raw, workspace) == [valid]

    malformed = (
        ["ref", "", fid],
        ["ref", "r" * (MAX_ATOM_NAME_BYTES + 1), fid],
        ["ref", "role", []],
        ["ref", "role", "not-a-fid"],
        ["offer", "", "value"],
        ["offer", "name", ""],
        ["offer", "name", "value", ""],
        ["offer", "n" * (MAX_ATOM_NAME_BYTES + 1), "value"],
        ["offer", "name", "v" * (MAX_ATOM_VALUE_BYTES + 1)],
        ["offer", "name", []],
    )
    for atom in malformed:
        poison = Fact("unknown", 1, [atom], {}, workspace)
        with pytest.raises(InvalidPile):
            close.decode_pile(
                close.encode_pile((poison,), workspace=workspace),
                workspace,
            )


def test_poisoned_pile_is_quarantined_and_unrelated_pile_continues(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "source", ts=1)
    survivor = facts.content.message.post(source, workspace, "general", "survives", ts=2)

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "source", [])
    good = closed_subset(source, workspace, [survivor])
    bad = poisoned_timestamp_pile(workspace)
    deliver(destination, workspace, bad, member="0000000000000000")
    deliver(destination, workspace, good, member="ffffffffffffffff")

    destination.turn(workspace)

    assert destination.fact_of(workspace, survivor) is not None
    assert destination.store(workspace).list("pile/") == []
    failures = status.describe(destination)["workspaces"][workspace][
        "ingress_failures"]
    assert len(failures) == 1
    assert failures[0]["error"] == "InvalidPile: fact shape"
    assert destination.store(workspace).get(
        "failed/pile/" + h(bad)) == bad

    restarted = Node(str(tmp_path / "destination"))
    assert restarted.fact_of(workspace, survivor) is not None
    assert restarted.store(workspace).list("pile/") == []
    assert status.describe(restarted)["workspaces"][workspace][
        "ingress_failures"] == failures


def queued_messages(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "source", ts=1)
    first = facts.content.message.post(source, workspace, "general", "first", ts=2)
    second = facts.content.message.post(source, workspace, "general", "second", ts=3)
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
    decode = repository_applier_module.decode_pile

    def program_failure(raw, expected_workspace):
        if raw == first_raw:
            raise ValueError("simulated decoder programming failure")
        return decode(raw, expected_workspace)

    monkeypatch.setattr(
        repository_applier_module, "decode_pile", program_failure)
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
def test_failed_root_commit_is_isolated_from_the_next_pile_and_retries(
        tmp_path, monkeypatch, boundary):
    node, workspace, first, second = queued_messages(tmp_path)
    first_fid, first_raw, first_key = first
    second_fid, _, second_key = second
    store = node.store(workspace)
    if boundary == "program":
        applier = node.applier(workspace)
        original = applier.commit
        calls = 0
        expected_error = "RuntimeError: simulated apply program failure"

        async def fail_first(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("simulated apply program failure")
            return await original(*args, **kwargs)

        monkeypatch.setattr(applier, "commit", fail_first)
    else:
        original = store.cas
        calls = 0
        expected_error = "OutcomeUnknown: simulated provider CAS outage"

        def fail_first(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OutcomeUnknown("simulated provider CAS outage")
            return original(*args, **kwargs)

        monkeypatch.setattr(store, "cas", fail_first)

    node.turn(workspace)

    assert store.get(first_key) == first_raw
    assert store.get(second_key) is None
    assert node.fact_of(workspace, first_fid) is None
    assert node.fact_of(workspace, first_fid) is None
    assert node.fact_of(workspace, second_fid) is not None
    assert store.list("failed/") == []
    failures = node.ingress_attempt_failures(workspace)
    assert len(failures) == 1
    assert failures[0]["source"] == first_key
    assert failures[0]["error"] == expected_error

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
    applier = node.applier(workspace)
    commit = applier.commit

    async def fail_first_pile(source, *args, **kwargs):
        if source == first_key:
            raise OutcomeUnknown("persistent provider outage for this pile")
        return await commit(source, *args, **kwargs)

    monkeypatch.setattr(applier, "commit", fail_first_pile)

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


def test_failed_root_read_is_isolated_from_the_next_pile(
        tmp_path, monkeypatch):
    node, workspace, first, second = queued_messages(tmp_path)
    first_fid, first_raw, first_key = first
    second_fid, _, second_key = second
    store = node.store(workspace)
    read_versioned = store.read_versioned
    calls = 0

    def fail_first_read(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OutcomeUnknown("authoritative root unavailable")
        return read_versioned(*args, **kwargs)

    monkeypatch.setattr(store, "read_versioned", fail_first_read)
    node.turn(workspace)

    assert store.get(first_key) == first_raw
    assert store.get(second_key) is None
    assert store.list("failed/") == []
    assert node.fact_of(workspace, first_fid) is None
    assert node.fact_of(workspace, second_fid) is not None
    failure = node.ingress_attempt_failures(workspace)[0]
    assert failure["source"] == first_key
    assert failure["error"] == \
        "OutcomeUnknown: authoritative root unavailable"


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
    workspace = facts.auth.workspace.create(source, "source", ts=1)
    survivor = facts.content.message.post(source, workspace, "general", "survives", ts=2)
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
    workspace = facts.auth.workspace.create(source, "source", ts=1)
    survivor = facts.content.message.post(source, workspace, "general", "survives", ts=2)
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


def test_failure_status_follows_short_native_pages_without_whole_list(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "node", ts=1)
    inner = node.store(workspace)
    expected = []
    for ordinal in range(3):
        record = {
            "error": f"InvalidPile: poison {ordinal}",
            "id": f"failure-{ordinal}",
            "source": f"pile/member/{ordinal}",
            "ts": ordinal,
        }
        raw = canon(record)
        inner.put_if_absent("failed/meta/" + h(raw), raw)
        expected.append(record)

    class ShortPages:
        def __init__(self):
            self.calls = []

        def __getattr__(self, name):
            return getattr(inner, name)

        def list(self, _prefix):
            raise AssertionError("failure status used whole LIST")

        def list_page(self, prefix, cursor, limit):
            self.calls.append((prefix, cursor, limit))
            return inner.list_page(prefix, cursor, 1)

    short = ShortPages()
    node._stores[workspace] = short

    assert node.ingress_failures(workspace) == expected
    assert len(short.calls) == len(expected)
    assert {prefix for prefix, _, _ in short.calls} == {
        "failed/meta/"}
    assert [limit for _, _, limit in short.calls] == [256, 255, 254]


def test_two_workers_share_immutable_rejection_evidence_without_clobber(
        tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    factory = lambda workspace: FsStore(str(shared / workspace))
    first = Node(str(tmp_path / "first"), store_factory=factory)
    workspace = facts.auth.workspace.create(first, "shared", ts=1)
    second = Node(str(tmp_path / "second"), store_factory=factory)
    second.add_workspace(workspace, "shared", [])
    second.rebuild(workspace)
    bad = poisoned_timestamp_pile(workspace)
    source = run(first.applier(workspace).stage(
        "0000000000000000", bad))

    listed = threading.Barrier(2)
    retiring = threading.Barrier(2)
    for node in (first, second):
        store = node.store(workspace)
        list_page = store.list_page
        delete = store.delete

        def synchronized_list_page(
                prefix, cursor, limit, list_page=list_page):
            page = list_page(prefix, cursor, limit)
            if prefix == "pile/":
                listed.wait(timeout=5)
            return page

        def synchronized_delete(key, delete=delete):
            if key == source:
                retiring.wait(timeout=5)
            return delete(key)

        monkeypatch.setattr(store, "list_page", synchronized_list_page)
        monkeypatch.setattr(store, "delete", synchronized_delete)

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
    workspace = facts.auth.workspace.create(node, "node", ts=1)
    peer = "https://peer.invalid"

    node.record_sync_failure(
        workspace, peer, ValueError("remote object integrity"))
    row = status.describe(node)["workspaces"][workspace]["sync_failures"]
    assert len(row) == 1
    assert row[0]["peer"] == peer
    assert row[0]["error"] == "ValueError: remote object integrity"

    node.record_sync_success(workspace, peer)
    assert status.describe(node)["workspaces"][workspace][
        "sync_failures"] == []


def test_legacy_removal_field_is_rejected_instead_of_partly_decoded(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "node", ts=1)
    store = node.store(workspace)
    root = json.loads(store.get("root"))
    root["removals"] = {"oid": "", "fp": ""}

    with pytest.raises(ValueError, match="root shape"):
        snapshot.decode_root(canon(root))


@pytest.mark.parametrize("decoder", [
    close.decode_pile,
    snapshot.decode_root,
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


def test_pile_and_root_codecs_reject_size_before_parsing(monkeypatch):
    workspace = "0" * 64
    cases = (
        (
            close, "MAX_PILE_BYTES",
            lambda raw: close.decode_pile(raw, workspace),
            canon({"ws": workspace, "facts": []}),
        ),
        (snapshot, "MAX_ROOT_BYTES", snapshot.decode_root, b'{"stamp":"x"}'),
    )
    for module, limit, decoder, raw in cases:
        monkeypatch.setattr(module, limit, len(raw) - 1)
        with pytest.raises(PayloadTooLarge):
            decoder(raw)


def test_pile_encoder_and_object_admission_enforce_the_reader_bounds(
        monkeypatch):
    workspace = "0" * 64
    empty = close.encode_pile((), workspace=workspace)
    monkeypatch.setattr(close, "MAX_PILE_BYTES", len(empty) - 1)
    with pytest.raises(PayloadTooLarge):
        close.encode_pile((), workspace=workspace)

    class NeverWritten:
        def put_if_absent(self, *_args):
            raise AssertionError("oversized object was written")

        def get(self, _key):
            raise AssertionError("oversized object was read")

    raw = b"too large"
    monkeypatch.setattr(object_store, "MAX_OBJECT_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="address"):
        run(repository_applier_module.RepositoryApplier(
            workspace, NeverWritten()).admit_object(h(raw), raw))


def test_daemon_body_rejects_claimed_oversize_without_reading():
    class NeverRead:
        def read(self, _count):
            raise AssertionError("oversized body was read")

    handler = object.__new__(daemon.Handler)
    handler.headers = {"Content-Length": "9"}
    handler.rfile = NeverRead()

    with pytest.raises(PayloadTooLarge):
        handler._body(8)


def test_repeated_retirement_failures_keep_one_exact_receipt_slot(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    raw = close.encode_pile((), workspace=workspace)
    source = node.stage_received_pile(
        workspace, node.member_for(workspace), raw)
    store = node.store(workspace)
    real_delete = store.delete
    applier = node.applier(workspace)
    real_propose = applier.propose
    proposals = 0

    async def counted_propose(value):
        nonlocal proposals
        proposals += 1
        return await real_propose(value)

    def failed_delete(_key):
        raise OSError("injected retirement outage")

    monkeypatch.setattr(store, "delete", failed_delete)
    monkeypatch.setattr(applier, "propose", counted_propose)

    for _ in range(5):
        node.turn(workspace)

    assert store.get(source) == raw
    assert proposals == 1
    assert len(applier._receipts) == 1
    assert store.list("failed/") == []
    assert node.ingress_attempt_failures(workspace)[0]["error"] == \
        "OSError: injected retirement outage"

    monkeypatch.setattr(store, "delete", real_delete)
    node.turn(workspace)
    assert store.get(source) is None
    assert applier._receipts == {}


def test_distinct_failed_applies_retain_only_store_bound_pile_bytes(
        tmp_path, monkeypatch):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    bootstrap = closed_subset(
        source, workspace, all_fids(source, workspace))
    fids = [
        facts.content.message.post(
            source, workspace, "general", f"failed-{ordinal}",
            ts=10 + ordinal)
        for ordinal in range(8)
    ]
    raws = [
        closed_subset(source, workspace, [fid])
        for fid in fids
    ]
    assert len(set(raws)) == 8

    node = Node(str(tmp_path / "node"))
    node.add_workspace(workspace, "alice", peers=[])
    deliver(node, workspace, bootstrap)
    node.turn(workspace)
    store = node.store(workspace)
    queued = {
        deliver(
            node, workspace, raw,
            member=f"{ordinal:016x}",
        ): raw
        for ordinal, raw in enumerate(raws)
    }
    assert len(queued) == 8
    applier = node.applier(workspace)

    async def fail_commit(*_args, **_options):
        raise OSError("injected root commit outage")

    monkeypatch.setattr(applier, "commit", fail_commit)
    node.turn(workspace)

    assert set(store.list("pile/")) == set(queued)
    assert all(store.get(key) == raw for key, raw in queued.items())
    assert applier._receipts == {}
    failures = node.ingress_attempt_failures(workspace)
    assert len(failures) == len(queued)
    assert {failure["source"] for failure in failures} == set(queued)
    assert {
        failure["error"] for failure in failures
    } == {"OSError: injected root commit outage"}
