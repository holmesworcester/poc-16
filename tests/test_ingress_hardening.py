"""Real ingress failures are isolated, durable and visible."""
import json

import pytest
from core import (
    btreap, close, cmds, daemon, fact, manifest, object_store, sync,
)
from core.crypto import h
from core.fact import canon
from core.limits import PayloadTooLarge
from core.node import Node
from tests.util import closed_subset, deliver


def poisoned_timestamp_pile():
    body = {}
    envelope = {
        "a": [],
        "bh": h(canon(body)),
        "t": "msg",
        "ts": -1,
    }
    return canon({"facts": [{"b": body, "e": envelope}]})


def test_poisoned_pile_is_quarantined_and_unrelated_pile_continues(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "source", ts=1)
    survivor = cmds.post(source, workspace, "general", "survives", ts=2)

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "source", [])
    good = closed_subset(source, workspace, [survivor])
    bad = poisoned_timestamp_pile()
    deliver(destination, workspace, bad, member="0000000000000000")
    deliver(destination, workspace, good, member="ffffffffffffffff")

    destination.turn(workspace)

    assert destination.fact_of(workspace, survivor) is not None
    assert destination.store(workspace).list("pile/") == []
    failures = cmds.status(destination)["workspaces"][workspace][
        "ingress_failures"]
    assert len(failures) == 1
    assert failures[0]["error"] == "ValueError: fact shape"
    assert destination.store(workspace).get(
        "failed/pile/" + h(bad)) == bad

    restarted = Node(str(tmp_path / "destination"))
    assert restarted.fact_of(workspace, survivor) is not None
    assert restarted.store(workspace).list("pile/") == []
    assert cmds.status(restarted)["workspaces"][workspace][
        "ingress_failures"] == failures


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
        decoder(nested)


def test_btreap_parser_recursion_is_also_a_value_error():
    nested = b"[" * 2_000 + b"0" + b"]" * 2_000

    with pytest.raises(ValueError, match="btreap page shape"):
        btreap._decode(nested, h(nested), h(b"seed"))


def test_pile_root_and_sibling_codecs_reject_size_before_parsing(monkeypatch):
    cases = (
        (close, "MAX_PILE_BYTES", close.decode_pile, b'{"facts":[]}'),
        (manifest, "MAX_ROOT_BYTES", manifest.decode_root, b'{"stamp":"x"}'),
        (sync, "MAX_OBJECT_BYTES", sync._sibling_keys, b'{"keys":[]}'),
    )
    for module, limit, decoder, raw in cases:
        monkeypatch.setattr(module, limit, len(raw) - 1)
        with pytest.raises(PayloadTooLarge):
            decoder(raw)


def test_pile_encoder_and_object_publisher_enforce_the_reader_bounds(
        monkeypatch):
    empty = close.encode_pile(())
    monkeypatch.setattr(close, "MAX_PILE_BYTES", len(empty) - 1)
    with pytest.raises(PayloadTooLarge):
        close.encode_pile(())

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
