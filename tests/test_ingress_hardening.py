"""Real ingress failures are isolated, durable and visible."""
import json

from core import cmds
from core.crypto import h
from core.fact import canon
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


def test_published_removal_decode_failure_is_guarded_and_reported(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "node", ts=1)
    store = node.store(workspace)
    root = json.loads(store.get("root"))
    malformed = canon({"entries": [], "refs": ["-1:" + "0" * 64]})
    store.put("obj/" + h(malformed), malformed)
    root["removals"] = {"oid": h(malformed), "fp": h(b"bad")}
    store.put("root", canon(root))

    assert node._published(workspace) == ((), ())
    failures = cmds.status(node)["workspaces"][workspace]["state_failures"]
    assert failures[0]["component"] == "published-removals"
    assert failures[0]["error"] == "ValueError: removal index shape"
