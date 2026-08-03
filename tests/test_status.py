"""Operational status reflects the accepted per-writer forest only."""
import asyncio

import facts

from core.crypto import keypair
from full_peer.node import FullPeer
from full_peer.status import describe
from tests.util import add_member


def test_status_has_no_predecessor_root_or_ingress_fields(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    before = tuple(node.store(workspace).list(""))

    row = describe(node)["workspaces"][workspace]

    assert {"root", "ingress_failures", "ingress_attempt_failures"}.isdisjoint(
        row)
    assert len(row["forest_fingerprint"]) == 64
    assert len(row["writers"]) == 1
    writer = row["writers"][0]
    assert writer["device"] == node.identity_id(workspace)
    assert writer["head"] == writer["projected_head"]
    assert row["projection_only"] == {}
    assert tuple(node.store(workspace).list("")) == before


def test_status_sorts_multiple_accepted_writer_checkpoints(tmp_path):
    alice = FullPeer(str(tmp_path / "alice"))
    workspace = facts.auth.workspace.create(alice, "alice", ts=1)
    bob_secret, bob_public = keypair()
    _, _, bob_join = add_member(
        alice,
        workspace,
        "bob",
        ts=10,
        member_identity=(bob_secret, bob_public),
        invite_identity=keypair(),
    )
    authority = alice.sender(workspace).close((bob_join,), {})
    bob = FullPeer(str(tmp_path / "bob"), initial_secret=bob_secret)
    bob.add_workspace(workspace, "bob", peers=[])
    bob.publish_closed(workspace, (authority,))

    result = asyncio.run(
        alice.mirror(workspace).sync_from(bob.store(workspace)))
    assert result.errors == ()

    row = describe(alice)["workspaces"][workspace]
    assert [writer["device"] for writer in row["writers"]] == sorted((
        alice.identity_id(workspace),
        bob.identity_id(workspace),
    ))
    assert all(
        writer["head"] == writer["projected_head"]
        for writer in row["writers"])


def test_status_replays_a_wiped_disposable_projection(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    message = facts.content.message.post(
        node, workspace, "general", "replay me", ts=10)
    expected = describe(node)["workspaces"][workspace]
    node.sql(workspace).reset()
    assert node.sql(workspace).fact_ids() == set()

    replayed = describe(node)["workspaces"][workspace]

    assert replayed["forest_fingerprint"] == expected["forest_fingerprint"]
    assert replayed["facts"] == expected["facts"]
    assert node.fact_of(workspace, message).body["text"] == "replay me"
    assert all(
        writer["head"] == writer["projected_head"]
        for writer in replayed["writers"])
