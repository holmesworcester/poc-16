"""Concurrent mobile endpoint cells converge through ordinary suppression."""
import facts

from core.crypto import h, keypair
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.auth.signature import signature
from full_peer.node import FullPeer


def test_replacement_suppresses_every_observed_installation_sibling(tmp_path):
    node = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    _first_secret, first_node = keypair()
    _second_secret, second_node = keypair()
    installation = h(b"one-installation")
    first = push_endpoint.register(
        node,
        workspace,
        installation,
        first_node,
        "android",
        "poc16.mobile",
        "production",
        push_endpoint.seal_target(first_node, "first-fid"),
        ts=2,
    )

    # This is the state produced when two independently registered branches
    # merge: family validity is monotone, so both facts are resident until an
    # ordinary suppression action joins the cell.
    sibling = push_endpoint.push_endpoint(
        workspace,
        node.pk,
        node.pk,
        installation,
        second_node,
        "android",
        "poc16.mobile",
        "production",
        push_endpoint.seal_target(second_node, "second-fid"),
        3,
    )
    signed = signature(node.sk, node.pk, sibling, 3)
    member = node.sql(workspace).resolve_offer(
        "member", node.pk, node.pk)
    device = node.sql(workspace).resolve_offer(
        "device_key", node.pk, node.pk)
    node.ingest_new(workspace, (signed, sibling), {
        signed.fid: (),
        sibling.fid: (signed.fid, member, device),
    })

    replacement = push_endpoint.replace(
        node,
        workspace,
        first,
        first_node,
        push_endpoint.seal_target(first_node, "current-fid"),
        ts=4,
    )

    view = node.sql(workspace)
    assert not view.fact_active(first)
    assert not view.fact_active(sibling.fid)
    assert view.fact_active(replacement)
    assert [row["fid"] for row in push_endpoint.endpoints(
        node, workspace, node.pk, installation)] == [replacement]
