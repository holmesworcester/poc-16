"""Authority labels remain admissible through every hosted read path."""
import asyncio
import base64
import json

import pytest

import facts
from core import peer_capability
from core.close import encode_pile
from core.crypto import keypair
from core.fact import Fact
from core.http import HttpGate
from core.kernel import drain
from core.limits import MAX_REPOSITORY_OBJECT_BYTES
from deploy.cloudflare_worker import runtime as cloudflare
from facts.auth._display import MAX_DISPLAY_BYTES
from facts.auth.device import device
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from full_peer.node import FullPeer, now_ms

from .util import add_member


def _rebody(item, **changes):
    return Fact(
        item.t,
        item.ts,
        item.atoms,
        {**item.body, **changes},
        item.ws,
    )


def _signed(secret, public, item):
    return signature(secret, public, item, item.ts)


def test_authority_display_facts_use_one_utf8_byte_bound():
    exact = "é" * 127 + "a"
    oversized = exact + "b"
    assert len(exact.encode()) == MAX_DISPLAY_BYTES
    assert len(oversized.encode()) == MAX_DISPLAY_BYTES + 1

    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, exact, 1)
    hostile_root = _rebody(root, name=oversized)
    assert drain((root,), root.fid).ok
    assert not drain((hostile_root,), hostile_root.fid).ok
    with pytest.raises(ValueError, match="display"):
        workspace(founder_secret, founder, oversized, 1)

    invite_secret, invite_public = keypair()
    invitation = user_invite(root.fid, founder, invite_public, 2)
    invitation_signature = _signed(
        founder_secret, founder, invitation)
    member_secret, member = keypair()
    joined = user(invitation, invite_secret, member, exact, 3)
    joined_signature = _signed(member_secret, member, joined)
    user_base = (root, invitation_signature, invitation)
    assert drain(user_base + (joined_signature, joined), root.fid).ok
    hostile_user = _rebody(joined, name=oversized)
    assert not drain(
        user_base + (
            _signed(member_secret, member, hostile_user),
            hostile_user,
        ),
        root.fid,
    ).ok
    with pytest.raises(ValueError, match="display"):
        user(invitation, invite_secret, member, oversized, 3)

    primary = device(root.fid, founder, exact, 4)
    primary_signature = _signed(founder_secret, founder, primary)
    assert drain(
        (root, primary_signature, primary), root.fid).ok
    hostile_device = _rebody(primary, label=oversized)
    assert not drain(
        (
            root,
            _signed(founder_secret, founder, hostile_device),
            hostile_device,
        ),
        root.fid,
    ).ok
    with pytest.raises(ValueError, match="display"):
        device(root.fid, founder, oversized, 4)

    _, sibling = keypair()
    granted = device_invite(
        root.fid, founder, founder, sibling, exact, 5)
    granted_signature = _signed(founder_secret, founder, granted)
    device_base = (root, primary_signature, primary)
    assert drain(
        device_base + (granted_signature, granted), root.fid).ok
    hostile_grant = _rebody(granted, label=oversized)
    assert not drain(
        device_base + (
            _signed(founder_secret, founder, hostile_grant),
            hostile_grant,
        ),
        root.fid,
    ).ok
    with pytest.raises(ValueError, match="display"):
        device_invite(
            root.fid, founder, founder, sibling, oversized, 5)


def test_repository_applier_rejects_a_signed_oversized_founder_name(
        tmp_path):
    exact = "é" * 127 + "a"
    oversized = exact + "b"
    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, exact, 1)
    hostile = _rebody(root, name=oversized)

    rejected = FullPeer(str(tmp_path / "rejected"))
    rejected.add_workspace(hostile.fid, "hostile", peers=[])
    rejected.receive_pile(
        hostile.fid,
        "feed" * 16,
        encode_pile((hostile,), workspace=hostile.fid),
    )
    assert rejected.store(hostile.fid).get("root") is None

    accepted = FullPeer(str(tmp_path / "accepted"))
    accepted.add_workspace(root.fid, "healthy", peers=[])
    accepted.receive_pile(
        root.fid,
        "feed" * 16,
        encode_pile((root,), workspace=root.fid),
    )
    assert accepted.reader(root.fid) is not None


def test_maximum_authority_labels_fit_cloudflare_mint_budgets(tmp_path):
    label = "é" * 127 + "a"
    oversized = label + "b"
    node = FullPeer(str(tmp_path / "node"))
    workspace_id = facts.auth.workspace.create(node, label, ts=1)
    store = node.store(workspace_id)

    class CountingReader:
        def __init__(self, reads):
            self.reads = reads

        async def get_bounded(self, key, maximum):
            raw = store.get_bounded(key, maximum)
            if self.reads is not None \
                    and key.startswith("obj/") and raw is not None:
                self.reads.append((key, len(raw), maximum))
            return raw

    def assert_current_identity_mints(public):
        now = now_ms()
        pile = encode_pile(facts.auth.request.payload(
            node,
            workspace_id,
            "sync",
            now + cloudflare.MAX_GRANT_TTL_MS,
            now,
        ))
        body = json.dumps(
            {
                "pile": base64.b64encode(pile).decode(),
                "ws": workspace_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        assert len(body) <= cloudflare.MAX_REQUEST_BYTES
        assert node.reader(workspace_id).mint(pile, now) \
            == (public, "sync")

        hosted = HttpGate(
            CountingReader(None),
            workspace_id,
            b"s" * 32,
            lambda: now,
        )
        hosted_response = asyncio.run(hosted.handle(
            "POST", "/mint", {"ws": workspace_id}, {}, body))

        object_reads = []
        edge = HttpGate(
            CountingReader(object_reads),
            workspace_id,
            b"s" * 32,
            lambda: now,
            sync_profile=peer_capability.READ_ONLY,
            max_request_bytes=cloudflare.MAX_REQUEST_BYTES,
            max_root_bytes=cloudflare.MAX_ROOT_BYTES,
            max_object_bytes=cloudflare.MAX_OBJECT_BYTES,
            max_batch_count=cloudflare.MAX_BATCH_COUNT,
            max_batch_bytes=cloudflare.MAX_BATCH_BYTES,
            max_mint_fetches=cloudflare.MAX_MINT_FETCHES,
            max_mint_fetch_bytes=cloudflare.MAX_MINT_FETCH_BYTES,
            grant_ttl_ms=cloudflare.MAX_GRANT_TTL_MS,
        )
        edge_response = asyncio.run(edge.handle(
            "POST", "/mint", {"ws": workspace_id}, {}, body))

        assert hosted_response.status == edge_response.status == 200
        hosted_answer = json.loads(hosted_response.body)
        edge_answer = json.loads(edge_response.body)
        assert {
            key: hosted_answer[key] for key in ("cap", "etag", "root")
        } == {
            key: edge_answer[key] for key in ("cap", "etag", "root")
        }
        assert object_reads
        assert len(object_reads) <= cloudflare.MAX_MINT_FETCHES
        assert sum(size for _, size, _ in object_reads) \
            <= cloudflare.MAX_MINT_FETCH_BYTES
        assert all(
            maximum == MAX_REPOSITORY_OBJECT_BYTES
            for _, _, maximum in object_reads
        )

    founder = node.identity(workspace_id)[1]
    assert_current_identity_mints(founder)

    member_secret, member, _ = add_member(
        node, workspace_id, label, ts=2)
    node.keychain.add_identity(member_secret)
    node.bind_identity(workspace_id, member)
    assert_current_identity_mints(member)

    node.bind_identity(workspace_id, founder)
    facts.auth.admin.grant(node, workspace_id, member)
    node.bind_identity(workspace_id, member)
    assert node.select(workspace_id, "admin", member)
    assert_current_identity_mints(member)

    before = store.get("root")
    with pytest.raises(ValueError, match="display"):
        facts.auth.device.bind(node, workspace_id, oversized)
    assert store.get("root") == before
    facts.auth.device.bind(node, workspace_id, label)
    assert store.get("root") != before

    sibling_secret, sibling = keypair()
    node.keychain.add_identity(sibling_secret)
    facts.auth.device_invite.grant(
        node, workspace_id, member, sibling, label)
    node.bind_identity(workspace_id, sibling)
    assert_current_identity_mints(sibling)
