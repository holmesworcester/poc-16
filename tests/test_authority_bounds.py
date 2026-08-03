"""Authority labels remain admissible through every hosted read path."""
import asyncio
import base64
import json

import pytest

import facts
from core import peer_capability
from .util import signed_pile_bytes
from core.authority import AuthorityRepository
from core.crypto import keypair
from core.fact import Fact
from core.http import HttpGate
from core.kernel import drain
from core.limits import MAX_REPOSITORY_OBJECT_BYTES
from core.repository_applier import RepositoryApplier
from core.repository_reader import RepositoryReader
from core.store import FsStore
from deploy.cloudflare_worker import runtime as cloudflare
from facts.auth._display import MAX_DISPLAY_BYTES
from facts.auth.device import device
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from full_peer.node import FullPeer, now_ms

from .util import add_member, all_fids, closed_subset


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

    rejected_store = FsStore(str(tmp_path / "rejected"))
    rejected = asyncio.run(RepositoryApplier(
        hostile.fid, rejected_store).receive_pile(
            founder,
            signed_pile_bytes(
                (hostile,), workspace=hostile.fid,
                secret=founder_secret),
        ))
    assert rejected.status == "rejected"
    assert rejected_store.get("root") is None

    accepted_store = FsStore(str(tmp_path / "accepted"))
    accepted = asyncio.run(RepositoryApplier(
        root.fid, accepted_store).receive_pile(
            founder,
            signed_pile_bytes(
                (root,), workspace=root.fid,
                secret=founder_secret),
        ))
    reader = RepositoryReader(
        root.fid,
        accepted.root,
        lambda oid: accepted_store.get("obj/" + oid),
    )
    assert reader.validated().fact(root.fid) == root


def test_maximum_authority_labels_fit_cloudflare_mint_budgets(tmp_path):
    label = "é" * 127 + "a"
    oversized = label + "b"
    node = FullPeer(str(tmp_path / "node"))
    workspace_id = facts.auth.workspace.create(node, label, ts=1)
    authority_store = FsStore(str(tmp_path / "authority"))
    publisher = AuthorityRepository(workspace_id, authority_store)

    def publish_authority():
        raw = closed_subset(
            node, workspace_id, all_fids(node, workspace_id))
        result = asyncio.run(publisher.publish(raw))
        assert result.status in {"applied", "noop"}

    def assert_current_identity_mints(public):
        now = now_ms()
        pile = node.sender(workspace_id).pack(
            facts.auth.request.payload(
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
        assert node.authorize_access(workspace_id, pile, "sync") \
            == (public, "sync")
        publish_authority()

        object_reads = []

        class CountingAuthorityStore:
            async def read_versioned(self, key):
                return authority_store.read_versioned(key)

            async def get_bounded(self, key, maximum):
                raw = authority_store.get_bounded(key, maximum)
                if key.startswith("obj/") and raw is not None:
                    object_reads.append((key, len(raw), maximum))
                return raw

        repository = AuthorityRepository(
            workspace_id, CountingAuthorityStore())

        async def authorize(proof, purpose):
            return await repository.authorize_access(
                proof,
                now,
                purpose=purpose,
                max_unique_fetches=cloudflare.MAX_MINT_FETCHES,
                max_fetch_bytes=cloudflare.MAX_MINT_FETCH_BYTES,
            )

        edge = HttpGate(
            CountingAuthorityStore(),
            workspace_id,
            b"s" * 32,
            lambda: now,
            sync_profile=peer_capability.READ_ONLY,
            mint_authorize=authorize,
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

        assert edge_response.status == 200
        edge_answer = json.loads(edge_response.body)
        assert set(edge_answer) == {"cap", "grant"}
        assert edge_answer["cap"] == peer_capability.READ_ONLY
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

    before = node.sql(workspace_id).fact_ids()
    with pytest.raises(ValueError, match="display"):
        facts.auth.device.bind(node, workspace_id, oversized)
    assert node.sql(workspace_id).fact_ids() == before
    facts.auth.device.bind(node, workspace_id, label)
    assert node.sql(workspace_id).fact_ids() != before

    sibling_secret, sibling = keypair()
    node.keychain.add_identity(sibling_secret)
    facts.auth.device_invite.grant(
        node, workspace_id, member, sibling, label)
    node.bind_identity(workspace_id, sibling)
    assert_current_identity_mints(sibling)
