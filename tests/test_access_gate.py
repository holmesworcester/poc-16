"""Real closed-pile tests for historical path and current access phases."""

import asyncio

import pytest

import facts
from core.access import AccessGate
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.removal_path import ProofRefreshRequired, RemovalDenied
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.writer_head import writer_store_binding
from core.writer_repository import WriterLog
from facts.auth.head_request import head_request
from facts.auth.removal_path_request import removal_path_request
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from facts.content.message import message


def run(awaitable):
    return asyncio.run(awaitable)


def world():
    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, "workspace", 1)
    invite_secret, invite_public = keypair()
    invited = user_invite(root.fid, founder, invite_public, 2)
    invited_sig = signature(founder_secret, founder, invited, 2)
    member_secret, member = keypair()
    joined = user(invited, invite_secret, member, "member", 3)
    joined_sig = signature(member_secret, member, joined, 3)
    return (
        root,
        member_secret,
        member,
        (root, invited_sig, invited, joined_sig, joined),
    )


def signed(secret, writer, root, facts_):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, writer, facts_))


def path_proof(secret, member, root, membership, *, exp=1_000):
    item = removal_path_request(root.fid, member, member, exp, 4)
    item_sig = signature(secret, member, item, 4)
    return signed(secret, member, root, (*membership, item_sig, item))


def access_proof(secret, member, root, membership, path, *, exp=1_000):
    item = request(root.fid, member, member, "sync", exp, path, 5)
    item_sig = signature(secret, member, item, 5)
    return signed(secret, member, root, (*membership, item_sig, item))


def head_proof(secret, member, root, membership, path, proposed):
    item = head_request(
        root.fid, member, member, None, proposed, 1_000, path, 6)
    item_sig = signature(secret, member, item, 6)
    return signed(secret, member, root, (*membership, item_sig, item))


def test_two_discarded_phases_mint_and_bind_head_without_mutating_state(tmp_path):
    root, secret, member, membership = world()
    store = FsStore(tmp_path / "store")
    gate = AccessGate(root.fid, store)
    assert run(gate.state.bootstrap(
        signed(secret, member, root, membership))).status == "applied"
    initial = run(gate.state.pin()).root_oid

    path = run(gate.removal_path(
        path_proof(secret, member, root, membership), 10))
    assert isinstance(path, bytes)
    assert run(gate.state.pin()).root_oid == initial

    assert run(gate.authorize_access(
        access_proof(secret, member, root, membership, path),
        10,
    )) == (member, "sync")
    content = message(root.fid, member, "general", "ordinary", 7)
    content_signature = signature(secret, member, content, 7)
    writer = WriterLog(
        root.fid,
        member,
        member,
        writer_store_binding(root.fid, member),
        secret,
        store,
    )
    update = run(writer.prepare((
        (*membership, content_signature, content),
    )))
    run(writer.establish(update))
    proposed = update.head_oid
    grant = run(gate.authorize_head(
        head_proof(secret, member, root, membership, path, proposed),
        proposed,
        10,
    ))
    assert (grant.workspace, grant.device, grant.head, grant.removal_root) == (
        root.fid, member, proposed, initial)
    assert run(gate.state.pin()).root_oid == initial


def test_stale_path_refreshes_then_current_removal_denies(tmp_path):
    root, secret, member, membership = world()
    gate = AccessGate(root.fid, FsStore(tmp_path / "store"))
    assert run(gate.state.bootstrap(
        signed(secret, member, root, membership))).status == "applied"
    historical = path_proof(secret, member, root, membership)
    stale_path = run(gate.removal_path(historical, 10))
    sid = scoped_id("member", member)
    assert run(gate.state.tree.apply((
        (sid, suppression_slot(h(b"remove member"))),
    ))).status == "applied"

    with pytest.raises(ProofRefreshRequired):
        run(gate.authorize_access(
            access_proof(secret, member, root, membership, stale_path), 10))
    refreshed = run(gate.removal_path(historical, 10))
    with pytest.raises(RemovalDenied):
        run(gate.authorize_access(
            access_proof(secret, member, root, membership, refreshed), 10))


def test_path_claim_cannot_relabel_writer_as_another_member(tmp_path):
    root, secret, member, membership = world()
    gate = AccessGate(root.fid, FsStore(tmp_path / "store"))
    assert run(gate.state.bootstrap(
        signed(secret, member, root, membership))).status == "applied"
    _other_secret, other = keypair()
    item = removal_path_request(root.fid, member, other, 1_000, 7)
    item_sig = signature(secret, member, item, 7)
    proof = signed(
        secret, member, root, (*membership, item_sig, item))

    with pytest.raises(ValueError):
        run(gate.removal_path(proof, 10))
