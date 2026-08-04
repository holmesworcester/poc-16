"""DB-free HTTP lifecycle for one member-owned secondary device."""

import asyncio
import base64
import json

import facts
from core import peer_capability
from core.access import AccessGate
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.head_permit import decode as decode_permit
from core.http import (
    AsyncFromSyncReader,
    HttpGate,
    encode_head_commit_request,
    encode_head_permit_request,
)
from core.removal_path import decode as decode_path
from core.store import FsStore
from core.writer_head import (
    decode_slot_at,
    head_slot_key,
    writer_store_binding,
)
from core.writer_repository import OpaqueHeadGate, WriterLog
from facts._policy import OWNER
from facts.auth.device import device
from facts.auth.device_invite import device_invite
from facts.auth.device_removal import device_removal
from facts.auth.head_request import head_request
from facts.auth.removal_path_request import removal_path_request
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.workspace import workspace
from facts.content.message import message


PERMIT_SECRET = b"device-removal-http-permit-secret" * 2
GRANT_SECRET = b"device-removal-http-grant-secret" * 2
EXPIRY = 10_000
TRUSTED_NOW = 10


def run(awaitable):
    return asyncio.run(awaitable)


def signed(secret, writer, root, closure):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, writer, tuple(closure)))


def envelope(root, pile):
    return json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": root.fid,
    }, sort_keys=True, separators=(",", ":")).encode()


def historical_proof(secret, device_pk, owner, root, identity, ts):
    item = removal_path_request(
        root.fid, device_pk, owner, EXPIRY, ts)
    item_signature = signature(secret, device_pk, item, ts)
    return signed(
        secret, device_pk, root, (*identity, item_signature, item))


def current_proof(
        secret, device_pk, owner, root, identity, path, ts):
    item = request(
        root.fid, device_pk, owner, "sync", EXPIRY, path, ts)
    item_signature = signature(secret, device_pk, item, ts)
    return signed(
        secret, device_pk, root, (*identity, item_signature, item))


def exact_head_proof(
        secret, device_pk, owner, root, identity, path,
        proposed, ts, base=None):
    item = head_request(
        root.fid, device_pk, owner, base, proposed,
        EXPIRY, path, ts)
    item_signature = signature(secret, device_pk, item, ts)
    return signed(
        secret, device_pk, root, (*identity, item_signature, item))


def put_head(store, label):
    raw = label.encode()
    oid = h(raw)
    store.put_if_absent("obj/" + oid, raw)
    return oid


def path_response(http, root, proof):
    return run(http.handle(
        "POST", "/removal/path", {"ws": root.fid}, {},
        envelope(root, proof),
    ))


def mint_response(http, root, proof):
    return run(http.handle(
        "POST", "/mint", {"ws": root.fid}, {},
        envelope(root, proof),
    ))


def gateway(root, store):
    access = AccessGate(root.fid, store)
    heads = OpaqueHeadGate(store, access.authorize_head)

    async def commit_permit(permit, proposed, secret):
        return await access.commit_head_permit(
            heads, permit, proposed, secret)

    http = HttpGate(
        AsyncFromSyncReader(store),
        root.fid,
        GRANT_SECRET,
        lambda: TRUSTED_NOW,
        sync_profile=peer_capability.OWNER,
        head_advance=heads.advance,
        head_permit_issue=access.issue_head_permit,
        head_permit_commit=commit_permit,
        permit_secret=PERMIT_SECRET,
        mint_authorize=access.authorize_access,
        path_authorize=access.removal_path,
        removal_bootstrap=access.state.bootstrap,
    )
    return access, http


async def state_at(access, sid):
    pin = await access.state.pin()
    proof = await pin.proof(sid)
    return pin.verify(sid, proof)


def test_secondary_self_removal_refreshes_and_denies_only_that_device(
        tmp_path):
    founder_secret, founder = keypair()
    target_secret, target = keypair()
    sibling_secret, sibling = keypair()
    root = workspace(founder_secret, founder, "workspace", 1)

    primary = device(root.fid, founder, "founder-primary", 2)
    primary_signature = signature(
        founder_secret, founder, primary, 2)
    target_grant = device_invite(
        root.fid, founder, target, "target-secondary", 3)
    target_signature = signature(
        founder_secret, founder, target_grant, 3)
    sibling_grant = device_invite(
        root.fid, founder, sibling, "sibling-secondary", 4)
    sibling_signature = signature(
        founder_secret, founder, sibling_grant, 4)
    primary_identity = (root, primary_signature, primary)
    target_identity = (
        *primary_identity, target_signature, target_grant)
    sibling_identity = (
        *primary_identity, sibling_signature, sibling_grant)

    store = FsStore(str(tmp_path / "recipient"))
    access, http = gateway(root, store)
    bootstrap = signed(founder_secret, founder, root, (root,))
    assert run(http.handle(
        "POST", "/removal/bootstrap", {"ws": root.fid}, {},
        bootstrap,
    )).status == 201

    # Establish the member-signed primary and both device grants through the
    # same removal-first control-head protocol used for later removal.
    founder_historical = historical_proof(
        founder_secret, founder, founder, root, (root,), 5)
    founder_path = path_response(
        http, root, founder_historical).body
    founder_writer = WriterLog(
        root.fid,
        founder,
        founder,
        writer_store_binding(root.fid, founder),
        founder_secret,
        store,
    )
    authority_update = run(founder_writer.prepare((
        primary_identity,
        target_identity,
        sibling_identity,
    )))
    run(founder_writer.establish(authority_update))
    authority_head = authority_update.head_oid
    authority_proof = exact_head_proof(
        founder_secret,
        founder,
        founder,
        root,
        (root,),
        founder_path,
        authority_head,
        6,
    )
    controls = (
        signed(founder_secret, founder, root, primary_identity),
        signed(founder_secret, founder, root, target_identity),
        signed(founder_secret, founder, root, sibling_identity),
    )
    permit_response = run(http.handle(
        "POST",
        f"/head/{authority_head}/permit",
        {"ws": root.fid},
        {},
        encode_head_permit_request(authority_proof, controls),
    ))
    assert permit_response.status == 200
    assert run(http.handle(
        "POST",
        f"/head/{authority_head}/commit",
        {"ws": root.fid},
        {},
        encode_head_commit_request(permit_response.body),
    )).status == 201

    # The secondary's discarded historical closure reveals exactly its own
    # liveness points. It can mint and install an ordinary head while clear.
    target_historical = historical_proof(
        target_secret, target, founder, root, target_identity, 7)
    target_path_response = path_response(
        http, root, target_historical)
    assert target_path_response.status == 200
    stale_path = target_path_response.body
    target_sids = {
        sid for sid, _proof in decode_path(stale_path).proofs
    }
    assert facts.principal_sid("device", target) in target_sids
    assert facts.principal_sid("device", sibling) not in target_sids
    stale_current = current_proof(
        target_secret, target, founder, root,
        target_identity, stale_path, 8)
    assert mint_response(http, root, stale_current).status == 200

    target_writer = WriterLog(
        root.fid,
        target,
        founder,
        writer_store_binding(root.fid, target),
        target_secret,
        store,
    )
    ordinary = message(
        root.fid, target, "general", "ordinary", 9, owner=founder)
    ordinary_signature = signature(
        target_secret, target, ordinary, 9)
    first_update = run(target_writer.prepare((
        (*target_identity, ordinary_signature, ordinary),
    )))
    run(target_writer.establish(first_update))
    first_head = first_update.head_oid
    first_head_proof = exact_head_proof(
        target_secret, target, founder, root, target_identity,
        stale_path, first_head, 9)
    assert run(http.handle(
        "POST", f"/head/{first_head}", {"ws": root.fid}, {},
        first_head_proof,
    )).status == 201

    # The target authors its own ordinary device-removal fact. Permit issuance
    # occurs while it is clear; commit reserves this exact head, activates the
    # caller's device SID, and still finalizes that one terminal transition.
    action = device_removal(
        root.fid, target, target, founder, OWNER, 10, founder)
    action_signature = signature(target_secret, target, action, 10)
    removal_control = signed(
        target_secret,
        target,
        root,
        (*target_identity, action_signature, action),
    )
    terminal_update = run(target_writer.prepare((
        (*target_identity, action_signature, action),
    )))
    run(target_writer.establish(terminal_update))
    terminal_head = terminal_update.head_oid
    terminal_proof = exact_head_proof(
        target_secret,
        target,
        founder,
        root,
        target_identity,
        stale_path,
        terminal_head,
        11,
        base=first_head,
    )
    issued = run(http.handle(
        "POST",
        f"/head/{terminal_head}/permit",
        {"ws": root.fid},
        {},
        encode_head_permit_request(
            terminal_proof, (removal_control,)),
    ))
    assert issued.status == 200
    target_sid = facts.principal_sid("device", target)
    terminal = decode_permit(issued.body, PERMIT_SECRET)
    assert any(
        sid == target_sid and value["state"] == "active"
        for sid, value in terminal.updates)
    assert run(http.handle(
        "POST",
        f"/head/{terminal_head}/commit",
        {"ws": root.fid},
        {},
        encode_head_commit_request(issued.body),
    )).status == 201
    slot_key = head_slot_key(root.fid, target)
    assert decode_slot_at(slot_key, store.get(slot_key)).head == terminal_head
    assert run(state_at(access, target_sid))["state"] == "active"
    assert run(state_at(
        access, facts.principal_sid("member", founder)
    ))["state"] == "clear"

    # The old root fails closed with a typed refresh. Historical membership
    # remains valid, but its fresh path now proves permanent device removal.
    stale = mint_response(http, root, stale_current)
    assert stale.status == 409
    assert json.loads(stale.body) == {
        "error": "proof_refresh_required",
    }
    fresh_path_response = path_response(
        http, root, target_historical)
    assert fresh_path_response.status == 200
    assert fresh_path_response.body != stale_path
    fresh_current = current_proof(
        target_secret, target, founder, root,
        target_identity, fresh_path_response.body, 12)
    assert mint_response(http, root, fresh_current).status == 403

    denied_head = put_head(store, "target denied later head")
    denied_proof = exact_head_proof(
        target_secret,
        target,
        founder,
        root,
        target_identity,
        fresh_path_response.body,
        denied_head,
        13,
        base=terminal_head,
    )
    assert run(http.handle(
        "POST", f"/head/{denied_head}", {"ws": root.fid}, {},
        denied_proof,
    )).status == 403

    # The sibling's path omits the removed target and still grants access.
    sibling_historical = historical_proof(
        sibling_secret, sibling, founder, root, sibling_identity, 14)
    sibling_path_response = path_response(
        http, root, sibling_historical)
    assert sibling_path_response.status == 200
    sibling_sids = {
        sid for sid, _proof in decode_path(sibling_path_response.body).proofs
    }
    assert target_sid not in sibling_sids
    assert facts.principal_sid("device", sibling) in sibling_sids
    sibling_current = current_proof(
        sibling_secret, sibling, founder, root,
        sibling_identity, sibling_path_response.body, 15)
    assert mint_response(http, root, sibling_current).status == 200
