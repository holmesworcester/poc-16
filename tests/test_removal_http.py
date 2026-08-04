"""HTTP contract for self-confined removal paths and strong access proofs."""

import asyncio
import base64
import json

from core.access import AccessGate
from core.crypto import h, keypair
from core.grants import make_token
from core.http import (
    MAX_HEAD_CONTROL_REQUEST_BYTES,
    AsyncFromSyncReader,
    HttpGate,
    encode_head_commit_request,
    encode_head_permit_request,
)
from core.limits import MAX_CONTROL_PILE_BYTES
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.writer_head import (
    decode_slot_at,
    head_slot_key,
    writer_store_binding,
)
from core.writer_repository import OpaqueHeadGate, WriterLog
from facts.auth.device import device
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature
from facts.content.message import message
from tests.test_access_gate import (
    access_proof,
    head_proof,
    path_proof,
    signed,
    world,
)


PERMIT_SECRET = b"removal-http-permit-secret" * 2


def run(awaitable):
    return asyncio.run(awaitable)


def envelope(workspace, pile):
    return json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }, sort_keys=True, separators=(",", ":")).encode()


def gateway(root, store):
    access = AccessGate(root.fid, store)
    head_gate = OpaqueHeadGate(store, access.authorize_head)

    async def commit_permit(permit, proposed, secret):
        return await access.commit_head_permit(
            head_gate, permit, proposed, secret)

    return access, HttpGate(
        AsyncFromSyncReader(store),
        root.fid,
        b"removal-http-secret" * 2,
        lambda: 10,
        path_authorize=access.removal_path,
        mint_authorize=access.authorize_access,
        removal_bootstrap=access.state.bootstrap,
        head_advance=head_gate.advance,
        head_permit_issue=access.issue_head_permit,
        head_permit_commit=commit_permit,
        permit_secret=PERMIT_SECRET,
    )


def prepared_head(store, secret, member, root, closure):
    writer = WriterLog(
        root.fid,
        member,
        member,
        writer_store_binding(root.fid, member),
        secret,
        store,
    )
    update = run(writer.prepare((closure,)))
    run(writer.establish(update))
    return update


def test_two_public_proof_phases_mint_and_advance_only_bound_head(tmp_path):
    root, secret, member, membership = world()
    store = FsStore(str(tmp_path / "repository"))
    access, http = gateway(root, store)
    bootstrap = signed(secret, member, root, membership)

    assert run(http.handle(
        "POST", "/removal/bootstrap", {"ws": root.fid}, {},
        bootstrap)).status == 201
    assert run(http.handle(
        "POST", "/removal/bootstrap", {"ws": root.fid}, {},
        bootstrap)).status == 204
    initial = run(access.state.pin()).root_oid

    historical = path_proof(secret, member, root, membership)
    path_response = run(http.handle(
        "POST", "/removal/path", {"ws": root.fid}, {},
        envelope(root.fid, historical)))
    assert path_response.status == 200
    assert path_response.headers["Cache-Control"] == "no-store"
    assert run(access.state.pin()).root_oid == initial

    current = access_proof(
        secret, member, root, membership, path_response.body)
    minted = run(http.handle(
        "POST", "/mint", {"ws": root.fid}, {},
        envelope(root.fid, current)))
    assert minted.status == 200
    assert run(access.state.pin()).root_oid == initial

    item = message(root.fid, member, "general", "ordinary", 7)
    item_signature = signature(secret, member, item, 7)
    proposed = prepared_head(
        store,
        secret,
        member,
        root,
        (*membership, item_signature, item),
    ).head_oid
    proof = head_proof(
        secret, member, root, membership, path_response.body, proposed)
    route = "/head/" + proposed
    assert run(http.handle(
        "POST", route, {"ws": root.fid}, {}, proof)).status == 201
    assert run(http.handle(
        "POST", route, {"ws": root.fid}, {}, proof)).status == 204

    key = head_slot_key(root.fid, member)
    accepted = store.get(key)
    slot = decode_slot_at(key, accepted)
    assert (slot.head, slot.removal_root) == (proposed, initial)

    redirected = h(b"redirected writer head")
    assert run(http.handle(
        "POST", "/head/" + redirected,
        {"ws": root.fid}, {}, proof)).status == 403
    assert store.get(key) == accepted


def test_stale_path_gets_typed_refresh_then_current_removal_denies(tmp_path):
    root, secret, member, membership = world()
    store = FsStore(str(tmp_path / "repository"))
    access, http = gateway(root, store)
    bootstrap = signed(secret, member, root, membership)
    assert run(http.handle(
        "POST", "/removal/bootstrap", {"ws": root.fid}, {},
        bootstrap)).status == 201
    historical = path_proof(secret, member, root, membership)
    stale = run(http.handle(
        "POST", "/removal/path", {"ws": root.fid}, {},
        envelope(root.fid, historical))).body

    assert run(access.state.tree.apply(((
        scoped_id("member", member),
        suppression_slot(h(b"remove member")),
    ),))).status == "applied"

    stale_response = run(http.handle(
        "POST", "/mint", {"ws": root.fid}, {},
        envelope(root.fid, access_proof(
            secret, member, root, membership, stale))))
    assert stale_response.status == 409
    assert json.loads(stale_response.body) == {
        "error": "proof_refresh_required"}

    fresh = run(http.handle(
        "POST", "/removal/path", {"ws": root.fid}, {},
        envelope(root.fid, historical))).body
    denied = run(http.handle(
        "POST", "/mint", {"ws": root.fid}, {},
        envelope(root.fid, access_proof(
            secret, member, root, membership, fresh))))
    assert denied.status == 403


def test_bootstrap_rejects_content_and_bounds_before_provider_work(tmp_path):
    root, secret, member, membership = world()
    store = FsStore(str(tmp_path / "repository"))
    _access, http = gateway(root, store)
    item = message(root.fid, member, "general", "not control", 7)
    item_signature = signature(secret, member, item, 7)
    content = signed(
        secret, member, root, (*membership, item_signature, item))

    assert run(http.handle(
        "POST", "/removal/bootstrap", {"ws": root.fid}, {},
        content)).status == 403
    assert store.list("") == []
    assert run(http.handle(
        "POST", "/removal/bootstrap", {"ws": root.fid}, {},
        b"x" * (MAX_CONTROL_PILE_BYTES + 1))).status == 413
    assert store.list("") == []


def test_exact_control_permit_commits_removal_before_head(tmp_path):
    root, secret, member, membership = world()
    store = FsStore(str(tmp_path / "repository"))
    access, http = gateway(root, store)
    assert run(access.state.bootstrap(signed(
        secret, member, root, membership))).status == "applied"
    primary = device(root.fid, member, "phone", 7)
    primary_signature = signature(secret, member, primary, 7)
    _secondary_secret, secondary = keypair()
    secondary_grant = device_invite(
        root.fid, member, secondary, "tablet", 8)
    secondary_signature = signature(
        secret, member, secondary_grant, 8)
    closure = (
        *membership,
        primary_signature,
        primary,
        secondary_signature,
        secondary_grant,
    )
    control = signed(
        secret, member, root, closure)
    path = run(access.removal_path(
        path_proof(secret, member, root, membership), 10))
    proposed = prepared_head(
        store,
        secret,
        member,
        root,
        closure,
    ).head_oid
    proof = head_proof(
        secret, member, root, membership, path, proposed)
    permit_route = f"/head/{proposed}/permit"
    commit_route = f"/head/{proposed}/commit"
    before = run(access.state.pin()).root_oid

    issued = run(http.handle(
        "POST", permit_route, {"ws": root.fid}, {},
        encode_head_permit_request(proof, (control,))))
    assert issued.status == 200
    assert run(access.state.pin()).root_oid == before
    assert run(http.handle(
        "POST", commit_route, {"ws": root.fid}, {},
        encode_head_commit_request(issued.body))).status == 201
    assert run(access.state.pin()).root_oid != before
    assert run(http.handle(
        "POST", commit_route, {"ws": root.fid}, {},
        encode_head_commit_request(issued.body))).status == 204

    assert HttpGate.request_limit("POST", "/removal/apply") == 0
    assert run(http.handle(
        "POST", "/removal/apply", {"ws": root.fid}, {},
        control)).status == 401
    assert run(http.handle(
        "POST", permit_route, {"ws": root.fid}, {}, b"malformed"
    )).status == 403
    assert run(http.handle(
        "POST", permit_route, {"ws": root.fid}, {},
        b"x" * (MAX_HEAD_CONTROL_REQUEST_BYTES + 1))).status == 413


def test_permit_issue_creates_no_slot_before_control_commit(
        tmp_path):
    root, secret, member, membership = world()
    store = FsStore(str(tmp_path / "repository"))
    access, http = gateway(root, store)
    assert run(access.state.bootstrap(signed(
        secret, member, root, membership))).status == "applied"
    path = run(access.removal_path(
        path_proof(secret, member, root, membership), 10))
    primary = device(root.fid, member, "phone", 7)
    primary_signature = signature(secret, member, primary, 7)
    control = signed(
        secret, member, root,
        (*membership, primary_signature, primary))
    update = prepared_head(
        store,
        secret,
        member,
        root,
        (*membership, primary_signature, primary),
    )
    proposed = update.head_oid
    proof = head_proof(
        secret, member, root, membership, path, proposed)
    issued = run(http.handle(
        "POST", f"/head/{proposed}/permit", {"ws": root.fid}, {},
        encode_head_permit_request(proof, (control,))))
    assert issued.status == 200

    assert store.get(head_slot_key(root.fid, member)) is None

    token = make_token(
        b"removal-http-secret" * 2,
        member,
        root.fid,
        issued_at=1,
        ttl_ms=1_000,
    )
    headers = {"Authorization": "Bearer " + token}
    hidden = run(http.handle(
        "GET", f"/head/{member}", {"ws": root.fid}, headers))
    assert hidden.status == 404
    directory = run(http.handle(
        "GET", "/heads", {"ws": root.fid}, headers))
    assert directory.status == 200
    document = json.loads(directory.body)
    assert document["heads"] == []
    assert proposed.encode() not in directory.body
    assert h(issued.body).encode() not in directory.body

    committed = run(http.handle(
        "POST", f"/head/{proposed}/commit", {"ws": root.fid}, {},
        encode_head_commit_request(issued.body)))
    assert committed.status == 201
    visible = run(http.handle(
        "GET", f"/head/{member}", {"ws": root.fid}, headers))
    assert visible.status == 200
    assert decode_slot_at(
        head_slot_key(root.fid, member), visible.body).head == proposed
