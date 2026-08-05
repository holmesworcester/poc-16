"""HTTP contract for the shared lookup gate and control-head permit."""

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
from core.removal_path import decode as decode_path
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.writer_head import decode_slot_at, head_slot_key, writer_store_binding
from core.writer_repository import OpaqueHeadGate, WriterLog
from facts.auth._access import lookup_claim
from facts.auth.device import device
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature
from facts.content.message import message
from tests.test_access_gate import access_proof, head_proof, signed, world


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


def mint(http, root, proof):
    return run(http.handle(
        "POST", "/mint", {"ws": root.fid}, {},
        envelope(root.fid, proof)))


def test_unknown_admits_clear_refreshes_and_active_returns_own_story(tmp_path):
    root, secret, member, membership = world()
    store = FsStore(str(tmp_path / "repository"))
    access, http = gateway(root, store)

    unknown = signed(secret, member, root, ())
    denied = mint(http, root, unknown)
    assert (denied.status, denied.body) == (403, b"")

    admitted = mint(
        http, root, access_proof(secret, member, root, membership))
    assert admitted.status == 200
    admission = json.loads(admitted.body)
    tip = admission["tip"]

    clear = mint(http, root, access_proof(
        secret, member, root, basis=tip))
    assert clear.status == 200
    assert json.loads(clear.body)["tip"] == tip

    assert run(access.state.tree.apply(((
        scoped_id("member", h(b"unrelated")), suppression_slot()),
    ))).status == "applied"
    stale = mint(http, root, access_proof(
        secret, member, root, basis=tip))
    assert stale.status == 409
    refreshed = json.loads(stale.body)
    assert refreshed == {
        "error": "proof_refresh_required",
        "tip": run(access.state.pin()).root_oid,
    }

    assert run(access.state.tree.apply(((
        scoped_id("member", member),
        suppression_slot(h(b"remove member"))),
    ))).status == "applied"
    active = mint(http, root, access_proof(
        secret, member, root, basis=refreshed["tip"]))
    assert active.status == 403
    body = json.loads(active.body)
    path = decode_path(base64.b64decode(body["path"], validate=True))
    assert body["error"] == "removed"
    assert body["tip"] == path.root == run(access.state.pin()).root_oid
    assert tuple(sid for sid, _proof in path.proofs) == \
        lookup_claim(member, member).scopes


def test_removal_path_route_is_not_a_gate_surface(tmp_path):
    root, _secret, _member, _membership = world()
    _access, http = gateway(root, FsStore(tmp_path / "repository"))
    assert HttpGate.request_limit("POST", "/removal/path") == 0
    assert not HttpGate.requires_access_callbacks("POST", "/removal/path")
    response = run(http.handle(
        "POST", "/removal/path", {"ws": root.fid}, {}, b"anything"))
    assert response.status == 401


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
    admitted = mint(
        http, root, access_proof(secret, member, root, membership))
    basis = json.loads(admitted.body)["tip"]
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
    control = signed(secret, member, root, closure)
    proposed = prepared_head(
        store, secret, member, root, closure).head_oid
    proof = head_proof(
        secret, member, root, membership, basis, proposed)
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

    assert run(http.handle(
        "POST", permit_route, {"ws": root.fid}, {}, b"malformed"
    )).status == 403
    assert run(http.handle(
        "POST", permit_route, {"ws": root.fid}, {},
        b"x" * (MAX_HEAD_CONTROL_REQUEST_BYTES + 1))).status == 413


def test_permit_issue_creates_no_slot_before_control_commit(tmp_path):
    root, secret, member, membership = world()
    store = FsStore(str(tmp_path / "repository"))
    access, http = gateway(root, store)
    basis = json.loads(mint(
        http, root,
        access_proof(secret, member, root, membership)).body)["tip"]
    primary = device(root.fid, member, "phone", 7)
    primary_signature = signature(secret, member, primary, 7)
    closure = (*membership, primary_signature, primary)
    control = signed(secret, member, root, closure)
    proposed = prepared_head(
        store, secret, member, root, closure).head_oid
    proof = head_proof(
        secret, member, root, membership, basis, proposed)
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
    directory = run(http.handle(
        "GET", "/heads", {"ws": root.fid}, headers))
    assert json.loads(directory.body)["heads"] == []

    committed = run(http.handle(
        "POST", f"/head/{proposed}/commit", {"ws": root.fid}, {},
        encode_head_commit_request(issued.body)))
    assert committed.status == 201
    visible = run(http.handle(
        "GET", f"/head/{member}", {"ws": root.fid}, headers))
    assert visible.status == 200
    assert decode_slot_at(
        head_slot_key(root.fid, member), visible.body).head == proposed
