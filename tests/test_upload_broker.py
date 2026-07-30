"""Running semantic boundary for direct isolated-ingress upload plans."""
import asyncio
import base64
from dataclasses import fields, replace
import json

import pytest

from core import cmds
from core.close import encode_pile
from core.crypto import h
from core.limits import MAX_OBJECT_BYTES, MAX_PILE_BYTES
from core.node import Node
from deploy.gateway import AsyncFromSyncReader, Gateway
from deploy.upload_broker import (
    AuthorizedPut,
    UploadBroker,
    UploadCapability,
    UploadDescriptor,
    UploadUnavailable,
    encode_upload_plan,
    staging_key,
    upload_plan_document,
)
from facts.auth import request


NOW = 100_000
SESSION = bytes.fromhex("d" * 32)


class RecordingSigner:
    def __init__(self):
        self.puts = []

    def sign(self, put):
        assert isinstance(put, AuthorizedPut)
        self.puts.append(put)
        return UploadCapability(
            "PUT",
            "https://uploads.example/" + put.key,
            (
                ("content-length", str(put.size)),
                ("content-type", put.content_type),
                ("if-none-match", "*"),
                ("x-checksum-sha256", put.digest),
            ),
            NOW + 60_000,
        )


def world(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    public = node.identity_id(workspace)
    proof = encode_pile(request.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    signer = RecordingSigner()
    broker = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)),
        workspace,
        signer,
        lambda: NOW,
        nonce=lambda count: SESSION if count == 16 else b"",
    )
    return node, workspace, public[:16], proof, signer, broker


def descriptor(workspace, member, object_class, raw):
    return UploadDescriptor(
        workspace, member, object_class, h(raw), len(raw),
        "application/octet-stream")


def issue(broker, proof, descriptors):
    return asyncio.run(broker.mint(proof, descriptors))


def gateway_call(gateway, workspace, proof):
    body = json.dumps({
        "pile": base64.b64encode(proof).decode(),
        "ws": workspace,
    }).encode()
    return asyncio.run(gateway.handle(
        "POST", "/mint", {"ws": workspace}, {}, body))


def test_broker_uses_kernel_proof_then_derives_one_pile_last_session(
        tmp_path):
    _, workspace, member, proof, signer, broker = world(tmp_path)
    first, second, pile = b"first object", b"second object", b"closed pile"
    descriptors = (
        descriptor(workspace, member, "obj", first),
        descriptor(workspace, member, "obj", second),
        descriptor(workspace, member, "pile", pile),
    )

    plan = issue(broker, proof, descriptors)

    assert plan.session == "d" * 32
    assert tuple(item.descriptor for item in plan.objects) == descriptors[:2]
    assert plan.pile.descriptor == descriptors[-1]
    assert [put.key for put in signer.puts] == [
        (
            f"ingress/v1/workspaces/{workspace}/sessions/{plan.session}/"
            f"obj/{h(first)}"
        ),
        (
            f"ingress/v1/workspaces/{workspace}/sessions/{plan.session}/"
            f"obj/{h(second)}"
        ),
        (
            f"ingress/v1/workspaces/{workspace}/sessions/{plan.session}/"
            f"pile/{member}/{h(pile)}"
        ),
    ]
    assert all(put.workspace == workspace for put in signer.puts)
    assert all(put.member == member for put in signer.puts)


def test_upload_purpose_is_accepted_only_by_upload_broker(tmp_path):
    node, workspace, member, upload_proof, signer, broker = world(tmp_path)
    gateway = Gateway(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: NOW)
    sync_proof = encode_pile(request.payload(
        node, workspace, "sync", NOW + 60_000, NOW))
    pile = descriptor(workspace, member, "pile", b"pile")

    assert gateway_call(gateway, workspace, upload_proof).status == 403
    assert gateway_call(gateway, workspace, sync_proof).status == 200
    assert issue(broker, sync_proof, (pile,)) is None
    assert issue(broker, upload_proof, (pile,)) is not None
    assert len(signer.puts) == 1


@pytest.mark.parametrize(
    "change",
    (
        lambda value: replace(value, workspace="e" * 64),
        lambda value: replace(value, member="e" * 16),
        lambda value: replace(value, member="e" * 15 + "/"),
        lambda value: replace(value, object_class="root"),
        lambda value: replace(value, digest="not-a-digest"),
        lambda value: replace(value, digest="A" * 64),
        lambda value: replace(value, size=-1),
        lambda value: replace(value, size=MAX_PILE_BYTES + 1),
        lambda value: replace(value, size=True),
        lambda value: replace(value, content_type="text/plain"),
    ),
)
def test_descriptor_json_is_never_treated_as_upload_authority(
        tmp_path, change):
    _, workspace, member, proof, signer, broker = world(tmp_path)
    candidate = change(
        descriptor(workspace, member, "pile", b"closed pile"))

    assert issue(broker, proof, (candidate,)) is None
    assert signer.puts == []


def test_plan_shape_rejects_marker_reordering_duplicates_and_overflow(
        tmp_path):
    _, workspace, member, proof, signer, broker = world(tmp_path)
    obj = descriptor(workspace, member, "obj", b"obj")
    pile = descriptor(workspace, member, "pile", b"pile")
    oversized_obj = replace(obj, size=MAX_OBJECT_BYTES + 1)

    for values in (
            (),
            (obj,),
            (pile, obj),
            (pile, pile),
            (obj, obj, pile),
            (oversized_obj, pile)):
        assert issue(broker, proof, values) is None
    assert signer.puts == []


def test_descriptor_iterator_is_consumed_only_to_the_hard_bound(tmp_path):
    _, workspace, member, proof, signer, broker = world(tmp_path)
    calls = []

    def unbounded():
        while True:
            calls.append(len(calls))
            yield descriptor(
                workspace, member, "obj",
                f"object-{len(calls)}".encode())

    assert issue(broker, proof, unbounded()) is None
    assert len(calls) == broker.max_descriptors + 1
    assert signer.puts == []


def test_session_is_broker_minted_and_no_client_key_field_exists(tmp_path):
    _, workspace, member, proof, signer, broker = world(tmp_path)
    pile = descriptor(workspace, member, "pile", b"pile")

    assert {field.name for field in fields(UploadDescriptor)} == {
        "workspace", "member", "object_class", "digest", "size",
        "content_type"}
    assert {field.name for field in fields(UploadCapability)} == {
        "method", "url", "headers", "expires_at_ms"}
    assert "key" not in {
        field.name for field in fields(UploadDescriptor)}
    assert not {
        "workspace", "member", "session", "object_class", "digest", "key",
    } & {field.name for field in fields(UploadCapability)}
    plan = issue(broker, proof, (pile,))
    assert signer.puts[0].key == staging_key(
        workspace, member, plan.session, "pile", pile.digest)

    invalid_nonce = UploadBroker(
        broker.store, workspace, RecordingSigner(), lambda: NOW,
        nonce=lambda _count: b"too short")
    with pytest.raises(UploadUnavailable, match="session nonce"):
        issue(invalid_nonce, proof, (pile,))


def test_provider_neutral_response_contains_wire_requests_not_credentials(
        tmp_path):
    _, workspace, member, proof, _, broker = world(tmp_path)
    plan = issue(broker, proof, (
        descriptor(workspace, member, "obj", b"obj"),
        descriptor(workspace, member, "pile", b"pile"),
    ))

    document = upload_plan_document(plan)
    assert json.loads(encode_upload_plan(plan)) == document
    assert document["schema"] == "poc16-direct-upload-v1"
    assert document["session"] == "d" * 32
    assert len(document["objects"]) == 1
    assert document["pile"]["put"]["method"] == "PUT"
    encoded = encode_upload_plan(plan).decode()
    for forbidden in (
            "secret_access_key", "session_token", "list", "delete", "root"):
        assert forbidden not in encoded.lower()


def test_broker_distinguishes_provider_failure_from_bad_proof(tmp_path):
    node, workspace, member, proof, _, _ = world(tmp_path)
    pile = descriptor(workspace, member, "pile", b"pile")

    class Failing:
        async def get(self, _key):
            raise OSError("injected provider outage")

    broker = UploadBroker(
        Failing(), workspace, RecordingSigner(), lambda: NOW)
    with pytest.raises(UploadUnavailable, match="root unavailable"):
        issue(broker, proof, (pile,))

    healthy = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, RecordingSigner(), lambda: NOW)
    assert issue(healthy, b"not a proof", (pile,)) is None
