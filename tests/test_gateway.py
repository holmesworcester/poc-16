"""Database-free serverless protocol gateway behavior."""
import asyncio
import base64
import json

from core import cmds
from core.close import encode_pile
from core.crypto import h, unseal
from core.grants import check_token
from core.node import Node
from deploy.gateway import AsyncFromSyncReader, Gateway
from facts.auth import request


def world(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    now = 100
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    gateway = Gateway(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: now)
    return node, workspace, now, pile, gateway


def call(gateway, method, path, query=None, headers=None, body=b""):
    return asyncio.run(
        gateway.handle(method, path, query, headers, body))


def mint(node, workspace, pile, gateway):
    response = call(
        gateway,
        "POST", "/mint", {"ws": workspace}, {},
        json.dumps({
            "pile": base64.b64encode(pile).decode(),
            "ws": workspace,
        }).encode(),
    )
    body = json.loads(response.body)
    token = unseal(
        node.identity(workspace)[0],
        base64.b64decode(body["grant"]),
    ).decode()
    return response, body, token


def test_gateway_mints_then_serves_one_pinned_snapshot(tmp_path):
    node, workspace, now, pile, gateway = world(tmp_path)
    response, body, token = mint(
        node, workspace, pile, gateway)

    assert response.status == 200
    assert body["capabilities"] == {"push": False}
    assert body["etag"] == h(node.store(workspace).get("root"))
    assert check_token(
        b"s" * 32, "Bearer " + token, workspace,
        trusted_now=now) == node.identity_id(workspace)[:16]

    headers = {"Authorization": "Bearer " + token}
    root = call(
        gateway,
        "GET", "/root", {"ws": workspace}, headers)
    assert root.status == 200
    assert root.body == node.store(workspace).get("root")
    assert call(
        gateway,
        "GET", "/root", {"ws": workspace},
        {**headers, "If-None-Match": root.headers["ETag"]},
    ).status == 304


def test_gateway_authenticates_ordered_batches_and_bounds_bytes(tmp_path):
    node, workspace, _, pile, gateway = world(tmp_path)
    _, _, token = mint(node, workspace, pile, gateway)
    headers = {"Authorization": "Bearer " + token}
    first, second = b"first", b"second"
    for raw in (first, second):
        node.store(workspace).put_if_absent("obj/" + h(raw), raw)
    request_body = json.dumps(
        [h(first), "0" * 64, h(second)]).encode()

    assert call(
        gateway,
        "POST", "/page", {"ws": workspace}, {}, request_body
    ).status == 401
    response = call(
        gateway,
        "POST", "/page", {"ws": workspace}, headers, request_body)
    assert json.loads(response.body) == [
        base64.b64encode(first).decode(), None,
        base64.b64encode(second).decode(),
    ]

    tiny = Gateway(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: 100,
        max_batch_bytes=8)
    assert call(
        tiny,
        "POST", "/page", {"ws": workspace}, headers, request_body
    ).status == 413


def test_gateway_is_read_only_and_workspace_scoped(tmp_path):
    node, workspace, _, pile, gateway = world(tmp_path)
    _, _, token = mint(node, workspace, pile, gateway)
    headers = {"Authorization": "Bearer " + token}

    assert call(
        gateway,
        "GET", "/healthz").status == 200
    assert call(
        gateway,
        "GET", "/root", {"ws": "other"}, headers).status == 404
    assert call(
        gateway,
        "PUT", "/pile/member/id", {"ws": workspace}, headers
    ).status == 405
    assert call(
        gateway,
        "POST", "/poke", {"ws": workspace}, headers
    ).status == 405


def test_gateway_mint_fails_closed_on_fetch_and_request_budgets(tmp_path):
    node, workspace, _, pile, _ = world(tmp_path)
    request_body = json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }).encode()
    no_fetches = Gateway(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: 100,
        max_mint_fetches=0)
    assert call(
        no_fetches,
        "POST", "/mint", {"ws": workspace}, {}, request_body
    ).status == 403
    tiny_request = Gateway(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: 100,
        max_request_bytes=1)
    assert call(
        tiny_request,
        "POST", "/mint", {"ws": workspace}, {}, request_body
    ).status == 413


def test_gateway_rejects_corrupt_content_addressed_reads(tmp_path):
    node, workspace, _, pile, healthy = world(tmp_path)
    _, _, token = mint(node, workspace, pile, healthy)
    headers = {"Authorization": "Bearer " + token}
    oid = "1" * 64

    class CorruptReader:
        async def get(self, key):
            if key == "obj/" + oid:
                return b"wrong"
            return node.store(workspace).get(key)

    gateway = Gateway(
        CorruptReader(), workspace, b"s" * 32, lambda: 100)

    assert call(
        gateway, "GET", f"/page/{oid}",
        {"ws": workspace}, headers).status == 503
    assert call(
        gateway, "POST", "/page",
        {"ws": workspace}, headers,
        json.dumps([oid]).encode()).status == 503


def test_gateway_pins_trusted_time_once_per_request(tmp_path):
    node, workspace, _, pile, _ = world(tmp_path)
    calls = []

    def now():
        calls.append(100)
        return 100

    gateway = Gateway(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, now)
    response, _, _ = mint(node, workspace, pile, gateway)

    assert response.status == 200
    assert calls == [100]
