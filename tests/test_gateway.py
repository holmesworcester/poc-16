"""Database-free serverless protocol gateway behavior."""
import asyncio
import base64
import json

import pytest

import facts

from core import peer_capability
from core.close import encode_pile
from core.crypto import h, unseal
from core.grants import check_token
from core.limits import (
    MAX_INVITE_BYTES,
    MAX_OBJECT_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PayloadTooLarge,
)
from full_peer.node import FullPeer
from core.http import AsyncFromSyncReader, HttpGate
from core.object_store import MAX_INVITE_ID_BYTES
from facts.auth import request


def world(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    now = 100
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    gateway = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: now)
    return node, workspace, now, pile, gateway


def call(gateway, method, path, query=None, headers=None, body=b""):
    return asyncio.run(
        gateway.handle(method, path, query, headers, body))


def test_gateway_has_no_whole_object_read_fallback():
    class WholeOnly:
        gets = 0

        async def get(self, _key):
            self.gets += 1
            raise AssertionError("whole-object fallback was used")

    store = WholeOnly()
    gateway = HttpGate(
        store, "0" * 64, b"s" * 32, lambda: 0)

    response = call(gateway, "GET", "/readyz")

    assert response.status == 503
    assert store.gets == 0


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
    assert body["cap"] == peer_capability.READ_ONLY
    assert body["etag"] == h(node.store(workspace).get("root"))
    assert check_token(
        b"s" * 32, "Bearer " + token, workspace,
        trusted_now=now) == node.identity_id(workspace)

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


def test_gateway_rejects_a_valid_request_pile_from_another_workspace(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    first = facts.auth.workspace.create(node, "first", ts=1)
    second = facts.auth.workspace.create(node, "second", ts=2)
    now = 100
    foreign = encode_pile(
        request.payload(node, first, "sync", now + 60_000, now),
        workspace=first,
    )
    gateway = HttpGate(
        AsyncFromSyncReader(node.store(second)),
        second, b"s" * 32, lambda: now)
    body = json.dumps({
        "ws": second,
        "pile": base64.b64encode(foreign).decode(),
    }).encode()

    assert call(
        gateway, "POST", "/mint", {"ws": second}, {}, body
    ).status == 403


def test_gateway_rejects_a_misbound_or_malformed_repository_root(tmp_path):
    node, workspace, _, pile, healthy = world(tmp_path)
    _, _, token = mint(node, workspace, pile, healthy)
    headers = {"Authorization": "Bearer " + token}
    foreign = FullPeer(str(tmp_path / "foreign"))
    foreign_workspace = facts.auth.workspace.create(foreign, "mallory", ts=1)
    foreign_root = foreign.store(foreign_workspace).get("root")
    request_body = json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }).encode()

    class RootOnly:
        def __init__(self, root):
            self.root = root

        async def get_bounded(self, key, _limit):
            return self.root if key == "root" else None

    for bad_root in (foreign_root, b"{}"):
        gateway = HttpGate(
            RootOnly(bad_root), workspace, b"s" * 32, lambda: 100)

        assert call(gateway, "GET", "/readyz").status == 503
        assert call(
            gateway, "GET", "/root",
            {"ws": workspace}, headers).status == 503
        assert call(
            gateway, "POST", "/mint", {"ws": workspace}, {},
            request_body).status == 503


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

    tiny = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: 100,
        max_batch_bytes=8)
    assert call(
        tiny,
        "POST", "/page", {"ws": workspace}, headers, request_body
    ).status == 413

    one_body = json.dumps([h(first), "0" * 64]).encode()
    exact_size = len(json.dumps(
        [base64.b64encode(first).decode(), None],
        sort_keys=True, separators=(",", ":")).encode())
    exact = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: 100,
        max_batch_bytes=exact_size)
    below = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: 100,
        max_batch_bytes=exact_size - 1)
    assert call(
        exact, "POST", "/page", {"ws": workspace}, headers, one_body
    ).status == 200
    assert call(
        below, "POST", "/page", {"ws": workspace}, headers, one_body
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
        "GET", "/readyz").status == 200
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
    ).status == 404


def test_gateway_mint_fails_closed_on_fetch_and_request_budgets(tmp_path):
    node, workspace, _, pile, _ = world(tmp_path)
    request_body = json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }).encode()
    no_fetches = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: 100,
        max_mint_fetches=0)
    assert call(
        no_fetches,
        "POST", "/mint", {"ws": workspace}, {}, request_body
    ).status == 403
    tiny_request = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: 100,
        max_request_bytes=1)
    assert call(
        tiny_request,
        "POST", "/mint", {"ws": workspace}, {}, request_body
    ).status == 413


def test_gateway_reports_provider_failures_as_observable_503(
        tmp_path, monkeypatch):
    node, workspace, _, pile, _ = world(tmp_path)
    request_body = json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }).encode()

    class FailingReader:
        async def get_bounded(self, key, _limit):
            if key == "root":
                return node.store(workspace).get("root")
            raise OSError("injected provider failure")

    gateway = HttpGate(
        FailingReader(), workspace, b"s" * 32, lambda: 100)

    assert call(
        gateway, "POST", "/mint", {"ws": workspace}, {},
        request_body).status == 503

    async def raising_after_fetch(
            _workspace, _root, fetch, _pile, _now, **_limits):
        await fetch("0" * 64)
        raise ValueError("verifier stopped after provider failure")

    monkeypatch.setattr(
        "core.http.RepositoryReader.mint_awaited",
        raising_after_fetch)
    assert call(
        gateway, "POST", "/mint", {"ws": workspace}, {},
        request_body).status == 503

    async def invalid_without_fetch(
            _workspace, _root, _fetch, _pile, _now, **_limits):
        raise ValueError("invalid proof")

    monkeypatch.setattr(
        "core.http.RepositoryReader.mint_awaited",
        invalid_without_fetch)
    assert call(
        gateway, "POST", "/mint", {"ws": workspace}, {},
        request_body).status == 403


def test_gateway_rejects_corrupt_content_addressed_reads(tmp_path):
    node, workspace, _, pile, healthy = world(tmp_path)
    _, _, token = mint(node, workspace, pile, healthy)
    headers = {"Authorization": "Bearer " + token}
    oid = "1" * 64
    reads = []

    class CorruptReader:
        async def get_bounded(self, key, limit):
            reads.append((key, limit))
            assert key == "obj/" + oid
            return b"wrong"

    gateway = HttpGate(
        CorruptReader(), workspace, b"s" * 32, lambda: 100)

    assert call(
        gateway, "GET", f"/page/{oid}",
        {"ws": workspace}, headers).status == 503
    assert call(
        gateway, "POST", "/page",
        {"ws": workspace}, headers,
        json.dumps([oid]).encode()).status == 503
    assert reads == [
        ("obj/" + oid, gateway.max_object_bytes),
        ("obj/" + oid, gateway.max_object_bytes),
    ]


def test_gateway_pins_trusted_time_once_per_request(tmp_path):
    node, workspace, _, pile, _ = world(tmp_path)
    calls = []

    def now():
        calls.append(100)
        return 100

    gateway = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, now)
    response, _, _ = mint(node, workspace, pile, gateway)

    assert response.status == 200
    assert calls == [100]


def test_gateway_rejects_object_limits_outside_serviceable_range(tmp_path):
    node, workspace, _, _, _ = world(tmp_path)

    with pytest.raises(ValueError, match="HTTP gate limits"):
        HttpGate(
            AsyncFromSyncReader(node.store(workspace)),
            workspace, b"s" * 32, lambda: 100,
            max_object_bytes=MAX_OBJECT_BYTES + 1)
    with pytest.raises(ValueError, match="serve canonical facts"):
        HttpGate(
            AsyncFromSyncReader(node.store(workspace)),
            workspace, b"s" * 32, lambda: 100,
            max_object_bytes=MAX_REPOSITORY_OBJECT_BYTES - 1)


@pytest.mark.parametrize(
    ("size", "status"),
    (
        (MAX_INVITE_BYTES, 200),
        (MAX_INVITE_BYTES + 1, 413),
    ),
)
def test_public_invites_use_the_hosted_reader_ceiling(size, status):
    raw = b"x" * size
    reads = []

    class InviteStore:
        async def get_bounded(self, key, limit):
            reads.append((key, limit))
            if len(raw) > limit:
                raise PayloadTooLarge("invite body")
            return raw

    gateway = HttpGate(
        InviteStore(), "0" * 64, b"s" * 32, lambda: 100)
    response = call(
        gateway,
        "GET",
        "/invite/valid",
        {"ws": "0" * 64},
    )

    assert response.status == status
    assert response.body == (raw if status == 200 else b"")
    assert reads == [("invite/valid", MAX_INVITE_BYTES)]


@pytest.mark.parametrize(
    ("identifier_bytes", "status", "read_count"),
    (
        (MAX_INVITE_ID_BYTES, 200, 1),
        (MAX_INVITE_ID_BYTES + 1, 404, 0),
    ),
)
def test_public_invite_identifier_has_one_shared_key_budget(
        identifier_bytes, status, read_count):
    reads = []

    class InviteStore:
        async def get_bounded(self, key, _limit):
            reads.append(key)
            return b"invite"

    gateway = HttpGate(
        InviteStore(), "0" * 64, b"s" * 32, lambda: 100)
    response = call(
        gateway,
        "GET",
        "/invite/" + "i" * identifier_bytes,
        {"ws": "0" * 64},
    )

    assert response.status == status
    assert len(reads) == read_count


def test_gateway_translates_preallocation_read_limit_to_413(tmp_path):
    node, workspace, _, pile, healthy = world(tmp_path)
    _, _, token = mint(node, workspace, pile, healthy)

    class Oversized:
        async def get_bounded(self, _key, _limit):
            raise PayloadTooLarge("provider body")

    gateway = HttpGate(
        Oversized(), workspace, b"s" * 32, lambda: 100)
    headers = {"Authorization": "Bearer " + token}

    assert call(
        gateway, "GET", "/page/" + "0" * 64,
        {"ws": workspace}, headers).status == 413
    assert call(
        gateway, "POST", "/page", {"ws": workspace}, headers,
        json.dumps(["0" * 64]).encode()).status == 413
    assert call(
        gateway, "GET", "/invite/example",
        {"ws": workspace}).status == 413
    assert call(
        gateway, "GET", "/root",
        {"ws": workspace}, headers).status == 503
    assert call(gateway, "GET", "/readyz").status == 503


def test_gateway_fetches_duplicate_batch_oids_once_and_preserves_order(
        tmp_path):
    node, workspace, _, pile, healthy = world(tmp_path)
    _, _, token = mint(node, workspace, pile, healthy)
    raw, calls = b"deduplicated", []
    oid = h(raw)

    class Counting:
        async def get_bounded(self, key, limit):
            calls.append((key, limit))
            return raw

    gateway = HttpGate(
        Counting(), workspace, b"s" * 32, lambda: 100)
    response = call(
        gateway, "POST", "/page", {"ws": workspace},
        {"Authorization": "Bearer " + token},
        json.dumps([oid] * 256).encode())

    assert response.status == 200
    assert json.loads(response.body) == [
        base64.b64encode(raw).decode()] * 256
    assert calls == [("obj/" + oid, gateway.max_object_bytes)]
