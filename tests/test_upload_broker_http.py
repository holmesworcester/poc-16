"""Hostile HTTP boundary for the one-pile upload protocol."""
import asyncio
import base64
from io import BytesIO
import json
import urllib.error
from urllib.parse import urlsplit

import facts
import pytest

from core.close import encode_pile
from core.crypto import h
from core.fact import canon
from core.http import AsyncFromSyncReader
from core.limits import MAX_MINT_REQUEST_BYTES
from deploy.upload_broker import AuthorizedPut, UploadBroker
from deploy.upload_broker_http import (
    MAX_UPLOAD_HTTP_HEADER_VALUE_BYTES,
    MAX_UPLOAD_HTTP_METHOD_BYTES,
    MAX_UPLOAD_HTTP_PATH_BYTES,
    UploadBrokerEndpoint,
)
from deploy.upload_session import SessionKey, UploadLeaf, UploadSessionPolicy
from deploy.upload_wire import (
    MAX_OPEN_REQUEST_BYTES,
    UploadCapability,
    encode_finalize_request,
    encode_open_request,
)
from facts.auth import request
from full_peer.node import FullPeer
from full_peer.upload_client import UploadRetryable, UploadSessionRejected
from full_peer.upload_client_http import HttpBrokerTransport


NOW = 3_000_000
KEY = SessionKey("key00001", b"k" * 32, 0, NOW + 10_000_000)


class Clock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        return self.value


class Signer:
    provider_binding = "fake-http-ingress-v2"

    def __init__(self, clock):
        self.clock, self.puts, self.failure = clock, [], None

    def sign(self, put):
        assert isinstance(put, AuthorizedPut)
        if self.failure is not None:
            raise self.failure
        self.puts.append(put)
        return UploadCapability(
            "PUT",
            "https://bucket.example/" + put.key + "?signature=opaque",
            tuple(sorted((
                ("content-length", str(put.size)),
                ("content-type", put.content_type),
                ("if-none-match", "*"),
            ))),
            min(self.clock() + 60_000, put.not_after_ms),
        )


class Applier:
    def __init__(self):
        self.calls, self.status, self.failure = [], "applied", None

    async def __call__(self, key, digest):
        if self.failure is not None:
            raise self.failure
        self.calls.append((key, digest))
        return self.status


class HttpResponse:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, maximum):
        return self.response.body[:maximum]


class EndpointOpener:
    def __init__(self, endpoint):
        self.endpoint, self.requests, self.responses = endpoint, [], []

    def __call__(self, request_value, timeout):
        del timeout
        self.requests.append(request_value.data)
        response = asyncio.run(self.endpoint.handle(
            request_value.method,
            urlsplit(request_value.full_url).path,
            dict(request_value.header_items()),
            request_value.data,
        ))
        self.responses.append(response)
        if response.status >= 400:
            raise urllib.error.HTTPError(
                request_value.full_url, response.status, "rejected",
                response.headers, BytesIO(response.body))
        return HttpResponse(response)


def world(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    proof = encode_pile(request.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    clock, signer, applier = Clock(), Signer(Clock()), Applier()
    signer.clock = clock
    broker = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)), workspace, signer, clock,
        UploadSessionPolicy(
            "http-broker-v2", KEY.key_id, (KEY,), ttl_ms=120_000,
            max_ttl_ms=120_000, clock_skew_ms=1_000),
        apply_exact=applier,
        nonce=lambda count: b"s" * count,
    )
    endpoint = UploadBrokerEndpoint(broker)
    opener = EndpointOpener(endpoint)
    transport = HttpBrokerTransport(
        "https://broker.example", opener=opener)
    return proof, clock, signer, applier, endpoint, opener, transport


def leaf(raw=b"one exact closed pile"):
    return UploadLeaf(h(raw), len(raw))


def direct(endpoint, path, body, *, method="POST", headers=None):
    return asyncio.run(endpoint.handle(
        method, path,
        {"Content-Type": "application/json"}
        if headers is None else headers,
        body,
    ))


def test_transport_carries_only_proof_metadata_and_exact_apply_poke(tmp_path):
    proof, _, signer, applier, _, opener, transport = world(tmp_path)
    pile = leaf()
    opened = transport.open(proof, pile)
    result = transport.finalize(opened.cursor)

    assert result.status == "applied"
    assert len(signer.puts) == 1
    assert applier.calls == [(signer.puts[0].key, pile.digest)]
    assert len(opener.requests) == 2
    assert all(b"one exact closed pile" not in body for body in opener.requests)
    assert all(canon(json.loads(response.body)) == response.body
               for response in opener.responses)
    assert all(response.headers["Cache-Control"] == "no-store"
               for response in opener.responses)


def test_endpoint_rejects_noncanonical_oversized_and_wrong_routes(tmp_path):
    proof, _, _, _, endpoint, _, _ = world(tmp_path)
    valid = encode_open_request(proof, leaf())
    value = json.loads(valid)
    bad = (
        b" " + valid,
        canon(dict(value, extra=False)),
        valid.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
    )
    assert [direct(endpoint, "/upload/open", body).status for body in bad] \
        == [400, 400, 400]
    assert direct(
        endpoint, "/upload/open", b"x" * (MAX_OPEN_REQUEST_BYTES + 1)
    ).status == 413
    assert direct(endpoint, "/upload/issue", b"{}").status == 404
    assert direct(endpoint, "/upload/open/", valid).status == 404
    assert direct(endpoint, "/upload/open", valid, method="GET").status == 405


def test_endpoint_bounds_embedded_proof_and_http_membrane(tmp_path):
    proof, _, _, _, endpoint, _, _ = world(tmp_path)
    value = json.loads(encode_open_request(proof, leaf()))
    value["proof"] = base64.b64encode(
        b"x" * (MAX_MINT_REQUEST_BYTES + 1)).decode()
    assert direct(endpoint, "/upload/open", canon(value)).status == 413

    cases = (
        ("X" * (MAX_UPLOAD_HTTP_METHOD_BYTES + 1), "/upload/open", {}, 400),
        ("POST", "/" + "x" * MAX_UPLOAD_HTTP_PATH_BYTES, {}, 414),
        ("POST", "/upload/open", {}, 415),
        ("POST", "/upload/open", {"Content-Type": "text/plain"}, 415),
        ("POST", "/upload/open", {
            "Content-Type": "application/json",
            "Content-Length": str(len(encode_open_request(proof, leaf())) + 1),
        }, 400),
        ("POST", "/upload/open", {
            "Content-Type": "application/json",
            "content-type": "application/json",
        }, 400),
        ("POST", "/upload/open", {
            "Content-Type": "application/json",
            "X-Large": "x" * (MAX_UPLOAD_HTTP_HEADER_VALUE_BYTES + 1),
        }, 400),
    )
    body = encode_open_request(proof, leaf())
    for method, path, headers, status in cases:
        response = direct(endpoint, path, body, method=method, headers=headers)
        assert (response.status, response.body) == (status, b"")


def test_failures_are_body_free_and_classified_without_secret_leaks(tmp_path):
    proof, clock, signer, applier, endpoint, opener, transport = world(tmp_path)
    with pytest.raises(UploadSessionRejected):
        transport.open(b"not authorization", leaf())
    assert (opener.responses[-1].status, opener.responses[-1].body) == (403, b"")

    opened = transport.open(proof, leaf())
    clock.value = opened.expires_at_ms
    with pytest.raises(UploadSessionRejected):
        transport.finalize(opened.cursor)
    assert opener.responses[-1].status == 409

    clock.value = NOW
    signer.failure = RuntimeError("provider-secret")
    with pytest.raises(UploadRetryable):
        transport.open(proof, leaf())
    assert opener.responses[-1].body == b""

    signer.failure = None
    opened = transport.open(proof, leaf())
    applier.failure = RuntimeError("applier-secret")
    with pytest.raises(UploadRetryable):
        transport.finalize(opened.cursor)
    assert opener.responses[-1].body == b""
    assert direct(endpoint, "/upload/finalize", encode_finalize_request(
        opened.cursor)).body == b""
