"""Hostile HTTP boundary tests over the production upload broker."""
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
from core.limits import MAX_MINT_REQUEST_BYTES, PayloadTooLarge
from full_peer.node import FullPeer
from deploy.upload_broker import (
    AuthorizedPut,
    UploadBroker,
)
from deploy.upload_broker_http import (
    MAX_UPLOAD_HTTP_HEADER_VALUE_BYTES,
    MAX_UPLOAD_HTTP_METHOD_BYTES,
    MAX_UPLOAD_HTTP_PATH_BYTES,
    UploadBrokerEndpoint,
)
from full_peer.upload_client import UploadRetryable, UploadSessionRejected
from full_peer.upload_client_http import HttpBrokerTransport
from deploy.upload_session import (
    MAX_RANGE_PROOF_BYTES,
    SessionKey,
    UploadLeaf,
    UploadSessionPolicy,
    UploadVector,
)
from deploy.upload_wire import (
    MAX_FINALIZE_RESPONSE_BYTES,
    MAX_ISSUE_RESPONSE_BYTES,
    MAX_OPEN_REQUEST_BYTES,
    MAX_OPEN_RESPONSE_BYTES,
    UploadCapability,
    encode_finalize_request,
    encode_issue_request,
    encode_open_request,
)
from facts.auth import request


NOW = 3_000_000
SESSION = b"s" * 16
KEY = SessionKey("key00001", b"k" * 32, 0, NOW + 10_000_000)


class Clock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        return self.value


class CanonicalStore:
    """Small async fake containing an exact snapshot of canonical objects."""

    def __init__(self, values):
        self.values = values
        self.failure = None

    async def get(self, key):
        if self.failure is not None:
            raise self.failure
        return self.values.get(key)

    async def get_bounded(self, key, maximum):
        value = await self.get(key)
        if value is not None and len(value) > maximum:
            raise PayloadTooLarge("fake canonical object")
        return value


class Signer:
    provider_binding = "fake-http-ingress-v1"

    def __init__(self, clock):
        self.clock = clock
        self.puts = []
        self.failure = None

    def sign(self, put):
        assert isinstance(put, AuthorizedPut)
        if self.failure is not None:
            raise self.failure
        self.puts.append(put)
        return UploadCapability(
            "PUT",
            "https://bucket.example/" + put.key + "?signature=opaque",
            (
                ("content-length", str(put.size)),
                ("content-type", put.content_type),
                ("if-none-match", "*"),
            ),
            min(self.clock() + 60_000, put.not_after_ms),
        )


class HttpResponse:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, maximum):
        return self.response.body[:maximum]


class EndpointOpener:
    """Run urllib requests against the transport-neutral endpoint."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.requests = []
        self.responses = []

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
                request_value.full_url,
                response.status,
                "upload broker rejected request",
                response.headers,
                BytesIO(response.body),
            )
        return HttpResponse(response)


def _leaf(raw):
    return UploadLeaf(h(raw), len(raw))


def world(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    proof = encode_pile(request.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    backing = node.store(workspace)
    store = CanonicalStore({
        key: backing.get(key) for key in backing.list("")
    })
    clock = Clock()
    signer = Signer(clock)
    broker = UploadBroker(
        store,
        workspace,
        signer,
        clock,
        UploadSessionPolicy(
            "http-broker-v1",
            KEY.key_id,
            (KEY,),
            ttl_ms=120_000,
            max_ttl_ms=120_000,
            clock_skew_ms=1_000,
        ),
        nonce=lambda count: SESSION if count == len(SESSION) else b"",
    )
    endpoint = UploadBrokerEndpoint(broker)
    opener = EndpointOpener(endpoint)
    transport = HttpBrokerTransport(
        "https://broker.example", opener=opener)
    return (
        workspace, proof, store, clock, signer,
        endpoint, opener, transport,
    )


def direct(endpoint, path, body, *, method="POST", headers=None):
    return asyncio.run(endpoint.handle(
        method,
        path,
        {"Content-Type": "application/json"}
        if headers is None else headers,
        body,
    ))


@pytest.mark.parametrize("objects", ((), (b"one", b"two", b"three")))
def test_http_transport_runs_complete_zero_and_multi_object_sessions(
        tmp_path, objects):
    (
        _, proof, _, _, signer, _, opener, transport,
    ) = world(tmp_path)
    vector = UploadVector(tuple(sorted(
        (_leaf(raw) for raw in objects),
        key=lambda item: item.digest,
    )))
    pile = _leaf(b"one closed pile")

    opened = transport.open(proof, vector.manifest, pile)
    cursor = opened.cursor
    for start in range(0, len(vector.leaves), 2):
        end = min(start + 2, len(vector.leaves))
        cursor = transport.issue(
            cursor,
            start,
            vector.leaves[start:end],
            vector.proof(start, end),
        ).cursor
    finalized = transport.finalize(cursor)

    assert finalized.pile.leaf == pile
    assert [put.object_class for put in signer.puts] == (
        ["obj"] * len(objects) + ["pile"])
    assert [response.status for response in opener.responses] == (
        [200] * (2 + (len(objects) + 1) // 2))
    limits = (
        [MAX_OPEN_RESPONSE_BYTES]
        + [MAX_ISSUE_RESPONSE_BYTES] * ((len(objects) + 1) // 2)
        + [MAX_FINALIZE_RESPONSE_BYTES]
    )
    for response, maximum in zip(opener.responses, limits):
        assert len(response.body) <= maximum
        assert canon(json.loads(response.body)) == response.body
        assert response.headers == {
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
        }
    # Broker HTTP carries only proof/manifest metadata. Provider object and
    # pile bodies are absent even though each exact digest and size is named.
    for raw in (*objects, b"one closed pile"):
        assert all(raw not in request_body for request_body in opener.requests)
    assert all(not hasattr(put, "body") for put in signer.puts)


def test_endpoint_rejects_noncanonical_and_wrongly_typed_documents(
        tmp_path):
    (
        _, proof, _, _, _, endpoint, _, transport,
    ) = world(tmp_path)
    vector = UploadVector((_leaf(b"one"),))
    pile = _leaf(b"pile")
    opened = transport.open(proof, vector.manifest, pile)
    valid_open = encode_open_request(proof, vector.manifest, pile)
    open_value = json.loads(valid_open)
    issue_value = json.loads(encode_issue_request(
        opened.cursor, 0, vector.leaves, vector.proof(0, 1)))
    finalize_value = json.loads(encode_finalize_request(opened.cursor))

    extra = dict(open_value, extra=False)
    wrong_schema = dict(open_value, schema="poc16-upload-open-request-v0")
    bool_count = json.loads(valid_open)
    bool_count["manifest"]["count"] = True
    noncanonical_b64 = dict(open_value, proof=open_value["proof"] + "===")
    whitespace_b64 = dict(open_value, proof=open_value["proof"] + "\n")
    duplicate = valid_open.replace(
        b'"schema":',
        b'"schema":"duplicate","schema":',
        1,
    )
    bool_start = dict(issue_value, start_index=True)
    extra_finalize = dict(finalize_value, extra=None)

    requests = (
        ("/upload/open", b" " + valid_open),
        ("/upload/open", canon(extra)),
        ("/upload/open", canon(wrong_schema)),
        ("/upload/open", canon(bool_count)),
        ("/upload/open", canon(noncanonical_b64)),
        ("/upload/open", canon(whitespace_b64)),
        ("/upload/open", duplicate),
        ("/upload/issue", canon(bool_start)),
        ("/upload/finalize", canon(extra_finalize)),
    )
    for path, body in requests:
        response = direct(endpoint, path, body)
        assert (response.status, response.body) == (400, b"")


def test_endpoint_enforces_body_and_embedded_proof_bounds(tmp_path):
    (
        _, proof, _, _, _, endpoint, _, transport,
    ) = world(tmp_path)
    vector = UploadVector((_leaf(b"one"),))
    pile = _leaf(b"pile")

    exact = direct(
        endpoint,
        "/upload/open",
        b"x" * MAX_OPEN_REQUEST_BYTES,
    )
    assert (exact.status, exact.body) == (400, b"")
    response = direct(
        endpoint,
        "/upload/open",
        b"x" * (MAX_OPEN_REQUEST_BYTES + 1),
    )
    assert (response.status, response.body) == (413, b"")
    response = direct(
        endpoint,
        "/upload/open",
        b"{}",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(MAX_OPEN_REQUEST_BYTES),
        },
    )
    assert response.status == 400
    response = direct(
        endpoint,
        "/upload/open",
        b"{}",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(MAX_OPEN_REQUEST_BYTES + 1),
        },
    )
    assert response.status == 413

    open_value = json.loads(encode_open_request(
        proof, vector.manifest, pile))
    open_value["proof"] = base64.b64encode(
        b"x" * (MAX_MINT_REQUEST_BYTES + 1)).decode()
    over_proof = canon(open_value)
    assert len(over_proof) <= MAX_OPEN_REQUEST_BYTES
    assert direct(endpoint, "/upload/open", over_proof).status == 413

    opened = transport.open(proof, vector.manifest, pile)
    issue_value = json.loads(encode_issue_request(
        opened.cursor, 0, vector.leaves, vector.proof(0, 1)))
    issue_value["proof"] = base64.b64encode(
        b"x" * (MAX_RANGE_PROOF_BYTES + 1)).decode()
    assert direct(
        endpoint, "/upload/issue", canon(issue_value)).status == 413


def test_endpoint_maps_authorization_rollback_expiry_and_provider_failure(
        tmp_path):
    (
        _, proof, _, clock, signer, endpoint, opener, transport,
    ) = world(tmp_path)
    vector = UploadVector(tuple(sorted(
        (_leaf(b"one"), _leaf(b"two"), _leaf(b"three")),
        key=lambda item: item.digest,
    )))
    pile = _leaf(b"pile")

    with pytest.raises(UploadSessionRejected):
        transport.open(b"not an authorization pile", vector.manifest, pile)
    assert (opener.responses[-1].status, opener.responses[-1].body) == (
        403, b"")

    opened = transport.open(proof, vector.manifest, pile)
    advanced = transport.issue(
        opened.cursor, 0, vector.leaves[:2], vector.proof(0, 2))
    with pytest.raises(UploadSessionRejected):
        transport.issue(
            advanced.cursor,
            1,
            vector.leaves[1:],
            vector.proof(1, 3),
        )
    assert (opener.responses[-1].status, opener.responses[-1].body) == (
        409, b"")

    clock.value = opened.expires_at_ms
    with pytest.raises(UploadSessionRejected):
        transport.issue(
            opened.cursor, 0, vector.leaves[:1], vector.proof(0, 1))
    assert opener.responses[-1].status == 409

    clock.value = NOW
    fresh = transport.open(proof, vector.manifest, pile)
    signer.failure = RuntimeError("provider-secret-must-not-leak")
    with pytest.raises(UploadRetryable):
        transport.issue(
            fresh.cursor, 0, vector.leaves[:1], vector.proof(0, 1))
    failed = opener.responses[-1]
    assert (failed.status, failed.body) == (503, b"")
    assert b"provider-secret" not in failed.body
    assert direct(
        endpoint,
        "/upload/issue",
        encode_issue_request(
            fresh.cursor, 0, vector.leaves[:1], vector.proof(0, 1)),
    ).body == b""


def test_endpoint_has_exact_http_paths_methods_headers_and_lengths(
        tmp_path):
    (
        _, proof, _, _, _, endpoint, _, _,
    ) = world(tmp_path)
    vector = UploadVector(())
    body = encode_open_request(proof, vector.manifest, _leaf(b"pile"))

    cases = (
        ("GET", "/upload/open", {}, 405),
        ("post", "/upload/open", {}, 405),
        ("POST", "/upload/open/", {}, 404),
        ("POST", "//upload/open", {}, 404),
        ("POST", "/upload/open?mode=other", {}, 404),
        ("POST", "/upload/open#fragment", {}, 404),
        ("POST", "/upload/%6fpen", {}, 404),
        ("POST", "/other", {}, 404),
        ("X" * (MAX_UPLOAD_HTTP_METHOD_BYTES + 1),
         "/upload/open", {}, 400),
        ("POST", "/" + "x" * MAX_UPLOAD_HTTP_PATH_BYTES, {}, 414),
        ("POST", "/upload/open", {}, 415),
        ("POST", "/upload/open",
         {"Content-Type": "text/plain"}, 415),
        ("POST", "/upload/open",
         {"Content-Type": "application/json; charset=utf-8"}, 415),
        ("POST", "/upload/open", {
            "Content-Type": "application/json",
            "Content-Length": str(len(body) + 1),
        }, 400),
        ("POST", "/upload/open", {
            "Content-Type": "application/json",
            "content-type": "application/json",
        }, 400),
        ("POST", "/upload/open", {
            "Content-Type": "application/json",
            "X-Large": "x" * (MAX_UPLOAD_HTTP_HEADER_VALUE_BYTES + 1),
        }, 400),
        ("POST", "/upload/open", [], 400),
    )
    for method, path, headers, expected in cases:
        response = direct(
            endpoint, path, body, method=method, headers=headers)
        assert (response.status, response.body) == (expected, b"")
        assert response.headers["Cache-Control"] == "no-store"
        if expected == 405:
            assert response.headers["Allow"] == "POST"

    accepted = direct(endpoint, "/upload/open", body, headers={
        "content-type": "application/json",
        "Content-Length": str(len(body)),
        "User-Agent": "poc16-test",
    })
    assert accepted.status == 200
