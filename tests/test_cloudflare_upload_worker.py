"""Cloudflare Worker boundary tests for the direct-upload broker."""
import asyncio
import base64
from io import BytesIO
import json
from types import SimpleNamespace
import urllib.error
from urllib.parse import unquote, urlsplit

import facts
import pytest

from core.close import encode_pile
from core.crypto import h
from core.limits import PayloadTooLarge
from full_peer.node import FullPeer
from deploy.cloudflare_upload.boundary import Deployment
from deploy.cloudflare_upload.reader import (
    R2CanonicalReader,
    R2FetchRequest,
    R2ReadConfig,
)
from deploy.cloudflare_upload.signer import R2UploadSigner
from deploy.cloudflare_upload.worker import runtime
from deploy.upload_keyring import UploadKeyring, encode_keyring
from deploy.upload_session import (
    SessionKey,
    UploadLeaf,
    UploadSessionPolicy,
    UploadVector,
)
from deploy.upload_wire import encode_open_request
from full_peer.upload_client_http import HttpBrokerTransport
from facts.auth import request as request_fact


NOW = 5_000_000
READ_ACCESS = "reader-access"
READ_SECRET = "reader-secret"
INGRESS_ACCESS = "parent-access"
INGRESS_SECRET = "parent-secret"
SESSION = b"s" * 16


def run(awaitable):
    return asyncio.run(awaitable)


def deployment(workspace):
    return Deployment(
        account_id="a" * 32,
        workspace=workspace,
        canonical_bucket="poc16-canonical",
        ingress_bucket="poc16-untrusted-ingress",
        owner="production-west",
        broker_name="poc16-upload-broker",
        applier_name="poc16-repository-applier",
        read_permission_group_id="c" * 32,
        write_permission_group_id="d" * 32,
        presign_ttl_seconds=60,
    )


class Headers:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def items(self):
        return self.values.items()

    def get(self, name):
        return self.values.get(name)


class StreamResult:
    def __init__(self, done, value=None):
        self.done = done
        self.value = value


class Reader:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.reads = 0
        self.cancelled = None
        self.released = False

    async def read(self):
        self.reads += 1
        if self.chunks:
            return StreamResult(False, self.chunks.pop(0))
        return StreamResult(True)

    async def cancel(self, reason):
        self.cancelled = reason

    def releaseLock(self):
        self.released = True


class Stream:
    def __init__(self, chunks):
        self.reader = Reader(chunks)

    def getReader(self):
        return self.reader


class Request:
    def __init__(
            self, method, url, body=b"", headers=None, stream=True):
        self.method = method
        self.url = url
        self.headers = Headers(headers)
        self._body = body
        self.body = Stream([body]) if stream is True \
            else None if stream is False else stream
        self.bytes_calls = 0

    async def bytes(self):
        self.bytes_calls += 1
        return self._body


class FetchResponse:
    def __init__(
            self, status, body=b"", *, declared=True, stream=True):
        self.status = status
        self._body = body
        self.headers = Headers(
            {"content-length": str(len(body))} if declared else {})
        self.body = Stream([body]) if stream else None
        self.array_calls = 0

    async def arrayBuffer(self):
        self.array_calls += 1
        return self._body


class CanonicalFetch:
    def __init__(self, candidate, values):
        self.candidate = candidate
        self.values = dict(values)
        self.requests = []

    async def __call__(self, request):
        assert isinstance(request, R2FetchRequest)
        assert request.method == "GET"
        assert request.headers == ()
        assert request.redirect == "error"
        assert request.cache == "no-store"
        self.requests.append(request)
        parsed = urlsplit(request.url)
        query = parsed.query
        assert parsed.scheme == "https"
        assert parsed.hostname == (
            "a" * 32 + ".r2.cloudflarestorage.com")
        assert "X-Amz-Signature=" in query
        assert f"X-Amz-Credential={READ_ACCESS}%2F" in query
        assert READ_SECRET not in request.url
        prefix = (
            f"/{self.candidate.canonical_bucket}/"
            f"{self.candidate.canonical_prefix}/"
        )
        assert parsed.path.startswith(prefix)
        key = unquote(parsed.path.removeprefix(prefix))
        value = self.values.get(key)
        return FetchResponse(
            404 if value is None else 200,
            b"" if value is None else value,
        )


class WorkerResponse:
    def __init__(self, response):
        self.status = response.status
        self.headers = response.headers
        self.body = response.body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, maximum):
        return self.body[:maximum]


class WorkerOpener:
    def __init__(self, environment, fetch):
        self.environment = environment
        self.fetch = fetch
        self.requests = []

    def __call__(self, request, timeout):
        del timeout
        incoming = Request(
            request.method,
            request.full_url,
            request.data,
            dict(request.header_items()),
        )
        self.requests.append(incoming)
        response = run(runtime.handle(
            incoming,
            self.environment,
            fetch=self.fetch,
            clock=lambda: NOW,
            nonce=lambda count: (
                SESSION if count == len(SESSION) else b""),
        ))
        wrapped = WorkerResponse(response)
        if response.status >= 400:
            raise urllib.error.HTTPError(
                request.full_url,
                response.status,
                "upload broker rejected request",
                response.headers,
                BytesIO(response.body),
            )
        return wrapped


def world(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    proof = encode_pile(request_fact.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    candidate = deployment(workspace)
    signer = R2UploadSigner(
        candidate,
        INGRESS_ACCESS,
        INGRESS_SECRET,
        clock=lambda: NOW,
    )
    key = SessionKey(
        "key00001", b"k" * 32, 0, NOW + 10_000_000)
    policy = UploadSessionPolicy(
        candidate.upload_issuer,
        key.key_id,
        (key,),
        ttl_ms=120_000,
        max_ttl_ms=120_000,
        clock_skew_ms=1_000,
    )
    keyring = encode_keyring(UploadKeyring(
        signer.provider_binding, policy)).decode("ascii")
    environment = SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="broker",
        CANONICAL_BUCKET_PROFILE="dedicated-workspace",
        UPLOAD_PROTOCOL="isolated-ingress-v1",
        UPLOAD_ORDER="objects-first-pile-last",
        WORKSPACE=workspace,
        R2_ENDPOINT=candidate.endpoint,
        CANONICAL_BUCKET=candidate.canonical_bucket,
        CANONICAL_PREFIX=candidate.canonical_prefix,
        INGRESS_BUCKET=candidate.ingress_bucket,
        INGRESS_PREFIX=candidate.ingress_prefix,
        PRESIGN_TTL_SECONDS=candidate.presign_ttl_seconds,
        UPLOAD_ISSUER=candidate.upload_issuer,
        CANONICAL_READ_ACCESS_KEY_ID=READ_ACCESS,
        CANONICAL_READ_SECRET_ACCESS_KEY=READ_SECRET,
        INGRESS_PARENT_ACCESS_KEY_ID=INGRESS_ACCESS,
        INGRESS_PARENT_SECRET_ACCESS_KEY=INGRESS_SECRET,
        UPLOAD_SESSION_KEYRING=keyring,
    )
    backing = node.store(workspace)
    canonical = CanonicalFetch(candidate, {
        key: backing.get(key) for key in backing.list("")
    })
    opener = WorkerOpener(environment, canonical)
    return (
        proof,
        candidate,
        canonical,
        opener,
        HttpBrokerTransport(
            "https://broker.example", opener=opener),
    )


def leaf(raw):
    return UploadLeaf(h(raw), len(raw))


@pytest.mark.parametrize("objects", ((), (b"one", b"two", b"three")))
def test_worker_runs_stateless_direct_upload_session_without_provider_bodies(
        tmp_path, objects):
    proof, candidate, canonical, opener, transport = world(tmp_path)
    vector = UploadVector(tuple(sorted(
        (leaf(raw) for raw in objects),
        key=lambda item: item.digest,
    )))
    pile = leaf(b"one closed fact pile")

    opened = transport.open(proof, vector.manifest, pile)
    cursor = opened.cursor
    capabilities = []
    for start in range(0, len(vector.leaves), 2):
        end = min(start + 2, len(vector.leaves))
        issued = transport.issue(
            cursor,
            start,
            vector.leaves[start:end],
            vector.proof(start, end),
        )
        capabilities.extend(
            grant.capability for grant in issued.objects)
        cursor = issued.cursor
    finalized = transport.finalize(cursor)
    capabilities.append(finalized.pile.capability)

    assert finalized.pile.leaf == pile
    assert all(
        capability.url.startswith(
            candidate.endpoint + "/" + candidate.ingress_bucket + "/")
        for capability in capabilities
    )
    incoming = [request._body for request in opener.requests]
    for raw in (*objects, b"one closed fact pile"):
        assert all(raw not in body for body in incoming)
    assert canonical.requests
    assert all(
        "/poc16-canonical/" in request.url
        for request in canonical.requests)
    assert not hasattr(opener.environment, "CANONICAL")
    assert not hasattr(opener.environment, "INGRESS")


def test_worker_rejects_query_percent_and_oversize_streams_body_free(
        tmp_path):
    _, _, canonical, opener, _ = world(tmp_path)
    environment = opener.environment
    safe = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    queried = run(runtime.handle(
        Request(
            "POST",
            "https://broker.example/upload/open?authority=extra",
            b"{}",
            {"content-type": "application/json"},
        ),
        environment,
        fetch=canonical,
        clock=lambda: NOW,
    ))
    encoded = run(runtime.handle(
        Request(
            "POST",
            "https://broker.example/upload/%6fpen",
            b"{}",
            {"content-type": "application/json"},
        ),
        environment,
        fetch=canonical,
        clock=lambda: NOW,
    ))
    limit = runtime.upload_request_body_limit("/upload/finalize")
    oversized_request = Request(
        "POST",
        "https://broker.example/upload/finalize",
        b"",
        {"content-type": "application/json"},
    )
    oversized_request.body = Stream([
        b"x" * limit,
        b"x",
        b"unread",
    ])
    oversized = run(runtime.handle(
        oversized_request,
        environment,
        fetch=canonical,
        clock=lambda: NOW,
    ))

    assert [queried.status, encoded.status, oversized.status] == [
        400, 400, 413]
    assert queried.headers == encoded.headers == oversized.headers == safe
    assert queried.body == encoded.body == oversized.body == b""
    assert oversized_request.body.reader.cancelled
    assert oversized_request.body.reader.released is True
    assert oversized_request.body.reader.reads == 2


def test_unknown_route_and_wrong_method_never_consume_body(tmp_path):
    _, _, canonical, opener, _ = world(tmp_path)
    for method, path, status in (
            ("POST", "/not-upload", 404),
            ("GET", "/upload/open", 405)):
        request = Request(
            method,
            "https://broker.example" + path,
            b"large-secret-body",
            {"content-type": "application/json"},
        )
        response = run(runtime.handle(
            request,
            opener.environment,
            fetch=canonical,
            clock=lambda: NOW,
        ))
        assert response.status == status
        assert request.body.reader.reads == 0
        assert request.bytes_calls == 0


def test_invalid_keyring_and_read_failure_fail_closed_without_secrets(
        tmp_path, capsys):
    proof, _, _canonical, opener, _ = world(tmp_path)
    environment = SimpleNamespace(**vars(opener.environment))
    environment.UPLOAD_SESSION_KEYRING += "\n"
    invalid_request = Request(
        "POST",
        "https://broker.example/upload/finalize",
        b"{}",
        {"content-type": "application/json"},
    )
    invalid = run(runtime.handle(
        invalid_request,
        environment,
        fetch=lambda _request: None,
        clock=lambda: NOW,
    ))

    async def failed(_request):
        raise RuntimeError("reader-secret must never escape")

    open_body = encode_open_request(
        proof,
        UploadVector(()).manifest,
        leaf(b"pile"),
    )
    open_request = Request(
        "POST",
        "https://broker.example/upload/open",
        open_body,
        {
            "content-length": str(len(open_body)),
            "content-type": "application/json",
        },
    )
    unavailable = run(runtime.handle(
        open_request,
        opener.environment,
        fetch=failed,
        clock=lambda: NOW,
    ))

    assert invalid.status == 500
    assert unavailable.status == 503
    output = capsys.readouterr()
    combined = output.out + output.err
    for secret in (
            READ_SECRET, INGRESS_SECRET,
            opener.environment.UPLOAD_SESSION_KEYRING):
        assert secret not in combined
        assert secret.encode() not in invalid.body
        assert secret.encode() not in unavailable.body


def test_worker_rejects_collapsed_bucket_authority_and_redacts_settings(
        tmp_path):
    _, _, canonical, opener, _ = world(tmp_path)
    settings = runtime.Settings.from_env(
        opener.environment, clock=lambda: NOW)
    rendered = repr(settings)
    assert READ_SECRET not in rendered
    assert INGRESS_SECRET not in rendered
    assert opener.environment.UPLOAD_SESSION_KEYRING not in rendered

    environment = SimpleNamespace(**vars(opener.environment))
    environment.INGRESS_BUCKET = environment.CANONICAL_BUCKET
    response = run(runtime.handle(
        Request(
            "POST",
            "https://broker.example/upload/finalize",
            b"{}",
            {"content-type": "application/json"},
        ),
        environment,
        fetch=canonical,
        clock=lambda: NOW,
    ))

    assert response.status == 500
    assert canonical.requests == []


def test_canonical_reader_bounds_declared_and_streamed_responses():
    config = R2ReadConfig(
        "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
        "poc16-canonical",
        "workspaces/" + "b" * 64,
    )

    async def declared(_request):
        response = FetchResponse(200, b"x" * 5)
        response.headers = Headers({"content-length": "5"})
        return response

    reader = R2CanonicalReader(
        config,
        READ_ACCESS,
        READ_SECRET,
        declared,
        clock=lambda: NOW,
    )
    with pytest.raises(PayloadTooLarge):
        run(reader.get_bounded("root", 4))

    streamed_response = FetchResponse(
        200, b"", declared=False, stream=True)
    streamed_response.body = Stream([b"1234", b"5", b"unread"])

    async def streamed(_request):
        return streamed_response

    reader = R2CanonicalReader(
        config,
        READ_ACCESS,
        READ_SECRET,
        streamed,
        clock=lambda: NOW,
    )
    with pytest.raises(PayloadTooLarge):
        run(reader.get_bounded("root", 4))
    assert streamed_response.body.reader.reads == 2
    assert streamed_response.body.reader.cancelled
    assert streamed_response.body.reader.released is True


def test_worker_request_and_canonical_fetch_never_whole_materialize():
    empty = Request(
        "POST", "https://broker.example/upload/open",
        stream=False)
    assert run(runtime._bounded_body(empty, 8)) == b""
    assert empty.bytes_calls == 0

    missing_stream = Request(
        "POST", "https://broker.example/upload/open",
        b"x", {"content-length": "1"}, stream=False)
    with pytest.raises(ValueError, match="body stream"):
        run(runtime._bounded_body(missing_stream, 8))
    assert missing_stream.bytes_calls == 0

    malformed_stream = Request(
        "POST", "https://broker.example/upload/open",
        b"x", stream=object())
    with pytest.raises(ValueError, match="body stream"):
        run(runtime._bounded_body(malformed_stream, 8))
    assert malformed_stream.bytes_calls == 0

    config = R2ReadConfig(
        "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
        "poc16-canonical",
        "workspaces/" + "b" * 64,
    )
    response = FetchResponse(200, b"root", stream=False)

    async def fetch(_request):
        return response

    reader = R2CanonicalReader(
        config,
        READ_ACCESS,
        READ_SECRET,
        fetch,
        clock=lambda: NOW,
    )
    with pytest.raises(RuntimeError, match="body stream"):
        run(reader.get_bounded("root", 8))
    assert response.array_calls == 0


def test_internal_fetch_request_repr_redacts_presigned_authority():
    request = R2FetchRequest(
        "GET",
        "https://example.invalid/root?X-Amz-Signature=secret",
        (),
    )

    assert "X-Amz-Signature" not in repr(request)
    assert "secret" not in repr(request)
