"""AWS Function URL boundary tests for the production upload broker."""
import asyncio
import base64
from io import BytesIO
import json
import sys
from types import SimpleNamespace
import urllib.error
from urllib.parse import urlsplit

import facts
import pytest

from core.close import encode_pile
from core.crypto import h
from full_peer.node import FullPeer
from deploy.aws_upload_broker import app
from deploy.aws_upload_broker.config import (
    SDK_CONNECT_TIMEOUT_SECONDS,
    SDK_READ_TIMEOUT_SECONDS,
    SDK_TOTAL_ATTEMPTS,
)
from core.http import Response
from deploy.upload_broker import (
    AuthorizedPut,
    UploadBroker,
)
from deploy.upload_broker_http import UploadBrokerEndpoint
from deploy.upload_wire import UploadCapability
from full_peer.upload_client_http import HttpBrokerTransport
from full_peer.upload_client import UploadSessionRejected
from deploy.upload_keyring import UploadKeyring, encode_keyring
from deploy.upload_session import (
    SessionKey,
    UploadLeaf,
    UploadSessionPolicy,
    UploadVector,
)
from facts.auth import request


NOW = 5_000_000
SESSION = b"s" * 16
PROVIDER = "fake-aws-lambda-ingress-v1"
KEY = SessionKey("key00001", b"k" * 32, 0, NOW + 10_000_000)


class Clock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


class CanonicalStore:
    def __init__(self, values):
        self.values = values

    async def get(self, key):
        return self.values.get(key)

    async def get_bounded(self, key, maximum):
        value = await self.get(key)
        if value is not None and len(value) > maximum:
            raise ValueError("fake object too large")
        return value


class Signer:
    provider_binding = PROVIDER

    def __init__(self, clock=None):
        self.clock = clock or (lambda: NOW)
        self.puts = []

    def sign(self, put):
        assert isinstance(put, AuthorizedPut)
        self.puts.append(put)
        return UploadCapability(
            "PUT",
            "https://ingress.example/" + put.key + "?signature=opaque",
            (
                ("content-length", str(put.size)),
                ("content-type", put.content_type),
                ("if-none-match", "*"),
            ),
            min(self.clock() + 60_000, put.not_after_ms),
        )


class LambdaResponse:
    def __init__(self, result):
        self.status = result["statusCode"]
        self.headers = result["headers"]
        self.body = base64.b64decode(result["body"], validate=True)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, maximum):
        return self.body[:maximum]


class LambdaOpener:
    """Run urllib client requests through the real Function URL adapter."""

    def __init__(self):
        self.events = []

    def __call__(self, request_value, timeout):
        del timeout
        event = function_event(
            request_value.method,
            urlsplit(request_value.full_url).path,
            request_value.data,
            dict(request_value.header_items()),
        )
        self.events.append(event)
        result = app.handler(
            event, SimpleNamespace(aws_request_id="request-1"))
        response = LambdaResponse(result)
        if response.status >= 400:
            raise urllib.error.HTTPError(
                request_value.full_url,
                response.status,
                "upload broker rejected request",
                response.headers,
                BytesIO(response.body),
            )
        return response


def function_event(
        method="POST", path="/upload/open", body=b"",
        headers=None, *, encoded=True, query=""):
    if encoded:
        wire_body = base64.b64encode(body).decode("ascii")
    else:
        wire_body = body.decode("utf-8")
    return {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": query,
        "headers": (
            {"content-type": "application/json"}
            if headers is None else headers
        ),
        "requestContext": {"http": {"method": method}},
        "body": wire_body,
        "isBase64Encoded": encoded,
    }


def world(tmp_path, monkeypatch, *, clock=None):
    clock = clock or Clock()
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    proof = encode_pile(request.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    backing = node.store(workspace)
    store = CanonicalStore({
        key: backing.get(key) for key in backing.list("")
    })
    signer = Signer(clock)
    broker = UploadBroker(
        store,
        workspace,
        signer,
        clock,
        UploadSessionPolicy(
            "aws-lambda-upload-test",
            KEY.key_id,
            (KEY,),
            ttl_ms=120_000,
            max_ttl_ms=120_000,
            clock_skew_ms=1_000,
        ),
        nonce=lambda count: SESSION if count == len(SESSION) else b"",
    )
    endpoint = UploadBrokerEndpoint(broker)
    monkeypatch.setattr(app, "_endpoint_cache", endpoint)
    opener = LambdaOpener()
    return (
        proof,
        signer,
        opener,
        HttpBrokerTransport(
            "https://broker.lambda-url.example",
            opener=opener,
        ),
    )


def leaf(raw):
    return UploadLeaf(h(raw), len(raw))


@pytest.mark.parametrize("objects", ((), (b"one", b"two", b"three")))
def test_function_url_runs_complete_direct_upload_session(
        tmp_path, monkeypatch, objects):
    proof, signer, opener, transport = world(tmp_path, monkeypatch)
    vector = UploadVector(tuple(sorted(
        (leaf(raw) for raw in objects),
        key=lambda item: item.digest,
    )))
    pile = leaf(b"one closed fact pile")

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
    result = transport.finalize(cursor)

    assert result.pile.leaf == pile
    assert [put.object_class for put in signer.puts] == (
        ["obj"] * len(objects) + ["pile"])
    assert all(
        event["rawPath"] in {
            "/upload/open", "/upload/issue", "/upload/finalize"}
        for event in opener.events
    )
    decoded_requests = [
        base64.b64decode(event["body"], validate=True)
        for event in opener.events
    ]
    # Function URL carries only authorization/manifest metadata. Neither the
    # file bodies nor the staged pile body crosses Lambda.
    for raw in (*objects, b"one closed fact pile"):
        assert all(raw not in body for body in decoded_requests)
    assert all(not hasattr(put, "body") for put in signer.puts)


def test_lambda_retries_only_until_the_open_session_deadline(
        tmp_path, monkeypatch):
    clock = Clock()
    proof, signer, _, transport = world(
        tmp_path, monkeypatch, clock=clock)
    vector = UploadVector((leaf(b"one object"),))
    pile = leaf(b"one closed fact pile")
    opened = transport.open(proof, vector.manifest, pile)
    issued = transport.issue(
        opened.cursor, 0, vector.leaves, vector.proof(0, 1))

    clock.value = opened.expires_at_ms - 1
    retried = transport.issue(
        opened.cursor, 0, vector.leaves, vector.proof(0, 1))
    finalized = transport.finalize(issued.cursor)
    assert retried.cursor == issued.cursor
    assert finalized.expires_at_ms == opened.expires_at_ms
    assert all(
        put.not_after_ms == opened.expires_at_ms for put in signer.puts)
    assert all(
        capability.expires_at_ms <= opened.expires_at_ms
        for capability in (
            retried.objects[0].capability, finalized.pile.capability)
    )

    clock.value = opened.expires_at_ms
    with pytest.raises(UploadSessionRejected):
        transport.issue(
            opened.cursor, 0, vector.leaves, vector.proof(0, 1))
    with pytest.raises(UploadSessionRejected):
        transport.finalize(issued.cursor)


class BombEndpoint:
    async def handle(self, *_args):
        raise AssertionError("endpoint must not run")


@pytest.mark.parametrize(
    ("change", "status"),
    (
        ({"version": "1.0"}, 400),
        ({"rawQueryString": "authority=surplus"}, 400),
        ({"body": "***", "isBase64Encoded": True}, 400),
        ({"body": 7}, 400),
        ({"isBase64Encoded": "true"}, 400),
    ),
)
def test_function_url_rejects_malformed_events_before_broker(
        monkeypatch, change, status):
    event = function_event(body=b"{}")
    event.update(change)
    monkeypatch.setattr(app, "_endpoint_cache", BombEndpoint())

    result = app.handler(event, SimpleNamespace(aws_request_id="request-2"))

    assert result["statusCode"] == status
    assert base64.b64decode(result["body"], validate=True) == b""
    assert result["headers"] == {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }


def test_function_url_bounds_base64_and_plain_bodies_before_broker(
        monkeypatch):
    monkeypatch.setattr(app, "_endpoint_cache", BombEndpoint())
    limit = app.upload_request_body_limit("/upload/finalize")
    oversized = b"x" * (limit + 1)

    encoded = app.handler(
        function_event(path="/upload/finalize", body=oversized),
        SimpleNamespace(aws_request_id="request-3"),
    )
    plain = app.handler(
        function_event(
            path="/upload/finalize",
            body=oversized,
            encoded=False,
        ),
        SimpleNamespace(aws_request_id="request-4"),
    )

    assert encoded["statusCode"] == plain["statusCode"] == 413
    assert encoded["headers"] == plain["headers"] == {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }


def test_unknown_route_and_wrong_method_do_not_decode_large_bodies(
        tmp_path, monkeypatch):
    _, _, _, _ = world(tmp_path, monkeypatch)
    huge = "not-base64" * 100_000
    unknown = function_event(path="/not-upload", body=b"")
    unknown["body"] = huge
    method = function_event(method="GET", body=b"")
    method["body"] = huge

    assert app.handler(
        unknown, SimpleNamespace(aws_request_id="request-5"))[
            "statusCode"] == 404
    assert app.handler(
        method, SimpleNamespace(aws_request_id="request-6"))[
            "statusCode"] == 405


class FailingEndpoint:
    async def handle(self, *_args):
        raise RuntimeError("must not be logged")


def test_handler_failure_log_excludes_request_authority(
        monkeypatch, caplog):
    secret = b"proof-cursor-presigned-url-must-not-appear"
    event = function_event(
        path="/upload/finalize",
        body=secret,
    )
    monkeypatch.setattr(app, "_endpoint_cache", FailingEndpoint())

    result = app.handler(
        event,
        SimpleNamespace(aws_request_id="request-7"),
    )

    assert result["statusCode"] == 503
    assert result["headers"] == {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    combined = "\n".join(record.message for record in caplog.records)
    assert secret.decode() not in combined
    assert "must not be logged" not in combined
    assert "request-7" in combined
    assert "/upload/finalize" in combined


def test_secret_loader_binds_keyring_to_signer_and_issuer(
        monkeypatch):
    policy = UploadSessionPolicy(
        "aws-upload-production",
        KEY.key_id,
        (KEY,),
        ttl_ms=120_000,
        max_ttl_ms=120_000,
    )
    raw = encode_keyring(UploadKeyring(PROVIDER, policy)).decode()

    class Secrets:
        def get_secret_value(self, **request_value):
            assert request_value == {
                "SecretId": "secret-arn",
                "VersionId": "v" * 32,
            }
            return {"SecretString": raw}

    fake_boto3 = SimpleNamespace(
        client=lambda service, config: (
            Secrets() if service == "secretsmanager" else None))
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setattr(app, "_botocore_config", lambda: object())
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_KEYRING_SECRET_ARN", "secret-arn")
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_KEYRING_VERSION_ID", "v" * 32)
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_ISSUER", policy.issuer)

    assert app._keyring(
        SimpleNamespace(provider_binding=PROVIDER)) == policy
    with pytest.raises(RuntimeError, match="invalid upload keyring"):
        app._keyring(SimpleNamespace(
            provider_binding="different-provider-v1"))
    monkeypatch.setenv("TINYP2P_UPLOAD_ISSUER", "wrong-issuer")
    with pytest.raises(RuntimeError, match="keyring issuer"):
        app._keyring(SimpleNamespace(provider_binding=PROVIDER))


def test_cold_sandbox_constructs_one_endpoint_from_one_keyring(
        monkeypatch):
    calls = []
    signer = Signer()
    session_policy = UploadSessionPolicy(
        "aws-upload-production",
        KEY.key_id,
        (KEY,),
    )
    monkeypatch.setattr(app, "_endpoint_cache", None)
    monkeypatch.setattr(app, "_signer", lambda: signer)
    monkeypatch.setattr(
        app, "_store", lambda: CanonicalStore({}))

    def load(candidate):
        calls.append(candidate)
        return session_policy

    monkeypatch.setattr(app, "_keyring", load)
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_WORKSPACE_ID", "a" * 64)

    first = app._endpoint()
    second = app._endpoint()

    assert first is second
    assert isinstance(first, UploadBrokerEndpoint)
    assert calls == [signer]


def test_aws_store_uses_one_attempt_deadline_and_read_only_wrapper(
        monkeypatch):
    captured = []

    class Store:
        def __init__(self, config):
            captured.append(config)

    monkeypatch.setattr(app, "S3Store", Store)
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_CANONICAL_BUCKET", "canonical-bucket")
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_CANONICAL_PREFIX", "workspaces/tenant")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_EXPECTED_BUCKET_OWNER", "123456789012")

    wrapped = app._store()

    assert wrapped.reader.__class__ is Store
    config = captured[0]
    assert config.connect_timeout == SDK_CONNECT_TIMEOUT_SECONDS
    assert config.read_timeout == SDK_READ_TIMEOUT_SECONDS
    assert config.read_total_max_attempts == SDK_TOTAL_ATTEMPTS
    assert config.probe_access_denied_missing is True
    assert config.expected_bucket_owner == "123456789012"


def test_runtime_requires_an_exact_bucket_owner(monkeypatch):
    monkeypatch.delenv(
        "TINYP2P_UPLOAD_EXPECTED_BUCKET_OWNER", raising=False)
    with pytest.raises(RuntimeError, match="missing"):
        app._expected_owner()
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_EXPECTED_BUCKET_OWNER", "")
    with pytest.raises(RuntimeError, match="missing"):
        app._expected_owner()
    monkeypatch.setenv(
        "TINYP2P_UPLOAD_EXPECTED_BUCKET_OWNER", "not-an-account")
    with pytest.raises(RuntimeError, match="invalid"):
        app._expected_owner()


def test_aws_sdk_deadline_budget_fails_before_handler_io(monkeypatch):
    assert app._sdk_budget() == (
        SDK_CONNECT_TIMEOUT_SECONDS,
        SDK_READ_TIMEOUT_SECONDS,
        SDK_TOTAL_ATTEMPTS,
    )
    monkeypatch.setenv("TINYP2P_UPLOAD_AWS_TOTAL_ATTEMPTS", "2")
    with pytest.raises(RuntimeError, match="deadline budget"):
        app._sdk_budget()
