"""AWS Function URL broker and private Lambda composition tests."""
import asyncio
import base64
from io import BytesIO
import sys
from types import SimpleNamespace
import urllib.error
from urllib.parse import urlsplit

import facts
import pytest

from core.close import encode_pile
from core.crypto import h
from core.fact import canon
from core.ingress import ingress_key
from deploy.aws_upload_broker import app
from deploy.aws_upload_broker.config import (
    SDK_CONNECT_TIMEOUT_SECONDS,
    SDK_READ_TIMEOUT_SECONDS,
    SDK_TOTAL_ATTEMPTS,
)
from deploy.repository_apply_wire import (
    APPLY_RESULT_SCHEMA,
    MAX_APPLY_RESULT_BYTES,
    encode_apply_request,
)
from deploy.upload_broker import AuthorizedPilePut, UploadBroker
from deploy.upload_broker_http import UploadBrokerEndpoint
from deploy.upload_session import SessionKey, UploadLeaf, UploadSessionPolicy
from deploy.upload_wire import UploadCapability
from facts.auth import request
from full_peer.node import FullPeer
from full_peer.upload_client import UploadSessionRejected
from full_peer.upload_client_http import HttpBrokerTransport


NOW = 5_000_000
SESSION = b"s" * 16
KEY = SessionKey("key00001", b"k" * 32, 0, NOW + 10_000_000)
FUNCTION = (
    "arn:aws:lambda:us-west-2:123456789012:"
    "function:poc16-repository-applier"
)


class Clock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


class CanonicalStore:
    def __init__(self, values):
        self.values = values

    async def get_bounded(self, key, maximum):
        value = self.values.get(key)
        if value is not None and len(value) > maximum:
            raise ValueError("fake object too large")
        return value


class Signer:
    provider_binding = "fake-aws-lambda-ingress-v2"

    def __init__(self, clock):
        self.clock, self.puts = clock, []

    def sign(self, put):
        assert isinstance(put, AuthorizedPilePut)
        self.puts.append(put)
        return UploadCapability(
            "https://ingress.example/" + put.key + "?signature=opaque",
            tuple(sorted((
                ("content-length", str(put.size)),
                ("content-type", "application/octet-stream"),
                ("if-none-match", "*"),
            ))),
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
        response = LambdaResponse(app.handler(
            event, SimpleNamespace(aws_request_id="request-1")))
        if response.status >= 400:
            raise urllib.error.HTTPError(
                request_value.full_url, response.status, "rejected",
                response.headers, BytesIO(response.body))
        return response


def function_event(
        method="POST", path="/upload/open", body=b"", headers=None, *,
        encoded=True, query=""):
    wire_body = base64.b64encode(body).decode("ascii") if encoded \
        else body.decode("utf-8")
    return {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": query,
        "headers": {"content-type": "application/json"}
        if headers is None else headers,
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
        key: backing.get(key) for key in backing.list("")})
    signer, calls = Signer(clock), []

    async def apply_exact(key, digest):
        calls.append((key, digest))
        return {"schema": APPLY_RESULT_SCHEMA, "status": "applied"}

    policy = UploadSessionPolicy(
        "aws-lambda-upload-test", KEY.key_id, (KEY,),
        ttl_ms=120_000, max_ttl_ms=120_000, clock_skew_ms=1_000,
    )
    app._endpoint_cache = UploadBrokerEndpoint(UploadBroker(
        store, workspace, signer, clock, policy,
        apply_exact=apply_exact,
        nonce=lambda count: SESSION if count == len(SESSION) else b"",
    ))
    opener = LambdaOpener()
    return (
        workspace, proof, signer, calls, opener,
        HttpBrokerTransport(
            "https://broker.lambda-url.example", opener=opener),
    )


def leaf(raw=b"one closed fact pile"):
    return UploadLeaf(h(raw), len(raw))


def test_function_url_runs_exact_open_and_private_finalize(
        tmp_path, monkeypatch):
    workspace, proof, signer, calls, opener, transport = world(
        tmp_path, monkeypatch)
    pile = leaf()

    opened = transport.open(proof, pile)
    result = transport.finalize(opened.cursor)

    assert result.status == "applied"
    assert len(signer.puts) == 1
    member = app._endpoint_cache.broker.tokens.decode(
        opened.cursor, NOW).member
    expected = ingress_key(
        workspace, opened.session, member, pile.digest)
    assert signer.puts[0].key == expected
    assert calls == [(expected, pile.digest)]
    assert [event["rawPath"] for event in opener.events] == [
        "/upload/open", "/upload/finalize"]
    bodies = [base64.b64decode(event["body"], validate=True)
              for event in opener.events]
    assert all(b"one closed fact pile" not in body for body in bodies)


def test_exact_cursor_expires_without_invoking_applier(
        tmp_path, monkeypatch):
    clock = Clock()
    _, proof, _, calls, _, transport = world(
        tmp_path, monkeypatch, clock=clock)
    opened = transport.open(proof, leaf())
    clock.value = opened.expires_at_ms

    with pytest.raises(UploadSessionRejected):
        transport.finalize(opened.cursor)
    assert calls == []


class Payload(BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.closed_by_adapter = False

    def close(self):
        self.closed_by_adapter = True
        super().close()


class LambdaClient:
    def __init__(self, response):
        self.response, self.calls = response, []

    def invoke(self, **request_value):
        self.calls.append(request_value)
        return self.response


def applier_callback(monkeypatch, response, workspace):
    client = LambdaClient(response)
    monkeypatch.setenv("TINYP2P_UPLOAD_APPLIER_FUNCTION_ARN", FUNCTION)
    monkeypatch.setattr(app, "_botocore_config", lambda: object())
    monkeypatch.setitem(
        sys.modules, "boto3",
        SimpleNamespace(client=lambda service, config: client),
    )
    return app._applier(workspace), client


def test_private_lambda_rpc_is_request_response_and_exactly_bounded(
        monkeypatch):
    workspace, digest = "a" * 64, "d" * 64
    key = ingress_key(workspace, "b" * 32, "c" * 64, digest)
    body = canon({"schema": APPLY_RESULT_SCHEMA, "status": "applied"})
    payload = Payload(body)
    callback, client = applier_callback(monkeypatch, {
        "StatusCode": 200,
        "Payload": payload,
    }, workspace)

    assert asyncio.run(callback(key, digest)) == {
        "schema": APPLY_RESULT_SCHEMA, "status": "applied"}
    assert client.calls == [{
        "FunctionName": FUNCTION,
        "InvocationType": "RequestResponse",
        "Payload": canon(encode_apply_request(workspace, key, digest)),
    }]
    assert payload.closed_by_adapter


@pytest.mark.parametrize("response", (
    {"StatusCode": 200, "FunctionError": "Unhandled", "Payload": Payload(b"")},
    {"StatusCode": 202, "Payload": Payload(b"")},
    {"StatusCode": 200, "Payload": Payload(b"x" * (
        MAX_APPLY_RESULT_BYTES + 1))},
    {"StatusCode": 200, "Payload": Payload(b'{"status":"applied"}')},
    {"StatusCode": 200, "Payload": object()},
))
def test_private_lambda_rpc_rejects_failure_oversize_and_malformed(
        monkeypatch, response):
    workspace, digest = "a" * 64, "d" * 64
    key = ingress_key(workspace, "b" * 32, "c" * 64, digest)
    callback, _ = applier_callback(monkeypatch, response, workspace)

    with pytest.raises(RuntimeError, match="Applier"):
        asyncio.run(callback(key, digest))


class BombEndpoint:
    async def handle(self, *_args):
        raise AssertionError("endpoint must not run")


@pytest.mark.parametrize("change", (
    {"version": "1.0"},
    {"rawQueryString": "authority=surplus"},
    {"body": "***", "isBase64Encoded": True},
    {"body": 7},
    {"isBase64Encoded": "true"},
))
def test_function_url_rejects_malformed_events_before_broker(
        monkeypatch, change):
    event = function_event(body=b"{}")
    event.update(change)
    monkeypatch.setattr(app, "_endpoint_cache", BombEndpoint())

    result = app.handler(event, SimpleNamespace(aws_request_id="request-2"))

    assert result["statusCode"] == 400
    assert base64.b64decode(result["body"], validate=True) == b""


def test_function_url_bounds_body_before_broker(monkeypatch):
    monkeypatch.setattr(app, "_endpoint_cache", BombEndpoint())
    limit = app.upload_request_body_limit("/upload/finalize")
    oversized = b"x" * (limit + 1)

    encoded = app.handler(
        function_event(path="/upload/finalize", body=oversized), None)
    plain = app.handler(function_event(
        path="/upload/finalize", body=oversized, encoded=False), None)

    assert encoded["statusCode"] == plain["statusCode"] == 413


def test_aws_canonical_reader_fails_closed_on_403(monkeypatch):
    captured = []

    class Store:
        def __init__(self, config):
            captured.append(config)

    monkeypatch.setattr(app, "S3Store", Store)
    monkeypatch.setenv("TINYP2P_UPLOAD_CANONICAL_BUCKET", "canonical-bucket")
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
    assert config.probe_access_denied_missing is False
    assert config.conditional_write_403_is_absent is False


def test_aws_sdk_deadline_budget_and_owner_fail_closed(monkeypatch):
    assert app._sdk_budget() == (
        SDK_CONNECT_TIMEOUT_SECONDS,
        SDK_READ_TIMEOUT_SECONDS,
        SDK_TOTAL_ATTEMPTS,
    )
    monkeypatch.setenv("TINYP2P_UPLOAD_AWS_TOTAL_ATTEMPTS", "2")
    with pytest.raises(RuntimeError, match="deadline budget"):
        app._sdk_budget()
    monkeypatch.setenv("TINYP2P_UPLOAD_EXPECTED_BUCKET_OWNER", "not-account")
    with pytest.raises(RuntimeError, match="invalid"):
        app._expected_owner()
