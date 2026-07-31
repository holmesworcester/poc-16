"""Bounded broker JSON and redirect-free streaming PUT effects."""
from io import BytesIO
import json
import socket
import urllib.error

import pytest

from core.crypto import h
from core.fact import canon
from deploy.upload_session import UploadLeaf
from deploy.upload_wire import (
    FINALIZE_REQUEST_SCHEMA,
    OPEN_REQUEST_SCHEMA,
    FinalizedUpload,
    OpenedUpload,
    UploadCapability,
    finalize_document,
    open_document,
)
from full_peer.upload_client import (
    CREATED,
    UploadCapabilityRejected,
    UploadCreateConflict,
    UploadOutcomeUnknown,
    UploadProtocolError,
    UploadRetryable,
    UploadSessionRejected,
)
from full_peer.upload_client_http import HttpBrokerTransport, HttpPutTransport


SESSION = "a" * 32
CURSOR = "opaque_cursor"
EXPIRY = 50_000
PILE = UploadLeaf(h(b"pile"), 4)
CAP = UploadCapability(
    "https://bucket.example/ingress/pile?signature=opaque",
    tuple(sorted((
        ("content-length", "4"),
        ("content-type", "application/octet-stream"),
        ("if-none-match", "*"),
    ))),
    EXPIRY,
)


class Response:
    def __init__(self, value):
        self.raw = json.dumps(
            value, sort_keys=True, separators=(",", ":")).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, maximum):
        return self.raw[:maximum]


class RawResponse(Response):
    def __init__(self, raw):
        self.raw = raw


def test_broker_transport_has_exactly_open_and_finalize_documents():
    calls = []
    opened_value = OpenedUpload(
        SESSION, CURSOR, CAP, EXPIRY)
    replies = [open_document(opened_value),
               finalize_document(FinalizedUpload("applied"))]

    def open_url(request, timeout):
        calls.append((request.full_url, json.loads(request.data),
                      request.method, timeout))
        return Response(replies.pop(0))

    transport = HttpBrokerTransport(
        "https://broker.example/base/", timeout=7, opener=open_url)
    assert transport.open(b"proof", PILE) == opened_value
    assert transport.finalize(CURSOR) == FinalizedUpload("applied")

    assert [call[0] for call in calls] == [
        "https://broker.example/base/upload/open",
        "https://broker.example/base/upload/finalize",
    ]
    assert [call[1]["schema"] for call in calls] == [
        OPEN_REQUEST_SCHEMA, FINALIZE_REQUEST_SCHEMA]
    assert calls[0][1]["pile"] == {
        "digest": PILE.digest, "size": PILE.size}
    assert all(call[2:] == ("POST", 7) for call in calls)


@pytest.mark.parametrize("mutate", (
    lambda raw: b" " + raw,
    lambda raw: raw.replace(
        b'"schema":', b'"schema":"duplicate","schema":', 1),
))
def test_broker_transport_rejects_noncanonical_or_ambiguous_responses(
        mutate):
    raw = canon(open_document(OpenedUpload(
        SESSION, CURSOR, CAP, EXPIRY)))
    transport = HttpBrokerTransport(
        "https://broker.example",
        opener=lambda *_args, **_kwargs: RawResponse(mutate(raw)),
    )

    with pytest.raises(UploadProtocolError, match="invalid OPEN response"):
        transport.open(b"proof", PILE)


@pytest.mark.parametrize("status,error", [
    (403, UploadSessionRejected),
    (409, UploadSessionRejected),
    (429, UploadRetryable),
    (503, UploadRetryable),
])
def test_broker_http_failures_are_classified_without_reading_secrets(
        status, error):
    failure = urllib.error.HTTPError(
        "https://broker.example/upload/finalize", status, "bad", {},
        BytesIO(b"sensitive provider response"))
    transport = HttpBrokerTransport(
        "https://broker.example",
        opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(failure))
    with pytest.raises(error):
        transport.finalize(CURSOR)


class ProviderResponse:
    def __init__(self, status):
        self.status = status

    def read(self, maximum):
        return b""


class Connection:
    def __init__(self, status=204, failure=None):
        self.status, self.failure = status, failure
        self.requested, self.closed = None, False

    def request(self, method, path, body, headers):
        if self.failure is not None:
            raise self.failure
        self.requested = (method, path, body.read(), headers)

    def getresponse(self):
        return ProviderResponse(self.status)

    def close(self):
        self.closed = True


def test_provider_streams_only_the_exact_put_with_granted_headers():
    connection = Connection()
    transport = HttpPutTransport(
        connection_factory=lambda parsed, timeout: connection)

    assert transport.put(CAP, BytesIO(b"pile"), 4) is CREATED
    assert connection.requested == (
        "PUT", "/ingress/pile?signature=opaque", b"pile",
        dict(CAP.headers))
    assert connection.closed


@pytest.mark.parametrize("connection,error", [
    (Connection(status=412), UploadCreateConflict),
    (Connection(status=403), UploadCapabilityRejected),
    (Connection(failure=socket.timeout()), UploadOutcomeUnknown),
    (Connection(status=503), UploadOutcomeUnknown),
])
def test_provider_preconditions_and_unknown_outcomes_stay_conservative(
        connection, error):
    transport = HttpPutTransport(
        connection_factory=lambda parsed, timeout: connection)
    with pytest.raises(error):
        transport.put(CAP, BytesIO(b"pile"), 4)
    assert connection.closed
