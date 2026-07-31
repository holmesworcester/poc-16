"""Bounded JSON broker transport and redirect-free streaming PUT tests."""
from io import BytesIO
import json
import socket
import urllib.error

import pytest

from core.crypto import h
from deploy.upload_broker import (
    finalize_document,
    issue_document,
    open_document,
)
from deploy.upload_wire import (
    FinalizedUpload,
    GrantedUpload,
    IssuedUpload,
    OpenedUpload,
    UploadCapability,
)
from full_peer.upload_client import (
    CREATED,
    UploadCreateConflict,
    UploadOutcomeUnknown,
    UploadSessionRejected,
)
from full_peer.upload_client_http import (
    HttpBrokerTransport,
    HttpPutTransport,
)
from deploy.upload_session import TOKEN_BYTES, UploadLeaf, UploadVector
from deploy.upload_wire import (
    FINALIZE_REQUEST_SCHEMA,
    ISSUE_REQUEST_SCHEMA,
    OPEN_REQUEST_SCHEMA,
)


SESSION = "a" * 32
CURSOR = "a" * TOKEN_BYTES
ADVANCED = "b" * TOKEN_BYTES
EXPIRY = 50_000
LEAF = UploadLeaf(h(b"body"), 4)
PILE = UploadLeaf(h(b"pile"), 4)
CAP = UploadCapability(
    "PUT",
    "https://bucket.example/ingress/object?signature=opaque",
    (
        ("content-length", "4"),
        ("content-type", "application/octet-stream"),
        ("if-none-match", "*"),
    ),
    EXPIRY,
)


class Response:
    def __init__(self, value):
        self.raw = json.dumps(
            value, sort_keys=True, separators=(",", ":")).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, maximum):
        return self.raw[:maximum]


def test_broker_http_transport_round_trips_all_three_bounded_documents():
    calls = []
    replies = [
        open_document(OpenedUpload(SESSION, CURSOR, EXPIRY)),
        issue_document(IssuedUpload(
            ADVANCED, 1, (GrantedUpload(LEAF, CAP),), EXPIRY)),
        finalize_document(FinalizedUpload(
            ADVANCED, GrantedUpload(PILE, CAP), EXPIRY)),
    ]

    def open_url(request, timeout):
        calls.append((
            request.full_url,
            json.loads(request.data),
            request.method,
            timeout,
        ))
        return Response(replies.pop(0))

    transport = HttpBrokerTransport(
        "https://broker.example/base/", timeout=7, opener=open_url)
    vector = UploadVector((LEAF,))

    opened = transport.open(b"proof", vector.manifest, PILE)
    issued = transport.issue(
        opened.cursor, 0, vector.leaves, vector.proof(0, 1))
    finalized = transport.finalize(issued.cursor)

    assert opened == OpenedUpload(SESSION, CURSOR, EXPIRY)
    assert issued.objects[0].capability == CAP
    assert finalized.pile.leaf == PILE
    assert [call[0] for call in calls] == [
        "https://broker.example/base/upload/open",
        "https://broker.example/base/upload/issue",
        "https://broker.example/base/upload/finalize",
    ]
    assert [call[1]["schema"] for call in calls] == [
        OPEN_REQUEST_SCHEMA, ISSUE_REQUEST_SCHEMA, FINALIZE_REQUEST_SCHEMA]
    assert all(call[2:] == ("POST", 7) for call in calls)
    assert calls[0][1]["manifest"] == {
        "count": 1,
        "root": vector.manifest.root,
        "total_bytes": 4,
    }
    assert len(calls[1][1]["leaves"]) == 1


def test_broker_http_maps_expired_cursor_without_exposing_response_body():
    error = urllib.error.HTTPError(
        "https://broker.example/upload/issue",
        410, "gone", {}, BytesIO(b"sensitive"))
    transport = HttpBrokerTransport(
        "https://broker.example",
        opener=lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )
    vector = UploadVector((LEAF,))

    with pytest.raises(UploadSessionRejected, match="ISSUE"):
        transport.issue(
            CURSOR, 0, vector.leaves, vector.proof(0, 1))


class ProviderResponse:
    def __init__(self, status):
        self.status = status

    def read(self, maximum):
        return b""


class Connection:
    def __init__(self, status=204, failure=None):
        self.status, self.failure, self.requested, self.closed = (
            status, failure, None, False)

    def request(self, method, path, body, headers):
        if self.failure is not None:
            raise self.failure
        self.requested = (
            method, path, body.read(), headers)

    def getresponse(self):
        return ProviderResponse(self.status)

    def close(self):
        self.closed = True


def test_provider_http_streams_only_the_exact_put_and_headers():
    connection = Connection()
    transport = HttpPutTransport(
        connection_factory=lambda parsed, timeout: connection)

    result = transport.put(CAP, BytesIO(b"body"), 4)

    assert result is CREATED
    assert connection.requested == (
        "PUT",
        "/ingress/object?signature=opaque",
        b"body",
        dict(CAP.headers),
    )
    assert connection.closed


@pytest.mark.parametrize(
    ("connection", "error"),
    (
        (Connection(status=412), UploadCreateConflict),
        (Connection(failure=socket.timeout()), UploadOutcomeUnknown),
        (Connection(status=503), UploadOutcomeUnknown),
    ),
)
def test_provider_http_keeps_precondition_and_unknown_outcomes_conservative(
        connection, error):
    transport = HttpPutTransport(
        connection_factory=lambda parsed, timeout: connection)

    with pytest.raises(error):
        transport.put(CAP, BytesIO(b"body"), 4)
    assert connection.closed
