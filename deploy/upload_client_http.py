"""Narrow HTTP adapters for :mod:`deploy.upload_client`.

Broker JSON carries only proof/manifest metadata and exact bearer requests.
Provider bodies go straight to the capability URL through a streaming PUT.
Neither adapter accepts bucket credentials, free-form object keys, LIST,
DELETE, or root authority.
"""
import http.client
import json
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from core.limits import PAGE_BATCH, PayloadTooLarge
from deploy.upload_broker import (
    MAX_FINALIZE_RESPONSE_BYTES,
    MAX_ISSUE_RESPONSE_BYTES,
    MAX_OPEN_RESPONSE_BYTES,
    FinalizedUpload,
    GrantedUpload,
    IssuedUpload,
    OpenedUpload,
    UploadCapability,
)
from deploy.upload_client import (
    CREATED,
    UploadCapabilityRejected,
    UploadClient,
    UploadCreateConflict,
    UploadOutcomeUnknown,
    UploadProtocolError,
    UploadRetryable,
    UploadSessionRejected,
)
from deploy.upload_session import (
    UploadLeaf,
    UploadManifest,
)
from deploy.upload_wire import (
    FINALIZE_REQUEST_SCHEMA,
    ISSUE_REQUEST_SCHEMA,
    InvalidUploadWire,
    MAX_FINALIZE_REQUEST_BYTES,
    MAX_ISSUE_REQUEST_BYTES,
    MAX_OPEN_REQUEST_BYTES,
    OPEN_REQUEST_SCHEMA,
    encode_finalize_request,
    encode_issue_request,
    encode_open_request,
)


MAX_PROVIDER_ERROR_BYTES = 4_096


def _system_now_ms():
    return time.time_ns() // 1_000_000


def _capability(value):
    try:
        if not isinstance(value, dict) or set(value) != {
                "expires_at_ms", "headers", "method", "url"} \
                or not isinstance(value["headers"], dict) \
                or not all(
                    isinstance(name, str) and isinstance(header, str)
                    for name, header in value["headers"].items()):
            raise ValueError
        return UploadCapability(
            value["method"],
            value["url"],
            tuple(sorted(value["headers"].items())),
            value["expires_at_ms"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise UploadProtocolError("invalid upload capability") from error


def _grant(value, label):
    try:
        if not isinstance(value, dict) \
                or set(value) != {"digest", "put", "size"}:
            raise ValueError
        return GrantedUpload(
            UploadLeaf(value["digest"], value["size"]),
            _capability(value["put"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise UploadProtocolError(f"invalid {label}") from error


def _document(raw, maximum, label):
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise UploadProtocolError(f"{label} exceeds response limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UploadProtocolError(f"invalid {label}") from error
    if not isinstance(value, dict):
        raise UploadProtocolError(f"invalid {label}")
    return value


class HttpBrokerTransport:
    """POST bounded protocol documents to one HTTPS upload broker."""

    def __init__(self, base_url, *, timeout=30, opener=None):
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname \
                or parsed.username is not None or parsed.password is not None \
                or parsed.query or parsed.fragment:
            raise ValueError("upload broker URL")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("upload broker timeout")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.opener = urllib.request.urlopen if opener is None else opener

    def _post(self, verb, raw, response_limit):
        request = urllib.request.Request(
            f"{self.base_url}/upload/{verb.lower()}",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                body = response.read(response_limit + 1)
        except urllib.error.HTTPError as error:
            if error.code in {401, 403, 409, 410}:
                raise UploadSessionRejected(
                    f"broker rejected {verb}") from error
            if error.code in {408, 425, 429} or error.code >= 500:
                raise UploadRetryable(
                    f"broker unavailable during {verb}") from error
            raise UploadProtocolError(
                f"broker returned HTTP {error.code} for {verb}") from error
        except (OSError, urllib.error.URLError) as error:
            raise UploadRetryable(
                f"broker unavailable during {verb}") from error
        return _document(body, response_limit, f"{verb} response")

    def open(self, proof, manifest, pile):
        if not isinstance(manifest, UploadManifest):
            raise TypeError("upload manifest")
        try:
            request = encode_open_request(proof, manifest, pile)
        except (InvalidUploadWire, PayloadTooLarge) as error:
            raise UploadProtocolError("invalid OPEN request") from error
        value = self._post(
            "OPEN",
            request,
            MAX_OPEN_RESPONSE_BYTES,
        )
        if set(value) != {
                "cursor", "expires_at_ms", "schema", "session"} \
                or value.get("schema") != "poc16-upload-open-v1":
            raise UploadProtocolError("invalid OPEN response")
        try:
            return OpenedUpload(
                value["session"], value["cursor"], value["expires_at_ms"])
        except (KeyError, TypeError) as error:
            raise UploadProtocolError("invalid OPEN response") from error

    def issue(self, cursor, start_index, leaves, proof):
        leaves = tuple(leaves)
        try:
            request = encode_issue_request(
                cursor, start_index, leaves, proof)
        except (InvalidUploadWire, PayloadTooLarge) as error:
            raise UploadProtocolError("invalid ISSUE request") from error
        value = self._post(
            "ISSUE",
            request,
            MAX_ISSUE_RESPONSE_BYTES,
        )
        if set(value) != {
                "cursor", "expires_at_ms", "next_index",
                "objects", "schema"} \
                or value.get("schema") != "poc16-upload-issue-v1" \
                or not isinstance(value.get("objects"), list) \
                or len(value["objects"]) > PAGE_BATCH:
            raise UploadProtocolError("invalid ISSUE response")
        try:
            return IssuedUpload(
                value["cursor"],
                value["next_index"],
                tuple(
                    _grant(item, "object grant")
                    for item in value["objects"]
                ),
                value["expires_at_ms"],
            )
        except (KeyError, TypeError) as error:
            raise UploadProtocolError("invalid ISSUE response") from error

    def finalize(self, cursor):
        try:
            request = encode_finalize_request(cursor)
        except (InvalidUploadWire, PayloadTooLarge) as error:
            raise UploadProtocolError(
                "invalid FINALIZE request") from error
        value = self._post(
            "FINALIZE",
            request,
            MAX_FINALIZE_RESPONSE_BYTES,
        )
        if set(value) != {
                "cursor", "expires_at_ms", "pile", "schema"} \
                or value.get("schema") != "poc16-upload-finalize-v1":
            raise UploadProtocolError("invalid FINALIZE response")
        try:
            return FinalizedUpload(
                value["cursor"],
                _grant(value["pile"], "pile grant"),
                value["expires_at_ms"],
            )
        except (KeyError, TypeError) as error:
            raise UploadProtocolError("invalid FINALIZE response") from error


class HttpPutTransport:
    """Perform one streaming, redirect-free PUT from an exact capability."""

    def __init__(self, *, timeout=60, connection_factory=None):
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("provider PUT timeout")
        self.timeout = timeout
        self.connection_factory = connection_factory

    def _connection(self, parsed):
        if self.connection_factory is not None:
            return self.connection_factory(parsed, self.timeout)
        return http.client.HTTPSConnection(
            parsed.hostname, parsed.port, timeout=self.timeout)

    def put(self, capability, body, size):
        if not isinstance(capability, UploadCapability) \
                or capability.method != "PUT" \
                or not callable(getattr(body, "read", None)) \
                or type(size) is not int or size < 0:
            raise TypeError("provider PUT")
        parsed = urlsplit(capability.url)
        if parsed.scheme != "https" or not parsed.hostname \
                or parsed.username is not None or parsed.password is not None \
                or parsed.fragment:
            raise UploadProtocolError("provider PUT URL")
        path = parsed.path + (
            "?" + parsed.query if parsed.query else "")
        connection = self._connection(parsed)
        try:
            connection.request(
                "PUT",
                path,
                body=body,
                headers=dict(capability.headers),
            )
            response = connection.getresponse()
            response.read(MAX_PROVIDER_ERROR_BYTES + 1)
            status = response.status
        except (
                OSError,
                socket.timeout,
                http.client.HTTPException,
        ) as error:
            raise UploadOutcomeUnknown(
                "provider PUT outcome unknown") from error
        finally:
            connection.close()
        if 200 <= status < 300:
            return CREATED
        if status in {409, 412}:
            # A PUT-only bearer cannot prove whether the incumbent is equal.
            raise UploadCreateConflict(
                "create-only staging key already exists")
        if status in {401, 403, 404, 410}:
            raise UploadCapabilityRejected(
                f"provider rejected capability with HTTP {status}")
        if status in {408, 425, 429} or status >= 500:
            raise UploadOutcomeUnknown(
                f"provider PUT returned HTTP {status}")
        raise UploadProtocolError(
            f"provider PUT returned HTTP {status}")


def run_http(
        source, broker_url, provider_origin, proof_factory, *,
        now=_system_now_ms, batch_size=PAGE_BATCH):
    """The production composition used by thin fact-family commands."""
    return UploadClient(
        source,
        HttpBrokerTransport(broker_url),
        HttpPutTransport(),
        now,
        batch_size=batch_size,
        provider_origin=provider_origin,
    ).run(proof_factory)


__all__ = (
    "HttpBrokerTransport",
    "HttpPutTransport",
    "run_http",
)
