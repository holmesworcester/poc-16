"""Narrow HTTPS effects for one exact-pile direct upload."""
import http.client
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from core.limits import PayloadTooLarge
import deploy.upload_wire as wire
from full_peer.upload_client import (
    CREATED,
    UploadCapabilityRejected,
    UploadClient,
    UploadCreateConflict,
    UploadOutcomeUnknown,
    UploadProtocolError,
    UploadRetryable,
    UploadSessionRejected,
)


MAX_PROVIDER_ERROR_BYTES = 4_096


def _system_now_ms():
    return time.time_ns() // 1_000_000


class HttpBrokerTransport:
    """POST bounded OPEN/FINALIZE documents to one HTTPS broker."""

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
        if not isinstance(body, bytes) or len(body) > response_limit:
            raise UploadProtocolError(f"{verb} response exceeds limit")
        return body

    def open(self, proof, pile):
        try:
            request = wire.encode_open_request(proof, pile)
        except (wire.InvalidUploadWire, PayloadTooLarge) as error:
            raise UploadProtocolError("invalid OPEN request") from error
        try:
            return wire.decode_open_response(self._post(
                "OPEN", request, wire.MAX_OPEN_RESPONSE_BYTES))
        except (wire.InvalidUploadWire, PayloadTooLarge) as error:
            raise UploadProtocolError("invalid OPEN response") from error

    def finalize(self, cursor):
        try:
            request = wire.encode_finalize_request(cursor)
        except (wire.InvalidUploadWire, PayloadTooLarge) as error:
            raise UploadProtocolError("invalid FINALIZE request") from error
        try:
            return wire.decode_finalize_response(self._post(
                "FINALIZE", request, wire.MAX_FINALIZE_RESPONSE_BYTES))
        except (wire.InvalidUploadWire, PayloadTooLarge) as error:
            raise UploadProtocolError("invalid FINALIZE response") from error


class HttpPutTransport:
    """Perform one streaming, redirect-free create-only PUT."""

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
        if not isinstance(capability, wire.UploadCapability) \
                or not callable(getattr(body, "read", None)) \
                or type(size) is not int or size < 0:
            raise TypeError("provider PUT")
        parsed = urlsplit(capability.url)
        if parsed.scheme != "https" or not parsed.hostname \
                or parsed.username is not None or parsed.password is not None \
                or parsed.fragment:
            raise UploadProtocolError("provider PUT URL")
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        connection = self._connection(parsed)
        try:
            connection.request(
                "PUT", path, body=body, headers=dict(capability.headers))
            response = connection.getresponse()
            response.read(MAX_PROVIDER_ERROR_BYTES + 1)
            status = response.status
        except (OSError, socket.timeout, http.client.HTTPException) as error:
            raise UploadOutcomeUnknown("provider PUT outcome unknown") from error
        finally:
            connection.close()
        if 200 <= status < 300:
            return CREATED
        if status in {409, 412}:
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
        now=_system_now_ms):
    return UploadClient(
        source,
        HttpBrokerTransport(broker_url),
        HttpPutTransport(),
        now,
        provider_origin=provider_origin,
    ).run(proof_factory)


__all__ = ("HttpBrokerTransport", "HttpPutTransport", "run_http")
