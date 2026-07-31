"""Hostile HTTP membrane for exact-pile OPEN and FINALIZE.

Deployment adapters are responsible only for reading a bounded body and
normalizing their provider request into :meth:`UploadBrokerEndpoint.handle`.
The endpoint owns the exact paths, canonical documents, and safe error map.
It never receives provider bodies or returns exception text.
"""
from core.limits import PayloadTooLarge
from core.http import Response
from deploy.upload_broker import (
    UploadBroker,
    UploadUnavailable,
    encode_finalize,
    encode_open,
)
from deploy.upload_session import InvalidUploadSession
from deploy.upload_wire import (
    InvalidUploadWire,
    MAX_FINALIZE_REQUEST_BYTES,
    MAX_OPEN_REQUEST_BYTES,
    decode_finalize_request,
    decode_open_request,
)


MAX_UPLOAD_HTTP_METHOD_BYTES = 16
MAX_UPLOAD_HTTP_PATH_BYTES = 64
MAX_UPLOAD_HTTP_HEADERS = 32
MAX_UPLOAD_HTTP_HEADER_NAME_BYTES = 64
MAX_UPLOAD_HTTP_HEADER_VALUE_BYTES = 4_096
MAX_UPLOAD_HTTP_HEADER_BYTES = 16 * 1024

_ROUTES = {
    "/upload/open": MAX_OPEN_REQUEST_BYTES,
    "/upload/finalize": MAX_FINALIZE_REQUEST_BYTES,
}
_SAFE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


class UnsupportedUploadMediaType(InvalidUploadWire):
    pass


def upload_request_body_limit(path):
    """Return the exact shared route ceiling, or ``None`` for no route."""
    return _ROUTES.get(path) if isinstance(path, str) else None


def upload_error_response(status, headers=None):
    """Return the shared body-free upload error with non-cacheable headers."""
    return Response(status, headers={**_SAFE_HEADERS, **(headers or {})})


def _success(body):
    return Response(
        200,
        body,
        {**_SAFE_HEADERS, "Content-Type": "application/json"},
    )


def _bounded_ascii(value, maximum):
    if not isinstance(value, str):
        raise InvalidUploadWire("invalid HTTP text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise InvalidUploadWire("invalid HTTP text") from error
    if not encoded or len(encoded) > maximum:
        raise InvalidUploadWire("invalid HTTP text")
    return value


def _request_headers(headers, body_size, body_limit):
    if not isinstance(headers, dict) \
            or len(headers) > MAX_UPLOAD_HTTP_HEADERS:
        raise InvalidUploadWire("invalid HTTP headers")
    normalized, total = {}, 0
    for name, value in headers.items():
        name = _bounded_ascii(
            name, MAX_UPLOAD_HTTP_HEADER_NAME_BYTES)
        value = _bounded_ascii(
            value, MAX_UPLOAD_HTTP_HEADER_VALUE_BYTES)
        lowered = name.lower()
        if lowered in normalized:
            raise InvalidUploadWire("ambiguous HTTP header")
        normalized[lowered] = value
        total += len(name.encode("ascii")) + len(value.encode("ascii"))
    if total > MAX_UPLOAD_HTTP_HEADER_BYTES:
        raise InvalidUploadWire("invalid HTTP headers")
    if normalized.get("content-type") != "application/json":
        raise UnsupportedUploadMediaType("upload Content-Type")
    length = normalized.get("content-length")
    if length is not None:
        if len(length) > 20 \
                or not length.isascii() or not length.isdecimal() \
                or str(int(length)) != length:
            raise InvalidUploadWire("invalid Content-Length")
        declared = int(length)
        if declared > body_limit:
            raise PayloadTooLarge("upload request too large")
        if declared != body_size:
            raise InvalidUploadWire("invalid Content-Length")


class UploadBrokerEndpoint:
    """Serve exactly OPEN and FINALIZE for one ``UploadBroker``."""

    def __init__(self, broker):
        if not isinstance(broker, UploadBroker):
            raise ValueError("upload broker")
        self.broker = broker

    async def handle(self, method, path, headers=None, body=b""):
        """Return a body-free error or one existing canonical broker reply."""
        try:
            method = _bounded_ascii(
                method, MAX_UPLOAD_HTTP_METHOD_BYTES)
        except InvalidUploadWire:
            return upload_error_response(400)
        if isinstance(path, str):
            try:
                path_bytes = path.encode("ascii")
            except UnicodeEncodeError:
                return upload_error_response(400)
            if len(path_bytes) > MAX_UPLOAD_HTTP_PATH_BYTES:
                return upload_error_response(414)
        try:
            path = _bounded_ascii(path, MAX_UPLOAD_HTTP_PATH_BYTES)
        except InvalidUploadWire:
            return upload_error_response(400)
        body_limit = _ROUTES.get(path)
        if body_limit is None:
            return upload_error_response(404)
        if method != "POST":
            return upload_error_response(405, {"Allow": "POST"})
        if not isinstance(body, bytes):
            return upload_error_response(400)
        if len(body) > body_limit:
            return upload_error_response(413)
        try:
            _request_headers(
                {} if headers is None else headers,
                len(body),
                body_limit,
            )
            if path == "/upload/open":
                result = await self.broker.open(
                    *decode_open_request(body))
                encoded = encode_open(result)
            else:
                result = await self.broker.finalize(
                    decode_finalize_request(body))
                encoded = encode_finalize(result)
        except PayloadTooLarge:
            return upload_error_response(413)
        except UnsupportedUploadMediaType:
            return upload_error_response(415)
        except InvalidUploadWire:
            return upload_error_response(400)
        except InvalidUploadSession:
            # OPEN has no session yet, so a broker rejection is failed
            # workspace authorization/policy. Later failures abandon the
            # presented cursor conservatively; neither path exposes why.
            return upload_error_response(
                403 if path == "/upload/open" else 409)
        except UploadUnavailable:
            return upload_error_response(503)
        except Exception:
            return upload_error_response(503)
        return _success(encoded)


__all__ = (
    "UploadBrokerEndpoint",
    "upload_error_response",
    "upload_request_body_limit",
)
