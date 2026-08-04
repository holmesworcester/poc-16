"""Native R2 PUT route that never buffers immutable object or pack bytes."""
from dataclasses import dataclass
import hmac
import time
from urllib.parse import parse_qsl, urlsplit

from core.limits import MAX_DIRECT_OBJECT_BYTES
from core.pack_access import (
    MAX_PACK_BYTES,
    MAX_SCOPED_TTL_MS,
    object_key,
    pack_key,
)
from core.shape import valid_fid

from .contract import (
    R2PackTarget,
    TICKET_FIELDS,
    ticket_query,
    ticket_secret,
    ticket_signature,
)


def _system_now_ms():
    return time.time_ns() // 1_000_000


def _if_none_match():
    """Use Headers under workerd and a mapping in CPython tests."""
    try:
        from js import Headers
    except ImportError:
        return {"If-None-Match": "*"}
    headers = Headers.new()
    headers.set("If-None-Match", "*")
    return headers


def _header(headers, name):
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name)
        if value is not None:
            return value
    try:
        matches = [
            value for candidate, value in headers.items()
            if isinstance(candidate, str) and candidate.lower() == name
        ]
    except (AttributeError, TypeError):
        return None
    return matches[0] if len(matches) == 1 else None


def _provider_status(error):
    for name in ("status", "status_code", "code"):
        try:
            return int(getattr(error, name))
        except (AttributeError, TypeError, ValueError):
            pass
    return None


@dataclass(frozen=True, slots=True)
class R2PackResponse:
    """Result that a tiny Worker entry point can render."""

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""


class R2ImmutablePut:
    """Validate one exact ticket, then give R2 the untouched body stream."""

    def __init__(
            self, target, bucket, put_ticket_secret, *, clock=_system_now_ms):
        if not isinstance(target, R2PackTarget):
            raise TypeError("R2 pack target")
        if bucket is None or not callable(clock):
            raise ValueError("R2 pack route")
        self.target = target
        self.bucket = bucket
        self._ticket_secret = ticket_secret(put_ticket_secret)
        self._clock = clock

    @staticmethod
    def _response(status, **headers):
        values = {
            "cache-control": "no-store",
            "content-length": "0",
        }
        values.update(headers)
        return R2PackResponse(status, tuple(sorted(values.items())))

    def _opened(self, request):
        if getattr(request, "method", None) != "PUT":
            return None, self._response(405, allow="PUT")
        try:
            parsed = urlsplit(request.url)
        except (AttributeError, TypeError, ValueError):
            return None, self._response(400)
        expected_origin = urlsplit(self.target.put_endpoint)
        if parsed.scheme != expected_origin.scheme \
                or parsed.netloc != expected_origin.netloc \
                or parsed.username is not None or parsed.password is not None \
                or parsed.fragment or parsed.path.count("/") != 2:
            return None, self._response(403)
        prefix, oid = parsed.path.strip("/").split("/", 1)
        if prefix not in {"obj", "pack"} or not valid_fid(oid):
            return None, self._response(403)
        logical_key = object_key(oid) if prefix == "obj" else pack_key(oid)
        try:
            pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=len(TICKET_FIELDS),
            )
            if tuple(name for name, _ in pairs) != TICKET_FIELDS:
                raise ValueError("ticket fields")
            values = dict(pairs)
            body_bytes = int(values["body_bytes"])
            expires_at_ms = int(values["expires_at_ms"])
            if str(body_bytes) != values["body_bytes"] \
                    or str(expires_at_ms) != values["expires_at_ms"]:
                raise ValueError("noncanonical ticket integer")
        except (KeyError, TypeError, ValueError):
            return None, self._response(403)
        expected_query = ticket_query(
            self._ticket_secret, logical_key, body_bytes, expires_at_ms)
        if parsed.query != expected_query or not hmac.compare_digest(
                values["signature"],
                ticket_signature(
                    self._ticket_secret,
                    logical_key,
                    body_bytes,
                    expires_at_ms)):
            return None, self._response(403)
        now = self._clock()
        if type(now) is not int or now < 0:
            return None, self._response(503)
        if not now < expires_at_ms <= now + MAX_SCOPED_TTL_MS:
            return None, self._response(403)
        maximum = MAX_DIRECT_OBJECT_BYTES \
            if prefix == "obj" else MAX_PACK_BYTES
        if not 1 <= body_bytes <= maximum:
            return None, self._response(413)
        headers = getattr(request, "headers", None)
        if _header(headers, "content-length") != str(body_bytes) \
                or _header(headers, "if-none-match") != "*" \
                or _header(headers, "range") is not None \
                or _header(headers, "content-range") is not None:
            return None, self._response(400)
        body = getattr(request, "body", None)
        if body is None:
            return None, self._response(400)
        return (logical_key, oid, body), None

    async def handle(self, request):
        opened, failure = self._opened(request)
        if failure is not None:
            return failure
        logical_key, oid, body = opened
        try:
            result = await self.bucket.put(
                self.target.physical_logical_key(logical_key),
                body,
                onlyIf=_if_none_match(),
                sha256=oid,
            )
        except Exception as error:
            status = _provider_status(error)
            return self._response(
                400 if status in {400, 422} else
                412 if status == 412 else 503)
        return self._response(201 if result is not None else 412)
