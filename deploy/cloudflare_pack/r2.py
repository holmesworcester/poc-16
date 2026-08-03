"""Exact R2 capabilities without putting pack bodies in Python memory.

Whole and range reads use ordinary R2 SigV4 URLs.  Writes use a tiny native
Worker route because R2's binding can pass ``request.body`` through unchanged
while enforcing both conditional creation and the pack's SHA-256 address.
"""
from dataclasses import dataclass
import hashlib
import hmac
import re
import time
from urllib.parse import parse_qsl, urlsplit

from core.object_store import (
    MAX_PROVIDER_KEY_BYTES,
    validate_store_prefix,
)
from core.pack_access import (
    MAX_PACK_BYTES,
    MAX_SCOPED_TTL_MS,
    PackOpen,
    ScopedRequest,
    pack_key,
)
from core.shape import valid_fid
from deploy.cloudflare_upload.signer import R2SigV4


_BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_TICKET_DOMAIN = b"poc16-r2-pack-put-v1\0"
_TICKET_FIELDS = ("expires_at_ms", "pack_bytes", "signature")


def _system_now_ms():
    return time.time_ns() // 1_000_000


def _base_url(value, label):
    parsed = urlsplit(value) if isinstance(value, str) else None
    if parsed is None or parsed.scheme != "https" \
            or not parsed.hostname or parsed.username is not None \
            or parsed.password is not None or parsed.port is not None \
            or parsed.path not in {"", "/"} or parsed.query \
            or parsed.fragment \
            or value.rstrip("/") != f"https://{parsed.hostname}":
        raise ValueError(label)
    return value.rstrip("/")


def _secret(value):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("R2 pack ticket secret")
    return value


def _ticket_message(oid, pack_bytes, expires_at_ms):
    return _TICKET_DOMAIN + b"\0".join((
        oid.encode("ascii"),
        str(pack_bytes).encode("ascii"),
        str(expires_at_ms).encode("ascii"),
    ))


def _signature(secret, oid, pack_bytes, expires_at_ms):
    return hmac.new(
        secret,
        _ticket_message(oid, pack_bytes, expires_at_ms),
        hashlib.sha256,
    ).hexdigest()


def _query(secret, oid, pack_bytes, expires_at_ms):
    signature = _signature(secret, oid, pack_bytes, expires_at_ms)
    return (
        f"expires_at_ms={expires_at_ms}&pack_bytes={pack_bytes}"
        f"&signature={signature}"
    )


def _if_none_match():
    """Use Headers when running in workerd and a mapping in CPython tests."""
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
class R2PackTarget:
    """Non-secret R2 namespace and public native-PUT endpoint."""

    endpoint: str
    bucket: str
    prefix: str
    put_endpoint: str
    ttl_seconds: int = 60

    def __post_init__(self):
        object.__setattr__(self, "endpoint", _base_url(
            self.endpoint, "R2 S3 endpoint"))
        object.__setattr__(self, "put_endpoint", _base_url(
            self.put_endpoint, "R2 pack PUT endpoint"))
        if not isinstance(self.bucket, str) \
                or _BUCKET.fullmatch(self.bucket) is None:
            raise ValueError("R2 pack bucket")
        if self.prefix:
            validate_store_prefix(self.prefix)
        elif self.prefix != "":
            raise ValueError("R2 pack prefix")
        if type(self.ttl_seconds) is not int \
                or not 1 <= self.ttl_seconds \
                <= MAX_SCOPED_TTL_MS // 1000:
            raise ValueError("R2 pack capability lifetime")
        self.physical_key("0" * 64)

    def physical_key(self, oid):
        logical = pack_key(oid)
        result = f"{self.prefix}/{logical}" if self.prefix else logical
        if len(result.encode("ascii")) > MAX_PROVIDER_KEY_BYTES:
            raise ValueError("R2 pack key exceeds 1024 bytes")
        return result


class R2PackIssuer:
    """Issue one exact, short-lived request for a gated ``PackOpen``."""

    def __init__(
            self, target, access_key_id, secret_access_key, ticket_secret,
            *, clock=_system_now_ms):
        if not isinstance(target, R2PackTarget):
            raise TypeError("R2 pack target")
        if not callable(clock):
            raise ValueError("R2 pack signing clock")
        self.target = target
        self._ticket_secret = _secret(ticket_secret)
        self._sigv4 = R2SigV4(
            target.endpoint,
            access_key_id,
            secret_access_key,
            clock=clock,
        )

    def __call__(self, member, opened, trusted_now):
        if not valid_fid(member) or not isinstance(opened, PackOpen) \
                or type(trusted_now) is not int or trusted_now < 0:
            raise ValueError("R2 pack request")
        expires_at_ms = trusted_now + self.target.ttl_seconds * 1000
        if opened.method == "GET":
            headers = {}
            if opened.offset is not None:
                headers["range"] = (
                    f"bytes={opened.offset}-"
                    f"{opened.offset + opened.length - 1}"
                )
            signed = self._sigv4.sign(
                "GET",
                self.target.bucket,
                self.target.physical_key(opened.oid),
                headers,
                self.target.ttl_seconds,
                not_after_ms=expires_at_ms,
            )
            return ScopedRequest(
                signed.method,
                signed.url,
                signed.headers,
                signed.expires_at_ms,
            )
        url = f"{self.target.put_endpoint}/{pack_key(opened.oid)}?" + _query(
            self._ticket_secret,
            opened.oid,
            opened.pack_bytes,
            expires_at_ms,
        )
        return ScopedRequest(
            "PUT",
            url,
            (
                ("content-length", str(opened.pack_bytes)),
                ("if-none-match", "*"),
            ),
            expires_at_ms,
        )


@dataclass(frozen=True, slots=True)
class R2PackResponse:
    """Provider-neutral result that a Worker entry point can render."""

    status: int
    headers: tuple[tuple[str, str], ...] = (
        ("cache-control", "no-store"),
        ("content-length", "0"),
    )
    body: bytes = b""


class R2PackPut:
    """Native Worker PUT route; the request stream is never inspected here."""

    def __init__(
            self, target, bucket, ticket_secret, *, clock=_system_now_ms):
        if not isinstance(target, R2PackTarget):
            raise TypeError("R2 pack target")
        if bucket is None or not callable(clock):
            raise ValueError("R2 pack route")
        self.target = target
        self.bucket = bucket
        self._ticket_secret = _secret(ticket_secret)
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
                or parsed.fragment or not parsed.path.startswith("/pack/") \
                or parsed.path.count("/") != 2:
            return None, self._response(403)
        oid = parsed.path[len("/pack/"):]
        if not valid_fid(oid):
            return None, self._response(403)
        try:
            pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=len(_TICKET_FIELDS),
            )
            if tuple(name for name, _ in pairs) != _TICKET_FIELDS:
                raise ValueError("ticket fields")
            values = dict(pairs)
            pack_bytes = int(values["pack_bytes"])
            expires_at_ms = int(values["expires_at_ms"])
            if str(pack_bytes) != values["pack_bytes"] \
                    or str(expires_at_ms) != values["expires_at_ms"]:
                raise ValueError("noncanonical ticket integer")
        except (KeyError, TypeError, ValueError):
            return None, self._response(403)
        expected_query = _query(
            self._ticket_secret, oid, pack_bytes, expires_at_ms)
        if parsed.query != expected_query or not hmac.compare_digest(
                values["signature"],
                _signature(
                    self._ticket_secret, oid, pack_bytes, expires_at_ms)):
            return None, self._response(403)
        now = self._clock()
        if type(now) is not int or now < 0:
            return None, self._response(503)
        if not now < expires_at_ms <= now + MAX_SCOPED_TTL_MS:
            return None, self._response(403)
        if not 1 <= pack_bytes <= MAX_PACK_BYTES:
            return None, self._response(413)
        headers = getattr(request, "headers", None)
        if _header(headers, "content-length") != str(pack_bytes) \
                or _header(headers, "if-none-match") != "*" \
                or _header(headers, "range") is not None \
                or _header(headers, "content-range") is not None:
            return None, self._response(400)
        body = getattr(request, "body", None)
        if body is None:
            return None, self._response(400)
        return (oid, body), None

    async def handle(self, request):
        opened, failure = self._opened(request)
        if failure is not None:
            return failure
        oid, body = opened
        try:
            result = await self.bucket.put(
                self.target.physical_key(oid),
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
