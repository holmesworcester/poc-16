"""Pure-stdlib SigV4 for exact Cloudflare R2 requests."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import re
import time
from urllib.parse import quote, urlsplit

from core.object_store import MAX_PROVIDER_KEY_BYTES


ALGORITHM = "AWS4-HMAC-SHA256"
PAYLOAD = "UNSIGNED-PAYLOAD"
REGION = "auto"
SERVICE = "s3"
TERMINATOR = "aws4_request"
MIN_CREDENTIAL_CHARS = 8
MAX_ACCESS_KEY_ID_CHARS = 128
MAX_SECRET_ACCESS_KEY_CHARS = 256
MAX_SIGV4_TTL_SECONDS = 7 * 24 * 60 * 60
MIN_R2_BUCKET_CHARS = 3
MAX_R2_BUCKET_CHARS = 63
ASCII_CREDENTIAL = re.compile(r"^[\x21-\x7e]+$")
ACCESS_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._+=~-]+$")
BUCKET_PATTERN = re.compile(
    rf"^[a-z0-9][a-z0-9-]"
    rf"{{{MIN_R2_BUCKET_CHARS - 2},{MAX_R2_BUCKET_CHARS - 2}}}"
    rf"[a-z0-9]$")
KEY_PATTERN = re.compile(r"^[a-z0-9:._/-]+$")


def system_now_ms():
    return time.time_ns() // 1_000_000


def credential(value, label, maximum):
    if not isinstance(value, str) \
            or not MIN_CREDENTIAL_CHARS <= len(value) <= maximum \
            or ASCII_CREDENTIAL.fullmatch(value) is None:
        raise ValueError(label)
    return value


def _encode(value):
    return quote(str(value), safe="-_.~", encoding="utf-8", errors="strict")


def _query(values):
    encoded = sorted(
        (_encode(name), _encode(value))
        for name, value in values.items()
    )
    return "&".join(
        f"{name}={value}" for name, value in encoded)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _mac(key, value):
    return hmac.new(key, value, hashlib.sha256).digest()


def _signing_key(secret, date):
    date_key = _mac(("AWS4" + secret).encode("ascii"), date.encode("ascii"))
    region_key = _mac(date_key, REGION.encode("ascii"))
    service_key = _mac(region_key, SERVICE.encode("ascii"))
    return _mac(service_key, TERMINATOR.encode("ascii"))


def _canonical_headers(headers, signed_headers):
    return "".join(
        f"{name}:{headers[name]}\n" for name in signed_headers)


def _canonical_uri(bucket, key):
    return quote(
        f"/{bucket}/{key}",
        safe="/-_.~",
        encoding="utf-8",
        errors="strict",
    )


@dataclass(frozen=True)
class R2SignedRequest:
    """One exact short-lived provider request, with credentials redacted."""

    method: str
    url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    expires_at_ms: int


class R2SigV4:
    """Sign exact R2 requests without giving callers the parent credential."""

    def __init__(
            self, endpoint, access_key_id, secret_access_key, *,
            clock=system_now_ms):
        parsed = urlsplit(endpoint) \
            if isinstance(endpoint, str) else None
        if parsed is None or parsed.scheme != "https" \
                or not parsed.hostname or parsed.username is not None \
                or parsed.password is not None or parsed.port is not None \
                or parsed.path not in {"", "/"} or parsed.query \
                or parsed.fragment or endpoint.rstrip("/") != (
                    f"https://{parsed.hostname}"):
            raise ValueError("R2 endpoint")
        if not callable(clock):
            raise ValueError("R2 signing clock")
        access = credential(
            access_key_id,
            "R2 parent access key id",
            MAX_ACCESS_KEY_ID_CHARS,
        )
        if ACCESS_KEY_PATTERN.fullmatch(access) is None:
            raise ValueError("R2 parent access key id")
        secret = credential(
            secret_access_key,
            "R2 parent secret access key",
            MAX_SECRET_ACCESS_KEY_CHARS,
        )
        self.endpoint = endpoint.rstrip("/")
        self.host = parsed.hostname
        self._access_key_id = access
        self._secret_access_key = secret
        self._clock = clock

    def sign(
            self, method, bucket, key, headers, ttl_seconds, *,
            not_after_ms=None):
        if method not in {"GET", "PUT"} \
                or not isinstance(bucket, str) \
                or BUCKET_PATTERN.fullmatch(bucket) is None \
                or not isinstance(key, str) or not key \
                or KEY_PATTERN.fullmatch(key) is None \
                or len(key.encode("ascii")) > MAX_PROVIDER_KEY_BYTES \
                or not isinstance(headers, dict) \
                or type(ttl_seconds) is not int \
                or not 1 <= ttl_seconds <= MAX_SIGV4_TTL_SECONDS \
                or not_after_ms is not None and (
                    type(not_after_ms) is not int or not_after_ms < 0):
            raise ValueError("R2 signed request")
        normalized = {"host": self.host}
        for name, value in headers.items():
            if not isinstance(name, str) or name != name.lower() \
                    or name == "host" or not name \
                    or not isinstance(value, str) or not value \
                    or any(character in value for character in "\r\n") \
                    or value != value.strip():
                raise ValueError("R2 signed headers")
            normalized[name] = value
        signed_headers = tuple(sorted(normalized))
        now_ms = self._clock()
        if type(now_ms) is not int or now_ms < 0:
            raise RuntimeError("R2 signing clock")
        issued_second = now_ms // 1000
        if not_after_ms is not None:
            ttl_seconds = min(
                ttl_seconds,
                (not_after_ms - issued_second * 1000) // 1000,
            )
        if ttl_seconds < 1:
            raise RuntimeError(
                "R2 request deadline leaves no signed second")
        try:
            issued = datetime.fromtimestamp(
                issued_second, timezone.utc)
        except (OverflowError, OSError, ValueError) as error:
            raise RuntimeError("R2 signing clock") from error
        timestamp = issued.strftime("%Y%m%dT%H%M%SZ")
        date = timestamp[:8]
        scope = f"{date}/{REGION}/{SERVICE}/{TERMINATOR}"
        uri = _canonical_uri(bucket, key)
        signed_names = ";".join(signed_headers)
        query = {
            "X-Amz-Algorithm": ALGORITHM,
            "X-Amz-Content-Sha256": PAYLOAD,
            "X-Amz-Credential": f"{self._access_key_id}/{scope}",
            "X-Amz-Date": timestamp,
            "X-Amz-Expires": str(ttl_seconds),
            "X-Amz-SignedHeaders": signed_names,
        }
        canonical_request = "\n".join((
            method,
            uri,
            _query(query),
            _canonical_headers(normalized, signed_headers),
            signed_names,
            PAYLOAD,
        ))
        string_to_sign = "\n".join((
            ALGORITHM,
            timestamp,
            scope,
            _digest(canonical_request.encode("utf-8")),
        ))
        signature = hmac.new(
            _signing_key(self._secret_access_key, date),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        expires_at_ms = (issued_second + ttl_seconds) * 1000
        if not_after_ms is not None and expires_at_ms > not_after_ms:
            raise RuntimeError("R2 signature exceeded request deadline")
        return R2SignedRequest(
            method,
            f"{self.endpoint}{uri}?{_query(query)}"
            f"&X-Amz-Signature={signature}",
            tuple(
                (name, normalized[name])
                for name in signed_headers if name != "host"
            ),
            expires_at_ms,
        )


__all__ = (
    "ACCESS_KEY_PATTERN",
    "ALGORITHM",
    "BUCKET_PATTERN",
    "MAX_ACCESS_KEY_ID_CHARS",
    "MAX_SECRET_ACCESS_KEY_CHARS",
    "MAX_SIGV4_TTL_SECONDS",
    "MAX_R2_BUCKET_CHARS",
    "MIN_CREDENTIAL_CHARS",
    "MIN_R2_BUCKET_CHARS",
    "PAYLOAD",
    "R2SignedRequest",
    "R2SigV4",
    "credential",
    "system_now_ms",
)
