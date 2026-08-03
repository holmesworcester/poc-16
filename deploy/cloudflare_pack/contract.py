"""Shared R2 namespace and direct immutable-creation ticket format."""
from dataclasses import dataclass
import hashlib
import hmac
import re
from urllib.parse import urlsplit

from core.object_store import (
    MAX_PROVIDER_KEY_BYTES,
    validate_store_prefix,
)
from core.pack_access import MAX_SCOPED_TTL_MS, object_key, pack_key


_BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
TICKET_FIELDS = ("body_bytes", "expires_at_ms", "signature")
_TICKET_DOMAIN = b"poc16-r2-immutable-put-v1\0"
PACK_TICKET_SECRET_BYTES = 32
DEFAULT_SCOPED_TTL_SECONDS = MAX_SCOPED_TTL_MS // 1000


def ticket_secret(value):
    if not isinstance(value, bytes) \
            or len(value) != PACK_TICKET_SECRET_BYTES:
        raise ValueError("R2 immutable ticket secret")
    return value


def ticket_signature(secret, logical_key, body_bytes, expires_at_ms):
    message = _TICKET_DOMAIN + b"\0".join((
        logical_key.encode("ascii"),
        str(body_bytes).encode("ascii"),
        str(expires_at_ms).encode("ascii"),
    ))
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def ticket_query(secret, logical_key, body_bytes, expires_at_ms):
    signature = ticket_signature(
        secret, logical_key, body_bytes, expires_at_ms)
    return (
        f"body_bytes={body_bytes}&expires_at_ms={expires_at_ms}"
        f"&signature={signature}"
    )


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


@dataclass(frozen=True, slots=True)
class R2PackTarget:
    """Non-secret R2 object namespace and public native-PUT endpoint."""

    endpoint: str
    bucket: str
    prefix: str
    put_endpoint: str
    ttl_seconds: int = DEFAULT_SCOPED_TTL_SECONDS

    def __post_init__(self):
        object.__setattr__(self, "endpoint", _base_url(
            self.endpoint, "R2 S3 endpoint"))
        object.__setattr__(self, "put_endpoint", _base_url(
            self.put_endpoint, "R2 immutable PUT endpoint"))
        if not isinstance(self.bucket, str) \
                or _BUCKET.fullmatch(self.bucket) is None:
            raise ValueError("R2 immutable bucket")
        if self.prefix:
            validate_store_prefix(self.prefix)
        elif self.prefix != "":
            raise ValueError("R2 immutable prefix")
        if type(self.ttl_seconds) is not int \
                or not 1 <= self.ttl_seconds \
                <= MAX_SCOPED_TTL_MS // 1000:
            raise ValueError("R2 immutable capability lifetime")
        self.physical_key("0" * 64)

    def _physical_key(self, logical):
        result = f"{self.prefix}/{logical}" if self.prefix else logical
        if len(result.encode("ascii")) > MAX_PROVIDER_KEY_BYTES:
            raise ValueError(
                "R2 key exceeds "
                f"{MAX_PROVIDER_KEY_BYTES} provider bytes")
        return result

    def physical_key(self, oid):
        return self._physical_key(pack_key(oid))

    def physical_object_key(self, oid):
        return self._physical_key(object_key(oid))

    def physical_logical_key(self, logical_key):
        if logical_key.startswith("obj/"):
            return self.physical_object_key(logical_key[4:])
        if logical_key.startswith("pack/"):
            return self.physical_key(logical_key[5:])
        raise ValueError("R2 direct immutable key")
