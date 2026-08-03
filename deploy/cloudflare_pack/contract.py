"""Small shared configuration and ticket format for R2 pack access."""
from dataclasses import dataclass
import hashlib
import hmac
import re
from urllib.parse import urlsplit

from core.object_store import (
    MAX_PROVIDER_KEY_BYTES,
    validate_store_prefix,
)
from core.pack_access import MAX_SCOPED_TTL_MS, pack_key


_BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
TICKET_FIELDS = ("expires_at_ms", "pack_bytes", "signature")
_TICKET_DOMAIN = b"poc16-r2-pack-put-v1\0"


def ticket_secret(value):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("R2 pack ticket secret")
    return value


def ticket_signature(secret, oid, pack_bytes, expires_at_ms):
    message = _TICKET_DOMAIN + b"\0".join((
        oid.encode("ascii"),
        str(pack_bytes).encode("ascii"),
        str(expires_at_ms).encode("ascii"),
    ))
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def ticket_query(secret, oid, pack_bytes, expires_at_ms):
    signature = ticket_signature(secret, oid, pack_bytes, expires_at_ms)
    return (
        f"expires_at_ms={expires_at_ms}&pack_bytes={pack_bytes}"
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
