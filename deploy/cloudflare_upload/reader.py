"""Bounded canonical R2 reads for the database-free upload broker Worker."""
from dataclasses import dataclass, field
import re

from core.limits import PayloadTooLarge
from core.object_store import (
    MAX_PROVIDER_KEY_BYTES,
    validate_key,
    validate_store_prefix,
)
from deploy.cloudflare_upload.signer import R2SigV4


_BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_ENDPOINT = re.compile(
    r"^https://[0-9a-f]{32}(?:\.(?:eu|fedramp))?"
    r"\.r2\.cloudflarestorage\.com$")
GET_TTL_SECONDS = 30
MAX_RESPONSE_CHUNKS = 65_536


@dataclass(frozen=True)
class R2ReadConfig:
    endpoint: str
    bucket: str
    prefix: str
    ttl_seconds: int = GET_TTL_SECONDS

    def __post_init__(self):
        try:
            validate_store_prefix(self.prefix)
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValueError("R2 canonical read config") from error
        if not isinstance(self.endpoint, str) \
                or _ENDPOINT.fullmatch(self.endpoint) is None \
                or not isinstance(self.bucket, str) \
                or _BUCKET.fullmatch(self.bucket) is None \
                or type(self.ttl_seconds) is not int \
                or not 1 <= self.ttl_seconds <= 60:
            raise ValueError("R2 canonical read config")


@dataclass(frozen=True)
class R2FetchRequest:
    """One internal GET. Its short-lived bearer URL must never be logged."""

    method: str
    url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    redirect: str = "error"
    cache: str = "no-store"


def _chunk_bytes(value):
    if isinstance(value, bytes):
        return value
    if hasattr(value, "to_bytes"):
        return value.to_bytes()
    if hasattr(value, "to_py"):
        value = value.to_py()
    return bytes(value)


def _content_length(response):
    headers = getattr(response, "headers", None)
    get = getattr(headers, "get", None)
    value = get("content-length") if callable(get) else None
    if value is None or str(value) == "":
        return None
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as error:
        raise RuntimeError("R2 canonical Content-Length") from error
    if parsed < 0 or str(parsed) != str(value):
        raise RuntimeError("R2 canonical Content-Length")
    return parsed


async def _bounded_response(response, maximum):
    if type(maximum) is not int or maximum < 0:
        raise ValueError("R2 canonical response bound")
    declared = _content_length(response)
    if declared is not None and declared > maximum:
        raise PayloadTooLarge("R2 canonical object")
    stream = getattr(response, "body", None)
    if stream is None or not hasattr(stream, "getReader"):
        raise RuntimeError("R2 canonical response body stream")
    reader = stream.getReader()
    chunks, total = [], 0
    try:
        for _ in range(MAX_RESPONSE_CHUNKS):
            result = await reader.read()
            if result.done:
                raw = b"".join(chunks)
                if declared is not None and len(raw) != declared:
                    raise RuntimeError("R2 canonical response length")
                return raw
            chunk = _chunk_bytes(result.value)
            total += len(chunk)
            if total > maximum:
                await reader.cancel("canonical response limit")
                raise PayloadTooLarge("R2 canonical object")
            chunks.append(chunk)
        await reader.cancel("canonical response chunk limit")
        raise RuntimeError("R2 canonical response chunk limit")
    finally:
        reader.releaseLock()


class R2CanonicalReader:
    """Expose only bounded GET over one exact canonical bucket prefix."""

    __slots__ = ("config", "_fetch", "_signer")

    def __init__(
            self, config, access_key_id, secret_access_key, fetch, *,
            clock):
        if not isinstance(config, R2ReadConfig) or not callable(fetch):
            raise ValueError("R2 canonical reader")
        self.config = config
        self._fetch = fetch
        self._signer = R2SigV4(
            config.endpoint,
            access_key_id,
            secret_access_key,
            clock=clock,
        )

    def _physical(self, key):
        key = validate_key(key)
        physical = f"{self.config.prefix}/{key}"
        if len(physical.encode("ascii")) > MAX_PROVIDER_KEY_BYTES:
            raise ValueError("R2 canonical key")
        return physical

    async def get_bounded(self, key, maximum):
        signed = self._signer.sign(
            "GET",
            self.config.bucket,
            self._physical(key),
            {},
            self.config.ttl_seconds,
        )
        response = await self._fetch(R2FetchRequest(
            signed.method,
            signed.url,
            signed.headers,
        ))
        status = getattr(response, "status", None)
        if status == 404:
            return None
        if status != 200:
            raise RuntimeError("R2 canonical GET failed")
        return await _bounded_response(response, maximum)


__all__ = (
    "R2CanonicalReader",
    "R2FetchRequest",
    "R2ReadConfig",
)
