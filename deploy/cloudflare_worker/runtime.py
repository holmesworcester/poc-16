"""Cloudflare request and binding translation around the shared HttpGate."""
import base64
from dataclasses import dataclass
import re
from time import time_ns
from urllib.parse import parse_qs, urlsplit

from adapters.r2.worker import R2BindingStore
from core import peer_capability
from core.crypto import load_sk, sign, verify
from core.limits import (
    MAX_MINT_FETCHES as CORE_MAX_MINT_FETCHES,
    MAX_MINT_FETCH_BYTES as CORE_MAX_MINT_FETCH_BYTES,
    MAX_MINT_REQUEST_BYTES,
    MAX_OBJECT_BYTES as CORE_MAX_OBJECT_BYTES,
    MAX_PAGE_BATCH_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    MAX_ROOT_BYTES as CORE_MAX_ROOT_BYTES,
    PAGE_BATCH,
)
from core.shape import valid_fid
from core.http import HttpGate, Response

if __package__:
    from .crypto_compat import seal_to, unseal
else:
    from crypto_compat import seal_to, unseal

MAX_REQUEST_BYTES = min(512 * 1024, MAX_MINT_REQUEST_BYTES)
MAX_ROOT_BYTES = min(64 * 1024, CORE_MAX_ROOT_BYTES)
MAX_OBJECT_BYTES = min(
    MAX_REPOSITORY_OBJECT_BYTES,
    CORE_MAX_OBJECT_BYTES,
    MAX_PAGE_BATCH_BYTES,
)
MAX_BATCH_COUNT = min(48, PAGE_BATCH)
MAX_BATCH_BYTES = min(4 * 1024 * 1024, MAX_PAGE_BATCH_BYTES)
MAX_MINT_FETCHES = min(48, CORE_MAX_MINT_FETCHES)
MAX_MINT_FETCH_BYTES = min(
    MAX_MINT_FETCHES * 8 * 1024, CORE_MAX_MINT_FETCH_BYTES)
MAX_QUERY_BYTES = 4 * 1024
MAX_QUERY_FIELDS = 8
MAX_GRANT_TTL_MS = 60_000

_BUDGETS = {
    "MAX_REQUEST_BYTES": MAX_REQUEST_BYTES,
    "MAX_ROOT_BYTES": MAX_ROOT_BYTES,
    "MAX_OBJECT_BYTES": MAX_OBJECT_BYTES,
    "MAX_BATCH_COUNT": MAX_BATCH_COUNT,
    "MAX_BATCH_BYTES": MAX_BATCH_BYTES,
    "MAX_MINT_FETCHES": MAX_MINT_FETCHES,
    "MAX_MINT_FETCH_BYTES": MAX_MINT_FETCH_BYTES,
    "MAX_QUERY_BYTES": MAX_QUERY_BYTES,
    "MAX_QUERY_FIELDS": MAX_QUERY_FIELDS,
    "GRANT_TTL_MS": MAX_GRANT_TTL_MS,
}

_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")

_CRYPTO_READY = False


def _crypto_self_test():
    """Fail the first request if the selected Pyodide/PyNaCl pair is broken."""
    global _CRYPTO_READY
    if _CRYPTO_READY:
        return
    secret = load_sk("42" * 32)
    public = secret.verify_key.encode().hex()
    message = "poc-16-cloudflare-python-compatibility"
    signature = sign(secret, message)
    if not verify(public, message, signature):
        raise RuntimeError("Cloudflare PyNaCl Ed25519 self-test")
    sealed = seal_to(public, message.encode())
    if unseal(secret, sealed) != message.encode():
        raise RuntimeError("Cloudflare PyNaCl sealed-box self-test")
    _CRYPTO_READY = True


def _text(env, name):
    value = getattr(env, name)
    if not isinstance(value, str):
        value = str(value)
    if not value:
        raise ValueError(f"missing {name} binding")
    return value


def _budget(env, name):
    value = getattr(env, name)
    if isinstance(value, bool):
        raise ValueError(f"{name} binding")
    try:
        value = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} binding") from error
    if not 0 < value <= _BUDGETS[name]:
        raise ValueError(f"{name} binding")
    return value


@dataclass(frozen=True)
class Settings:
    bucket: object
    workspace: str
    prefix: str
    secret: bytes
    max_request_bytes: int
    max_root_bytes: int
    max_object_bytes: int
    max_batch_count: int
    max_batch_bytes: int
    max_mint_fetches: int
    max_mint_fetch_bytes: int
    max_query_bytes: int
    max_query_fields: int
    grant_ttl_ms: int

    @classmethod
    def from_env(cls, env):
        workspace = _text(env, "WORKSPACE")
        if not valid_fid(workspace):
            raise ValueError("WORKSPACE binding")
        prefix = _text(env, "STORE_PREFIX").strip("/")
        if not prefix:
            raise ValueError("STORE_PREFIX binding")
        try:
            secret = base64.b64decode(
                _text(env, "GRANT_SECRET"), validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("GRANT_SECRET binding") from error
        if len(secret) != 32:
            raise ValueError("GRANT_SECRET binding")
        return cls(
            getattr(env, "BUCKET"),
            workspace,
            prefix,
            secret,
            *(_budget(env, name) for name in _BUDGETS),
        )


class ReadOnlyStore:
    """Narrow an R2 ObjectStore binding to the HttpGate's read capability."""

    __slots__ = ("_store",)

    def __init__(self, bucket, prefix):
        self._store = R2BindingStore(bucket, prefix)

    async def get_bounded(self, key, max_bytes):
        return await self._store.get_bounded(key, max_bytes)

    async def has(self, key):
        return await self._store.has(key)


def now_ms():
    return time_ns() // 1_000_000


def gateway(settings, clock=None):
    clock = now_ms if clock is None else clock
    return HttpGate(
        ReadOnlyStore(settings.bucket, settings.prefix),
        settings.workspace,
        settings.secret,
        clock,
        sync_profile=peer_capability.READ_ONLY,
        max_request_bytes=settings.max_request_bytes,
        max_root_bytes=settings.max_root_bytes,
        max_object_bytes=settings.max_object_bytes,
        max_batch_count=settings.max_batch_count,
        max_batch_bytes=settings.max_batch_bytes,
        max_mint_fetches=settings.max_mint_fetches,
        max_mint_fetch_bytes=settings.max_mint_fetch_bytes,
        grant_ttl_ms=settings.grant_ttl_ms,
        seal=seal_to,
    )


def _query(url, max_bytes, max_fields):
    """Bound the encoded query before percent decoding or field allocation."""
    raw = str(url)
    start = raw.find("?")
    encoded = "" if start < 0 else raw[start + 1:].split("#", 1)[0]
    if len(encoded) > max_bytes \
            or len(encoded.encode("utf-8")) > max_bytes:
        raise OverflowError("query byte budget")
    if _BAD_PERCENT.search(encoded):
        raise ValueError("query percent encoding")
    return parse_qs(
        encoded,
        keep_blank_values=True,
        strict_parsing=True,
        max_num_fields=max_fields,
        encoding="utf-8",
        errors="strict",
    )


def _headers(request):
    return dict(request.headers.items())


def _method(request):
    method = request.method
    return method.value if hasattr(method, "value") else str(method)


def _content_length(headers):
    value = next(
        (value for key, value in headers.items()
         if key.lower() == "content-length"),
        None,
    )
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Content-Length") from error
    if parsed < 0:
        raise ValueError("Content-Length")
    return parsed


def _chunk_bytes(value):
    if hasattr(value, "to_bytes"):
        return value.to_bytes()
    if hasattr(value, "to_py"):
        value = value.to_py()
    return bytes(value)


async def _bounded_body(request, limit):
    """Consume a Workers ReadableStream without buffering past ``limit``."""
    stream = getattr(request, "body", None)
    if stream is None:
        declared = _content_length(dict(request.headers.items()))
        if declared not in {None, 0}:
            raise ValueError("request body stream")
        return b""
    if not hasattr(stream, "getReader"):
        raise ValueError("request body stream")
    reader = stream.getReader()
    chunks, total = [], 0
    try:
        while True:
            result = await reader.read()
            if result.done:
                return b"".join(chunks)
            chunk = _chunk_bytes(result.value)
            total += len(chunk)
            if total > limit:
                await reader.cancel("request body limit")
                return None
            chunks.append(chunk)
    finally:
        reader.releaseLock()


def _secured(response):
    return Response(
        response.status,
        response.body,
        {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            **response.headers,
        },
    )


async def handle(request, env):
    """Translate one Workers SDK request into the shared HttpGate contract."""
    try:
        _crypto_self_test()
        settings = Settings.from_env(env)
    except Exception:
        return _secured(Response(500))
    try:
        method = _method(request)
        headers = _headers(request)
        length = _content_length(headers)
    except Exception:
        return _secured(Response(400))
    if length is not None and length > settings.max_request_bytes:
        return _secured(Response(413))
    try:
        body = await _bounded_body(
            request, settings.max_request_bytes) if method in {
            "POST", "PUT", "PATCH"} else b""
    except Exception:
        return _secured(Response(400))
    if body is None:
        return _secured(Response(413))

    try:
        query = _query(
            request.url,
            settings.max_query_bytes,
            settings.max_query_fields,
        )
        url = urlsplit(str(request.url))
    except OverflowError:
        return _secured(Response(414))
    except (TypeError, ValueError, UnicodeError):
        return _secured(Response(400))
    result = await gateway(settings).handle(
        method,
        url.path,
        query,
        headers,
        body,
    )
    return _secured(result)
