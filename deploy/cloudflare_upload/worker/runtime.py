"""Cloudflare request and outbound-R2 translation for the upload broker."""
from dataclasses import dataclass, field
import secrets
import time
from urllib.parse import urlsplit

from core.shape import valid_fid
from deploy.cloudflare_upload.reader import (
    R2CanonicalReader,
    R2FetchRequest,
    R2ReadConfig,
)
from deploy.cloudflare_upload.signer import (
    R2UploadSigner,
    R2UploadTarget,
)
from deploy.upload_broker import UploadBroker
from deploy.upload_broker_http import (
    UploadBrokerEndpoint,
    upload_error_response,
    upload_request_body_limit,
)
from deploy.upload_keyring import decode_keyring


UPLOAD_PROTOCOL = "exact-pile-v2"
MAX_REQUEST_CHUNKS = 65_536


def now_ms():
    return time.time_ns() // 1_000_000


def _text(env, name):
    value = getattr(env, name)
    if not isinstance(value, str):
        value = str(value)
    if not value:
        raise ValueError(f"missing {name} binding")
    return value


def _integer(env, name):
    value = _text(env, name)
    if not value.isascii() or not value.isdecimal() \
            or str(int(value)) != value:
        raise ValueError(f"{name} binding")
    return int(value)


@dataclass(frozen=True)
class Settings:
    workspace: str
    read_config: R2ReadConfig
    upload_target: R2UploadTarget
    read_access_key_id: str
    read_secret_access_key: str = field(repr=False)
    ingress_access_key_id: str
    ingress_secret_access_key: str = field(repr=False)
    session_policy: object = field(repr=False)
    applier: object = field(repr=False)

    @classmethod
    def from_env(cls, env, *, clock):
        if _text(env, "POC16_DEPLOYMENT_ROLE") != "broker" \
                or _text(
                    env, "CANONICAL_BUCKET_PROFILE",
                ) != "dedicated-workspace" \
                or _text(env, "UPLOAD_PROTOCOL") != UPLOAD_PROTOCOL:
            raise ValueError("upload broker role binding")
        workspace = _text(env, "WORKSPACE")
        if not valid_fid(workspace):
            raise ValueError("WORKSPACE binding")
        endpoint = _text(env, "R2_ENDPOINT")
        read_config = R2ReadConfig(
            endpoint,
            _text(env, "CANONICAL_BUCKET"),
            _text(env, "CANONICAL_PREFIX"),
        )
        upload_target = R2UploadTarget(
            endpoint.removeprefix("https://").split(".", 1)[0],
            workspace,
            _text(env, "INGRESS_BUCKET"),
            _text(env, "INGRESS_PREFIX"),
            _jurisdiction(endpoint),
            _integer(env, "PRESIGN_TTL_SECONDS"),
        )
        if read_config.bucket == upload_target.ingress_bucket:
            raise ValueError("canonical and ingress buckets must differ")
        ingress_access = _text(
            env, "INGRESS_PARENT_ACCESS_KEY_ID")
        ingress_secret = _text(
            env, "INGRESS_PARENT_SECRET_ACCESS_KEY")
        signer = R2UploadSigner(
            upload_target,
            ingress_access,
            ingress_secret,
            clock=clock,
        )
        try:
            keyring = decode_keyring(
                _text(
                    env, "UPLOAD_SESSION_KEYRING",
                ).encode("ascii"),
                signer.provider_binding,
            )
        except (UnicodeError, ValueError) as error:
            raise ValueError("UPLOAD_SESSION_KEYRING binding") from error
        if keyring.policy.issuer != _text(env, "UPLOAD_ISSUER"):
            raise ValueError("UPLOAD_ISSUER binding")
        applier = getattr(env, "APPLIER")
        if not callable(getattr(applier, "apply", None)):
            raise ValueError("APPLIER service binding")
        return cls(
            workspace,
            read_config,
            upload_target,
            _text(env, "CANONICAL_READ_ACCESS_KEY_ID"),
            _text(env, "CANONICAL_READ_SECRET_ACCESS_KEY"),
            ingress_access,
            ingress_secret,
            keyring.policy,
            applier,
        )


def _jurisdiction(endpoint):
    host = urlsplit(endpoint).hostname
    if host is None:
        raise ValueError("R2 endpoint binding")
    parts = host.split(".")
    return "default" if len(parts) == 4 else parts[1]


def _method(request):
    method = request.method
    return method.value if hasattr(method, "value") else str(method)


def _headers(request):
    return dict(request.headers.items())


def _content_length(headers):
    values = [
        value for name, value in headers.items()
        if str(name).lower() == "content-length"
    ]
    if not values:
        return None
    if len(values) != 1:
        raise ValueError("Content-Length")
    value = str(values[0])
    if not value.isascii() or not value.isdecimal() \
            or str(int(value)) != value:
        raise ValueError("Content-Length")
    return int(value)


def _chunk_bytes(value):
    if isinstance(value, bytes):
        return value
    if hasattr(value, "to_bytes"):
        return value.to_bytes()
    if hasattr(value, "to_py"):
        value = value.to_py()
    return bytes(value)


async def _bounded_body(request, limit):
    stream = getattr(request, "body", None)
    if stream is None:
        declared = _content_length(_headers(request))
        if declared not in {None, 0}:
            raise ValueError("upload request body stream")
        return b""
    if not hasattr(stream, "getReader"):
        raise ValueError("upload request body stream")
    reader = stream.getReader()
    chunks, total = [], 0
    try:
        for _ in range(MAX_REQUEST_CHUNKS):
            result = await reader.read()
            if result.done:
                return b"".join(chunks)
            chunk = _chunk_bytes(result.value)
            total += len(chunk)
            if total > limit:
                await reader.cancel("upload request body limit")
                return None
            chunks.append(chunk)
        await reader.cancel("upload request chunk limit")
        raise ValueError("upload request chunk limit")
    finally:
        reader.releaseLock()


async def workerd_fetch(request):
    """Perform one redirect-rejecting subrequest through the Workers FFI."""
    if not isinstance(request, R2FetchRequest):
        raise TypeError("R2 fetch request")
    from js import Object, fetch
    from pyodide.ffi import to_js

    options = to_js(
        {
            "cache": request.cache,
            "headers": dict(request.headers),
            "method": request.method,
            "redirect": request.redirect,
        },
        dict_converter=Object.fromEntries,
    )
    return await fetch(request.url, options)


def broker(settings, fetch, clock, nonce):
    signer = R2UploadSigner(
        settings.upload_target,
        settings.ingress_access_key_id,
        settings.ingress_secret_access_key,
        clock=clock,
    )
    reader = R2CanonicalReader(
        settings.read_config,
        settings.read_access_key_id,
        settings.read_secret_access_key,
        fetch,
        clock=clock,
    )
    async def apply_exact(key, digest):
        value = await settings.applier.apply(key, digest)
        convert = getattr(value, "to_py", None)
        return convert() if callable(convert) else value

    return UploadBrokerEndpoint(UploadBroker(
        reader,
        settings.workspace,
        signer,
        clock,
        settings.session_policy,
        apply_exact=apply_exact,
        nonce=nonce,
    ))


async def handle(
        request, env, *, fetch=workerd_fetch, clock=now_ms,
        nonce=secrets.token_bytes):
    """Translate one Worker request into the shared metadata-only membrane."""
    try:
        settings = Settings.from_env(env, clock=clock)
    except Exception:
        return upload_error_response(500)
    try:
        method = _method(request)
        raw_url = str(request.url)
        parsed = urlsplit(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc \
                or parsed.username is not None \
                or parsed.password is not None or parsed.query \
                or parsed.fragment or "%" in parsed.path:
            raise ValueError("upload request URL")
        path = parsed.path
        headers = _headers(request)
        limit = upload_request_body_limit(path)
        length = _content_length(headers)
        if limit is not None and method == "POST" \
                and length is not None and length > limit:
            return upload_error_response(413)
        body = await _bounded_body(request, limit) \
            if limit is not None and method == "POST" else b""
        if body is None:
            return upload_error_response(413)
    except Exception:
        return upload_error_response(400)
    try:
        return await broker(
            settings, fetch, clock, nonce,
        ).handle(method, path, headers, body)
    except Exception:
        return upload_error_response(503)


__all__ = ("Settings", "handle")
