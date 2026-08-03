"""Exact AWS S3 capabilities for immutable writer-pack HTTP requests.

This module signs metadata only.  Pack bodies travel between the caller and
S3, never through Lambda or :class:`core.http.HttpGate`.
"""
from dataclasses import dataclass
import base64
from datetime import datetime, timezone
import re
from urllib.parse import parse_qs, unquote, urlsplit

from adapters.s3 import S3Config
from core.pack_access import (
    MAX_SCOPED_TTL_MS,
    PackOpen,
    ScopedRequest,
    pack_key,
)
from core.shape import valid_fid


PACK_CONTENT_TYPE = "application/octet-stream"
DEFAULT_PACK_TTL_SECONDS = MAX_SCOPED_TTL_MS // 1000

_AWS_HOST = re.compile(
    r"^(?:s3(?:[.-][a-z0-9-]+)*\.)?amazonaws\.com(?:\.cn)?$")
_REQUIRED_QUERY = frozenset({
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-Signature",
    "X-Amz-SignedHeaders",
})
_OPTIONAL_QUERY = frozenset({
    "X-Amz-Security-Token",
    "x-amz-checksum-mode",
    "x-id",
})
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class S3PackBinding:
    """The one deployed S3 namespace and bearer lifetime an issuer may use."""

    config: S3Config
    ttl_seconds: int = DEFAULT_PACK_TTL_SECONDS

    def __post_init__(self):
        if not isinstance(self.config, S3Config) \
                or not self.config.prefix \
                or self.config.region_name is None \
                or self.config.endpoint_url is not None \
                or type(self.ttl_seconds) is not int \
                or not 1 <= self.ttl_seconds \
                <= DEFAULT_PACK_TTL_SECONDS:
            raise ValueError("AWS S3 pack binding")

    def physical_key(self, oid):
        return f"{self.config.prefix}/{pack_key(oid)}"


def _new_client(binding):
    try:
        import boto3
        from botocore.config import Config
        from botocore.session import get_session
    except ImportError as error:
        raise RuntimeError(
            "AWS pack signing requires boto3 and botocore") from error
    from adapters.s3.sdk_smoke import require_s3_capabilities

    require_s3_capabilities(Config, get_session())
    config = binding.config
    return boto3.client(
        "s3",
        region_name=config.region_name,
        config=Config(
            connect_timeout=config.connect_timeout,
            ignore_configured_endpoint_urls=True,
            read_timeout=config.read_timeout,
            retries={"mode": "standard", "total_max_attempts": 1},
            signature_version="s3v4",
            s3={"addressing_style": config.addressing_style or "auto"},
        ),
    )


def _one(query, name):
    values = query.get(name)
    if not isinstance(values, list) or len(values) != 1:
        raise RuntimeError(f"S3 pack presigner omitted {name}")
    return values[0]


def _endpoint_host(client):
    meta = getattr(client, "meta", None)
    endpoint = getattr(meta, "endpoint_url", None)
    try:
        parsed = urlsplit(endpoint)
    except (TypeError, ValueError) as error:
        raise RuntimeError("S3 pack presigner endpoint") from error
    if parsed.scheme != "https" or not parsed.hostname \
            or parsed.port is not None or parsed.path not in {"", "/"} \
            or _AWS_HOST.fullmatch(parsed.hostname) is None:
        raise RuntimeError("S3 pack presigner endpoint")
    return parsed.hostname


def _checksum(oid):
    try:
        raw = bytes.fromhex(oid)
    except (TypeError, ValueError) as error:
        raise ValueError("pack checksum") from error
    if len(raw) != 32 or raw.hex() != oid:
        raise ValueError("pack checksum")
    return base64.b64encode(raw).decode("ascii")


def _headers(opened, config):
    values = {}
    if opened.method == "PUT":
        values.update({
            "content-length": str(opened.pack_bytes),
            "content-type": PACK_CONTENT_TYPE,
            "if-none-match": "*",
            "x-amz-checksum-sha256": _checksum(opened.oid),
        })
        if config.server_side_encryption is not None:
            values["x-amz-server-side-encryption"] = (
                config.server_side_encryption)
        if config.sse_kms_key_id is not None:
            values["x-amz-server-side-encryption-aws-kms-key-id"] = (
                config.sse_kms_key_id)
        if config.bucket_key_enabled is not None:
            values["x-amz-server-side-encryption-bucket-key-enabled"] = (
                str(config.bucket_key_enabled).lower())
    elif opened.offset is not None:
        values["range"] = (
            f"bytes={opened.offset}-{opened.offset + opened.length - 1}")
    if config.expected_bucket_owner is not None:
        values["x-amz-expected-bucket-owner"] = (
            config.expected_bucket_owner)
    return tuple(sorted(values.items()))


def _params(opened, binding, headers):
    config = binding.config
    values = dict(headers)
    params = {
        "Bucket": config.bucket,
        "Key": binding.physical_key(opened.oid),
    }
    if config.expected_bucket_owner is not None:
        params["ExpectedBucketOwner"] = config.expected_bucket_owner
    if opened.method == "GET":
        if opened.offset is not None:
            params["Range"] = values["range"]
        return params
    params.update({
        "ChecksumSHA256": values["x-amz-checksum-sha256"],
        "ContentLength": opened.pack_bytes,
        "ContentType": PACK_CONTENT_TYPE,
        "IfNoneMatch": "*",
    })
    if config.server_side_encryption is not None:
        params["ServerSideEncryption"] = config.server_side_encryption
    if config.sse_kms_key_id is not None:
        params["SSEKMSKeyId"] = config.sse_kms_key_id
    if config.bucket_key_enabled is not None:
        params["BucketKeyEnabled"] = config.bucket_key_enabled
    return params


def _expected_target(endpoint, bucket, key):
    return {
        (f"{bucket}.{endpoint}", "/" + key),
        (endpoint, f"/{bucket}/{key}"),
    }


def _inspect(url, opened, binding, client, headers, trusted_now):
    config = binding.config
    try:
        parsed = urlsplit(url)
        query = parse_qs(
            parsed.query, keep_blank_values=True, strict_parsing=True)
    except (TypeError, ValueError) as error:
        raise RuntimeError("S3 pack presigner URL") from error
    target = (parsed.hostname, unquote(parsed.path))
    if parsed.scheme != "https" or parsed.username is not None \
            or parsed.password is not None or parsed.port is not None \
            or parsed.fragment or target not in _expected_target(
                _endpoint_host(client), config.bucket,
                binding.physical_key(opened.oid)):
        raise RuntimeError("S3 pack presigner target")
    if set(query) - _REQUIRED_QUERY - _OPTIONAL_QUERY \
            or _REQUIRED_QUERY - set(query) \
            or any(len(values) != 1 for values in query.values()):
        raise RuntimeError("S3 pack presigner query shape")
    if _one(query, "X-Amz-Algorithm") != "AWS4-HMAC-SHA256" \
            or _one(query, "X-Amz-Expires") \
            != str(binding.ttl_seconds) \
            or _SIGNATURE.fullmatch(
                _one(query, "X-Amz-Signature")) is None:
        raise RuntimeError("S3 pack presigner query authority")
    if "x-id" in query and _one(query, "x-id") != (
            "GetObject" if opened.method == "GET" else "PutObject"):
        raise RuntimeError("S3 pack presigner operation")
    if "x-amz-checksum-mode" in query and (
            opened.method != "GET"
            or _one(query, "x-amz-checksum-mode") != "ENABLED"):
        raise RuntimeError("S3 pack presigner checksum mode")

    expected_headers = {name for name, _ in headers} | {"host"}
    signed_headers = set(
        _one(query, "X-Amz-SignedHeaders").split(";"))
    if signed_headers != expected_headers:
        raise RuntimeError(
            "S3 pack presigner did not sign every constraint")
    credential = _one(query, "X-Amz-Credential").split("/")
    issued_raw = _one(query, "X-Amz-Date")
    if len(credential) != 5 or credential[1] != issued_raw[:8] \
            or credential[2:] != [
                config.region_name, "s3", "aws4_request"]:
        raise RuntimeError("S3 pack presigner credential scope")
    try:
        issued = datetime.strptime(
            issued_raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as error:
        raise RuntimeError("S3 pack presigner timestamp") from error
    expires_at_ms = (
        int(issued.timestamp()) + binding.ttl_seconds) * 1000
    if type(trusted_now) is not int or not trusted_now < expires_at_ms \
            <= trusted_now + binding.ttl_seconds * 1000:
        raise RuntimeError("S3 pack presigner clock")
    return ScopedRequest(
        opened.method, url, headers, expires_at_ms)


class S3PackIssuer:
    """Issue one exact, short-lived S3 request after ``HttpGate`` auth."""

    def __init__(self, binding, client=None):
        if not isinstance(binding, S3PackBinding):
            raise TypeError("S3 pack binding")
        self.binding = binding
        self.client = _new_client(binding) if client is None else client
        if not callable(
                getattr(self.client, "generate_presigned_url", None)):
            raise ValueError("S3 pack presigner client")
        _endpoint_host(self.client)

    def open(self, member, opened, trusted_now):
        if not valid_fid(member) or not isinstance(opened, PackOpen) \
                or type(trusted_now) is not int:
            raise ValueError("authorized S3 pack request")
        headers = _headers(opened, self.binding.config)
        operation = "get_object" if opened.method == "GET" else "put_object"
        try:
            url = self.client.generate_presigned_url(
                operation,
                Params=_params(opened, self.binding, headers),
                ExpiresIn=self.binding.ttl_seconds,
                HttpMethod=opened.method,
            )
        except Exception as error:
            raise RuntimeError("S3 pack presigning failed") from error
        return _inspect(
            url, opened, self.binding, self.client,
            headers, trusted_now)


__all__ = (
    "DEFAULT_PACK_TTL_SECONDS",
    "PACK_CONTENT_TYPE",
    "S3PackBinding",
    "S3PackIssuer",
)
