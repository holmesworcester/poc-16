"""AWS SigV4 translation for exact isolated-ingress PUT capabilities."""
from dataclasses import dataclass
import base64
from datetime import datetime, timezone
import re
from urllib.parse import parse_qs, urlsplit

from core.limits import MAX_OBJECT_BYTES, MAX_PILE_BYTES
from core.staged_intent import staging_key
from deploy.upload_broker import (
    AuthorizedPut,
    UPLOAD_CONTENT_TYPE,
    UploadCapability,
)


_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_REGION_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
_RESERVED_BUCKET_PREFIXES = ("amzn-s3-demo-", "xn--", "sthree-")
_RESERVED_BUCKET_SUFFIXES = (
    "-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
_REQUIRED_QUERY = frozenset({
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-Signature",
    "X-Amz-SignedHeaders",
})
_OPTIONAL_QUERY = frozenset({"X-Amz-Security-Token"})
_BASE_SIGNED_HEADERS = frozenset({
    "content-length",
    "content-type",
    "host",
    "if-none-match",
    "x-amz-checksum-sha256",
})


@dataclass(frozen=True)
class S3UploadConfig:
    """One AWS ingress bucket and a deliberately short bearer lifetime."""

    bucket: str
    region_name: str
    ttl_seconds: int = 60
    expected_bucket_owner: str | None = None

    def __post_init__(self):
        if not isinstance(self.bucket, str) \
                or not _BUCKET_RE.fullmatch(self.bucket) \
                or self.bucket.startswith(_RESERVED_BUCKET_PREFIXES) \
                or self.bucket.endswith(_RESERVED_BUCKET_SUFFIXES):
            raise ValueError("S3 ingress bucket")
        if not isinstance(self.region_name, str) \
                or not _REGION_RE.fullmatch(self.region_name):
            raise ValueError("S3 ingress region")
        if type(self.ttl_seconds) is not int \
                or not 1 <= self.ttl_seconds <= 15 * 60:
            raise ValueError("S3 upload TTL")
        owner = self.expected_bucket_owner
        if owner is not None and (
                not isinstance(owner, str)
                or len(owner) != 12 or not owner.isdigit()):
            raise ValueError("S3 expected bucket owner")


def _new_client(config):
    try:
        import boto3
        from botocore.config import Config
        from botocore.session import get_session
    except ImportError as error:
        raise RuntimeError(
            "AWS upload signing requires boto3 and botocore") from error
    from adapters.s3.sdk_smoke import require_s3_capabilities

    require_s3_capabilities(Config, get_session())
    session = boto3.Session(region_name=config.region_name)
    return session.client(
        "s3",
        region_name=config.region_name,
        config=Config(
            signature_version="s3v4",
            ignore_configured_endpoint_urls=True,
            s3={"addressing_style": "virtual"},
        ),
    )


def _checksum(digest):
    try:
        raw = bytes.fromhex(digest)
    except (TypeError, ValueError) as error:
        raise ValueError("upload digest") from error
    if len(raw) != 32 or digest != raw.hex():
        raise ValueError("upload digest")
    return base64.b64encode(raw).decode("ascii")


def _headers(put, config):
    values = {
        "content-length": str(put.size),
        "content-type": put.content_type,
        "if-none-match": "*",
        "x-amz-checksum-sha256": _checksum(put.digest),
    }
    if config.expected_bucket_owner is not None:
        values["x-amz-expected-bucket-owner"] = (
            config.expected_bucket_owner)
    return tuple(sorted(values.items()))


def _params(put, config, headers):
    values = dict(headers)
    params = {
        "Bucket": config.bucket,
        "ChecksumSHA256": values["x-amz-checksum-sha256"],
        "ContentLength": put.size,
        "ContentType": put.content_type,
        "IfNoneMatch": "*",
        "Key": put.key,
    }
    if config.expected_bucket_owner is not None:
        params["ExpectedBucketOwner"] = config.expected_bucket_owner
    return params


def _one(query, name):
    values = query.get(name)
    if not isinstance(values, list) or len(values) != 1:
        raise RuntimeError(f"S3 presigner omitted {name}")
    return values[0]


def _endpoint_host(client):
    meta = getattr(client, "meta", None)
    endpoint = getattr(meta, "endpoint_url", None)
    parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
    if parsed is None or parsed.scheme != "https" \
            or not parsed.hostname or parsed.port is not None \
            or parsed.path not in {"", "/"}:
        raise RuntimeError("S3 presigner endpoint")
    return parsed.hostname


def _inspect_url(url, put, config, client, headers, ttl_seconds):
    try:
        parsed = urlsplit(url)
        query = parse_qs(
            parsed.query, keep_blank_values=True, strict_parsing=True)
    except (TypeError, ValueError) as error:
        raise RuntimeError("S3 presigner URL") from error
    if parsed.scheme != "https" or parsed.username is not None \
            or parsed.password is not None or parsed.port is not None \
            or parsed.fragment or parsed.path != "/" + put.key \
            or parsed.hostname != (
                f"{config.bucket}.{_endpoint_host(client)}"):
        raise RuntimeError("S3 presigner target")
    if set(query) - _REQUIRED_QUERY - _OPTIONAL_QUERY \
            or _REQUIRED_QUERY - set(query):
        raise RuntimeError("S3 presigner query shape")
    if any(len(values) != 1 for values in query.values()) \
            or _one(query, "X-Amz-Algorithm") != "AWS4-HMAC-SHA256" \
            or _one(query, "X-Amz-Expires") != str(ttl_seconds) \
            or not _SIGNATURE_RE.fullmatch(
                _one(query, "X-Amz-Signature")):
        raise RuntimeError("S3 presigner query authority")

    signed = frozenset(
        _one(query, "X-Amz-SignedHeaders").split(";"))
    expected = _BASE_SIGNED_HEADERS | (
        {"x-amz-expected-bucket-owner"}
        if config.expected_bucket_owner is not None else set())
    if signed != expected:
        raise RuntimeError("S3 presigner did not sign every constraint")

    credential = _one(query, "X-Amz-Credential").split("/")
    if len(credential) != 5 \
            or credential[2:] != [
                config.region_name, "s3", "aws4_request"]:
        raise RuntimeError("S3 presigner credential scope")
    try:
        issued = datetime.strptime(
            _one(query, "X-Amz-Date"),
            "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as error:
        raise RuntimeError("S3 presigner timestamp") from error
    expires_at_ms = (
        int(issued.timestamp()) + ttl_seconds) * 1000
    return UploadCapability(
        "PUT", url, headers, expires_at_ms)


def _presign(client, put, config, headers, ttl_seconds):
    try:
        url = client.generate_presigned_url(
            "put_object",
            Params=_params(put, config, headers),
            ExpiresIn=ttl_seconds,
            HttpMethod="PUT",
        )
    except Exception as error:
        raise RuntimeError("S3 presigning failed") from error
    return _inspect_url(
        url, put, config, client, headers, ttl_seconds)


class S3UploadSigner:
    """Translate one authorized staging address into a checked SigV4 URL."""

    def __init__(self, config, client=None):
        if not isinstance(config, S3UploadConfig):
            raise TypeError("S3 upload config")
        self.config = config
        self.provider_binding = ":".join((
            "aws-s3-v1",
            config.region_name,
            config.bucket,
            config.expected_bucket_owner or "bucket-owner-unpinned",
        ))
        self.client = _new_client(config) if client is None else client
        if not callable(
                getattr(self.client, "generate_presigned_url", None)):
            raise ValueError("S3 presigner client")
        _endpoint_host(self.client)

    def sign(self, put):
        if not isinstance(put, AuthorizedPut) \
                or put.key != staging_key(
                    put.workspace,
                    put.member,
                    put.session,
                    put.object_class,
                    put.digest,
                ) \
                or put.content_type != UPLOAD_CONTENT_TYPE \
                or type(put.size) is not int or put.size < 0 \
                or type(put.not_after_ms) is not int \
                or put.not_after_ms < 0:
            raise ValueError("authorized S3 upload")
        maximum = MAX_OBJECT_BYTES \
            if put.object_class == "obj" else MAX_PILE_BYTES
        if put.size > maximum:
            raise ValueError("authorized S3 upload size")
        headers = _headers(put, self.config)
        capability = _presign(
            self.client,
            put,
            self.config,
            headers,
            self.config.ttl_seconds,
        )
        if capability.expires_at_ms <= put.not_after_ms:
            return capability

        # SigV4 exposes only whole-second lifetimes. Derive the presigner's
        # actual issue second from its checked response, round the remaining
        # authority down, and fail closed when no full second remains.
        issued_at_ms = (
            capability.expires_at_ms - self.config.ttl_seconds * 1000)
        ttl_seconds = (put.not_after_ms - issued_at_ms) // 1000
        if ttl_seconds < 1:
            raise RuntimeError(
                "S3 session deadline leaves no whole-second capability")
        capability = _presign(
            self.client,
            put,
            self.config,
            headers,
            ttl_seconds,
        )
        if capability.expires_at_ms > put.not_after_ms:
            raise RuntimeError("S3 presigner exceeded session deadline")
        return capability
