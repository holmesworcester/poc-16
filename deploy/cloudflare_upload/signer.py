"""Pure-stdlib SigV4 capabilities for exact isolated-ingress R2 PUTs.

The long-lived parent credential never leaves this translator.  Each result is
the same ``UploadCapability`` used by the AWS path: one bearer URL, one exact
method/header set, and one session-bounded expiry.  R2 receives
``UNSIGNED-PAYLOAD`` deliberately; staged bytes remain untrusted until the
publisher verifies their SHA-256 address before canonical promotion.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import re
import time
from urllib.parse import quote, urlsplit

from core.limits import MAX_OBJECT_BYTES, MAX_PILE_BYTES
from core.staged_intent import staging_key
from deploy.upload_broker import (
    AuthorizedPut,
    UPLOAD_CONTENT_TYPE,
    UploadCapability,
)
from .boundary import Deployment


ALGORITHM = "AWS4-HMAC-SHA256"
PAYLOAD = "UNSIGNED-PAYLOAD"
REGION = "auto"
SERVICE = "s3"
_TERMINATOR = "aws4_request"
_ASCII_CREDENTIAL = re.compile(r"^[\x21-\x7e]+$")
_ACCESS_KEY = re.compile(r"^[A-Za-z0-9._+=~-]+$")
_ACCOUNT = re.compile(r"^[0-9a-f]{32}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_FID = re.compile(r"^[0-9a-f]{64}$")
_KEY = re.compile(r"^[a-z0-9:._/-]+$")
_PARENT_DOMAIN = b"poc16-r2-parent-access-key-v1\0"
_JURISDICTIONS = frozenset({"default", "eu", "fedramp"})


def _system_now_ms():
    return time.time_ns() // 1_000_000


def _credential(value, label, maximum):
    if not isinstance(value, str) \
            or not 8 <= len(value) <= maximum \
            or _ASCII_CREDENTIAL.fullmatch(value) is None:
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
    return _mac(service_key, _TERMINATOR.encode("ascii"))


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


@dataclass(frozen=True)
class R2UploadTarget:
    """Only the non-secret provider scope needed by a broker isolate."""

    account_id: str
    workspace: str
    ingress_bucket: str
    ingress_prefix: str
    jurisdiction: str
    presign_ttl_seconds: int

    def __post_init__(self):
        expected = f"ingress/v1/workspaces/{self.workspace}"
        if not isinstance(self.account_id, str) \
                or _ACCOUNT.fullmatch(self.account_id) is None \
                or not isinstance(self.workspace, str) \
                or _FID.fullmatch(self.workspace) is None \
                or not isinstance(self.ingress_bucket, str) \
                or _BUCKET.fullmatch(self.ingress_bucket) is None \
                or self.ingress_prefix != expected \
                or self.jurisdiction not in _JURISDICTIONS \
                or type(self.presign_ttl_seconds) is not int \
                or not 1 <= self.presign_ttl_seconds <= 60 * 60:
            raise ValueError("R2 upload target")

    @property
    def endpoint(self):
        jurisdiction = (
            "" if self.jurisdiction == "default"
            else f".{self.jurisdiction}"
        )
        return (
            f"https://{self.account_id}{jurisdiction}."
            "r2.cloudflarestorage.com"
        )

    @classmethod
    def from_deployment(cls, deployment):
        if not isinstance(deployment, Deployment):
            raise TypeError("R2 upload deployment")
        return cls(
            deployment.account_id,
            deployment.workspace,
            deployment.ingress_bucket,
            deployment.ingress_prefix,
            deployment.jurisdiction,
            deployment.presign_ttl_seconds,
        )


class R2SigV4:
    """Sign exact R2 requests without giving callers the parent credential."""

    def __init__(
            self, endpoint, access_key_id, secret_access_key, *,
            clock=_system_now_ms):
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
        access = _credential(
            access_key_id, "R2 parent access key id", 128)
        if _ACCESS_KEY.fullmatch(access) is None:
            raise ValueError("R2 parent access key id")
        secret = _credential(
            secret_access_key, "R2 parent secret access key", 256)
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
                or _BUCKET.fullmatch(bucket) is None \
                or not isinstance(key, str) or not key \
                or _KEY.fullmatch(key) is None \
                or len(key.encode("ascii")) > 1024 \
                or not isinstance(headers, dict) \
                or type(ttl_seconds) is not int \
                or not 1 <= ttl_seconds <= 604_800 \
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
        scope = f"{date}/{REGION}/{SERVICE}/{_TERMINATOR}"
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
        if not_after_ms is not None \
                and expires_at_ms > not_after_ms:
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


class R2UploadSigner:
    """Attenuate one isolated-ingress parent into exact presigned PUTs."""

    def __init__(
            self, deployment, parent_access_key_id,
            parent_secret_access_key, *, clock=_system_now_ms):
        if isinstance(deployment, Deployment):
            deployment = R2UploadTarget.from_deployment(deployment)
        if not isinstance(deployment, R2UploadTarget):
            raise TypeError("R2 upload deployment")
        access = _credential(
            parent_access_key_id, "R2 parent access key id", 128)
        if _ACCESS_KEY.fullmatch(access) is None:
            raise ValueError("R2 parent access key id")
        secret = _credential(
            parent_secret_access_key, "R2 parent secret access key", 256)
        parent = hashlib.sha256(
            _PARENT_DOMAIN + access.encode("ascii")).hexdigest()
        self.provider_binding = ":".join((
            "cloudflare-r2-v1",
            deployment.account_id,
            deployment.jurisdiction,
            deployment.ingress_bucket,
            parent,
        ))
        self.deployment = deployment
        self._sigv4 = R2SigV4(
            deployment.endpoint,
            access,
            secret,
            clock=clock,
        )

    def _authorized(self, put):
        deployment = self.deployment
        if not isinstance(put, AuthorizedPut) \
                or put.workspace != deployment.workspace \
                or put.key != staging_key(
                    put.workspace,
                    put.member,
                    put.session,
                    put.object_class,
                    put.digest,
                ) \
                or not put.key.startswith(deployment.ingress_prefix + "/") \
                or put.content_type != UPLOAD_CONTENT_TYPE \
                or type(put.size) is not int or put.size < 0 \
                or type(put.not_after_ms) is not int \
                or put.not_after_ms < 0:
            raise ValueError("authorized R2 upload")
        maximum = MAX_OBJECT_BYTES \
            if put.object_class == "obj" else MAX_PILE_BYTES
        if put.size > maximum:
            raise ValueError("authorized R2 upload size")

    def sign(self, put):
        self._authorized(put)
        headers = {
            "content-length": str(put.size),
            "content-type": put.content_type,
            "if-none-match": "*",
        }
        request = self._sigv4.sign(
            "PUT",
            self.deployment.ingress_bucket,
            put.key,
            headers,
            self.deployment.presign_ttl_seconds,
            not_after_ms=put.not_after_ms,
        )
        return UploadCapability(
            request.method,
            request.url,
            request.headers,
            request.expires_at_ms,
        )
