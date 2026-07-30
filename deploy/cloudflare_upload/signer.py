"""Pure-stdlib SigV4 capabilities for exact isolated-ingress R2 PUTs.

The long-lived parent credential never leaves this translator.  Each result is
the same ``UploadCapability`` used by the AWS path: one bearer URL, one exact
method/header set, and one session-bounded expiry.  R2 receives
``UNSIGNED-PAYLOAD`` deliberately; staged bytes remain untrusted until the
publisher verifies their SHA-256 address before canonical promotion.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import re
import time
from urllib.parse import quote

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
_SIGNED_HEADERS = (
    "content-length",
    "content-type",
    "host",
    "if-none-match",
)
_ASCII_CREDENTIAL = re.compile(r"^[\x21-\x7e]+$")
_ACCESS_KEY = re.compile(r"^[A-Za-z0-9._+=~-]+$")
_PARENT_DOMAIN = b"poc16-r2-parent-access-key-v1\0"


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


def _canonical_headers(headers):
    return "".join(
        f"{name}:{headers[name]}\n" for name in _SIGNED_HEADERS)


def _canonical_uri(bucket, key):
    return quote(
        f"/{bucket}/{key}",
        safe="/-_.~",
        encoding="utf-8",
        errors="strict",
    )


class R2UploadSigner:
    """Attenuate one isolated-ingress parent into exact presigned PUTs."""

    def __init__(
            self, deployment, parent_access_key_id,
            parent_secret_access_key, *, clock=_system_now_ms):
        if not isinstance(deployment, Deployment):
            raise TypeError("R2 upload deployment")
        if not callable(clock):
            raise ValueError("R2 signing clock")
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
        self._access_key_id = access
        self._secret_access_key = secret
        self._clock = clock

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
        now_ms = self._clock()
        if type(now_ms) is not int or now_ms < 0:
            raise RuntimeError("R2 signing clock")
        issued_second = now_ms // 1000
        ttl_seconds = min(
            self.deployment.presign_ttl_seconds,
            (put.not_after_ms - issued_second * 1000) // 1000,
        )
        if ttl_seconds < 1:
            raise RuntimeError(
                "R2 session deadline leaves no signed second")
        try:
            issued = datetime.fromtimestamp(
                issued_second, timezone.utc)
        except (OverflowError, OSError, ValueError) as error:
            raise RuntimeError("R2 signing clock") from error
        timestamp = issued.strftime("%Y%m%dT%H%M%SZ")
        date = timestamp[:8]
        scope = f"{date}/{REGION}/{SERVICE}/{_TERMINATOR}"
        host = self.deployment.endpoint.removeprefix("https://")
        uri = _canonical_uri(
            self.deployment.ingress_bucket, put.key)
        headers = {
            "content-length": str(put.size),
            "content-type": put.content_type,
            "host": host,
            "if-none-match": "*",
        }
        signed_headers = ";".join(_SIGNED_HEADERS)
        query = {
            "X-Amz-Algorithm": ALGORITHM,
            "X-Amz-Content-Sha256": PAYLOAD,
            "X-Amz-Credential": f"{self._access_key_id}/{scope}",
            "X-Amz-Date": timestamp,
            "X-Amz-Expires": str(ttl_seconds),
            "X-Amz-SignedHeaders": signed_headers,
        }
        canonical_request = "\n".join((
            "PUT",
            uri,
            _query(query),
            _canonical_headers(headers),
            signed_headers,
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
        if expires_at_ms > put.not_after_ms:
            raise RuntimeError("R2 signature exceeded session deadline")
        return UploadCapability(
            "PUT",
            f"{self.deployment.endpoint}{uri}?{_query(query)}"
            f"&X-Amz-Signature={signature}",
            tuple(
                (name, headers[name])
                for name in _SIGNED_HEADERS
                if name != "host"
            ),
            expires_at_ms,
        )
