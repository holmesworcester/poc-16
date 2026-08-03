"""Pure-stdlib SigV4 capabilities for exact isolated-ingress R2 PUTs.

The long-lived parent credential never leaves this translator.  Each result is
the same ``UploadCapability`` used by the AWS path: one bearer URL, one exact
method/header set, and one session-bounded expiry.  R2 receives
``UNSIGNED-PAYLOAD`` deliberately; staged bytes remain untrusted until the
applier verifies their SHA-256 address before canonical promotion.
"""
from dataclasses import dataclass
import hashlib
import re

from core.limits import MAX_PILE_BYTES
from deploy.cloudflare_sigv4 import (
    ACCESS_KEY_PATTERN as _ACCESS_KEY,
    ALGORITHM,
    BUCKET_PATTERN as _BUCKET,
    MAX_ACCESS_KEY_ID_CHARS,
    MAX_SECRET_ACCESS_KEY_CHARS,
    PAYLOAD,
    R2SignedRequest,
    R2SigV4,
    credential as _credential,
    system_now_ms as _system_now_ms,
)
from deploy.upload_broker import AuthorizedPilePut
from deploy.upload_wire import UPLOAD_CONTENT_TYPE, UploadCapability
from .boundary import Deployment


_ACCOUNT = re.compile(r"^[0-9a-f]{32}$")
_FID = re.compile(r"^[0-9a-f]{64}$")
_PARENT_DOMAIN = b"poc16-r2-parent-access-key-v1\0"
_JURISDICTIONS = frozenset({"default", "eu", "fedramp"})


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
            parent_access_key_id,
            "R2 parent access key id",
            MAX_ACCESS_KEY_ID_CHARS,
        )
        if _ACCESS_KEY.fullmatch(access) is None:
            raise ValueError("R2 parent access key id")
        secret = _credential(
            parent_secret_access_key,
            "R2 parent secret access key",
            MAX_SECRET_ACCESS_KEY_CHARS,
        )
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
        if not isinstance(put, AuthorizedPilePut) \
                or put.workspace != deployment.workspace \
                or not put.key.startswith(deployment.ingress_prefix + "/") \
                or type(put.size) is not int or put.size < 0 \
                or type(put.not_after_ms) is not int \
                or put.not_after_ms < 0:
            raise ValueError("authorized R2 upload")
        if put.size > MAX_PILE_BYTES:
            raise ValueError("authorized R2 upload size")

    def sign(self, put):
        self._authorized(put)
        headers = {
            "content-length": str(put.size),
            "content-type": UPLOAD_CONTENT_TYPE,
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
        if request.method != "PUT":
            raise RuntimeError("R2 presigner method")
        return UploadCapability(
            request.url,
            request.headers,
            request.expires_at_ms,
        )
