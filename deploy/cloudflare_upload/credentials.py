"""Mint and inspect exact PutObject-only R2 temporary credentials.

R2 validates these locally signed JWTs.  They deliberately target untrusted
staging, not canonical content-addressed keys: the temporary credential does
not bind a collision-resistant body digest, so the publisher must verify the
staged bytes before promotion.
"""
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets

from core.staged_intent import staging_key as logical_staging_key
from .boundary import Deployment, endpoint_host


HEX_32 = re.compile(r"^[0-9a-f]{32}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SCOPE = "object-read-write"
ACTION = "PutObject"


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64url(text):
    if not isinstance(text, str) or not text \
            or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise ValueError("JWT encoding")
    padding = "=" * (-len(text) % 4)
    try:
        return base64.b64decode(
            text + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("JWT encoding") from error


def _json_part(value):
    return _b64url(json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode())


def _document(raw, label):
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(label) from error
    if not isinstance(value, dict):
        raise ValueError(label)
    return value


def new_session_id():
    return secrets.token_hex(16)


def staging_key(
        deployment, *, member, session, kind, digest):
    if not isinstance(deployment, Deployment):
        raise TypeError("deployment")
    key = logical_staging_key(
        deployment.workspace, member, session, kind, digest)
    if not key.startswith(deployment.ingress_prefix + "/"):
        raise ValueError("staging deployment prefix")
    return key


@dataclass(frozen=True)
class TemporaryCredentials:
    endpoint: str
    bucket: str
    key: str
    expires_at: int
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)


@dataclass(frozen=True)
class UploadAuthority:
    account_id: str
    issuer: str
    audience: str
    bucket: str
    key: str
    issued_at: int
    expires_at: int

    def allows(self, *, bucket, key, action, now):
        return (
            bucket == self.bucket
            and key == self.key
            and action == ACTION
            and isinstance(now, int)
            and not isinstance(now, bool)
            and self.issued_at <= now < self.expires_at
        )


def mint_put_credentials(
        deployment, *, member, session, kind, digest,
        parent_access_key_id, parent_secret_access_key, now,
        ttl_seconds=None):
    """Mint one exact staging-object credential from trusted broker inputs."""
    if not HEX_32.fullmatch(parent_access_key_id or ""):
        raise ValueError("parent access key id")
    if not HEX_64.fullmatch(parent_secret_access_key or ""):
        raise ValueError("parent secret access key")
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        raise ValueError("current time")
    ttl = (
        deployment.child_ttl_seconds
        if ttl_seconds is None else ttl_seconds
    )
    if not isinstance(ttl, int) or isinstance(ttl, bool) \
            or not 1 <= ttl <= deployment.child_ttl_seconds:
        raise ValueError("credential TTL")
    key = staging_key(
        deployment,
        member=member,
        session=session,
        kind=kind,
        digest=digest,
    )
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "actions": [ACTION],
        "aud": endpoint_host(deployment),
        "bucket": deployment.ingress_bucket,
        "exp": now + ttl,
        "iat": now,
        "iss": parent_access_key_id,
        "paths": {
            "objectPaths": [key],
            "prefixPaths": [],
        },
        "scope": SCOPE,
        "sub": deployment.account_id,
    }
    unsigned = f"{_json_part(header)}.{_json_part(claims)}"
    signature = hmac.new(
        parent_secret_access_key.encode(),
        unsigned.encode(),
        hashlib.sha256,
    ).digest()
    jwt = f"{unsigned}.{_b64url(signature)}"
    derived = hashlib.sha256(jwt.encode()).hexdigest()
    token = base64.b64encode(f"jwt/{jwt}".encode()).decode()
    credentials = TemporaryCredentials(
        endpoint=deployment.endpoint,
        bucket=deployment.ingress_bucket,
        key=key,
        expires_at=now + ttl,
        access_key_id=parent_access_key_id,
        secret_access_key=derived,
        session_token=token,
    )
    # Keep the returned wire material and the locally signed claim in lockstep.
    inspect_put_credentials(
        deployment,
        credentials,
        parent_secret_access_key=parent_secret_access_key,
        now=now,
    )
    return credentials


def inspect_put_credentials(
        deployment, credentials, *, parent_secret_access_key, now):
    """Verify one generated credential and return its effective authority.

    This is a credential-free conformance seam, not live proof of R2's
    verifier.  It mirrors the documented HS256 temporary-credential format so
    tests can mutate every authority-bearing claim.
    """
    if not isinstance(credentials, TemporaryCredentials):
        raise ValueError("temporary credentials")
    if not HEX_64.fullmatch(parent_secret_access_key or ""):
        raise ValueError("parent secret access key")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("current time")
    try:
        framed = base64.b64decode(
            credentials.session_token, validate=True).decode()
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("session token") from error
    if not framed.startswith("jwt/"):
        raise ValueError("session token")
    jwt = framed[4:]
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("session token")
    unsigned = ".".join(parts[:2])
    expected = hmac.new(
        parent_secret_access_key.encode(),
        unsigned.encode(),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(_unb64url(parts[2]), expected):
        raise ValueError("session token signature")
    header = _document(_unb64url(parts[0]), "JWT header")
    claims = _document(_unb64url(parts[1]), "JWT claims")
    if header != {"alg": "HS256", "typ": "JWT"}:
        raise ValueError("JWT header")
    required = {
        "actions", "aud", "bucket", "exp", "iat", "iss",
        "paths", "scope", "sub",
    }
    if set(claims) != required:
        raise ValueError("JWT claims")
    if claims["actions"] != [ACTION] \
            or claims["scope"] != SCOPE:
        raise ValueError("temporary credential action")
    paths = claims["paths"]
    if not isinstance(paths, dict) or set(paths) != {
            "objectPaths", "prefixPaths"} \
            or paths["prefixPaths"] != [] \
            or not isinstance(paths["objectPaths"], list) \
            or len(paths["objectPaths"]) != 1 \
            or not isinstance(paths["objectPaths"][0], str):
        raise ValueError("temporary credential path")
    if claims["bucket"] != deployment.ingress_bucket \
            or claims["sub"] != deployment.account_id \
            or claims["aud"] != endpoint_host(deployment):
        raise ValueError("temporary credential deployment")
    if claims["iss"] != credentials.access_key_id \
            or not HEX_32.fullmatch(claims["iss"] or ""):
        raise ValueError("temporary credential issuer")
    issued = claims["iat"]
    expires = claims["exp"]
    if not isinstance(issued, int) or isinstance(issued, bool) \
            or not isinstance(expires, int) or isinstance(expires, bool) \
            or not 0 < expires - issued <= deployment.child_ttl_seconds \
            or now < issued or now >= expires:
        raise ValueError("temporary credential expiry")
    if credentials.endpoint != deployment.endpoint \
            or credentials.bucket != claims["bucket"] \
            or credentials.key != paths["objectPaths"][0] \
            or credentials.expires_at != expires \
            or credentials.secret_access_key != hashlib.sha256(
                jwt.encode()).hexdigest():
        raise ValueError("temporary credential wire fields")
    return UploadAuthority(
        account_id=claims["sub"],
        issuer=claims["iss"],
        audience=claims["aud"],
        bucket=claims["bucket"],
        key=paths["objectPaths"][0],
        issued_at=issued,
        expires_at=expires,
    )
