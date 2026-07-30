"""Provider-neutral direct-upload authorization and capability plans.

The broker has two deliberately separate doors:

* the existing signed fact closure is judged by ``core.mint`` for the
  endpoint-selected ``upload`` purpose;
* only then are untrusted descriptors attenuated to exact staging keys and
  handed to a provider signer.

Provider signers receive no proof bytes and perform no workspace policy.
Clients receive wire requests, not bucket credentials.
"""
from dataclasses import dataclass
from itertools import islice
import json
import secrets
from urllib.parse import urlsplit

from core import manifest, mint
from core.limits import (
    MAX_MINT_FETCH_BYTES,
    MAX_MINT_FETCHES,
    MAX_MINT_REQUEST_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PILE_BYTES,
    MAX_ROOT_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
)
from core.shape import valid_fid


UPLOAD_PURPOSE = "upload"
UPLOAD_CONTENT_TYPE = "application/octet-stream"
SESSION_BYTES = 16
SESSION_HEX_BYTES = 2 * SESSION_BYTES
STAGING_PREFIX = "ingress/v1"


class UploadUnavailable(RuntimeError):
    """The authenticated snapshot could not be read or signed safely."""


@dataclass(frozen=True)
class UploadDescriptor:
    """Untrusted requested upload metadata; never an authority claim."""

    workspace: str
    member: str
    object_class: str
    digest: str
    size: int
    content_type: str = UPLOAD_CONTENT_TYPE


@dataclass(frozen=True)
class AuthorizedPut:
    """One broker-derived semantic grant presented to a provider signer."""

    workspace: str
    member: str
    session: str
    object_class: str
    digest: str
    size: int
    content_type: str
    key: str


@dataclass(frozen=True)
class UploadCapability:
    """The provider-neutral HTTP request a client is allowed to perform.

    The bearer signature remains embedded in ``url``.  Semantic issuer fields
    are intentionally absent: the object store sees only an exact method,
    URL, headers, expiry, and body supplied later by the client.
    """

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    expires_at_ms: int


@dataclass(frozen=True)
class GrantedUpload:
    descriptor: UploadDescriptor
    capability: UploadCapability


@dataclass(frozen=True)
class UploadPlan:
    """Objects are ordered before the sole closed-pile ready marker."""

    session: str
    objects: tuple[GrantedUpload, ...]
    pile: GrantedUpload


def _valid_member(value):
    return isinstance(value, str) \
        and len(value) == 16 \
        and all(character in "0123456789abcdef" for character in value)


def _valid_session(value):
    return isinstance(value, str) \
        and len(value) == SESSION_HEX_BYTES \
        and all(character in "0123456789abcdef" for character in value)


def staging_key(
        workspace, member, session, object_class, digest):
    """Derive the one versioned isolated-ingress grammar."""
    if not valid_fid(workspace) or not _valid_member(member) \
            or not _valid_session(session) or not valid_fid(digest):
        raise ValueError("staging key component")
    base = (
        f"{STAGING_PREFIX}/workspaces/{workspace}/"
        f"sessions/{session}")
    if object_class == "obj":
        return f"{base}/obj/{digest}"
    if object_class == "pile":
        return f"{base}/pile/{member}/{digest}"
    raise ValueError("staging object class")


def _valid_descriptor(descriptor, workspace, member):
    if not isinstance(descriptor, UploadDescriptor) \
            or descriptor.workspace != workspace \
            or descriptor.member != member \
            or not valid_fid(descriptor.workspace) \
            or not _valid_member(descriptor.member) \
            or descriptor.object_class not in {"obj", "pile"} \
            or not valid_fid(descriptor.digest) \
            or type(descriptor.size) is not int \
            or descriptor.size < 0 \
            or descriptor.content_type != UPLOAD_CONTENT_TYPE:
        return False
    maximum = MAX_OBJECT_BYTES \
        if descriptor.object_class == "obj" else MAX_PILE_BYTES
    return descriptor.size <= maximum


def _checked_capability(value, trusted_now):
    parsed = urlsplit(value.url) \
        if isinstance(value, UploadCapability) \
        and isinstance(value.url, str) else None
    if not isinstance(value, UploadCapability) \
            or value.method != "PUT" \
            or parsed is None \
            or parsed.scheme != "https" or not parsed.hostname \
            or parsed.username is not None or parsed.password is not None \
            or parsed.fragment \
            or type(value.expires_at_ms) is not int \
            or value.expires_at_ms <= trusted_now \
            or not isinstance(value.headers, tuple):
        raise UploadUnavailable("provider signer returned an invalid request")
    names = []
    for name, header_value in value.headers:
        if not isinstance(name, str) or name != name.lower() \
                or not name or not isinstance(header_value, str):
            raise UploadUnavailable(
                "provider signer returned invalid headers")
        names.append(name)
    if len(names) != len(set(names)) or names != sorted(names):
        raise UploadUnavailable(
            "provider signer returned ambiguous headers")
    return value


def upload_plan_document(plan):
    """Return the stable provider-neutral client response shape."""
    if not isinstance(plan, UploadPlan):
        raise TypeError("upload plan")

    def granted(value):
        descriptor = value.descriptor
        capability = value.capability
        return {
            "content_type": descriptor.content_type,
            "digest": descriptor.digest,
            "put": {
                "expires_at_ms": capability.expires_at_ms,
                "headers": dict(capability.headers),
                "method": capability.method,
                "url": capability.url,
            },
            "size": descriptor.size,
        }

    return {
        "objects": [granted(value) for value in plan.objects],
        "pile": granted(plan.pile),
        "schema": "poc16-direct-upload-v1",
        "session": plan.session,
    }


def encode_upload_plan(plan):
    return json.dumps(
        upload_plan_document(plan),
        sort_keys=True, separators=(",", ":")).encode()


class UploadBroker:
    """Authorize one objects-first, closed-pile-last staging plan."""

    def __init__(
            self, store, workspace, signer, now, *,
            nonce=secrets.token_bytes,
            max_descriptors=PAGE_BATCH,
            max_mint_fetches=MAX_MINT_FETCHES,
            max_mint_fetch_bytes=MAX_MINT_FETCH_BYTES):
        if not valid_fid(workspace):
            raise ValueError("workspace")
        if not callable(getattr(store, "get", None)) \
                or not callable(getattr(signer, "sign", None)) \
                or not callable(now) or not callable(nonce):
            raise ValueError("upload broker dependency")
        if type(max_descriptors) is not int \
                or not 1 <= max_descriptors <= PAGE_BATCH \
                or type(max_mint_fetches) is not int \
                or not 0 <= max_mint_fetches <= MAX_MINT_FETCHES \
                or type(max_mint_fetch_bytes) is not int \
                or not 0 <= max_mint_fetch_bytes <= MAX_MINT_FETCH_BYTES:
            raise ValueError("upload broker limit")
        self.store = store
        self.workspace = workspace
        self.signer = signer
        self.now = now
        self.nonce = nonce
        self.max_descriptors = max_descriptors
        self.max_mint_fetches = max_mint_fetches
        self.max_mint_fetch_bytes = max_mint_fetch_bytes

    async def _get(self, key, maximum):
        bounded = getattr(self.store, "get_bounded", None)
        value = await bounded(key, maximum) \
            if callable(bounded) else await self.store.get(key)
        if value is not None and (
                not isinstance(value, bytes) or len(value) > maximum):
            raise PayloadTooLarge("upload broker read")
        return value

    async def _authorize(self, proof, trusted_now):
        if not isinstance(proof, bytes) \
                or len(proof) > MAX_MINT_REQUEST_BYTES:
            return None
        try:
            root = await self._get("root", MAX_ROOT_BYTES)
            if not root \
                    or manifest.decode_root(root).anchor != self.workspace:
                raise UploadUnavailable("workspace root unavailable")
        except UploadUnavailable:
            raise
        except Exception as error:
            raise UploadUnavailable("workspace root unavailable") from error

        fetch_error = None

        async def fetch(oid):
            nonlocal fetch_error
            try:
                return await self._get("obj/" + oid, MAX_OBJECT_BYTES)
            except Exception as error:
                fetch_error = error
                return None

        try:
            grant = await mint.async_stateless(
                proof, root, fetch, trusted_now,
                max_unique_fetches=self.max_mint_fetches,
                max_fetch_bytes=self.max_mint_fetch_bytes,
                purpose=UPLOAD_PURPOSE,
            )
        except Exception as error:
            if fetch_error is not None:
                raise UploadUnavailable(
                    "authorization object unavailable") from fetch_error
            raise UploadUnavailable("upload authorization failed") from error
        if fetch_error is not None:
            raise UploadUnavailable(
                "authorization object unavailable") from fetch_error
        return grant

    async def mint(self, proof, descriptors):
        """Return a plan, or ``None`` for malformed/unauthorized input."""
        try:
            descriptors = tuple(islice(
                iter(descriptors), self.max_descriptors + 1))
        except (TypeError, ValueError):
            return None
        if not 1 <= len(descriptors) <= self.max_descriptors:
            return None

        trusted_now = self.now()
        if type(trusted_now) is not int or trusted_now < 0:
            raise UploadUnavailable("trusted clock")
        grant = await self._authorize(proof, trusted_now)
        if grant is None:
            return None
        if not isinstance(grant, tuple) or len(grant) != 2:
            return None
        public, purpose = grant
        if purpose != UPLOAD_PURPOSE or not valid_fid(public):
            return None
        member = public[:16]

        if any(
                not _valid_descriptor(value, self.workspace, member)
                for value in descriptors) \
                or descriptors[-1].object_class != "pile" \
                or any(
                    value.object_class != "obj"
                    for value in descriptors[:-1]) \
                or len({
                    (value.object_class, value.digest)
                    for value in descriptors
                }) != len(descriptors):
            return None

        try:
            raw_session = self.nonce(SESSION_BYTES)
        except Exception as error:
            raise UploadUnavailable("session nonce") from error
        if not isinstance(raw_session, bytes) \
                or len(raw_session) != SESSION_BYTES:
            raise UploadUnavailable("session nonce")
        session = raw_session.hex()

        granted = []
        for descriptor in descriptors:
            authorized = AuthorizedPut(
                descriptor.workspace,
                descriptor.member,
                session,
                descriptor.object_class,
                descriptor.digest,
                descriptor.size,
                descriptor.content_type,
                staging_key(
                    descriptor.workspace,
                    descriptor.member,
                    session,
                    descriptor.object_class,
                    descriptor.digest,
                ),
            )
            try:
                capability = self.signer.sign(authorized)
            except Exception as error:
                raise UploadUnavailable(
                    "provider signing failed") from error
            granted.append(GrantedUpload(
                descriptor,
                _checked_capability(capability, trusted_now),
            ))
        return UploadPlan(
            session,
            tuple(granted[:-1]),
            granted[-1],
        )
