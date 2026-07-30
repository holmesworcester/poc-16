"""Kernel-authorized, provider-neutral direct-upload session broker.

``OPEN`` judges one upload-purpose fact closure and fixes a finite manifest.
``ISSUE`` verifies only a bounded contiguous slice and attenuates it to exact
provider PUT requests. ``FINALIZE`` can name only the pile fixed by ``OPEN``.
The HMAC cursor is the complete broker state; file and pile bytes never cross
this module.
"""
from dataclasses import dataclass, field, replace
from itertools import islice
import json
import secrets
from urllib.parse import urlsplit

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
from core.repository_reader import RepositoryReader, RepositoryRootError
from core.staged_intent import (
    SESSION_HEX_BYTES,
    staging_key,
)
from deploy.upload_session import (
    InvalidUploadSession,
    SessionState,
    SessionTokenCodec,
    UploadLeaf,
    UploadManifest,
    UploadSessionPolicy,
    UploadVector,
    valid_leaf,
    valid_manifest,
    valid_provider_binding,
    verify_range,
)


UPLOAD_PURPOSE = "upload"
UPLOAD_CONTENT_TYPE = "application/octet-stream"
SESSION_BYTES = SESSION_HEX_BYTES // 2

MAX_CAPABILITY_URL_BYTES = 2_048
MAX_CAPABILITY_QUERY_BYTES = 1_536
MAX_CAPABILITY_HEADERS = 16
MAX_CAPABILITY_HEADER_NAME_BYTES = 64
MAX_CAPABILITY_HEADER_VALUE_BYTES = 512
MAX_CAPABILITY_HEADER_BYTES = 2_048
MAX_CAPABILITY_DOCUMENT_BYTES = 1_536
MAX_OPEN_RESPONSE_BYTES = 2_048
MAX_ISSUE_RESPONSE_BYTES = 512 * 1024
MAX_FINALIZE_RESPONSE_BYTES = 4_096

_EMPTY_MANIFEST = UploadVector(()).manifest


class UploadUnavailable(RuntimeError):
    """The authenticated snapshot or provider signer is unavailable."""


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
    not_after_ms: int


@dataclass(frozen=True)
class UploadCapability:
    """The exact provider request a client may perform.

    Bearer material remains inside ``url`` and the signed headers. No bucket
    credential or semantic path input crosses this interface.
    """

    method: str
    url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    expires_at_ms: int


@dataclass(frozen=True)
class GrantedUpload:
    leaf: UploadLeaf
    capability: UploadCapability


@dataclass(frozen=True)
class OpenedUpload:
    session: str
    cursor: str
    expires_at_ms: int


@dataclass(frozen=True)
class IssuedUpload:
    cursor: str
    next_index: int
    objects: tuple[GrantedUpload, ...]
    expires_at_ms: int


@dataclass(frozen=True)
class FinalizedUpload:
    cursor: str
    pile: GrantedUpload
    expires_at_ms: int


def _wire_size(value):
    try:
        return len(value.encode("utf-8"))
    except (AttributeError, UnicodeError) as error:
        raise UploadUnavailable(
            "provider signer returned non-text authority") from error


def _capability_document(capability):
    return {
        "expires_at_ms": capability.expires_at_ms,
        "headers": dict(capability.headers),
        "method": capability.method,
        "url": capability.url,
    }


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode()


def _bounded_document(value, maximum, label):
    encoded = _canonical(value)
    if len(encoded) > maximum:
        raise UploadUnavailable(f"{label} exceeds wire limit")
    return encoded


def _checked_capability(value, trusted_now, session_expires_at):
    parsed = urlsplit(value.url) \
        if isinstance(value, UploadCapability) \
        and isinstance(value.url, str) else None
    if not isinstance(value, UploadCapability) \
            or value.method != "PUT" \
            or parsed is None \
            or parsed.scheme != "https" or not parsed.hostname \
            or parsed.username is not None or parsed.password is not None \
            or parsed.fragment \
            or _wire_size(value.url) > MAX_CAPABILITY_URL_BYTES \
            or _wire_size(parsed.query) > MAX_CAPABILITY_QUERY_BYTES \
            or type(value.expires_at_ms) is not int \
            or not trusted_now < value.expires_at_ms \
            <= session_expires_at \
            or not isinstance(value.headers, tuple) \
            or len(value.headers) > MAX_CAPABILITY_HEADERS:
        raise UploadUnavailable("provider signer returned an invalid request")
    names = []
    header_bytes = 0
    for pair in value.headers:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise UploadUnavailable(
                "provider signer returned invalid headers")
        name, header_value = pair
        if not isinstance(name, str) or name != name.lower() \
                or not name or not isinstance(header_value, str) \
                or _wire_size(name) > MAX_CAPABILITY_HEADER_NAME_BYTES \
                or _wire_size(
                    header_value) > MAX_CAPABILITY_HEADER_VALUE_BYTES:
            raise UploadUnavailable(
                "provider signer returned invalid headers")
        names.append(name)
        header_bytes += _wire_size(name) + _wire_size(header_value)
    if header_bytes > MAX_CAPABILITY_HEADER_BYTES \
            or len(names) != len(set(names)) or names != sorted(names):
        raise UploadUnavailable(
            "provider signer returned ambiguous headers")
    _bounded_document(
        _capability_document(value),
        MAX_CAPABILITY_DOCUMENT_BYTES,
        "provider capability",
    )
    return value


def _granted_document(grant):
    return {
        "digest": grant.leaf.digest,
        "put": _capability_document(grant.capability),
        "size": grant.leaf.size,
    }


def open_document(result):
    if not isinstance(result, OpenedUpload):
        raise TypeError("opened upload")
    return {
        "cursor": result.cursor,
        "expires_at_ms": result.expires_at_ms,
        "schema": "poc16-upload-open-v1",
        "session": result.session,
    }


def issue_document(result):
    if not isinstance(result, IssuedUpload):
        raise TypeError("issued upload")
    return {
        "cursor": result.cursor,
        "expires_at_ms": result.expires_at_ms,
        "next_index": result.next_index,
        "objects": [
            _granted_document(grant) for grant in result.objects],
        "schema": "poc16-upload-issue-v1",
    }


def finalize_document(result):
    if not isinstance(result, FinalizedUpload):
        raise TypeError("finalized upload")
    return {
        "cursor": result.cursor,
        "expires_at_ms": result.expires_at_ms,
        "pile": _granted_document(result.pile),
        "schema": "poc16-upload-finalize-v1",
    }


def encode_open(result):
    return _bounded_document(
        open_document(result), MAX_OPEN_RESPONSE_BYTES, "OPEN response")


def encode_issue(result):
    return _bounded_document(
        issue_document(result), MAX_ISSUE_RESPONSE_BYTES, "ISSUE response")


def encode_finalize(result):
    return _bounded_document(
        finalize_document(result),
        MAX_FINALIZE_RESPONSE_BYTES,
        "FINALIZE response",
    )


class UploadBroker:
    """Authorize a finite, resumable objects-first upload session."""

    def __init__(
            self, store, workspace, signer, now, session_policy, *,
            nonce=secrets.token_bytes,
            max_mint_fetches=MAX_MINT_FETCHES,
            max_mint_fetch_bytes=MAX_MINT_FETCH_BYTES):
        provider = getattr(signer, "provider_binding", None)
        if not valid_fid(workspace):
            raise ValueError("workspace")
        if not callable(getattr(store, "get", None)) \
                or not callable(getattr(signer, "sign", None)) \
                or not valid_provider_binding(provider) \
                or not callable(now) or not callable(nonce) \
                or not isinstance(session_policy, UploadSessionPolicy):
            raise ValueError("upload broker dependency")
        if type(max_mint_fetches) is not int \
                or not 0 <= max_mint_fetches <= MAX_MINT_FETCHES \
                or type(max_mint_fetch_bytes) is not int \
                or not 0 <= max_mint_fetch_bytes <= MAX_MINT_FETCH_BYTES:
            raise ValueError("upload broker limit")
        self.store = store
        self.workspace = workspace
        self.signer = signer
        self.now = now
        self.nonce = nonce
        self.session_policy = session_policy
        self.tokens = SessionTokenCodec(session_policy, provider)
        self.max_mint_fetches = max_mint_fetches
        self.max_mint_fetch_bytes = max_mint_fetch_bytes

    def _now(self):
        trusted_now = self.now()
        if type(trusted_now) is not int or trusted_now < 0:
            raise UploadUnavailable("trusted clock")
        return trusted_now

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
            raise InvalidUploadSession("upload authorization")
        try:
            root = await self._get("root", MAX_ROOT_BYTES)
            if not root:
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
            grant = await RepositoryReader.mint_awaited(
                self.workspace,
                root,
                fetch,
                proof,
                trusted_now,
                max_unique_fetches=self.max_mint_fetches,
                max_fetch_bytes=self.max_mint_fetch_bytes,
                purpose=UPLOAD_PURPOSE,
            )
        except RepositoryRootError as error:
            raise UploadUnavailable(
                "workspace root unavailable") from error
        except Exception as error:
            if fetch_error is not None:
                raise UploadUnavailable(
                    "authorization object unavailable") from fetch_error
            raise UploadUnavailable("upload authorization failed") from error
        if fetch_error is not None:
            raise UploadUnavailable(
                "authorization object unavailable") from fetch_error
        if not isinstance(grant, tuple) or len(grant) != 2:
            raise InvalidUploadSession("upload authorization")
        public, purpose = grant
        if purpose != UPLOAD_PURPOSE or not valid_fid(public):
            raise InvalidUploadSession("upload authorization")
        return public[:16]

    def _state(self, cursor, trusted_now):
        state = self.tokens.decode(cursor, trusted_now)
        if state.workspace != self.workspace:
            raise InvalidUploadSession("upload cursor workspace")
        return state

    def _new_session(self):
        try:
            raw = self.nonce(SESSION_BYTES)
        except Exception as error:
            raise UploadUnavailable("session nonce") from error
        if not isinstance(raw, bytes) or len(raw) != SESSION_BYTES:
            raise UploadUnavailable("session nonce")
        return raw.hex()

    async def open(self, proof, upload_manifest, pile):
        """Authorize the closure and return an index-zero cursor, no PUTs."""
        policy = self.session_policy
        if not valid_manifest(
                upload_manifest,
                max_bytes=policy.max_bytes,
        ) \
                or not valid_leaf(pile) or pile.size > MAX_PILE_BYTES \
                or upload_manifest.total_bytes + pile.size \
                > policy.max_bytes \
                or upload_manifest.count == 0 \
                and upload_manifest != _EMPTY_MANIFEST:
            raise InvalidUploadSession("upload OPEN metadata")
        trusted_now = self._now()
        member = await self._authorize(proof, trusted_now)
        key = policy.key(policy.active_key_id)
        expires_at_ms = trusted_now + policy.ttl_ms
        if trusted_now < key.issue_from_ms \
                or expires_at_ms + policy.clock_skew_ms \
                > key.verify_until_ms:
            raise UploadUnavailable(
                "active upload session key has insufficient lifetime")
        state = SessionState(
            self.workspace,
            member,
            self._new_session(),
            upload_manifest,
            pile,
            0,
            0,
            None,
            trusted_now,
            expires_at_ms,
            key.key_id,
        )
        result = OpenedUpload(
            state.session,
            self.tokens.encode(state),
            expires_at_ms,
        )
        encode_open(result)
        return result

    def _sign(self, state, leaf, object_class, trusted_now):
        authorized = AuthorizedPut(
            state.workspace,
            state.member,
            state.session,
            object_class,
            leaf.digest,
            leaf.size,
            UPLOAD_CONTENT_TYPE,
            staging_key(
                state.workspace,
                state.member,
                state.session,
                object_class,
                leaf.digest,
            ),
            state.expires_at_ms,
        )
        try:
            capability = self.signer.sign(authorized)
        except Exception as error:
            raise UploadUnavailable("provider signing failed") from error
        return GrantedUpload(
            leaf,
            _checked_capability(
                capability, trusted_now, state.expires_at_ms),
        )

    def issue(self, cursor, start_index, leaves, proof):
        """Issue one verified prefix slice or reissue covered exact keys."""
        trusted_now = self._now()
        state = self._state(cursor, trusted_now)
        try:
            leaves = tuple(islice(iter(leaves), PAGE_BATCH + 1))
        except (TypeError, ValueError) as error:
            raise InvalidUploadSession("upload ISSUE leaves") from error
        if len(leaves) > PAGE_BATCH:
            raise InvalidUploadSession("upload ISSUE leaf count")
        leaves = verify_range(
            state.manifest, start_index, leaves, proof)
        end_index = start_index + len(leaves)
        if start_index > state.next_index:
            raise InvalidUploadSession("upload ISSUE gap")
        if start_index < state.next_index < end_index:
            raise InvalidUploadSession("upload ISSUE partial overlap")
        if end_index <= state.next_index:
            grants = tuple(
                self._sign(state, leaf, "obj", trusted_now)
                for leaf in leaves
            )
            result = IssuedUpload(
                cursor, state.next_index, grants, state.expires_at_ms)
            encode_issue(result)
            return result

        if start_index != state.next_index \
                or state.last_digest is not None \
                and leaves[0].digest <= state.last_digest:
            raise InvalidUploadSession("upload ISSUE ordering")
        issued_bytes = state.issued_bytes + sum(
            leaf.size for leaf in leaves)
        if issued_bytes > state.manifest.total_bytes \
                or end_index == state.manifest.count \
                and issued_bytes != state.manifest.total_bytes:
            raise InvalidUploadSession("upload ISSUE byte quota")
        advanced = replace(
            state,
            next_index=end_index,
            issued_bytes=issued_bytes,
            last_digest=leaves[-1].digest,
        )
        next_cursor = self.tokens.encode(advanced)
        grants = tuple(
            self._sign(state, leaf, "obj", trusted_now)
            for leaf in leaves
        )
        result = IssuedUpload(
            next_cursor, end_index, grants, state.expires_at_ms)
        encode_issue(result)
        return result

    def finalize(self, cursor):
        """Issue only the precommitted pile after the entire vector."""
        trusted_now = self._now()
        state = self._state(cursor, trusted_now)
        if state.next_index != state.manifest.count \
                or state.issued_bytes != state.manifest.total_bytes:
            raise InvalidUploadSession("upload FINALIZE incomplete")
        result = FinalizedUpload(
            cursor,
            self._sign(state, state.pile, "pile", trusted_now),
            state.expires_at_ms,
        )
        encode_finalize(result)
        return result
