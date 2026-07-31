"""Read-authorized broker for one exact direct-to-bucket pile.

``OPEN`` pins current upload authority and returns one exact create-only PUT.
After the client performs that PUT, ``FINALIZE`` verifies the same cursor and
privately invokes the database-free RepositoryApplier with its fixed key.
"""
from dataclasses import dataclass
import inspect
import json
import secrets
from urllib.parse import urlsplit

from core.limits import (
    MAX_MINT_FETCH_BYTES,
    MAX_MINT_FETCHES,
    MAX_MINT_REQUEST_BYTES,
    MAX_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    PayloadTooLarge,
)
from core.repository_reader import RepositoryReader, RepositoryRootError
from core.shape import valid_fid
from core.staged_intent import SESSION_HEX_BYTES, staging_key
import deploy.upload_wire as wire
from deploy.upload_session import (
    InvalidUploadSession,
    SessionState,
    SessionTokenCodec,
    UploadLeaf,
    UploadSessionPolicy,
    valid_leaf,
    valid_provider_binding,
)


UPLOAD_PURPOSE = "upload"
SESSION_BYTES = SESSION_HEX_BYTES // 2
MAX_CAPABILITY_URL_BYTES = 2_048
MAX_CAPABILITY_QUERY_BYTES = 1_536
MAX_CAPABILITY_HEADERS = 16
MAX_CAPABILITY_HEADER_NAME_BYTES = 64
MAX_CAPABILITY_HEADER_VALUE_BYTES = 512
MAX_CAPABILITY_HEADER_BYTES = 2_048
MAX_CAPABILITY_DOCUMENT_BYTES = 1_536


class UploadUnavailable(RuntimeError):
    """The authenticated snapshot, signer, or private Applier is unavailable."""


@dataclass(frozen=True, slots=True)
class AuthorizedPut:
    """One exact provider PUT derived only from an authenticated lease."""

    workspace: str
    member: str
    session: str
    object_class: str
    digest: str
    size: int
    content_type: str
    key: str
    not_after_ms: int


def _wire_size(value):
    try:
        return len(value.encode("utf-8"))
    except (AttributeError, UnicodeError) as error:
        raise UploadUnavailable("provider signer returned non-text authority") \
            from error


def _capability_document(value):
    return {
        "expires_at_ms": value.expires_at_ms,
        "headers": dict(value.headers),
        "method": value.method,
        "url": value.url,
    }


def _bounded_document(value, maximum, label):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > maximum:
        raise UploadUnavailable(f"{label} exceeds wire limit")
    return encoded


def _checked_capability(value, trusted_now, session_expires_at):
    parsed = urlsplit(value.url) \
        if isinstance(value, wire.UploadCapability) \
        and isinstance(value.url, str) else None
    if parsed is None or value.method != "PUT" \
            or parsed.scheme != "https" or not parsed.hostname \
            or parsed.username is not None or parsed.password is not None \
            or parsed.fragment \
            or _wire_size(value.url) > MAX_CAPABILITY_URL_BYTES \
            or _wire_size(parsed.query) > MAX_CAPABILITY_QUERY_BYTES \
            or type(value.expires_at_ms) is not int \
            or not trusted_now < value.expires_at_ms <= session_expires_at \
            or not isinstance(value.headers, tuple) \
            or len(value.headers) > MAX_CAPABILITY_HEADERS:
        raise UploadUnavailable("provider signer returned an invalid request")
    names, header_bytes = [], 0
    for pair in value.headers:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise UploadUnavailable("provider signer returned invalid headers")
        name, header = pair
        if not isinstance(name, str) or name != name.lower() or not name \
                or not isinstance(header, str) \
                or _wire_size(name) > MAX_CAPABILITY_HEADER_NAME_BYTES \
                or _wire_size(header) > MAX_CAPABILITY_HEADER_VALUE_BYTES:
            raise UploadUnavailable("provider signer returned invalid headers")
        names.append(name)
        header_bytes += _wire_size(name) + _wire_size(header)
    if header_bytes > MAX_CAPABILITY_HEADER_BYTES \
            or names != sorted(names) or len(names) != len(set(names)):
        raise UploadUnavailable("provider signer returned ambiguous headers")
    _bounded_document(
        _capability_document(value),
        MAX_CAPABILITY_DOCUMENT_BYTES,
        "provider capability",
    )
    return value


def _grant_document(grant):
    return {
        "digest": grant.leaf.digest,
        "put": _capability_document(grant.capability),
        "size": grant.leaf.size,
    }


def open_document(result):
    if not isinstance(result, wire.OpenedUpload):
        raise TypeError("opened upload")
    return {
        "cursor": result.cursor,
        "expires_at_ms": result.expires_at_ms,
        "pile": _grant_document(result.pile),
        "schema": wire.OPEN_RESPONSE_SCHEMA,
        "session": result.session,
    }


def finalize_document(result):
    if not isinstance(result, wire.FinalizedUpload):
        raise TypeError("finalized upload")
    return {
        "schema": wire.FINALIZE_RESPONSE_SCHEMA,
        "status": result.status,
    }


def encode_open(result):
    return _bounded_document(
        open_document(result), wire.MAX_OPEN_RESPONSE_BYTES, "OPEN response")


def encode_finalize(result):
    return _bounded_document(
        finalize_document(result),
        wire.MAX_FINALIZE_RESPONSE_BYTES,
        "FINALIZE response",
    )


def _final_status(value):
    status = value if isinstance(value, str) else getattr(value, "status", None)
    if status is None:
        nested = getattr(value, "result", None)
        status = getattr(nested, "status", None)
    if status in {"applied", "admitted", "confirmed"}:
        return "applied"
    if status == "noop":
        return "noop"
    if status in {"rejected", "rejected-staging"}:
        return "rejected"
    if status in {"retryable", "missing", "rootless", "stale"}:
        return "retryable"
    raise UploadUnavailable("private Applier returned an invalid result")


class UploadBroker:
    """Attenuate current member authority to one pile PUT and exact poke."""

    def __init__(
            self, store, workspace, signer, now, session_policy, *,
            apply_exact=None, nonce=secrets.token_bytes,
            max_mint_fetches=MAX_MINT_FETCHES,
            max_mint_fetch_bytes=MAX_MINT_FETCH_BYTES):
        provider = getattr(signer, "provider_binding", None)
        if not valid_fid(workspace):
            raise ValueError("workspace")
        if not callable(getattr(store, "get_bounded", None)) \
                or not callable(getattr(signer, "sign", None)) \
                or not valid_provider_binding(provider) \
                or not callable(now) or not callable(nonce) \
                or not isinstance(session_policy, UploadSessionPolicy) \
                or apply_exact is not None and not callable(apply_exact):
            raise ValueError("upload broker dependency")
        if type(max_mint_fetches) is not int \
                or not 0 <= max_mint_fetches <= MAX_MINT_FETCHES \
                or type(max_mint_fetch_bytes) is not int \
                or not 0 <= max_mint_fetch_bytes <= MAX_MINT_FETCH_BYTES:
            raise ValueError("upload broker limit")
        self.store, self.workspace, self.signer = store, workspace, signer
        self.now, self.nonce, self.apply_exact = now, nonce, apply_exact
        self.session_policy = session_policy
        self.tokens = SessionTokenCodec(session_policy, provider)
        self.max_mint_fetches = max_mint_fetches
        self.max_mint_fetch_bytes = max_mint_fetch_bytes

    def _now(self):
        value = self.now()
        if type(value) is not int or value < 0:
            raise UploadUnavailable("trusted clock")
        return value

    async def _get(self, key, maximum):
        value = await self.store.get_bounded(key, maximum)
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
        except Exception as error:
            raise UploadUnavailable("workspace root unavailable") from error
        if not root:
            raise UploadUnavailable("workspace root unavailable")
        fetch_error = None

        async def fetch(oid):
            nonlocal fetch_error
            try:
                return await self._get(
                    "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES)
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
            raise UploadUnavailable("workspace root unavailable") from error
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

    def _new_session(self):
        try:
            raw = self.nonce(SESSION_BYTES)
        except Exception as error:
            raise UploadUnavailable("session nonce") from error
        if not isinstance(raw, bytes) or len(raw) != SESSION_BYTES:
            raise UploadUnavailable("session nonce")
        return raw.hex()

    def _sign(self, state, trusted_now):
        leaf = state.pile
        put = AuthorizedPut(
            state.workspace,
            state.member,
            state.session,
            "pile",
            leaf.digest,
            leaf.size,
            wire.UPLOAD_CONTENT_TYPE,
            staging_key(
                state.workspace,
                state.member,
                state.session,
                "pile",
                leaf.digest,
            ),
            state.expires_at_ms,
        )
        try:
            capability = self.signer.sign(put)
        except Exception as error:
            raise UploadUnavailable("provider signing failed") from error
        return wire.GrantedUpload(
            leaf,
            _checked_capability(
                capability, trusted_now, state.expires_at_ms),
        )

    async def open(self, proof, pile):
        """Pin current authority and return the sole exact PUT capability."""
        policy = self.session_policy
        if not valid_leaf(pile, maximum=policy.max_bytes) \
                or pile.size > MAX_PILE_BYTES:
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
            pile,
            trusted_now,
            expires_at_ms,
            key.key_id,
        )
        result = wire.OpenedUpload(
            state.session,
            self.tokens.encode(state),
            self._sign(state, trusted_now),
            state.expires_at_ms,
        )
        encode_open(result)
        return result

    async def finalize(self, cursor):
        """Invoke the private Applier for the exact pile fixed by ``OPEN``."""
        state = self.tokens.decode(cursor, self._now())
        if state.workspace != self.workspace:
            raise InvalidUploadSession("upload cursor workspace")
        if self.apply_exact is None:
            raise UploadUnavailable("private Applier unavailable")
        key = staging_key(
            state.workspace,
            state.member,
            state.session,
            "pile",
            state.pile.digest,
        )
        try:
            value = self.apply_exact(key, state.pile.digest)
            if inspect.isawaitable(value):
                value = await value
        except Exception as error:
            raise UploadUnavailable("private Applier unavailable") from error
        result = wire.FinalizedUpload(_final_status(value))
        encode_finalize(result)
        return result


__all__ = (
    "AuthorizedPut",
    "UploadBroker",
    "UploadUnavailable",
    "encode_finalize",
    "encode_open",
    "finalize_document",
    "open_document",
)
