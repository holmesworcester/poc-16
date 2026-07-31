"""Read-authorized broker for one exact direct-to-bucket pile.

``OPEN`` pins current upload authority and returns one exact create-only PUT.
After the client performs that PUT, ``FINALIZE`` verifies the same cursor and
privately invokes the database-free RepositoryApplier with its fixed key.
"""
from dataclasses import dataclass
import secrets
from urllib.parse import urlsplit

from core.fact import canon
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
from core.ingress import SESSION_HEX_CHARS, ingress_key
from deploy.repository_apply_wire import decode_apply_result
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
SESSION_BYTES = SESSION_HEX_CHARS // 2
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
class AuthorizedPilePut:
    """One exact pile PUT derived only from an authenticated lease."""

    workspace: str
    member: str
    session: str
    digest: str
    size: int
    not_after_ms: int

    @property
    def key(self):
        return ingress_key(
            self.workspace, self.session, self.member, self.digest)


def _wire_size(value):
    try:
        return len(value.encode("utf-8"))
    except (AttributeError, UnicodeError) as error:
        raise UploadUnavailable("provider signer returned non-text authority") \
            from error


def _checked_capability(value, trusted_now, session_expires_at):
    parsed = urlsplit(value.url) \
        if isinstance(value, wire.UploadCapability) \
        and isinstance(value.url, str) else None
    if parsed is None or parsed.scheme != "https" or not parsed.hostname \
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
    try:
        encoded = canon(wire.capability_document(value))
    except (TypeError, ValueError) as error:
        raise UploadUnavailable(
            "provider signer returned an invalid request") from error
    if len(encoded) > MAX_CAPABILITY_DOCUMENT_BYTES:
        raise UploadUnavailable("provider capability exceeds wire limit")
    return value


class UploadBroker:
    """Attenuate current member authority to one pile PUT and exact poke."""

    def __init__(
            self, store, workspace, signer, now, session_policy, *,
            apply_exact, nonce=secrets.token_bytes,
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
                or not callable(apply_exact):
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
        return public

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
        put = AuthorizedPilePut(
            state.workspace,
            state.member,
            state.session,
            leaf.digest,
            leaf.size,
            state.expires_at_ms,
        )
        try:
            capability = self.signer.sign(put)
        except Exception as error:
            raise UploadUnavailable("provider signing failed") from error
        return _checked_capability(
            capability, trusted_now, state.expires_at_ms)

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
        return result

    async def finalize(self, cursor):
        """Invoke the private Applier for the exact pile fixed by ``OPEN``."""
        state = self.tokens.decode(cursor, self._now())
        if state.workspace != self.workspace:
            raise InvalidUploadSession("upload cursor workspace")
        key = ingress_key(
            state.workspace,
            state.session,
            state.member,
            state.pile.digest,
        )
        try:
            response = await self.apply_exact(key, state.pile.digest)
            status = decode_apply_result(response)
        except Exception as error:
            raise UploadUnavailable("private Applier unavailable") from error
        return wire.FinalizedUpload(status)


__all__ = (
    "AuthorizedPilePut",
    "UploadBroker",
    "UploadUnavailable",
)
