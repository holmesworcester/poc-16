"""One fixed-expiry authorization for one exact staged pile.

The broker authenticates the uploader once, then signs this bounded cursor.
The cursor can authorize only the exact create-only pile PUT and the matching
``FINALIZE`` poke.  It is not repository admission authority.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import re

from core.fact import canon
from core.limits import MAX_PILE_BYTES, decode_json
from core.shape import valid_fid
from core.staged_intent import MEMBER_HEX_BYTES, SESSION_HEX_BYTES


PROTOCOL_VERSION = 2
MAX_SESSION_BYTES = MAX_PILE_BYTES
MAX_SESSION_TTL_MS = 24 * 60 * 60 * 1000
MAX_SESSION_CLOCK_SKEW_MS = 5 * 60 * 1000
MAX_CURSOR_BYTES = 2_048

_SCHEMA = "poc16-upload-cursor-v2"
_TOKEN_DOMAIN = b"poc16-upload-cursor-v2\0"
_ISSUER_DOMAIN = b"poc16-upload-issuer-v2\0"
_PROVIDER_DOMAIN = b"poc16-upload-provider-v2\0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{8}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]+$")
_U64_MAX = (1 << 64) - 1


class InvalidUploadSession(ValueError):
    """Untrusted upload metadata or cursor is not admissible."""


@dataclass(frozen=True, slots=True)
class UploadLeaf:
    """The exact staged pile body fixed by one lease."""

    digest: str
    size: int

    def __post_init__(self):
        if not valid_fid(self.digest) \
                or type(self.size) is not int \
                or not 0 <= self.size <= MAX_PILE_BYTES:
            raise ValueError("upload pile")


@dataclass(frozen=True, slots=True)
class SessionKey:
    """One rotation-bounded HMAC key."""

    key_id: str
    secret: bytes = field(repr=False)
    issue_from_ms: int
    verify_until_ms: int

    def __post_init__(self):
        if not isinstance(self.key_id, str) \
                or _KEY_ID.fullmatch(self.key_id) is None \
                or not isinstance(self.secret, bytes) \
                or len(self.secret) != 32 \
                or not _uint(self.issue_from_ms, _U64_MAX) \
                or not _uint(self.verify_until_ms, _U64_MAX) \
                or self.issue_from_ms >= self.verify_until_ms:
            raise ValueError("upload session key")


@dataclass(frozen=True, slots=True)
class UploadSessionPolicy:
    """Issuer, rotation keys, and the maximum lifetime of one pile lease."""

    issuer: str
    active_key_id: str
    keys: tuple[SessionKey, ...]
    ttl_ms: int = MAX_SESSION_TTL_MS
    max_ttl_ms: int = MAX_SESSION_TTL_MS
    clock_skew_ms: int = MAX_SESSION_CLOCK_SKEW_MS
    max_bytes: int = MAX_SESSION_BYTES

    def __post_init__(self):
        key_ids = {
            key.key_id for key in self.keys
            if isinstance(key, SessionKey)
        } if isinstance(self.keys, tuple) else set()
        if not _valid_identifier(self.issuer) \
                or not isinstance(self.keys, tuple) or not self.keys \
                or len(key_ids) != len(self.keys) \
                or self.active_key_id not in key_ids \
                or not _uint(self.ttl_ms, MAX_SESSION_TTL_MS) \
                or self.ttl_ms == 0 \
                or not _uint(self.max_ttl_ms, MAX_SESSION_TTL_MS) \
                or not self.ttl_ms <= self.max_ttl_ms \
                or not _uint(
                    self.clock_skew_ms, MAX_SESSION_CLOCK_SKEW_MS) \
                or not _uint(self.max_bytes, MAX_SESSION_BYTES) \
                or self.max_bytes == 0:
            raise ValueError("upload session policy")

    def key(self, key_id):
        for key in self.keys:
            if key.key_id == key_id:
                return key
        raise InvalidUploadSession("upload cursor key")


@dataclass(frozen=True, slots=True)
class SessionState:
    workspace: str
    member: str
    session: str
    pile: UploadLeaf
    issued_at_ms: int
    expires_at_ms: int
    key_id: str


def _uint(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _lower_hex(value, length):
    return isinstance(value, str) and len(value) == length \
        and all(character in "0123456789abcdef" for character in value)


def _valid_identifier(value):
    return isinstance(value, str) \
        and len(value.encode("ascii", errors="ignore")) == len(value) \
        and _IDENTIFIER.fullmatch(value) is not None


def valid_provider_binding(value):
    return _valid_identifier(value)


def valid_leaf(value, *, maximum=MAX_PILE_BYTES):
    return isinstance(value, UploadLeaf) \
        and value.size <= maximum


def valid_cursor(value):
    return isinstance(value, str) \
        and 1 <= len(value) <= MAX_CURSOR_BYTES \
        and value.isascii() \
        and _TOKEN.fullmatch(value) is not None


def _hash(domain, value):
    return hashlib.sha256(domain + value.encode("ascii")).hexdigest()


class SessionTokenCodec:
    """Encode and verify one exact-pile lease with no server-side state."""

    def __init__(self, policy, provider_binding):
        if not isinstance(policy, UploadSessionPolicy) \
                or not valid_provider_binding(provider_binding):
            raise ValueError("upload cursor configuration")
        self.policy = policy
        self.provider_binding = provider_binding
        self._issuer = _hash(_ISSUER_DOMAIN, policy.issuer)
        self._provider = _hash(_PROVIDER_DOMAIN, provider_binding)

    def _document(self, state):
        self._validate_state(state)
        return {
            "digest": state.pile.digest,
            "expires_at_ms": state.expires_at_ms,
            "issued_at_ms": state.issued_at_ms,
            "issuer": self._issuer,
            "key_id": state.key_id,
            "member": state.member,
            "provider": self._provider,
            "schema": _SCHEMA,
            "session": state.session,
            "size": state.pile.size,
            "workspace": state.workspace,
        }

    def _validate_state(self, state):
        if not isinstance(state, SessionState) \
                or not valid_fid(state.workspace) \
                or not _lower_hex(state.member, MEMBER_HEX_BYTES) \
                or not _lower_hex(state.session, SESSION_HEX_BYTES) \
                or not valid_leaf(
                    state.pile, maximum=self.policy.max_bytes) \
                or not _uint(state.issued_at_ms, _U64_MAX) \
                or not _uint(state.expires_at_ms, _U64_MAX) \
                or not 0 < state.expires_at_ms - state.issued_at_ms \
                <= self.policy.max_ttl_ms \
                or state.key_id not in {
                    key.key_id for key in self.policy.keys
                }:
            raise InvalidUploadSession("upload cursor state")

    def encode(self, state):
        payload = canon(self._document(state))
        key = self.policy.key(state.key_id)
        mac = hmac.new(
            key.secret, _TOKEN_DOMAIN + payload, hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(
            payload + mac).rstrip(b"=").decode("ascii")
        if not valid_cursor(token):
            raise InvalidUploadSession("upload cursor size")
        return token

    def decode(self, token, trusted_now):
        if not valid_cursor(token) or not _uint(trusted_now, _U64_MAX):
            raise InvalidUploadSession("upload cursor")
        try:
            raw = base64.b64decode(
                token + "=" * (-len(token) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (TypeError, ValueError) as error:
            raise InvalidUploadSession("upload cursor") from error
        if len(raw) <= 32 or len(raw) > MAX_CURSOR_BYTES \
                or base64.urlsafe_b64encode(raw).rstrip(
                    b"=").decode("ascii") != token:
            raise InvalidUploadSession("upload cursor")
        payload, presented = raw[:-32], raw[-32:]
        try:
            value = decode_json(payload, MAX_CURSOR_BYTES, "upload cursor")
            if canon(value) != payload or not isinstance(value, dict) \
                    or set(value) != {
                        "digest", "expires_at_ms", "issued_at_ms", "issuer",
                        "key_id", "member", "provider", "schema", "session",
                        "size", "workspace",
                    } \
                    or value["schema"] != _SCHEMA:
                raise ValueError
            key = self.policy.key(value["key_id"])
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidUploadSession("upload cursor") from error
        expected = hmac.new(
            key.secret, _TOKEN_DOMAIN + payload, hashlib.sha256).digest()
        if not hmac.compare_digest(presented, expected):
            raise InvalidUploadSession("upload cursor")
        try:
            state = SessionState(
                value["workspace"],
                value["member"],
                value["session"],
                UploadLeaf(value["digest"], value["size"]),
                value["issued_at_ms"],
                value["expires_at_ms"],
                value["key_id"],
            )
            self._validate_state(state)
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidUploadSession("upload cursor") from error
        if value["issuer"] != self._issuer \
                or value["provider"] != self._provider \
                or state.issued_at_ms < key.issue_from_ms \
                or state.expires_at_ms + self.policy.clock_skew_ms \
                > key.verify_until_ms \
                or not state.issued_at_ms <= trusted_now \
                < state.expires_at_ms:
            raise InvalidUploadSession("upload cursor")
        return state


__all__ = (
    "InvalidUploadSession",
    "MAX_CURSOR_BYTES",
    "MAX_SESSION_BYTES",
    "MAX_SESSION_CLOCK_SKEW_MS",
    "MAX_SESSION_TTL_MS",
    "PROTOCOL_VERSION",
    "SessionKey",
    "SessionState",
    "SessionTokenCodec",
    "UploadLeaf",
    "UploadSessionPolicy",
    "valid_cursor",
    "valid_leaf",
    "valid_provider_binding",
)
