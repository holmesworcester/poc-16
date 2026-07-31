"""Stateless upload-session commitments, proofs, and authenticated cursors.

The broker sees at most one ``PAGE_BATCH`` slice of the client manifest at a
time.  A fixed Merkle vector confines every replay or fork to the same finite
set of ``(digest, size)`` leaves, while the HMAC cursor advances only a
validated prefix.  Neither construction is an object-store capability by
itself.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import hmac
from itertools import islice
import re
import struct

from core.limits import MAX_OBJECT_BYTES, PAGE_BATCH
from core.shape import valid_fid
from core.staged_intent import (
    MEMBER_HEX_BYTES,
    SESSION_HEX_BYTES,
)


PROTOCOL_VERSION = 1
MAX_SESSION_OBJECTS = 65_536
MAX_SESSION_BYTES = 1 << 40
MAX_SESSION_TTL_MS = 24 * 60 * 60 * 1000
MAX_SESSION_CLOCK_SKEW_MS = 5 * 60 * 1000
MAX_SESSION_DEPTH = 16
MAX_RANGE_PROOF_NODES = 2 * MAX_SESSION_DEPTH

_TOKEN_MAGIC = b"P16U"
_PROOF_MAGIC = b"P16P"
_TOKEN_MAC_DOMAIN = b"poc16-upload-cursor-mac-v1\0"
_ISSUER_DOMAIN = b"poc16-upload-issuer-v1\0"
_PROVIDER_DOMAIN = b"poc16-upload-provider-v1\0"
_LEAF_DOMAIN = b"poc16-upload-leaf-v1\0"
_PADDING_DOMAIN = b"poc16-upload-padding-v1\0"
_NODE_DOMAIN = b"poc16-upload-node-v1\0"
_ROOT_DOMAIN = b"poc16-upload-root-v1\0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{8}$")
_U64_MAX = (1 << 64) - 1
_MEMBER_BYTES = MEMBER_HEX_BYTES // 2
_SESSION_BYTES = SESSION_HEX_BYTES // 2

# magic, version, key id, issuer hash, provider hash, workspace, member,
# session, vector root, object count/bytes, pile digest/size, next index,
# issued bytes, last digest, issued time, and fixed expiry.
_TOKEN = struct.Struct(
    f">4sB8s32s32s32s{_MEMBER_BYTES}s{_SESSION_BYTES}s"
    "32sIQ32sQIQ32sQQ")
_PROOF_HEADER = struct.Struct(">4sBB")
TOKEN_RAW_BYTES = _TOKEN.size + hashlib.sha256().digest_size
TOKEN_BYTES = len(base64.urlsafe_b64encode(
    b"\0" * TOKEN_RAW_BYTES).rstrip(b"="))
MAX_RANGE_PROOF_BYTES = (
    _PROOF_HEADER.size + 32 * MAX_RANGE_PROOF_NODES)


class InvalidUploadSession(ValueError):
    """Untrusted session metadata, proof, or cursor is not admissible."""


def valid_cursor(token):
    """Whether an opaque cursor has the protocol's exact bounded wire shape."""
    return isinstance(token, str) and len(token) == TOKEN_BYTES \
        and token.isascii()


@dataclass(frozen=True)
class UploadLeaf:
    """The only client-supplied per-object metadata."""

    digest: str
    size: int


@dataclass(frozen=True)
class UploadManifest:
    """A wrapped Merkle-vector commitment fixed before capability issuance."""

    root: str
    count: int
    total_bytes: int


@dataclass(frozen=True)
class SessionKey:
    """One rotation-bounded HMAC key.

    ``verify_until_ms`` must cover every cursor it issues through that
    cursor's expiry plus the configured deployment skew.
    """

    key_id: str
    secret: bytes = field(repr=False)
    issue_from_ms: int
    verify_until_ms: int

    def __post_init__(self):
        if not isinstance(self.key_id, str) \
                or not _KEY_ID.fullmatch(self.key_id) \
                or not isinstance(self.secret, bytes) \
                or len(self.secret) != 32 \
                or not _uint(self.issue_from_ms, _U64_MAX) \
                or not _uint(self.verify_until_ms, _U64_MAX) \
                or self.issue_from_ms >= self.verify_until_ms:
            raise ValueError("upload session key")


@dataclass(frozen=True)
class UploadSessionPolicy:
    """Issuer, keys, quotas, and fixed maximum authorization staleness."""

    issuer: str
    active_key_id: str
    keys: tuple[SessionKey, ...]
    ttl_ms: int = MAX_SESSION_TTL_MS
    max_ttl_ms: int = MAX_SESSION_TTL_MS
    clock_skew_ms: int = MAX_SESSION_CLOCK_SKEW_MS
    max_bytes: int = MAX_SESSION_BYTES

    def __post_init__(self):
        if not _valid_identifier(self.issuer) \
                or not isinstance(self.keys, tuple) or not self.keys \
                or any(not isinstance(key, SessionKey) for key in self.keys) \
                or len({key.key_id for key in self.keys}) != len(self.keys) \
                or self.active_key_id not in {
                    key.key_id for key in self.keys
                } \
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


@dataclass(frozen=True)
class SessionState:
    workspace: str
    member: str
    session: str
    manifest: UploadManifest
    pile: UploadLeaf
    next_index: int
    issued_bytes: int
    last_digest: str | None
    issued_at_ms: int
    expires_at_ms: int
    key_id: str


def _uint(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _valid_identifier(value):
    return isinstance(value, str) \
        and len(value.encode("ascii", errors="ignore")) == len(value) \
        and _IDENTIFIER.fullmatch(value) is not None


def valid_provider_binding(value):
    return _valid_identifier(value)


def valid_leaf(value):
    return isinstance(value, UploadLeaf) \
        and valid_fid(value.digest) \
        and _uint(value.size, MAX_OBJECT_BYTES)


def valid_manifest(value, *, max_bytes=MAX_SESSION_BYTES):
    return isinstance(value, UploadManifest) \
        and valid_fid(value.root) \
        and _uint(value.count, MAX_SESSION_OBJECTS) \
        and _uint(value.total_bytes, max_bytes)


def _hash(domain, *parts):
    digest = hashlib.sha256()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _leaf_hash(index, leaf):
    return _hash(
        _LEAF_DOMAIN,
        index.to_bytes(4, "big"),
        bytes.fromhex(leaf.digest),
        leaf.size.to_bytes(8, "big"),
    )


def _padding_hash(index):
    return _hash(_PADDING_DOMAIN, index.to_bytes(4, "big"))


def _node_hash(level, left, right):
    return _hash(
        _NODE_DOMAIN, level.to_bytes(1, "big"), left, right)


def _wrapped_root(count, total_bytes, depth, tree_root):
    return _hash(
        _ROOT_DOMAIN,
        count.to_bytes(4, "big"),
        total_bytes.to_bytes(8, "big"),
        depth.to_bytes(1, "big"),
        tree_root,
    ).hex()


def _depth(count):
    return (max(1, count) - 1).bit_length()


def _bounded_leaves(values, maximum):
    try:
        materialized = tuple(islice(iter(values), maximum + 1))
    except (TypeError, ValueError) as error:
        raise InvalidUploadSession("upload leaves") from error
    if len(materialized) > maximum:
        raise InvalidUploadSession("upload leaf count")
    return materialized


def _validate_sorted(leaves):
    previous = None
    total = 0
    for leaf in leaves:
        if not valid_leaf(leaf) \
                or previous is not None and leaf.digest <= previous:
            raise InvalidUploadSession(
                "upload leaves must be digest-sorted and unique")
        previous = leaf.digest
        total += leaf.size
        if total > MAX_SESSION_BYTES:
            raise InvalidUploadSession("upload byte quota")
    return total


class UploadVector:
    """Efficient client-side commitment and range-proof preparation.

    This helper creates no capabilities and performs no network upload.
    Building the levels once makes thousands of bounded range proofs linear
    in the manifest plus proof output rather than linear per batch.
    """

    def __init__(self, leaves):
        leaves = _bounded_leaves(leaves, MAX_SESSION_OBJECTS)
        total = _validate_sorted(leaves)
        depth = _depth(len(leaves))
        width = 1 << depth
        first = tuple(
            _leaf_hash(index, leaves[index])
            if index < len(leaves) else _padding_hash(index)
            for index in range(width)
        )
        levels = [first]
        for level in range(1, depth + 1):
            lower = levels[-1]
            levels.append(tuple(
                _node_hash(level, lower[index], lower[index + 1])
                for index in range(0, len(lower), 2)
            ))
        self.leaves = leaves
        self._levels = tuple(levels)
        self.manifest = UploadManifest(
            _wrapped_root(len(leaves), total, depth, levels[-1][0]),
            len(leaves),
            total,
        )

    def proof(self, start, end):
        if type(start) is not int or type(end) is not int \
                or not 0 <= start < end <= len(self.leaves) \
                or end - start > PAGE_BATCH:
            raise InvalidUploadSession("upload proof range")
        nodes = []
        depth = len(self._levels) - 1

        def visit(level, index):
            node_start = index << level
            node_end = node_start + (1 << level)
            if end <= node_start or start >= node_end:
                nodes.append(self._levels[level][index])
                return
            if start <= node_start and node_end <= end:
                return
            if level == 0:
                return
            visit(level - 1, 2 * index)
            visit(level - 1, 2 * index + 1)

        visit(depth, 0)
        return encode_range_proof(tuple(nodes))


def encode_range_proof(nodes):
    if not isinstance(nodes, tuple) \
            or len(nodes) > MAX_RANGE_PROOF_NODES \
            or any(not isinstance(node, bytes) or len(node) != 32
                   for node in nodes):
        raise InvalidUploadSession("upload range proof")
    return _PROOF_HEADER.pack(
        _PROOF_MAGIC, PROTOCOL_VERSION, len(nodes)) + b"".join(nodes)


def decode_range_proof(raw):
    if not isinstance(raw, bytes) \
            or not _PROOF_HEADER.size <= len(raw) <= MAX_RANGE_PROOF_BYTES:
        raise InvalidUploadSession("upload range proof")
    try:
        magic, version, count = _PROOF_HEADER.unpack(
            raw[:_PROOF_HEADER.size])
    except struct.error as error:
        raise InvalidUploadSession("upload range proof") from error
    if magic != _PROOF_MAGIC or version != PROTOCOL_VERSION \
            or count > MAX_RANGE_PROOF_NODES \
            or len(raw) != _PROOF_HEADER.size + 32 * count:
        raise InvalidUploadSession("upload range proof")
    return tuple(
        raw[offset:offset + 32]
        for offset in range(_PROOF_HEADER.size, len(raw), 32)
    )


def verify_range(manifest, start, leaves, proof):
    """Verify one non-empty, bounded contiguous range against ``manifest``."""
    if not valid_manifest(manifest) or type(start) is not int:
        raise InvalidUploadSession("upload range")
    leaves = _bounded_leaves(leaves, PAGE_BATCH)
    end = start + len(leaves)
    if not leaves or not 0 <= start < end <= manifest.count:
        raise InvalidUploadSession("upload range")
    _validate_sorted(leaves)
    nodes = decode_range_proof(proof)
    node_cursor = 0
    leaf_cursor = 0
    depth = _depth(manifest.count)

    def visit(level, index):
        nonlocal node_cursor, leaf_cursor
        node_start = index << level
        node_end = node_start + (1 << level)
        if end <= node_start or start >= node_end:
            if node_cursor >= len(nodes):
                raise InvalidUploadSession("upload range proof")
            value = nodes[node_cursor]
            node_cursor += 1
            return value
        if level == 0:
            if leaf_cursor >= len(leaves) \
                    or node_start != start + leaf_cursor:
                raise InvalidUploadSession("upload range proof")
            value = _leaf_hash(node_start, leaves[leaf_cursor])
            leaf_cursor += 1
            return value
        left = visit(level - 1, 2 * index)
        right = visit(level - 1, 2 * index + 1)
        return _node_hash(level, left, right)

    tree_root = visit(depth, 0)
    if node_cursor != len(nodes) or leaf_cursor != len(leaves) \
            or not hmac.compare_digest(
                _wrapped_root(
                    manifest.count,
                    manifest.total_bytes,
                    depth,
                    tree_root,
                ),
                manifest.root,
            ):
        raise InvalidUploadSession("upload range proof")
    return leaves


class SessionTokenCodec:
    """Encode and verify the fixed-size authenticated progress cursor."""

    def __init__(self, policy, provider_binding):
        if not isinstance(policy, UploadSessionPolicy) \
                or not valid_provider_binding(provider_binding):
            raise ValueError("upload cursor configuration")
        self.policy = policy
        self.provider_binding = provider_binding
        self._issuer_hash = _hash(
            _ISSUER_DOMAIN, policy.issuer.encode("ascii"))
        self._provider_hash = _hash(
            _PROVIDER_DOMAIN, provider_binding.encode("ascii"))

    def _validate_state(self, state):
        if not isinstance(state, SessionState) \
                or not valid_fid(state.workspace) \
                or not isinstance(state.member, str) \
                or len(state.member) != MEMBER_HEX_BYTES \
                or any(character not in "0123456789abcdef"
                       for character in state.member) \
                or not isinstance(state.session, str) \
                or len(state.session) != SESSION_HEX_BYTES \
                or any(character not in "0123456789abcdef"
                       for character in state.session) \
                or not valid_manifest(
                    state.manifest,
                    max_bytes=self.policy.max_bytes,
                ) \
                or not valid_leaf(state.pile) \
                or state.manifest.total_bytes + state.pile.size \
                > self.policy.max_bytes \
                or not _uint(
                    state.next_index, state.manifest.count) \
                or not _uint(
                    state.issued_bytes, state.manifest.total_bytes) \
                or not _uint(state.issued_at_ms, _U64_MAX) \
                or not _uint(state.expires_at_ms, _U64_MAX) \
                or not 0 < state.expires_at_ms - state.issued_at_ms \
                <= self.policy.max_ttl_ms \
                or state.key_id not in {
                    key.key_id for key in self.policy.keys
                }:
            raise InvalidUploadSession("upload cursor state")
        if state.next_index == 0:
            if state.issued_bytes != 0 or state.last_digest is not None:
                raise InvalidUploadSession("upload cursor prefix")
        elif not valid_fid(state.last_digest):
            raise InvalidUploadSession("upload cursor prefix")
        if state.next_index == state.manifest.count \
                and state.issued_bytes != state.manifest.total_bytes:
            raise InvalidUploadSession("upload cursor byte total")

    def encode(self, state):
        self._validate_state(state)
        payload = _TOKEN.pack(
            _TOKEN_MAGIC,
            PROTOCOL_VERSION,
            state.key_id.encode("ascii"),
            self._issuer_hash,
            self._provider_hash,
            bytes.fromhex(state.workspace),
            bytes.fromhex(state.member),
            bytes.fromhex(state.session),
            bytes.fromhex(state.manifest.root),
            state.manifest.count,
            state.manifest.total_bytes,
            bytes.fromhex(state.pile.digest),
            state.pile.size,
            state.next_index,
            state.issued_bytes,
            bytes.fromhex(state.last_digest)
            if state.last_digest is not None else b"\0" * 32,
            state.issued_at_ms,
            state.expires_at_ms,
        )
        key = self.policy.key(state.key_id)
        mac = hmac.new(
            key.secret, _TOKEN_MAC_DOMAIN + payload,
            hashlib.sha256).digest()
        encoded = base64.urlsafe_b64encode(
            payload + mac).rstrip(b"=").decode("ascii")
        if len(encoded) != TOKEN_BYTES:
            raise AssertionError("upload cursor size")
        return encoded

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
        if len(raw) != TOKEN_RAW_BYTES \
                or base64.urlsafe_b64encode(raw).rstrip(
                    b"=").decode("ascii") != token:
            raise InvalidUploadSession("upload cursor")
        payload, presented_mac = raw[:-32], raw[-32:]
        try:
            values = _TOKEN.unpack(payload)
            key_id = values[2].decode("ascii")
            key = self.policy.key(key_id)
        except (struct.error, UnicodeDecodeError, ValueError) as error:
            raise InvalidUploadSession("upload cursor") from error
        expected_mac = hmac.new(
            key.secret, _TOKEN_MAC_DOMAIN + payload,
            hashlib.sha256).digest()
        if not hmac.compare_digest(presented_mac, expected_mac):
            raise InvalidUploadSession("upload cursor")
        (
            magic,
            version,
            _key_id,
            issuer_hash,
            provider_hash,
            workspace,
            member,
            session,
            vector_root,
            count,
            total_bytes,
            pile_digest,
            pile_size,
            next_index,
            issued_bytes,
            last_digest,
            issued_at_ms,
            expires_at_ms,
        ) = values
        if magic != _TOKEN_MAGIC or version != PROTOCOL_VERSION \
                or not hmac.compare_digest(
                    issuer_hash, self._issuer_hash) \
                or not hmac.compare_digest(
                    provider_hash, self._provider_hash) \
                or issued_at_ms < key.issue_from_ms \
                or not 0 < expires_at_ms - issued_at_ms \
                <= self.policy.max_ttl_ms \
                or expires_at_ms + self.policy.clock_skew_ms \
                > key.verify_until_ms \
                or not issued_at_ms <= trusted_now < expires_at_ms \
                or next_index == 0 and last_digest != b"\0" * 32:
            raise InvalidUploadSession("upload cursor")
        state = SessionState(
            workspace.hex(),
            member.hex(),
            session.hex(),
            UploadManifest(vector_root.hex(), count, total_bytes),
            UploadLeaf(pile_digest.hex(), pile_size),
            next_index,
            issued_bytes,
            last_digest.hex() if next_index else None,
            issued_at_ms,
            expires_at_ms,
            key_id,
        )
        self._validate_state(state)
        return state
