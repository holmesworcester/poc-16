"""Pure object-store contract shared by local and remote implementations.

The protocol uses these namespaces:

``obj/<sha256>``
    A grow-only content-addressed map of facts, Merkle pages, signed writer
    piles, and heads. Conditional creation may report either that the bytes
    were created or that identical bytes already existed. Large signed piles
    use the direct streaming HTTP path rather than buffered semantic reads.

``removal``, ``removal-node/<sha256>``
    One private suppression-root CAS cell and its immutable proof nodes.
    These names are available only to the access engine; they are never
    mapped into generic object, pack, grant, or public LIST routes.

``cursor``
    A generic operational CAS cell used only by isolated subsystems such as
    notification delivery. It is never workspace fact authority.

``heads/<workspace>/<device>``, ``layouts/<workspace>/<device>/<window>``
    Independent linearizable CAS registers. Heads are signed logical history;
    layout pages are untrusted source-local transfer hints.

``pack/<sha256>``
    Immutable large transfer objects. Their keys share this namespace and
    mutation policy, but their bodies use the separate streaming data plane
    rather than the bounded semantic-object methods in this trait.

Provider and POSIX implementations live outside this module so the
database-free authorization path can import integrity helpers in runtimes
without files, locks, threads, or SQLite.
"""
from dataclasses import dataclass
from enum import Enum
import inspect
import re
from typing import Protocol

from .crypto import h
from .limits import (
    MAX_OBJECT_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    WRITER_LAYOUT_WINDOW_PILES,
    PayloadTooLarge,
)

KEY_RE = re.compile(r"^[a-z0-9:._/-]+$")
REMOVAL_ROOT_KEY = "removal"
REMOVAL_NODE_PREFIX = "removal-node/"
OPERATIONAL_CURSOR_KEY = "cursor"
SINGLETON_CAS_KEYS = frozenset((
    REMOVAL_ROOT_KEY,
    OPERATIONAL_CURSOR_KEY,
))

# S3 and R2 both cap one complete object key at 1,024 bytes. A configured
# prefix must leave room for every logical namespace the shared store may
# address, not merely the ingress key that happened to be longest before
# public invitations were included in this inventory.
MAX_PROVIDER_KEY_BYTES = 1024
MAX_INVITE_ID_BYTES = 256
MAX_LOGICAL_KEY_BYTES = max(
    len(OPERATIONAL_CURSOR_KEY),
    len("obj/") + 64,
    len(REMOVAL_NODE_PREFIX) + 64,
    len("heads/") + 64 + 1 + 64,
    len("invite/") + MAX_INVITE_ID_BYTES,
)
MAX_STORE_PREFIX_BYTES = (
    MAX_PROVIDER_KEY_BYTES - 1 - MAX_LOGICAL_KEY_BYTES)


def validate_key(key):
    """Validate one provider-neutral relative object key."""
    if not isinstance(key, str) or not KEY_RE.fullmatch(key):
        raise ValueError(f"bad key {key!r}")
    parts = key.split("/")
    if any(not part or part in {".", ".."} for part in parts) \
            or parts[0] in {".cas.lock", ".root.lock"} \
            or key == "root" or key.startswith("root/"):
        raise ValueError(f"reserved key {key!r}")
    return key


def validate_store_prefix(prefix):
    """Validate a prefix that leaves room for every logical store key."""
    if not isinstance(prefix, str) or not KEY_RE.fullmatch(prefix) \
            or any(
                not part or part in {".", ".."}
                for part in prefix.split("/")):
        raise ValueError("store key prefix")
    if len(prefix.encode("ascii")) > MAX_STORE_PREFIX_BYTES:
        raise ValueError("store prefix exceeds provider object-key budget")
    return prefix


def authoritative_key(key):
    """Whether a public unconditional mutation must reject this key."""
    return key in SINGLETON_CAS_KEYS \
        or key.startswith("cursor/") \
        or key.startswith(REMOVAL_NODE_PREFIX) \
        or key == "obj" or key.startswith("obj/") \
        or key == "heads" or key.startswith("heads/") \
        or key == "layouts" or key.startswith("layouts/") \
        or key == "pack" or key.startswith("pack/")


def mutable_key(key):
    """Whether ``key`` is one exact protocol CAS register."""
    key = validate_key(key)
    if key in SINGLETON_CAS_KEYS:
        return True
    parts = key.split("/")
    if len(parts) == 3 and parts[0] == "heads":
        return all(
            re.fullmatch(r"[0-9a-f]{64}", part) for part in parts[1:])
    if len(parts) != 4 or parts[0] != "layouts" \
            or not all(
                re.fullmatch(r"[0-9a-f]{64}", part)
                for part in parts[1:3]):
        return False
    # Keep the low-level store independent of the layout codec while still
    # accepting only its canonical fixed-window address arithmetic.
    sequence = parts[3]
    if len(sequence) != 16 or not sequence.isascii() \
            or not sequence.isdigit():
        return False
    start = int(sequence)
    return 1 <= start <= (1 << 53) - 1 \
        and (start - 1) % WRITER_LAYOUT_WINDOW_PILES == 0


def validate_create(key, value):
    """Validate one conditional-create address before provider mutation."""
    key = validate_key(key)
    if not isinstance(value, bytes):
        raise TypeError("object value must be bytes")
    if mutable_key(key) \
            or key == "heads" or key.startswith("heads/"):
        raise ValueError("mutable register requires compare-and-swap")
    for prefix in ("obj/", "pack/", REMOVAL_NODE_PREFIX):
        if key == prefix[:-1] or key.startswith(prefix) and (
                len(key) != len(prefix) + 64
                or key[len(prefix):] != h(value)):
            raise ValueError("immutable object address")
    return key


@dataclass(frozen=True)
class VersionToken:
    """Opaque implementation-supplied conditional-write capability."""

    value: str

    def __post_init__(self):
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("version token")


@dataclass(frozen=True)
class Versioned:
    """Bytes and the opaque token returned by the same atomic read."""

    value: bytes
    token: VersionToken

    def __post_init__(self):
        if not isinstance(self.value, bytes) \
                or not isinstance(self.token, VersionToken):
            raise TypeError("versioned object")


@dataclass(frozen=True)
class Applied:
    """A conditional replacement definitely committed."""

    token: VersionToken


@dataclass(frozen=True, slots=True)
class ListPage:
    """One bounded discovery page and its provider-opaque continuation."""

    keys: tuple[str, ...]
    cursor: str | None

    def __post_init__(self):
        if not isinstance(self.keys, tuple) \
                or any(not isinstance(key, str) for key in self.keys) \
                or tuple(sorted(set(self.keys))) != self.keys \
                or self.cursor is not None and (
                    not isinstance(self.cursor, str) or not self.cursor):
            raise ValueError("object-store list page")


class Absent(Enum):
    """The key was absent at the linearization point of a read."""

    RESULT = "absent"


ABSENT = Absent.RESULT


class Stale(Enum):
    """The conditional replacement definitely did not commit."""

    RESULT = "stale"


STALE = Stale.RESULT


class CreateResult(Enum):
    """Outcome of an acknowledged conditional create."""

    CREATED = "created"
    EXISTS = "exists"


CREATED = CreateResult.CREATED
EXISTS = CreateResult.EXISTS


class StoreError(OSError):
    """A store operation did not complete normally."""


class RetryableStoreError(StoreError):
    """A mutation definitely did not commit and may be retried."""


class OutcomeUnknown(StoreError):
    """A mutation may have committed, but its response was not received."""


class ObjectStore(Protocol):
    """The complete bounded mutation surface used by every repository role."""

    def get_bounded(
            self, key: str, max_bytes: int) -> bytes | None: ...

    def copy_pile_object(
            self, oid: str, max_bytes: int, write) -> int | None: ...

    def has(self, key: str) -> bool: ...

    def read_versioned(self, key: str) -> Versioned | Absent: ...

    def put_if_absent(
            self, key: str, value: bytes) -> CreateResult: ...

    def cas(
            self, key: str, token: VersionToken | Absent,
            value: bytes) -> Applied | Stale: ...

    def list_page(
            self, prefix: str, cursor: str | None = None,
            limit: int = 256) -> ListPage: ...

class AsyncObjectStore(Protocol):
    """Awaited equivalent of the exact object-store contract."""

    async def get_bounded(
            self, key: str, max_bytes: int) -> bytes | None: ...

    async def copy_pile_object(
            self, oid: str, max_bytes: int, write) -> int | None: ...

    async def has(self, key: str) -> bool: ...

    async def read_versioned(self, key: str) -> Versioned | Absent: ...

    async def put_if_absent(
            self, key: str, value: bytes) -> CreateResult: ...

    async def cas(
            self, key: str, token: VersionToken | Absent,
            value: bytes) -> Applied | Stale: ...

    async def list_page(
            self, prefix: str, cursor: str | None = None,
            limit: int = 256) -> ListPage: ...


class SyncStoreAdapter:
    """Expose one already-conforming synchronous store as awaited methods."""

    def __init__(self, store):
        self.store = store

    async def get_bounded(self, key, max_bytes):
        value = self.store.get_bounded(key, max_bytes)
        if value is not None and (
                not isinstance(value, bytes) or len(value) > max_bytes):
            raise PayloadTooLarge("object-store read exceeds byte limit")
        return value

    async def copy_pile_object(self, oid, max_bytes, write):
        return self.store.copy_pile_object(oid, max_bytes, write)

    async def has(self, key):
        return self.store.has(key)

    async def read_versioned(self, key):
        return self.store.read_versioned(key)

    async def put_if_absent(self, key, value):
        return self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        return self.store.cas(key, token, value)

    async def list_page(self, prefix, cursor=None, limit=256):
        return self.store.list_page(prefix, cursor, limit)

    def namespace_id(self):
        return store_namespace(self.store)


def store_namespace(store):
    """Return a concrete adapter's stable physical namespace, when known.

    Service proxies may not expose this. Their deployment must prove disjoint
    bindings structurally instead of inventing a capability identity.
    """
    identity = getattr(store, "namespace_id", None)
    if not callable(identity):
        return None
    value = identity()
    if value is not None:
        try:
            hash(value)
        except TypeError as error:
            raise TypeError("object-store namespace identity") from error
    return value


def async_store(store):
    """Return one awaited store without introducing provider branches."""
    method = getattr(type(store), "get_bounded", None)
    return store if inspect.iscoroutinefunction(method) \
        else SyncStoreAdapter(store)


def verified_object(
        oid, fetch, *, max_bytes=MAX_REPOSITORY_OBJECT_BYTES):
    """Fetch one content-addressed object and verify its name."""
    if type(max_bytes) is not int \
            or not 0 < max_bytes <= MAX_OBJECT_BYTES:
        raise ValueError("object byte limit")
    raw = fetch(oid) if oid else None
    if not isinstance(raw, bytes) \
            or len(raw) > max_bytes \
            or h(raw) != oid:
        raise ValueError("object integrity")
    return raw


async def ensure_object_async(store, oid, raw):
    """Establish one immutable buffered semantic object."""
    if not isinstance(raw, bytes) \
            or len(raw) > MAX_REPOSITORY_OBJECT_BYTES \
            or not isinstance(oid, str) or h(raw) != oid:
        raise ValueError("immutable object address")
    key = "obj/" + oid
    maximum = max(1, len(raw))
    unknown = None
    for _ in range(2):
        try:
            result = await store.put_if_absent(key, raw)
        except OutcomeUnknown as error:
            unknown = error
            try:
                incumbent = await store.get_bounded(key, maximum)
            except PayloadTooLarge as conflict:
                raise ValueError(
                    "immutable object conflict") from conflict
            if incumbent == raw:
                return EXISTS
            if incumbent is not None:
                raise ValueError("immutable object conflict") from error
            continue
        if result is CREATED:
            return CREATED
        if result is not EXISTS:
            raise TypeError("conditional-create result")
        try:
            incumbent = await store.get_bounded(key, maximum)
        except PayloadTooLarge as conflict:
            raise ValueError("immutable object conflict") from conflict
        if incumbent != raw:
            raise ValueError("immutable object conflict")
        return EXISTS
    raise unknown
