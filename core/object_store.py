"""Pure object-store contract shared by local and remote implementations.

The authoritative layout needs only two storage objects:

``obj/<sha256>``
    A grow-only content-addressed map. Conditional creation may report either
    that the bytes were created or that identical bytes already existed.

``root``
    One linearizable value-CAS register. A version token is an opaque
    comparison capability for the exact bytes returned by the same read; it is
    not a content digest or a globally unique generation.

Provider and POSIX implementations live outside this module so the
database-free authorization path can import integrity helpers in runtimes
without files, locks, threads, or SQLite.
"""
from dataclasses import dataclass
from enum import Enum
import re
from typing import Protocol

from .crypto import h
from .limits import MAX_OBJECT_BYTES

KEY_RE = re.compile(r"^[a-z0-9:._/-]+$")


def validate_key(key):
    """Validate one provider-neutral relative object key."""
    if not isinstance(key, str) or not KEY_RE.fullmatch(key):
        raise ValueError(f"bad key {key!r}")
    parts = key.split("/")
    if any(not part or part in {".", ".."} for part in parts) \
            or parts[0] == ".root.lock" \
            or key.startswith("root/"):
        raise ValueError(f"reserved key {key!r}")
    return key


def authoritative_key(key):
    """Whether a public unconditional mutation must reject this key."""
    return key == "root" or key.startswith("root/") \
        or key == "obj" or key.startswith("obj/")


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


class ObjectReader(Protocol):
    """The immutable read surface shared with remote HTTP peers."""

    def get(self, key: str) -> bytes | None: ...

    def has(self, key: str) -> bool: ...


class ObjectStore(ObjectReader, Protocol):
    """The S3/R2-shaped operations used by a writable publisher."""

    def read_versioned(self, key: str) -> Versioned | Absent: ...

    def put(self, key: str, value: bytes): ...

    def put_if_absent(
            self, key: str, value: bytes) -> CreateResult: ...

    def cas(
            self, key: str, token: VersionToken | Absent,
            value: bytes) -> Applied | Stale: ...

    def list(self, prefix: str) -> list[str]: ...

    def delete(self, key: str): ...


class AsyncObjectReader(Protocol):
    """Awaited immutable reads used by edge bindings."""

    async def get(self, key: str) -> bytes | None: ...

    async def has(self, key: str) -> bool: ...


class AsyncObjectStore(AsyncObjectReader, Protocol):
    """Awaited equivalent of the writable ObjectStore contract."""

    async def read_versioned(self, key: str) -> Versioned | Absent: ...

    async def put(self, key: str, value: bytes): ...

    async def put_if_absent(
            self, key: str, value: bytes) -> CreateResult: ...

    async def cas(
            self, key: str, token: VersionToken | Absent,
            value: bytes) -> Applied | Stale: ...

    async def list(self, prefix: str) -> list[str]: ...

    async def delete(self, key: str): ...


def verified_object(oid, fetch):
    """Fetch one content-addressed object and verify its name."""
    raw = fetch(oid) if oid else None
    if not isinstance(raw, bytes) or len(raw) > MAX_OBJECT_BYTES \
            or h(raw) != oid:
        raise ValueError("object integrity")
    return raw


def ensure_object(store, oid, raw):
    """Establish one immutable object before a root may reference it.

    A conditional collision is not success until the incumbent has been
    fetched and byte-verified.  An ambiguous create is reconciled by a strong
    read and retried once when the key is still absent; it is never collapsed
    into ``EXISTS``.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_OBJECT_BYTES \
            or not isinstance(oid, str) or h(raw) != oid:
        raise ValueError("immutable object address")
    key = "obj/" + oid
    unknown = None
    for _ in range(2):
        try:
            result = store.put_if_absent(key, raw)
        except OutcomeUnknown as error:
            unknown = error
            incumbent = store.get(key)
            if incumbent == raw:
                return EXISTS
            if incumbent is not None:
                raise ValueError("immutable object conflict") from error
            continue
        if result is CREATED:
            return CREATED
        if result is not EXISTS:
            raise TypeError("conditional-create result")
        incumbent = store.get(key)
        if incumbent != raw:
            raise ValueError("immutable object conflict")
        return EXISTS
    raise unknown


def retire_exact(store, key, raw):
    """Delete one replace-proof work item and reconcile an unknown response.

    This helper does not authorize deletion. The caller must already hold the
    durable publication/rejection/promotion witness for ``raw`` and establish
    that accepted same-address writes cannot change its value (normally
    create-only plus key/body binding). That invariant makes the initial exact
    read stable until DELETE linearizes. A lost DELETE response is success
    only after a strong read observes absence; a surviving or changed value
    is never silently discharged.
    """
    if not isinstance(raw, bytes):
        raise TypeError("exact retirement bytes required")
    current = store.get(key)
    if current is None:
        return False
    if current != raw:
        raise OSError("retirement source changed")
    try:
        store.delete(key)
    except Exception as error:
        try:
            current = store.get(key)
        except Exception:
            raise error
        if current is None:
            return True
        if current != raw:
            raise OSError("retirement source changed") from error
        raise error
    current = store.get(key)
    if current is None:
        return True
    if current != raw:
        raise OSError("retirement source changed")
    raise OSError("retirement did not remove the source")


async def ensure_object_async(store, oid, raw):
    """Awaited equivalent of :func:`ensure_object` for edge bindings."""
    if not isinstance(raw, bytes) or len(raw) > MAX_OBJECT_BYTES \
            or not isinstance(oid, str) or h(raw) != oid:
        raise ValueError("immutable object address")
    key = "obj/" + oid
    unknown = None
    for _ in range(2):
        try:
            result = await store.put_if_absent(key, raw)
        except OutcomeUnknown as error:
            unknown = error
            incumbent = await store.get(key)
            if incumbent == raw:
                return EXISTS
            if incumbent is not None:
                raise ValueError("immutable object conflict") from error
            continue
        if result is CREATED:
            return CREATED
        if result is not EXISTS:
            raise TypeError("conditional-create result")
        if await store.get(key) != raw:
            raise ValueError("immutable object conflict")
        return EXISTS
    raise unknown
