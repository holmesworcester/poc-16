"""Pure object-store contract shared by local and remote implementations.

The root-authoritative snapshot uses only two namespaces:

``obj/<sha256>``
    A grow-only content-addressed map. Conditional creation may report either
    that the bytes were created or that identical bytes already existed.

``root``
    One linearizable value-CAS register. A version token is an opaque
    comparison capability for the exact bytes returned by the same read; it is
    not a content digest or a globally unique generation.

The same canonical bucket may also contain Applier-owned operational work:
internal ``pile/`` generations, immutable ``failed/`` rejection evidence,
``staged/`` receipts/claims, and ``applier/cursor/`` liveness hints. Those
objects are not repository answers and are never read through
``RepositoryReader``. Client-writable ``ingress/v1/`` markers and detached
objects live in the separate ingress compartment.

Provider and POSIX implementations live outside this module so the
database-free authorization path can import integrity helpers in runtimes
without files, locks, threads, or SQLite.
"""
from dataclasses import dataclass
from enum import Enum
import re
from typing import Protocol

from .crypto import h
from .limits import (
    MAX_OBJECT_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PayloadTooLarge,
)

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
    """The S3/R2-shaped operations used by a RepositoryApplier."""

    def get_bounded(
            self, key: str, max_bytes: int) -> bytes | None: ...

    def read_versioned(self, key: str) -> Versioned | Absent: ...

    def put(self, key: str, value: bytes): ...

    def put_if_absent(
            self, key: str, value: bytes) -> CreateResult: ...

    def cas(
            self, key: str, token: VersionToken | Absent,
            value: bytes) -> Applied | Stale: ...

    def list_page(
            self, prefix: str, cursor: str | None,
            limit: int) -> ListPage: ...

    def delete(self, key: str): ...


class AsyncObjectStore(Protocol):
    """Awaited equivalent of the writable ObjectStore contract."""

    async def get_bounded(
            self, key: str, max_bytes: int) -> bytes | None: ...

    async def read_versioned(self, key: str) -> Versioned | Absent: ...

    async def put(self, key: str, value: bytes): ...

    async def put_if_absent(
            self, key: str, value: bytes) -> CreateResult: ...

    async def cas(
            self, key: str, token: VersionToken | Absent,
            value: bytes) -> Applied | Stale: ...

    async def list_page(
            self, prefix: str, cursor: str | None,
            limit: int) -> ListPage: ...

    async def delete(self, key: str): ...


def verified_object(oid, fetch):
    """Fetch one content-addressed object and verify its name."""
    raw = fetch(oid) if oid else None
    if not isinstance(raw, bytes) \
            or len(raw) > MAX_REPOSITORY_OBJECT_BYTES \
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
    maximum = max(1, len(raw))
    unknown = None
    for _ in range(2):
        try:
            result = store.put_if_absent(key, raw)
        except OutcomeUnknown as error:
            unknown = error
            try:
                incumbent = store.get_bounded(key, maximum)
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
            incumbent = store.get_bounded(key, maximum)
        except PayloadTooLarge as conflict:
            raise ValueError("immutable object conflict") from conflict
        if incumbent != raw:
            raise ValueError("immutable object conflict")
        return EXISTS
    raise unknown


async def ensure_object_async(store, oid, raw):
    """Awaited equivalent of :func:`ensure_object` for edge bindings."""
    if not isinstance(raw, bytes) or len(raw) > MAX_OBJECT_BYTES \
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


async def retire_exact_async(store, key, raw):
    """Retire one exact hosted work item and reconcile an unknown response.

    This helper reconciles bounded deletion mechanics only. The caller must
    first prove through F10 that the exact durable work item may be retired.
    """
    if not isinstance(raw, bytes):
        raise TypeError("exact retirement bytes required")
    if len(raw) > MAX_OBJECT_BYTES:
        raise PayloadTooLarge("exact retirement bytes exceed limit")
    maximum = max(1, len(raw))

    async def current_value():
        try:
            return await store.get_bounded(key, maximum)
        except PayloadTooLarge as error:
            raise OSError("retirement source changed") from error

    current = await current_value()
    if current is None:
        return False
    if current != raw:
        raise OSError("retirement source changed")
    try:
        await store.delete(key)
    except Exception as error:
        try:
            current = await store.get_bounded(key, maximum)
        except PayloadTooLarge as changed:
            raise OSError("retirement source changed") from changed
        except Exception:
            raise error
        if current is None:
            return True
        if current != raw:
            raise OSError("retirement source changed") from error
        raise error
    current = await current_value()
    if current is None:
        return True
    if current != raw:
        raise OSError("retirement source changed")
    raise OSError("retirement did not remove the source")
