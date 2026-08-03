"""Provider-request accounting for per-device writer-log scenarios.

The trace records protocol operations and bytes without baking volatile cloud
prices into correctness tests. A report may apply current provider rates to
the resulting :class:`CostVector` separately.
"""
from dataclasses import asdict, dataclass

from core.object_store import ABSENT, Versioned, async_store


def _kind(key):
    if key.startswith("heads/"):
        return "slot"
    if key.startswith("obj/"):
        return "object"
    return "other"


@dataclass(frozen=True, slots=True)
class CostVector:
    lists: int = 0
    slot_gets: int = 0
    object_gets: int = 0
    other_gets: int = 0
    object_puts: int = 0
    slot_cas: int = 0
    other_puts: int = 0
    read_bytes: int = 0
    write_bytes: int = 0

    @property
    def requests(self):
        return sum((
            self.lists,
            self.slot_gets,
            self.object_gets,
            self.other_gets,
            self.object_puts,
            self.slot_cas,
            self.other_puts,
        ))

    def to_json(self):
        return {**asdict(self), "requests": self.requests}


class CountingStore:
    """Awaited ObjectStore decorator counting physical adapter attempts."""

    def __init__(self, store):
        self.store = async_store(store)
        self.clear()

    def clear(self):
        self._counts = {
            "lists": 0,
            "slot_gets": 0,
            "object_gets": 0,
            "other_gets": 0,
            "object_puts": 0,
            "slot_cas": 0,
            "other_puts": 0,
            "read_bytes": 0,
            "write_bytes": 0,
        }

    def snapshot(self):
        return CostVector(**self._counts)

    def _read(self, key, value):
        self._counts[f"{_kind(key)}_gets"] += 1
        if isinstance(value, bytes):
            self._counts["read_bytes"] += len(value)
        elif isinstance(value, Versioned):
            self._counts["read_bytes"] += len(value.value)

    async def get_bounded(self, key, max_bytes):
        value = await self.store.get_bounded(key, max_bytes)
        self._read(key, value)
        return value

    async def copy_pile_object(self, oid, max_bytes, write):
        self._counts["object_gets"] += 1

        def counted(chunk):
            self._counts["read_bytes"] += len(chunk)
            write(chunk)

        return await self.store.copy_pile_object(oid, max_bytes, counted)

    async def has(self, key):
        value = await self.store.has(key)
        self._counts[f"{_kind(key)}_gets"] += 1
        return value

    async def read_versioned(self, key):
        value = await self.store.read_versioned(key)
        self._read(key, value)
        return value

    async def put_if_absent(self, key, value):
        kind = _kind(key)
        self._counts[
            "object_puts" if kind == "object" else "other_puts"] += 1
        self._counts["write_bytes"] += len(value)
        return await self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        kind = _kind(key)
        self._counts["slot_cas" if kind == "slot" else "other_puts"] += 1
        self._counts["write_bytes"] += len(value)
        return await self.store.cas(key, token, value)

    async def list_page(self, prefix, cursor=None, limit=256):
        self._counts["lists"] += 1
        return await self.store.list_page(prefix, cursor, limit)

    def namespace_id(self):
        identity = getattr(self.store, "namespace_id", None)
        return identity() if callable(identity) else None


__all__ = ("CostVector", "CountingStore")
