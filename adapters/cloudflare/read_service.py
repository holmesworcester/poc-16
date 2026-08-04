"""Validated client for a private bounded object-read service binding."""

from core.limits import MAX_ROOT_BYTES, MAX_STORE_READ_BYTES, PayloadTooLarge
from core.object_store import ABSENT, ListPage, Versioned, VersionToken


class ReadServiceStore:
    """Expose the read subset consumed by notification discovery/workers."""

    __slots__ = ("service", "versioned")

    def __init__(self, service, *, versioned=True):
        if not callable(getattr(service, "get_bounded", None)) \
                or versioned and not callable(
                    getattr(service, "read_versioned", None)) \
                or versioned and not callable(
                    getattr(service, "list_page", None)):
            raise TypeError("Cloudflare read service binding")
        self.service = service
        self.versioned = versioned

    @staticmethod
    def _maximum(maximum):
        if type(maximum) is not int \
                or not 0 < maximum <= MAX_STORE_READ_BYTES:
            raise ValueError("service read byte limit")
        return maximum

    async def get_bounded(self, key, maximum):
        maximum = self._maximum(maximum)
        value = await self.service.get_bounded(key, maximum)
        if value is not None and (
                not isinstance(value, bytes) or len(value) > maximum):
            raise PayloadTooLarge("read service exceeded byte limit")
        return value

    async def read_versioned(self, key):
        if not self.versioned:
            raise TypeError("read service has no versioned capability")
        value = await self.service.read_versioned(key, MAX_ROOT_BYTES)
        if value == {"status": "absent"}:
            return ABSENT
        if not isinstance(value, dict) or set(value) != {
                "status", "token", "value"} \
                or value.get("status") != "versioned" \
                or not isinstance(value.get("value"), bytes) \
                or len(value["value"]) > MAX_ROOT_BYTES:
            raise ValueError("read service versioned response")
        return Versioned(value["value"], VersionToken(value.get("token")))

    async def list_page(self, prefix, cursor=None, limit=256):
        value = await self.service.list_page(prefix, cursor, limit)
        if not isinstance(value, dict) or set(value) != {"cursor", "keys"} \
                or not isinstance(value.get("keys"), list) \
                or not all(isinstance(key, str) for key in value["keys"]) \
                or value.get("cursor") is not None \
                and not isinstance(value["cursor"], str):
            raise ValueError("read service list response")
        return ListPage(tuple(value["keys"]), value["cursor"])

    async def copy_pile_object(self, oid, maximum, write):
        """Small-body service fallback; direct large reads stay segregated."""
        raw = await self.get_bounded(
            "obj/" + oid, min(maximum, MAX_STORE_READ_BYTES))
        if raw is None:
            return None
        write(raw)
        return len(raw)


__all__ = ("ReadServiceStore",)
