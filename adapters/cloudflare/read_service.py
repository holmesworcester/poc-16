"""Validated client for a private bounded object-read service binding."""

from core.limits import MAX_ROOT_BYTES, MAX_STORE_READ_BYTES, PayloadTooLarge
from core.object_store import ABSENT, Versioned, VersionToken


class ReadServiceStore:
    """Expose the read subset consumed by notification discovery/workers."""

    __slots__ = ("service", "versioned")

    def __init__(self, service, *, versioned=True):
        if not callable(getattr(service, "get_bounded", None)) \
                or versioned and not callable(
                    getattr(service, "read_versioned", None)):
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


__all__ = ("ReadServiceStore",)
