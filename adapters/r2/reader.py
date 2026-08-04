"""Native R2 binding with no mutation methods for a private read gateway."""

from core.limits import MAX_STORE_READ_BYTES, PayloadTooLarge
from core.object_store import (
    ABSENT,
    StoreError,
    Versioned,
    VersionToken,
    validate_key,
    validate_store_prefix,
)
from .listing import list_page as _list_page


class R2ReadBindingStore:
    """Bounded immutable reads plus paginated writer-head discovery."""

    __slots__ = ("bucket", "prefix")

    def __init__(self, bucket, prefix=""):
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        if self.prefix:
            validate_store_prefix(self.prefix)

    def _key(self, key):
        key = validate_key(key)
        return f"{self.prefix}/{key}" if self.prefix else key

    @staticmethod
    def _token(obj):
        value = getattr(obj, "etag", None)
        if not isinstance(value, str) or not value or value.startswith("W/"):
            raise StoreError("R2 response has no usable strong ETag")
        return VersionToken(value)

    @staticmethod
    async def _bounded(obj, maximum):
        size = getattr(obj, "size", None)
        if type(size) is not int or size < 0:
            raise StoreError("R2 response has invalid size")
        if size > maximum:
            raise PayloadTooLarge("R2 response exceeds byte limit")
        value = await obj.arrayBuffer()
        if hasattr(value, "to_py"):
            value = value.to_py()
        value = bytes(value)
        if len(value) > maximum:
            raise PayloadTooLarge("R2 response exceeds byte limit")
        if len(value) != size:
            raise StoreError("R2 response size mismatch")
        return value

    async def get_bounded(self, key, maximum):
        if type(maximum) is not int \
                or not 0 < maximum <= MAX_STORE_READ_BYTES:
            raise ValueError("R2 read byte limit")
        try:
            obj = await self.bucket.get(self._key(key))
            return None if obj is None else await self._bounded(obj, maximum)
        except (PayloadTooLarge, StoreError):
            raise
        except Exception as error:
            raise StoreError(f"R2 read failed for {key}") from error

    async def read_versioned(self, key, maximum):
        if type(maximum) is not int \
                or not 0 < maximum <= MAX_STORE_READ_BYTES:
            raise ValueError("R2 read byte limit")
        try:
            obj = await self.bucket.get(self._key(key))
            if obj is None:
                return ABSENT
            return Versioned(
                await self._bounded(obj, maximum), self._token(obj))
        except (PayloadTooLarge, StoreError):
            raise
        except Exception as error:
            raise StoreError(f"R2 versioned read failed for {key}") from error

    async def list_page(self, prefix, cursor=None, limit=256):
        return await _list_page(
            self.bucket, self.prefix, prefix, cursor, limit)


__all__ = ("R2ReadBindingStore",)
