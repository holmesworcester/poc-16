"""Cloudflare Worker R2-binding implementation of AsyncObjectStore."""
from core.crypto import h
from core.limits import MAX_OBJECT_BYTES, MAX_ROOT_BYTES, PayloadTooLarge
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    StoreError,
    ListPage,
    Versioned,
    VersionToken,
    authoritative_key,
    validate_key,
)


def _if_none_match():
    """Use the Headers form because R2Conditional has no absence predicate."""
    try:
        from js import Headers
    except ImportError:
        return {"If-None-Match": "*"}
    headers = Headers.new()
    headers.set("If-None-Match", "*")
    return headers


def _status(error):
    for name in ("status", "status_code", "code"):
        value = getattr(error, name, None)
        try:
            return int(value)
        except (TypeError, ValueError):
            pass
    return None


class R2BindingStore:
    """Direct, strongly consistent R2 access through a Worker binding.

    R2's raw ``etag`` is preserved as the CAS token. ``httpEtag`` is only a
    presentation header and never enters the publication protocol.
    """

    def __init__(self, bucket, prefix="", *, max_list_pages=10_000):
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        if self.prefix:
            validate_key(self.prefix)
        if type(max_list_pages) is not int or max_list_pages < 1:
            raise ValueError("R2 list page budget")
        self.max_list_pages = max_list_pages

    def _key(self, key):
        key = validate_key(key)
        physical = f"{self.prefix}/{key}" if self.prefix else key
        if len(physical.encode("ascii")) > 1024:
            raise ValueError("R2 object key exceeds 1024 bytes")
        return physical

    def _list_prefix(self, prefix):
        if not isinstance(prefix, str):
            raise ValueError("bad list prefix")
        trailing = prefix.endswith("/")
        logical = prefix[:-1] if trailing else prefix
        if logical:
            validate_key(logical)
        physical = f"{self.prefix}/" if self.prefix else ""
        if logical:
            physical += logical
        if trailing:
            physical += "/"
        if len(physical.encode("ascii")) > 1024:
            raise ValueError("R2 list prefix exceeds 1024 bytes")
        return physical

    def _logical(self, physical):
        base = f"{self.prefix}/" if self.prefix else ""
        try:
            oversized = len(physical.encode("ascii")) > 1024
        except UnicodeEncodeError as error:
            raise StoreError("R2 returned an invalid logical key") from error
        if oversized:
            raise StoreError("R2 returned an invalid logical key")
        if not physical.startswith(base):
            raise StoreError("R2 returned a key outside the configured prefix")
        logical = physical[len(base):]
        try:
            return validate_key(logical)
        except (TypeError, ValueError) as error:
            raise StoreError("R2 returned an invalid logical key") from error

    @staticmethod
    def _page_objects(values, limit):
        """Consume at most one object beyond the native LIST page budget."""
        try:
            iterator = iter(values)
        except TypeError as error:
            raise StoreError("R2 LIST objects are not iterable") from error
        objects = []
        try:
            for _ in range(limit + 1):
                objects.append(next(iterator))
        except StopIteration:
            pass
        except Exception as error:
            raise StoreError("R2 LIST object iteration failed") from error
        if len(objects) > limit:
            raise StoreError("R2 LIST exceeded the requested page limit")
        return tuple(objects)

    @staticmethod
    async def _bytes(obj):
        value = await obj.arrayBuffer()
        if hasattr(value, "to_py"):
            value = value.to_py()
        return bytes(value)

    @classmethod
    async def _bounded_bytes(cls, obj, max_bytes):
        size = getattr(obj, "size", None)
        if size is None:
            raise StoreError("R2 response has no size")
        if type(size) is not int or size < 0:
            raise StoreError("R2 response has invalid size")
        if size > max_bytes:
            raise PayloadTooLarge("R2 response exceeds byte limit")
        value = await cls._bytes(obj)
        if len(value) > max_bytes:
            raise PayloadTooLarge("R2 response exceeds byte limit")
        if len(value) != size:
            raise StoreError("R2 response size mismatch")
        return value

    async def get(self, key):
        limit = MAX_ROOT_BYTES if key == "root" else MAX_OBJECT_BYTES
        return await self.get_bounded(key, limit)

    async def get_bounded(self, key, max_bytes):
        """Reject a known oversized R2 body before allocating its ArrayBuffer."""
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_OBJECT_BYTES:
            raise ValueError("R2 read byte limit")
        try:
            obj = await self.bucket.get(self._key(key))
            if obj is None:
                return None
            return await self._bounded_bytes(obj, max_bytes)
        except (PayloadTooLarge, StoreError):
            raise
        except Exception as error:
            raise StoreError(f"R2 read failed for {key}") from error

    async def read_versioned(self, key):
        try:
            obj = await self.bucket.get(self._key(key))
            if obj is None:
                return ABSENT
            limit = MAX_ROOT_BYTES if key == "root" else MAX_OBJECT_BYTES
            return Versioned(
                await self._bounded_bytes(obj, limit), self._token(obj))
        except (PayloadTooLarge, StoreError):
            raise
        except Exception as error:
            raise StoreError(
                f"R2 versioned read failed for {key}") from error

    async def has(self, key):
        try:
            return await self.bucket.head(self._key(key)) is not None
        except Exception as error:
            raise StoreError(f"R2 head failed for {key}") from error

    @staticmethod
    def _token(obj):
        value = getattr(obj, "etag", None)
        # Pyodide converts JavaScript primitive strings at the binding
        # boundary. Do not stringify arbitrary proxies or malformed provider
        # values: that would fabricate a CAS token which R2 never returned.
        if not isinstance(value, str) \
                or not value or value.startswith("W/"):
            raise StoreError("R2 response has no usable strong ETag")
        return VersionToken(value)

    @staticmethod
    def _mutation_error(key, error):
        if _status(error) == 429:
            return RetryableStoreError(f"R2 throttled mutation for {key}")
        return OutcomeUnknown(f"R2 mutation outcome unknown for {key}")

    async def _put(self, key, value, **options):
        try:
            return await self.bucket.put(
                self._key(key), value,
                sha256=bytes.fromhex(h(value)), **options)
        except Exception as error:
            raise self._mutation_error(key, error) from error

    async def put(self, key, value):
        if authoritative_key(key):
            raise ValueError("authoritative keys require conditional writes")
        result = await self._put(key, value)
        if result is None:
            raise OutcomeUnknown(f"R2 returned no mutation result for {key}")

    async def put_if_absent(self, key, value):
        if key == "root" or key.startswith("root/"):
            raise ValueError("root requires compare-and-swap")
        if key == "obj" or key.startswith("obj/") and key[4:] != h(value):
            raise ValueError("immutable object address")
        result = await self._put(
            key, value, onlyIf=_if_none_match())
        return CREATED if result is not None else EXISTS

    async def cas(self, key, token, value):
        if key != "root":
            raise ValueError("only root is mutable by CAS")
        if token is ABSENT:
            condition = _if_none_match()
        elif isinstance(token, VersionToken):
            condition = {"etagMatches": token.value}
        else:
            raise TypeError("version token")
        result = await self._put(
            key, value, onlyIf=condition)
        return STALE if result is None else Applied(self._token(result))

    async def list_page(self, prefix, cursor=None, limit=1000):
        """Issue exactly one bounded native R2 LIST request."""
        if type(limit) is not int or not 0 < limit <= 1000:
            raise ValueError("R2 list page limit")
        if cursor is not None and (
                not isinstance(cursor, str) or not cursor):
            raise ValueError("R2 list cursor")
        physical = self._list_prefix(prefix)
        try:
            options = {"prefix": physical, "limit": limit}
            if cursor is not None:
                options["cursor"] = cursor
            page = await self.bucket.list(**options)
            objects = self._page_objects(page.objects, limit)
            truncated = page.truncated
            next_cursor = page.cursor
        except StoreError:
            raise
        except Exception as error:
            raise StoreError(
                f"R2 list failed for {prefix}") from error
        keys = set()
        for obj in objects:
            key = getattr(obj, "key", None)
            if not isinstance(key, str):
                raise StoreError("R2 LIST returned a non-string key")
            if not key.startswith(physical):
                raise StoreError(
                    "R2 LIST returned an out-of-prefix key")
            keys.add(self._logical(key))
        keys = tuple(sorted(keys))
        if not isinstance(truncated, bool):
            raise StoreError("R2 LIST returned invalid truncation")
        if not truncated:
            return ListPage(keys, None)
        if not isinstance(next_cursor, str) \
                or not next_cursor or next_cursor == cursor:
            raise StoreError("R2 LIST returned a repeated cursor")
        return ListPage(keys, next_cursor)

    async def list(self, prefix):
        """Compatibility/admin helper; receiving code uses ``list_page``."""
        cursor, out = None, set()
        for _ in range(self.max_list_pages):
            page = await self.list_page(prefix, cursor, 1000)
            out.update(page.keys)
            if page.cursor is None:
                return sorted(out)
            cursor = page.cursor
        raise StoreError("R2 LIST exceeded page budget")

    async def delete(self, key):
        if authoritative_key(key):
            raise ValueError("authoritative keys are not deletable")
        try:
            await self.bucket.delete(self._key(key))
        except Exception as error:
            raise self._mutation_error(key, error) from error
