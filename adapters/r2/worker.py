"""Cloudflare Worker R2-binding implementation of AsyncObjectStore."""
from core.crypto import h
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    StoreError,
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
        return f"{self.prefix}/{key}" if self.prefix else key

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
        return physical

    def _logical(self, physical):
        base = f"{self.prefix}/" if self.prefix else ""
        if not physical.startswith(base):
            raise StoreError("R2 returned a key outside the configured prefix")
        return physical[len(base):]

    @staticmethod
    async def _bytes(obj):
        value = await obj.arrayBuffer()
        if hasattr(value, "to_py"):
            value = value.to_py()
        return bytes(value)

    async def get(self, key):
        try:
            obj = await self.bucket.get(self._key(key))
            return None if obj is None else await self._bytes(obj)
        except StoreError:
            raise
        except Exception as error:
            raise StoreError(f"R2 read failed for {key}") from error

    async def read_versioned(self, key):
        try:
            obj = await self.bucket.get(self._key(key))
            if obj is None:
                return ABSENT
            return Versioned(
                await self._bytes(obj), self._token(obj))
        except StoreError:
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
        if value is None:
            raise StoreError("R2 response has no ETag")
        value = str(value)
        if not value:
            raise StoreError("R2 response has no ETag")
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

    async def list(self, prefix):
        physical, cursor, out = self._list_prefix(prefix), None, []
        for _ in range(self.max_list_pages):
            try:
                options = {"prefix": physical, "limit": 1000}
                if cursor is not None:
                    options["cursor"] = cursor
                page = await self.bucket.list(**options)
                objects = tuple(page.objects)
                truncated = page.truncated
                next_cursor = page.cursor
            except Exception as error:
                raise StoreError(
                    f"R2 list failed for {prefix}") from error
            out.extend(self._logical(str(obj.key)) for obj in objects)
            if not truncated:
                return sorted(out)
            if next_cursor is None:
                raise StoreError("R2 LIST returned no cursor")
            next_cursor = str(next_cursor)
            if not next_cursor or next_cursor == cursor:
                raise StoreError("R2 LIST returned a repeated cursor")
            cursor = next_cursor
        raise StoreError("R2 LIST exceeded page budget")

    async def delete(self, key):
        if authoritative_key(key):
            raise ValueError("authoritative keys are not deletable")
        try:
            await self.bucket.delete(self._key(key))
        except Exception as error:
            raise self._mutation_error(key, error) from error
