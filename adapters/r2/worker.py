"""Cloudflare Worker R2-binding implementation of AsyncObjectStore."""
from core.crypto import h
from core.limits import (
    MAX_DIRECT_OBJECT_BYTES,
    MAX_DIRECT_STREAM_FRAGMENTS,
    MAX_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    MAX_STORE_READ_BYTES,
    PayloadTooLarge,
)
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    MAX_PROVIDER_KEY_BYTES,
    SINGLETON_CAS_KEYS,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    StoreError,
    UNCHANGED,
    Versioned,
    VersionToken,
    authoritative_key,
    mutable_key,
    validate_create,
    validate_key,
    validate_store_prefix,
)
from core.shape import valid_fid
from .listing import list_page as _list_page


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
            validate_store_prefix(self.prefix)
        if type(max_list_pages) is not int or max_list_pages < 1:
            raise ValueError("R2 list page budget")
        self.max_list_pages = max_list_pages

    def namespace_id(self):
        return "r2-binding", id(self.bucket), self.prefix

    def _key(self, key):
        key = validate_key(key)
        physical = f"{self.prefix}/{key}" if self.prefix else key
        if len(physical.encode("ascii")) > MAX_PROVIDER_KEY_BYTES:
            raise ValueError("R2 object key exceeds 1024 bytes")
        return physical

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

    @staticmethod
    def _chunk_bytes(value):
        if hasattr(value, "to_bytes"):
            value = value.to_bytes()
        elif hasattr(value, "to_py"):
            value = value.to_py()
        try:
            return bytes(value)
        except (TypeError, ValueError) as error:
            raise StoreError("R2 response stream chunk is not bytes") \
                from error

    @classmethod
    async def _copy_body(cls, obj, max_bytes, write):
        size = getattr(obj, "size", None)
        if type(size) is not int or size < 0:
            raise StoreError("R2 response has invalid size")
        if size > max_bytes:
            raise PayloadTooLarge("R2 response exceeds byte limit")
        stream = getattr(obj, "body", None)
        if stream is None or not callable(getattr(stream, "getReader", None)):
            raise StoreError("R2 response has no readable stream")
        reader = stream.getReader()
        total = 0
        try:
            for _ in range(MAX_DIRECT_STREAM_FRAGMENTS):
                result = await reader.read()
                if not isinstance(getattr(result, "done", None), bool):
                    raise StoreError("R2 response stream result")
                if result.done:
                    if total != size:
                        raise StoreError("R2 response size mismatch")
                    return total
                chunk = cls._chunk_bytes(getattr(result, "value", None))
                total += len(chunk)
                if total > size:
                    raise StoreError("R2 response size mismatch")
                if total > max_bytes:
                    raise PayloadTooLarge("R2 response exceeds byte limit")
                write(chunk)
            raise StoreError("R2 response exceeded fragment budget")
        finally:
            release = getattr(reader, "releaseLock", None)
            if callable(release):
                release()

    async def get(self, key):
        limit = MAX_ROOT_BYTES \
            if key in SINGLETON_CAS_KEYS else MAX_OBJECT_BYTES
        return await self.get_bounded(key, limit)

    async def get_bounded(self, key, max_bytes):
        """Reject a known oversized R2 body before allocating its ArrayBuffer."""
        if type(max_bytes) is not int \
                or not 0 < max_bytes <= MAX_STORE_READ_BYTES:
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

    async def copy_pile_object(self, oid, max_bytes, write):
        """Stream one large signed pile without allocating an ArrayBuffer."""
        if not valid_fid(oid) or type(max_bytes) is not int \
                or not 0 < max_bytes <= MAX_DIRECT_OBJECT_BYTES \
                or not callable(write):
            raise ValueError("R2 pile copy")
        try:
            obj = await self.bucket.get(self._key("obj/" + oid))
            if obj is None:
                return None
            return await self._copy_body(obj, max_bytes, write)
        except (PayloadTooLarge, StoreError):
            raise
        except Exception as error:
            raise StoreError("R2 pile read failed") from error

    async def read_versioned(self, key):
        try:
            obj = await self.bucket.get(self._key(key))
            if obj is None:
                return ABSENT
            limit = MAX_ROOT_BYTES \
                if key in SINGLETON_CAS_KEYS else MAX_OBJECT_BYTES
            return Versioned(
                await self._bounded_bytes(obj, limit), self._token(obj))
        except (PayloadTooLarge, StoreError):
            raise
        except Exception as error:
            raise StoreError(
                f"R2 versioned read failed for {key}") from error

    async def read_versioned_if_changed(self, key, token):
        """Use R2Conditional so a warm gate does not download root bytes."""
        if not isinstance(token, VersionToken):
            raise TypeError("R2 conditional read token")
        try:
            obj = await self.bucket.get(self._key(key), {
                "onlyIf": {"etagDoesNotMatch": token.value},
            })
            if obj is None:
                return ABSENT
            if getattr(obj, "body", None) is None:
                current = self._token(obj)
                if current != token:
                    raise StoreError("R2 conditional response token changed")
                return UNCHANGED
            limit = MAX_ROOT_BYTES \
                if key in SINGLETON_CAS_KEYS else MAX_OBJECT_BYTES
            return Versioned(
                await self._bounded_bytes(obj, limit), self._token(obj))
        except (PayloadTooLarge, StoreError):
            raise
        except Exception as error:
            raise StoreError(
                f"R2 conditional read failed for {key}") from error

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
        key = validate_create(key, value)
        result = await self._put(
            key, value, onlyIf=_if_none_match())
        return CREATED if result is not None else EXISTS

    async def cas(self, key, token, value):
        if not mutable_key(key):
            raise ValueError("key is not a CAS register")
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
        return await _list_page(
            self.bucket, self.prefix, prefix, cursor, limit)

    async def list(self, prefix):
        """Administrative full traversal; receiving code uses ``list_page``."""
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
