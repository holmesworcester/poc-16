"""Shared, bounded R2 LIST decoding for read-only and writable bindings."""

from core.object_store import (
    ListPage,
    MAX_PROVIDER_KEY_BYTES,
    StoreError,
    validate_key,
)


def _physical_prefix(configured_prefix, prefix):
    if not isinstance(prefix, str):
        raise ValueError("bad list prefix")
    trailing = prefix.endswith("/")
    logical = prefix[:-1] if trailing else prefix
    if logical:
        validate_key(logical)
    physical = f"{configured_prefix}/" if configured_prefix else ""
    if logical:
        physical += logical
    if trailing:
        physical += "/"
    if len(physical.encode("ascii")) > MAX_PROVIDER_KEY_BYTES:
        raise ValueError("R2 list prefix exceeds 1024 bytes")
    return physical


def _logical_key(configured_prefix, physical):
    base = f"{configured_prefix}/" if configured_prefix else ""
    try:
        oversized = len(physical.encode("ascii")) > MAX_PROVIDER_KEY_BYTES
    except (AttributeError, UnicodeEncodeError) as error:
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


async def list_page(bucket, configured_prefix, prefix, cursor=None, limit=1000):
    """Issue exactly one bounded native R2 LIST request."""
    if type(limit) is not int or not 0 < limit <= 1000:
        raise ValueError("R2 list page limit")
    if cursor is not None and (
            not isinstance(cursor, str) or not cursor):
        raise ValueError("R2 list cursor")
    physical = _physical_prefix(configured_prefix, prefix)
    try:
        options = {"prefix": physical, "limit": limit}
        if cursor is not None:
            options["cursor"] = cursor
        page = await bucket.list(**options)
        objects = _page_objects(page.objects, limit)
        truncated = page.truncated
        next_cursor = page.cursor
    except StoreError:
        raise
    except Exception as error:
        raise StoreError(f"R2 list failed for {prefix}") from error
    keys = set()
    for obj in objects:
        key = getattr(obj, "key", None)
        if not isinstance(key, str):
            raise StoreError("R2 LIST returned a non-string key")
        if not key.startswith(physical):
            raise StoreError("R2 LIST returned an out-of-prefix key")
        keys.add(_logical_key(configured_prefix, key))
    keys = tuple(sorted(keys))
    if not isinstance(truncated, bool):
        raise StoreError("R2 LIST returned invalid truncation")
    if not truncated:
        return ListPage(keys, None)
    if not isinstance(next_cursor, str) \
            or not next_cursor or next_cursor == cursor:
        raise StoreError("R2 LIST returned a repeated cursor")
    return ListPage(keys, next_cursor)


__all__ = ("list_page",)
