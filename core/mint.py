"""SQLite-free request authorization over one authenticated composite root."""

from .crypto import h
from .worker import WorkerView


class _ObjectMiss(BaseException):
    """Control flow from the synchronous verifier to its async object source."""

    __slots__ = ("oid",)

    def __init__(self, oid):
        super().__init__(oid)
        self.oid = oid


def stateless(
        pile_bytes, root_bytes, fetch, now, view=None, *,
        purpose="sync"):
    """Authorize a bounded request closure using exact authenticated reads.

    A caller may cache ``WorkerView`` only while its root ETag matches. Cold
    and changed-root reads construct a lightweight view; neither path scans a
    tree or reconstructs SQLite.
    """
    if isinstance(view, WorkerView) and view.etag == h(root_bytes):
        return view.mint(pile_bytes, now, purpose=purpose)
    try:
        return WorkerView.from_root(root_bytes, fetch).mint(
            pile_bytes, now, purpose=purpose)
    except Exception:
        return None


async def async_stateless(
        pile_bytes, root_bytes, fetch, now, *,
        max_unique_fetches, max_fetch_bytes, purpose="sync"):
    """Authorize against one pinned root using an awaited immutable reader.

    ``stateless`` and ``WorkerView`` remain the only verifier and policy path.
    The synchronous fetch they receive can only read this request's cache.  A
    cache miss escapes their fail-closed ``Exception`` boundaries, is awaited
    here exactly once, and then causes the same deterministic decision to be
    retried.  Root bytes are supplied once by the host and are never fetched
    or repinned by this driver.
    """
    if type(max_unique_fetches) is not int or max_unique_fetches < 0:
        raise ValueError("async mint unique-fetch budget")
    if type(max_fetch_bytes) is not int or max_fetch_bytes < 0:
        raise ValueError("async mint byte budget")

    cache = {}
    fetched_bytes = 0

    def cached_fetch(oid):
        if oid not in cache:
            raise _ObjectMiss(oid)
        return cache[oid]

    while True:
        try:
            return stateless(
                pile_bytes, root_bytes, cached_fetch, now,
                purpose=purpose)
        except _ObjectMiss as miss:
            oid = miss.oid

        if oid in cache:
            return None
        if len(cache) >= max_unique_fetches:
            return None
        try:
            raw = await fetch(oid)
        except Exception:
            return None
        if raw is not None and not isinstance(raw, bytes):
            return None
        fetched_bytes += len(raw) if raw is not None else 0
        if fetched_bytes > max_fetch_bytes:
            return None
        cache[oid] = raw
