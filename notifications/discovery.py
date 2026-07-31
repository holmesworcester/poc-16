"""Bounded post-publication discovery over authenticated FactTree diffs.

The repository remains unaware of notifications.  A separate operational
store retains old root bytes as immutable objects and uses its own ``root``
CAS register for one small cursor.  Carrier acceptance precedes cursor
progress, so crashes and races can duplicate an exact hint but cannot skip it.
"""
from dataclasses import dataclass
import facts

from core import indexes, merkle_map, snapshot
from core.crypto import h
from core.fact import canon
from core.fact_index import TYPE_INDEX
from core.limits import (
    MAX_MERKLE_PAGE_BYTES,
    MAX_ROOT_BYTES,
    PayloadTooLarge,
    decode_json,
)
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    STALE,
    Applied,
    OutcomeUnknown,
    Versioned,
    async_store,
    store_namespace,
)
from core.repository_reader import RepositoryReader
from core.shape import valid_fid

from .carrier import Carrier, CarrierAccepted
from .hints import NotificationHint, encode_hint, hint_id


CURSOR_FORMAT = "notification-cursor-v2"
MAX_CURSOR_BYTES = 4 * 1024


@dataclass(frozen=True, slots=True)
class Cursor:
    workspace: str
    owner: str
    base: str | None = None
    target: str | None = None
    after: str | None = None

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.owner) \
                or self.base is not None and not valid_fid(self.base) \
                or self.target is not None and not valid_fid(self.target) \
                or self.after is not None and self.target is None \
                or self.target is not None and self.target == self.base:
            raise ValueError("notification cursor")
        try:
            if self.after is not None:
                merkle_map.checked_query_key(self.after)
        except ValueError as error:
            raise ValueError("notification cursor") from error


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    status: str
    target: str | None = None
    continuation: str | None = None
    hint_id: str | None = None


def encode_cursor(cursor):
    if not isinstance(cursor, Cursor):
        raise TypeError("notification cursor")
    raw = canon({
        "after": cursor.after,
        "base": cursor.base,
        "format": CURSOR_FORMAT,
        "owner": cursor.owner,
        "target": cursor.target,
        "workspace": cursor.workspace,
    })
    if len(raw) > MAX_CURSOR_BYTES:
        raise ValueError("notification cursor too large")
    return raw


def decode_cursor(raw):
    value = decode_json(raw, MAX_CURSOR_BYTES, "notification cursor")
    if not isinstance(value, dict) or set(value) != {
            "after", "base", "format", "owner", "target", "workspace"} \
            or value.get("format") != CURSOR_FORMAT:
        raise ValueError("notification cursor shape")
    cursor = Cursor(
        value.get("workspace"), value.get("owner"), value.get("base"),
        value.get("target"), value.get("after"))
    if encode_cursor(cursor) != raw:
        raise ValueError("notification cursor encoding")
    return cursor


class NotificationDiscovery:
    """Publish at most one bounded FactTree-diff page per invocation.

    An absent cursor deliberately starts at the empty map: first activation
    backfills every historical trigger. Later deployments must preserve the
    cursor store if they do not want activation to repeat that backfill.
    """

    def __init__(
            self, repository_store, cursor_store, workspace, carrier, *,
            owner, page_rows=merkle_map.MAX_RANGE_ROWS):
        repository_namespace = store_namespace(repository_store)
        cursor_namespace = store_namespace(cursor_store)
        if not valid_fid(workspace) or not valid_fid(owner) \
                or repository_store is cursor_store \
                or repository_namespace is not None \
                and repository_namespace == cursor_namespace \
                or not callable(getattr(carrier, "publish", None)) \
                or type(page_rows) is not int \
                or not 1 <= page_rows <= merkle_map.MAX_RANGE_ROWS:
            raise ValueError("notification discovery")
        self.repository_store = async_store(repository_store)
        self.cursor_store = async_store(cursor_store)
        self.workspace = workspace
        self.owner = owner
        self.carrier = carrier
        self.page_rows = page_rows

    @staticmethod
    async def _get(store, key, maximum):
        raw = await store.get_bounded(key, maximum)
        if raw is not None and (
                not isinstance(raw, bytes) or len(raw) > maximum):
            raise PayloadTooLarge("notification read exceeds byte limit")
        return raw

    async def _root(self, store, oid):
        raw = await self._get(store, "obj/" + oid, MAX_ROOT_BYTES)
        if not isinstance(raw, bytes) or h(raw) != oid:
            raise ValueError("notification root object")
        return raw

    async def _ensure_root(self, raw):
        oid, key = h(raw), "obj/" + h(raw)
        unknown = None
        for _ in range(2):
            try:
                result = await self.cursor_store.put_if_absent(key, raw)
            except OutcomeUnknown as error:
                unknown = error
            else:
                if result not in {CREATED, EXISTS}:
                    raise TypeError("notification root create result")
            incumbent = await self._get(
                self.cursor_store, key, MAX_ROOT_BYTES)
            if incumbent == raw:
                return oid
            if incumbent is not None:
                raise ValueError("notification root conflict")
        raise unknown or OSError("notification root was not preserved")

    async def _read_cursor(self):
        current = await self.cursor_store.read_versioned("root")
        if current is ABSENT:
            return Cursor(self.workspace, self.owner), ABSENT
        if not isinstance(current, Versioned):
            raise TypeError("notification cursor read")
        cursor = decode_cursor(current.value)
        if cursor.workspace != self.workspace or cursor.owner != self.owner:
            raise ValueError("notification cursor owner")
        return cursor, current.token

    async def _pin(self, cursor, token):
        current = await self.repository_store.read_versioned("root")
        if current is ABSENT:
            return cursor, token, DiscoveryResult("idle")
        if not isinstance(current, Versioned):
            raise TypeError("repository root read")
        RepositoryReader(self.workspace, current.value, lambda _oid: None)
        oid = await self._ensure_root(current.value)
        if oid == cursor.base:
            return cursor, token, DiscoveryResult("idle", oid)
        pinned = Cursor(self.workspace, self.owner, cursor.base, oid)
        result = await self.cursor_store.cas(
            "root", token, encode_cursor(pinned))
        if result is STALE:
            return cursor, token, DiscoveryResult("raced", oid)
        if not isinstance(result, Applied):
            raise TypeError("notification cursor CAS")
        return pinned, result.token, None

    @staticmethod
    def _map_reader(root, fetch):
        descriptor = root.maps[indexes.FACT]
        return merkle_map.Reader(
            descriptor["root"], root.layout_seed, fetch,
            max_page_depth=descriptor["depth"],
            expected_count=descriptor["count"],
            expected_depth=descriptor["depth"],
        )

    async def _page(self, cursor):
        target_raw = await self._root(
            self.cursor_store, cursor.target)
        target = RepositoryReader(
            self.workspace, target_raw, lambda _oid: None)
        target_root = target.root
        if cursor.base is None:
            base_descriptor = snapshot.empty_descriptor()
        else:
            base_raw = await self._root(
                self.cursor_store, cursor.base)
            base_root = RepositoryReader(
                self.workspace, base_raw, lambda _oid: None).root
            base_descriptor = base_root.maps[indexes.FACT]

        target_descriptor = target_root.maps[indexes.FACT]
        if target_descriptor["count"] < base_descriptor["count"]:
            raise ValueError("notification FactTree is not monotone")

        async def fetch(oid):
            return await self._get(
                self.repository_store, "obj/" + oid,
                MAX_MERKLE_PAGE_BYTES)

        remote = self._map_reader(target_root, fetch)
        local = merkle_map.Reader(
            base_descriptor["root"], target_root.layout_seed, fetch,
            max_page_depth=base_descriptor["depth"],
            expected_count=base_descriptor["count"],
            expected_depth=base_descriptor["depth"],
        )
        type_start = indexes.posting_prefix(TYPE_INDEX)
        page = await remote.diff_page_awaited(
            local,
            start=type_start,
            stop=type_start + "\uffff",
            after=cursor.after,
            limit=self.page_rows,
        )

        discovered = []
        for key, value in page.differing:
            if not indexes.is_posting_key(key):
                continue
            row = indexes.decode_posting_key(key)
            if value != {"state": indexes.POSTING_VALUE, "fid": row.fid}:
                raise ValueError("notification FactTree posting")
            family = facts.family_for(row.k0) \
                if row.kind == TYPE_INDEX and row.k1 == "" else None
            if family is not None \
                    and getattr(family, "notification_trigger", None) \
                    is not None:
                discovered.append(row.fid)
        return page.cursor, tuple(sorted(discovered))

    async def run_once(self):
        cursor, token = await self._read_cursor()
        if cursor.target is None:
            cursor, token, result = await self._pin(cursor, token)
            if result is not None:
                return result

        continuation, fids = await self._page(cursor)
        emitted = None
        if fids:
            hint = NotificationHint(self.workspace, cursor.target, fids)
            accepted = await self.carrier.publish(encode_hint(hint))
            if not isinstance(accepted, CarrierAccepted):
                raise TypeError("notification carrier did not accept hint")
            emitted = hint_id(hint)

        advanced = Cursor(
            self.workspace,
            self.owner,
            cursor.target if continuation is None else cursor.base,
            None if continuation is None else cursor.target,
            continuation,
        )
        result = await self.cursor_store.cas(
            "root", token, encode_cursor(advanced))
        if result is STALE:
            return DiscoveryResult(
                "raced", cursor.target, continuation, emitted)
        if not isinstance(result, Applied):
            raise TypeError("notification cursor CAS")
        return DiscoveryResult(
            "published" if emitted is not None else "advanced",
            cursor.target, continuation, emitted)


__all__ = (
    "Cursor",
    "DiscoveryResult",
    "NotificationDiscovery",
    "decode_cursor",
    "encode_cursor",
)
