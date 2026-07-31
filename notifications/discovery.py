"""Bounded post-publication discovery over authenticated FactTree diffs.

The repository remains unaware of notifications.  A separate operational
store retains old root bytes as immutable objects and uses its own ``root``
CAS register for one small cursor. The cursor retains one exact pending hint
until a worker records terminal completion. Carriers merely wake workers.
"""
from dataclasses import dataclass
import secrets
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
    STALE,
    Applied,
    OutcomeUnknown,
    Versioned,
    async_store,
    ensure_object_async,
    store_namespace,
)
from core.repository_reader import RepositoryReader
from core.shape import valid_fid

from .carrier import CarrierAccepted
from .hints import (
    MAX_HINT_BYTES,
    NotificationHint,
    decode_hint,
    encode_hint,
)


CURSOR_FORMAT = "notification-cursor-v3"
MAX_CURSOR_BYTES = 8 * 1024
BOOTSTRAP_CURRENT = "current"
BOOTSTRAP_BACKFILL = "backfill"
PENDING_CURRENT = "current"
PENDING_NONCURRENT = "noncurrent"
PENDING_RETRY = "retry"


class CursorNotInitialized(RuntimeError):
    """Discovery requires an explicit current or backfill bootstrap."""


@dataclass(frozen=True, slots=True)
class Pending:
    oid: str
    base: str | None
    target: str | None
    after: str | None

    def __post_init__(self):
        if not valid_fid(self.oid) \
                or self.base is not None and not valid_fid(self.base) \
                or self.target is not None and not valid_fid(self.target) \
                or self.after is not None and self.target is None:
            raise ValueError("notification pending")
        if self.target is not None and self.target == self.base:
            raise ValueError("notification pending")
        try:
            if self.after is not None:
                merkle_map.checked_query_key(self.after)
        except ValueError as error:
            raise ValueError("notification pending") from error


@dataclass(frozen=True, slots=True)
class Cursor:
    workspace: str
    owner: str
    generation: str
    bootstrap: str
    base: str | None = None
    target: str | None = None
    after: str | None = None
    pending: Pending | None = None

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.owner) \
                or not valid_fid(self.generation) \
                or self.bootstrap not in {
                    BOOTSTRAP_CURRENT, BOOTSTRAP_BACKFILL} \
                or self.base is not None and not valid_fid(self.base) \
                or self.target is not None and not valid_fid(self.target) \
                or self.after is not None and self.target is None \
                or self.target is not None and self.target == self.base \
                or self.pending is not None and (
                    not isinstance(self.pending, Pending)
                    or self.target is None):
            raise ValueError("notification cursor")
        try:
            if self.after is not None:
                merkle_map.checked_query_key(self.after)
        except ValueError as error:
            raise ValueError("notification cursor") from error
        pending = self.pending
        if pending is not None:
            continuation = pending.target is not None
            if continuation and (
                    pending.base != self.base
                    or pending.target != self.target
                    or pending.after is None
                    or self.after is not None
                    and pending.after <= self.after) \
                    or not continuation and (
                        pending.base != self.target
                        or pending.after is not None):
                raise ValueError("notification pending successor")

    def advance(self):
        if self.pending is None:
            raise ValueError("notification cursor is not pending")
        return Cursor(
            self.workspace, self.owner, self.generation, self.bootstrap,
            self.pending.base, self.pending.target, self.pending.after)


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    status: str
    target: str | None = None
    continuation: str | None = None
    hint_oid: str | None = None


def encode_cursor(cursor):
    if not isinstance(cursor, Cursor):
        raise TypeError("notification cursor")
    pending = None if cursor.pending is None else {
        "after": cursor.pending.after,
        "base": cursor.pending.base,
        "oid": cursor.pending.oid,
        "target": cursor.pending.target,
    }
    raw = canon({
        "after": cursor.after,
        "base": cursor.base,
        "bootstrap": cursor.bootstrap,
        "format": CURSOR_FORMAT,
        "generation": cursor.generation,
        "owner": cursor.owner,
        "pending": pending,
        "target": cursor.target,
        "workspace": cursor.workspace,
    })
    if len(raw) > MAX_CURSOR_BYTES:
        raise ValueError("notification cursor too large")
    return raw


def decode_cursor(raw):
    value = decode_json(raw, MAX_CURSOR_BYTES, "notification cursor")
    if not isinstance(value, dict) or set(value) != {
            "after", "base", "bootstrap", "format", "generation", "owner",
            "pending", "target", "workspace"} \
            or value.get("format") != CURSOR_FORMAT:
        raise ValueError("notification cursor shape")
    raw_pending = value.get("pending")
    if raw_pending is not None and (
            not isinstance(raw_pending, dict) or set(raw_pending) != {
                "after", "base", "oid", "target"}):
        raise ValueError("notification pending shape")
    pending = None if raw_pending is None else Pending(
        raw_pending.get("oid"), raw_pending.get("base"),
        raw_pending.get("target"),
        raw_pending.get("after"))
    cursor = Cursor(
        value.get("workspace"), value.get("owner"),
        value.get("generation"), value.get("bootstrap"), value.get("base"),
        value.get("target"), value.get("after"), pending)
    if encode_cursor(cursor) != raw:
        raise ValueError("notification cursor encoding")
    return cursor


class NotificationState:
    """The worker's narrow capability over one notification cursor store."""

    def __init__(self, store, workspace, owner):
        if not valid_fid(workspace) or not valid_fid(owner):
            raise ValueError("notification state")
        self.store = async_store(store)
        self.workspace = workspace
        self.owner = owner

    async def get_bounded(self, key, maximum):
        raw = await self.store.get_bounded(key, maximum)
        if raw is not None and (
                not isinstance(raw, bytes) or len(raw) > maximum):
            raise PayloadTooLarge("notification read exceeds byte limit")
        return raw

    async def _read(self):
        current = await self.store.read_versioned("root")
        if current is ABSENT:
            return None, ABSENT
        if not isinstance(current, Versioned):
            raise TypeError("notification cursor read")
        cursor = decode_cursor(current.value)
        if cursor.workspace != self.workspace or cursor.owner != self.owner:
            raise ValueError("notification cursor owner")
        return cursor, current.token

    @staticmethod
    def _classify(cursor, oid):
        return PENDING_CURRENT if cursor is not None \
            and cursor.pending is not None \
            and cursor.pending.oid == oid else PENDING_NONCURRENT

    @staticmethod
    def _validate(oid):
        if not valid_fid(oid):
            raise ValueError("notification pending identity")

    async def pending(self, oid):
        """Classify an exact carrier body against durable pending state."""
        self._validate(oid)
        cursor, _token = await self._read()
        return self._classify(cursor, oid)

    async def complete(self, oid):
        """Advance only the exact pending hint after terminal worker output."""
        self._validate(oid)
        cursor, token = await self._read()
        if self._classify(cursor, oid) != PENDING_CURRENT:
            return PENDING_NONCURRENT
        try:
            result = await self.store.cas(
                "root", token, encode_cursor(cursor.advance()))
        except OutcomeUnknown:
            pass
        else:
            if isinstance(result, Applied):
                return PENDING_NONCURRENT
            if result is not STALE:
                raise TypeError("notification completion CAS")
        current, _token = await self._read()
        return PENDING_RETRY if self._classify(
            current, oid) == PENDING_CURRENT else PENDING_NONCURRENT


class NotificationDiscovery:
    """Publish at most one bounded FactTree-diff page per invocation.

    Bootstrap is explicit. Every fair invocation republishes durable pending
    work; only :class:`NotificationState` may advance it after worker success.
    """

    def __init__(
            self, repository_store, cursor_store, workspace, carrier, *,
            owner, page_rows=merkle_map.MAX_RANGE_ROWS,
            generation_factory=None):
        repository_namespace = store_namespace(repository_store)
        cursor_namespace = store_namespace(cursor_store)
        if not valid_fid(workspace) or not valid_fid(owner) \
                or repository_store is cursor_store \
                or repository_namespace is not None \
                and repository_namespace == cursor_namespace \
                or not callable(getattr(carrier, "publish", None)) \
                or generation_factory is not None \
                and not callable(generation_factory) \
                or type(page_rows) is not int \
                or not 1 <= page_rows <= merkle_map.MAX_RANGE_ROWS:
            raise ValueError("notification discovery")
        self.repository_store = async_store(repository_store)
        self.cursor_store = async_store(cursor_store)
        self.workspace = workspace
        self.owner = owner
        self.carrier = carrier
        self.page_rows = page_rows
        self.generation_factory = generation_factory \
            or (lambda: secrets.token_hex(32))
        self.state = NotificationState(cursor_store, workspace, owner)

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

    async def _ensure_object(self, raw, maximum):
        if not isinstance(raw, bytes) or len(raw) > maximum:
            raise ValueError("notification immutable object")
        oid = h(raw)
        await ensure_object_async(self.cursor_store, oid, raw)
        return oid

    async def _read_cursor(self):
        cursor, token = await self.state._read()
        if cursor is None:
            raise CursorNotInitialized("notification cursor is absent")
        return cursor, token

    async def _cas_exact(self, token, cursor):
        desired = encode_cursor(cursor)
        try:
            result = await self.cursor_store.cas("root", token, desired)
        except OutcomeUnknown:
            current = await self.cursor_store.read_versioned("root")
            if isinstance(current, Versioned) and current.value == desired:
                return current.token
            return None
        if isinstance(result, Applied):
            return result.token
        if result is STALE:
            return None
        raise TypeError("notification cursor CAS")

    async def _bootstrap(self, mode):
        current = await self.cursor_store.read_versioned("root")
        if isinstance(current, Versioned):
            cursor = decode_cursor(current.value)
            if cursor.workspace != self.workspace \
                    or cursor.owner != self.owner \
                    or cursor.bootstrap != mode:
                raise ValueError("notification bootstrap conflict")
            return cursor
        if current is not ABSENT:
            raise TypeError("notification cursor read")

        base = None
        if mode == BOOTSTRAP_CURRENT:
            repository = await self.repository_store.read_versioned("root")
            if isinstance(repository, Versioned):
                RepositoryReader(
                    self.workspace, repository.value, lambda _oid: None)
                base = await self._ensure_object(
                    repository.value, MAX_ROOT_BYTES)
            elif repository is not ABSENT:
                raise TypeError("repository root read")
        generation = self.generation_factory()
        if not valid_fid(generation):
            raise ValueError("notification bootstrap generation")
        cursor = Cursor(
            self.workspace, self.owner, generation, mode, base=base)
        token = await self._cas_exact(ABSENT, cursor)
        if token is not None:
            return cursor

        incumbent, _token = await self.state._read()
        if incumbent is not None \
                and incumbent.bootstrap == mode:
            return incumbent
        raise OSError("notification bootstrap was not preserved")

    async def bootstrap_current(self):
        """Start after the repository root current at explicit bootstrap."""
        return await self._bootstrap(BOOTSTRAP_CURRENT)

    async def bootstrap_backfill(self):
        """Start at the empty FactTree and discover existing history."""
        return await self._bootstrap(BOOTSTRAP_BACKFILL)

    async def _pin(self, cursor, token):
        current = await self.repository_store.read_versioned("root")
        if current is ABSENT:
            return cursor, token, DiscoveryResult("idle")
        if not isinstance(current, Versioned):
            raise TypeError("repository root read")
        RepositoryReader(self.workspace, current.value, lambda _oid: None)
        oid = await self._ensure_object(current.value, MAX_ROOT_BYTES)
        if oid == cursor.base:
            return cursor, token, DiscoveryResult("idle", oid)
        pinned = Cursor(
            cursor.workspace, cursor.owner, cursor.generation,
            cursor.bootstrap,
            cursor.base, oid)
        next_token = await self._cas_exact(token, pinned)
        if next_token is None:
            return cursor, token, DiscoveryResult("raced", oid)
        return pinned, next_token, None

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

    @staticmethod
    def _successor(cursor, continuation):
        if continuation is None:
            return cursor.target, None, None
        return cursor.base, cursor.target, continuation

    async def _pending_body(self, cursor):
        pending = cursor.pending
        raw = await self._get(
            self.cursor_store, "obj/" + pending.oid, MAX_HINT_BYTES)
        if not isinstance(raw, bytes) or h(raw) != pending.oid:
            raise ValueError("notification pending body")
        reference = decode_hint(raw)
        if reference.workspace != cursor.workspace \
                or reference.owner != cursor.owner \
                or reference.generation != cursor.generation \
                or reference.root_oid != cursor.target:
            raise ValueError("notification pending identity")
        return raw

    async def _publish(self, raw):
        accepted = await self.carrier.publish(raw)
        if not isinstance(accepted, CarrierAccepted):
            raise TypeError("notification carrier did not accept hint")

    async def run_once(self):
        cursor, token = await self._read_cursor()
        if cursor.pending is not None:
            raw = await self._pending_body(cursor)
            await self._publish(raw)
            return DiscoveryResult(
                "republished", cursor.target, cursor.pending.after,
                cursor.pending.oid)
        if cursor.target is None:
            cursor, token, result = await self._pin(cursor, token)
            if result is not None:
                return result

        continuation, fids = await self._page(cursor)
        next_base, next_target, next_after = self._successor(
            cursor, continuation)
        if fids:
            hint = NotificationHint(
                self.workspace, self.owner, cursor.generation,
                cursor.target, fids)
            raw = encode_hint(hint)
            oid = await self._ensure_object(raw, MAX_HINT_BYTES)
            pending = Pending(
                oid, next_base, next_target, next_after)
            desired = Cursor(
                cursor.workspace, cursor.owner, cursor.generation,
                cursor.bootstrap, cursor.base,
                cursor.target, cursor.after, pending)
            if await self._cas_exact(token, desired) is None:
                return DiscoveryResult(
                    "raced", cursor.target, continuation)
            await self._publish(raw)
            return DiscoveryResult(
                "published", cursor.target, continuation, pending.oid)

        advanced = Cursor(
            cursor.workspace, cursor.owner, cursor.generation,
            cursor.bootstrap,
            next_base, next_target, next_after)
        if await self._cas_exact(token, advanced) is None:
            return DiscoveryResult("raced", cursor.target, continuation)
        return DiscoveryResult("advanced", cursor.target, continuation)


__all__ = (
    "BOOTSTRAP_BACKFILL",
    "BOOTSTRAP_CURRENT",
    "Cursor",
    "CursorNotInitialized",
    "DiscoveryResult",
    "NotificationDiscovery",
    "NotificationState",
    "PENDING_CURRENT",
    "PENDING_NONCURRENT",
    "PENDING_RETRY",
    "Pending",
    "decode_cursor",
    "encode_cursor",
)
