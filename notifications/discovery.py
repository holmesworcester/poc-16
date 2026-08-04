"""Durable notification discovery over validated per-writer head diffs.

The operational cursor owns three small authenticated maps: acknowledged head
OID by writer, exact rejected head OID by writer, and already-emitted trigger
FID by fact-object OID. One scan is pinned to one exact signed writer slot.
RepositoryMirror and FactConsumer do all head, tree, pile-signature, closure,
and fact validation. No workspace content root is read, written, or retained
here.
"""
import asyncio
from dataclasses import dataclass, replace
import secrets

import facts

from core import merkle_map
from core.crypto import h
from core.fact import canon, decode
from core.limits import (
    MAX_FACT_BYTES,
    MAX_MERKLE_PAGE_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
    decode_json,
)
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    STALE,
    Applied,
    ListPage,
    OutcomeUnknown,
    OPERATIONAL_CURSOR_KEY,
    Versioned,
    VersionToken,
    async_store,
    ensure_object_async,
    store_namespace,
)
from core.shape import valid_fid
from core.writer_head import (
    HeadSlot,
    decode_slot_at,
    encode_slot,
    head_slot_key,
    head_slot_prefix,
)
from core.writer_repository import (
    FactConsumer,
    RepositoryMirror,
    ValidatedBatch,
)

from .carrier import CarrierAccepted
from .forest import MemoryStore, claimed_writer_binding
from .hints import (
    EventRef,
    MAX_HINT_BYTES,
    MAX_HINT_EVENTS,
    NotificationHint,
    decode_hint,
    encode_hint,
)


CURSOR_FORMAT = "notification-writer-cursor-v1"
MAX_CURSOR_BYTES = 16 * 1024
BOOTSTRAP_CURRENT = "current"
BOOTSTRAP_BACKFILL = "backfill"
PENDING_CURRENT = "current"
PENDING_NONCURRENT = "noncurrent"
PENDING_RETRY = "retry"


def empty_descriptor():
    """Canonical empty state for one notification cursor map."""
    return {"root": "", "count": 0, "depth": 0}


def built_descriptor(value):
    """Reduce one generic Merkle build result to cursor state."""
    return {
        "root": value.root,
        "count": value.count,
        "depth": value.page_depth,
    }


class CursorNotInitialized(RuntimeError):
    """Discovery requires a completed explicit current/backfill bootstrap."""


def _descriptor(value):
    if not isinstance(value, dict) or set(value) != {
            "root", "count", "depth"} \
            or not isinstance(value.get("root"), str) \
            or value["root"] and not valid_fid(value["root"]) \
            or type(value.get("count")) is not int \
            or value["count"] < 0 \
            or type(value.get("depth")) is not int \
            or not 0 <= value["depth"] <= merkle_map.MAX_PAGE_DEPTH \
            or bool(value["root"]) != bool(value["count"]) \
            or bool(value["root"]) != bool(value["depth"]):
        raise ValueError("notification map descriptor")
    return dict(value)


@dataclass(frozen=True, slots=True)
class Scan:
    device: str
    head: str
    removal_root: str

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.device, self.head, self.removal_root)):
            raise ValueError("notification scan")


@dataclass(frozen=True, slots=True)
class Pending:
    oid: str
    heads: dict
    seen: dict

    def __post_init__(self):
        if not valid_fid(self.oid):
            raise ValueError("notification pending")
        object.__setattr__(self, "heads", _descriptor(self.heads))
        object.__setattr__(self, "seen", _descriptor(self.seen))


@dataclass(frozen=True, slots=True)
class Cursor:
    workspace: str
    owner: str
    generation: str
    bootstrap: str
    initialized: bool
    heads: dict
    rejected: dict
    seen: dict
    scan: Scan | None = None
    pending: Pending | None = None

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.owner) \
                or not valid_fid(self.generation) \
                or self.bootstrap not in {
                    BOOTSTRAP_CURRENT, BOOTSTRAP_BACKFILL} \
                or not isinstance(self.initialized, bool) \
                or self.scan is not None and not isinstance(self.scan, Scan) \
                or self.pending is not None and (
                    not isinstance(self.pending, Pending)
                    or self.scan is None):
            raise ValueError("notification cursor")
        object.__setattr__(self, "heads", _descriptor(self.heads))
        object.__setattr__(self, "rejected", _descriptor(self.rejected))
        object.__setattr__(self, "seen", _descriptor(self.seen))
        if not self.initialized and (
                self.heads != empty_descriptor()
                or self.rejected != empty_descriptor()
                or self.seen != empty_descriptor()
                or self.scan is not None or self.pending is not None):
            raise ValueError("notification cursor initialization")
        if self.pending is not None and self.pending.heads != self.heads:
            raise ValueError("notification pending successor")

    def advance(self):
        if self.pending is None:
            raise ValueError("notification cursor is not pending")
        return Cursor(
            self.workspace, self.owner, self.generation, self.bootstrap,
            self.initialized, self.pending.heads, self.rejected,
            self.pending.seen,
            self.scan,
        )


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    status: str
    target: str | None = None
    continuation: str | None = None
    hint_oid: str | None = None


def _descriptor_body(value):
    return {
        "count": value["count"],
        "depth": value["depth"],
        "root": value["root"],
    }


def _scan_body(value):
    return None if value is None else {
        "device": value.device,
        "head": value.head,
        "removal_root": value.removal_root,
    }


def encode_cursor(cursor):
    if not isinstance(cursor, Cursor):
        raise TypeError("notification cursor")
    pending = None if cursor.pending is None else {
        "heads": _descriptor_body(cursor.pending.heads),
        "oid": cursor.pending.oid,
        "seen": _descriptor_body(cursor.pending.seen),
    }
    raw = canon({
        "bootstrap": cursor.bootstrap,
        "format": CURSOR_FORMAT,
        "generation": cursor.generation,
        "heads": _descriptor_body(cursor.heads),
        "initialized": cursor.initialized,
        "owner": cursor.owner,
        "pending": pending,
        "rejected": _descriptor_body(cursor.rejected),
        "scan": _scan_body(cursor.scan),
        "seen": _descriptor_body(cursor.seen),
        "workspace": cursor.workspace,
    })
    if len(raw) > MAX_CURSOR_BYTES:
        raise ValueError("notification cursor too large")
    return raw


def decode_cursor(raw):
    value = decode_json(raw, MAX_CURSOR_BYTES, "notification cursor")
    if not isinstance(value, dict) or set(value) != {
            "bootstrap", "format", "generation", "heads", "initialized",
            "owner", "pending", "rejected", "scan", "seen", "workspace"} \
            or value.get("format") != CURSOR_FORMAT:
        raise ValueError("notification cursor shape")
    raw_scan = value.get("scan")
    raw_pending = value.get("pending")
    if raw_scan is not None and (
            not isinstance(raw_scan, dict) or set(raw_scan) != {
                "device", "head", "removal_root"}):
        raise ValueError("notification scan shape")
    if raw_pending is not None and (
            not isinstance(raw_pending, dict) or set(raw_pending) != {
                "heads", "oid", "seen"}):
        raise ValueError("notification pending shape")
    scan = None if raw_scan is None else Scan(
        raw_scan.get("device"), raw_scan.get("head"),
        raw_scan.get("removal_root"))
    pending = None if raw_pending is None else Pending(
        raw_pending.get("oid"), raw_pending.get("heads"),
        raw_pending.get("seen"))
    cursor = Cursor(
        value.get("workspace"), value.get("owner"),
        value.get("generation"), value.get("bootstrap"),
        value.get("initialized"), value.get("heads"),
        value.get("rejected"), value.get("seen"), scan, pending)
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
        current = await self.store.read_versioned(OPERATIONAL_CURSOR_KEY)
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
        self._validate(oid)
        cursor, _token = await self._read()
        return self._classify(cursor, oid)

    async def complete(self, oid):
        self._validate(oid)
        cursor, token = await self._read()
        if self._classify(cursor, oid) != PENDING_CURRENT:
            return PENDING_NONCURRENT
        try:
            result = await self.store.cas(
                OPERATIONAL_CURSOR_KEY, token, encode_cursor(cursor.advance()))
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


class _CollectState:
    """One scan's validated facts plus caller-selected projected checkpoints."""

    def __init__(self, projected=None):
        self.facts = {}
        self.projected = dict(projected or {})

    def fact_bytes(self, fid):
        return self.facts.get(fid)

    def fact_ids(self):
        return set(self.facts)

    def projected_head(self, device):
        return self.projected.get(device)

    def commit(self, batch, *, device, head):
        if not isinstance(batch, ValidatedBatch) \
                or not valid_fid(device) or not valid_fid(head):
            raise ValueError("notification consumer commit")
        additions = []
        for fid, raw in batch.facts:
            incumbent = self.facts.get(fid)
            if incumbent is not None and incumbent != raw:
                raise ValueError("notification fact conflict")
            if incumbent is None:
                self.facts[fid] = raw
                additions.append(fid)
        self.projected[device] = head
        return tuple(additions)


class _PinnedSource:
    """Expose one exact observed slot while delegating immutable reads."""

    def __init__(self, source, workspace, scan):
        self.source = source
        self.key = head_slot_key(workspace, scan.device)
        self.raw = encode_slot(HeadSlot(
            workspace, scan.device, scan.head, scan.removal_root))

    async def get_bounded(self, key, maximum):
        return await self.source.get_bounded(key, maximum)

    async def copy_pile_object(self, oid, maximum, write):
        return await self.source.copy_pile_object(oid, maximum, write)

    async def read_versioned(self, key):
        if key == self.key:
            return Versioned(self.raw, VersionToken(h(self.raw)))
        return await self.source.read_versioned(key)

    async def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        if cursor is not None or not self.key.startswith(prefix) or limit < 1:
            return ListPage((), None)
        return ListPage((self.key,), None)


class _ScanStore:
    """Discarded mirror target pinned to the cursor's acknowledged head.

    RepositoryMirror commits its accepted slot before returning.  That is the
    right durable boundary for a peer, but notification progress belongs to
    the cursor CAS.  Keep the mirror side effects in memory so a crash before
    that CAS cannot make a retry mistake an already-mirrored head for an
    acknowledged one.  Immutable fallback reads are safe because every body
    is still verified by its content address.
    """

    def __init__(self, source, workspace, scan, base):
        self.source = source
        self.values = {}
        self.key = head_slot_key(workspace, scan.device)
        if base is not None:
            self.values[self.key] = encode_slot(HeadSlot(
                workspace, scan.device, base, scan.removal_root))

    async def get_bounded(self, key, maximum):
        raw = self.values.get(key)
        return await self.source.get_bounded(key, maximum) \
            if raw is None else raw

    async def copy_pile_object(self, oid, maximum, write):
        raw = self.values.get("obj/" + oid)
        if raw is None:
            return await self.source.copy_pile_object(oid, maximum, write)
        if len(raw) > maximum:
            raise PayloadTooLarge("notification scan pile")
        write(raw)
        return len(raw)

    async def read_versioned(self, key):
        raw = self.values.get(key)
        return ABSENT if raw is None else Versioned(
            raw, VersionToken(h(raw)))

    async def put_if_absent(self, key, raw):
        incumbent = self.values.get(key)
        if incumbent is None:
            self.values[key] = raw
            return CREATED
        if incumbent != raw:
            raise ValueError("notification scan object conflict")
        return EXISTS

    async def cas(self, key, token, raw):
        current = await self.read_versioned(key)
        current_token = current.token \
            if isinstance(current, Versioned) else ABSENT
        if current_token != token:
            return STALE
        self.values[key] = raw
        return Applied(VersionToken(h(raw)))

    async def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        keys = sorted(
            key for key in self.values
            if key.startswith(prefix) and (cursor is None or key > cursor))
        selected = tuple(keys[:limit])
        return ListPage(
            selected,
            selected[-1] if len(keys) > limit else None,
        )


class NotificationDiscovery:
    """Publish at most one validated writer-trigger page per invocation."""

    def __init__(
            self, repository_store, cursor_store, workspace, carrier, *,
            owner, page_rows=MAX_HINT_EVENTS, generation_factory=None):
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
                or not 1 <= page_rows <= MAX_HINT_EVENTS:
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

    async def _ensure_object(self, raw, maximum):
        if not isinstance(raw, bytes) or len(raw) > maximum:
            raise ValueError("notification immutable object")
        oid = h(raw)
        await ensure_object_async(self.cursor_store, oid, raw)
        return oid

    async def _read_cursor(self, *, initialized=True):
        cursor, token = await self.state._read()
        if cursor is None or initialized and not cursor.initialized:
            raise CursorNotInitialized("notification cursor is absent")
        return cursor, token

    async def _cas_exact(self, token, cursor):
        desired = encode_cursor(cursor)
        try:
            result = await self.cursor_store.cas(
                OPERATIONAL_CURSOR_KEY, token, desired)
        except OutcomeUnknown:
            current = await self.cursor_store.read_versioned(
                OPERATIONAL_CURSOR_KEY)
            if isinstance(current, Versioned) and current.value == desired:
                return current.token
            return None
        if isinstance(result, Applied):
            return result.token
        if result is STALE:
            return None
        raise TypeError("notification cursor CAS")

    def _seed(self, name):
        return h(canon([
            "notification-writer-cursor-map-v1",
            self.workspace,
            name,
        ]))

    async def _map_fetch(self, oid):
        raw = await self._get(
            self.cursor_store, "obj/" + oid, MAX_MERKLE_PAGE_BYTES)
        if not isinstance(raw, bytes) or h(raw) != oid:
            raise ValueError("notification cursor map object")
        return raw

    async def _map_points(self, name, descriptor, keys):
        keys = tuple(sorted(set(keys)))
        values, _pages = await merkle_map.get_many_awaited(
            descriptor["root"], self._seed(name), keys, self._map_fetch,
            max_page_depth=descriptor["depth"],
            expected_count=descriptor["count"],
            expected_depth=descriptor["depth"],
        )
        return values

    async def _map_update(self, name, descriptor, changes):
        changes = tuple(sorted(changes))
        if not changes:
            return descriptor

        async def emit(raw):
            return await self._ensure_object(raw, MAX_MERKLE_PAGE_BYTES)

        built = await merkle_map.update_awaited(
            descriptor["root"], self._seed(name), changes,
            self._map_fetch, emit,
            expected_count=descriptor["count"],
            expected_depth=descriptor["depth"],
        )
        return built_descriptor(built)

    @staticmethod
    def _trigger_rows(state):
        rows = []
        for fid, raw in state.facts.items():
            fact = decode(raw)
            family = facts.family_for(fact.t)
            if family is not None \
                    and getattr(family, "notification_trigger", None) \
                    is not None:
                rows.append((fid, h(raw), raw))
        return tuple(sorted(rows))

    async def _unseen(self, descriptor, rows):
        values = await self._map_points(
            "seen", descriptor, (fid for fid, _oid, _raw in rows))
        out = []
        for fid, oid, raw in rows:
            incumbent = values[fid]
            if incumbent is None:
                out.append((fid, oid, raw))
            elif incumbent != oid:
                raise ValueError("notification seen fact conflict")
        return tuple(out)

    async def _bootstrap(self, mode):
        current = await self.cursor_store.read_versioned(
            OPERATIONAL_CURSOR_KEY)
        if isinstance(current, Versioned):
            cursor = decode_cursor(current.value)
            if cursor.workspace != self.workspace \
                    or cursor.owner != self.owner \
                    or cursor.bootstrap != mode:
                raise ValueError("notification bootstrap conflict")
            if cursor.initialized:
                return cursor
            token = current.token
        elif current is ABSENT:
            generation = self.generation_factory()
            if not valid_fid(generation):
                raise ValueError("notification bootstrap generation")
            cursor = Cursor(
                self.workspace, self.owner, generation, mode, False,
                empty_descriptor(), empty_descriptor(),
                empty_descriptor())
            token = await self._cas_exact(ABSENT, cursor)
            if token is None:
                incumbent, _token = await self.state._read()
                if incumbent is None or incumbent.bootstrap != mode:
                    raise OSError("notification bootstrap was not preserved")
                cursor = incumbent
                if cursor.initialized:
                    return cursor
                _cursor, token = await self._read_cursor(initialized=False)
        else:
            raise TypeError("notification cursor read")

        heads = cursor.heads
        seen = cursor.seen
        if mode == BOOTSTRAP_CURRENT:
            state = _CollectState()
            result = await RepositoryMirror(
                self.workspace, MemoryStore(),
                claimed_writer_binding, FactConsumer(self.workspace, state),
            ).sync_from(self.repository_store)
            if result.errors:
                raise ValueError("notification bootstrap writer forest")
            heads = await self._map_update(
                "heads", heads, tuple(state.projected.items()))
            triggers = self._trigger_rows(state)
            seen = await self._map_update(
                "seen", seen,
                tuple((fid, oid) for fid, oid, _raw in triggers))
        desired = replace(
            cursor, initialized=True, heads=heads, seen=seen)
        next_token = await self._cas_exact(token, desired)
        if next_token is not None:
            return desired
        incumbent, _token = await self.state._read()
        if incumbent is not None and incumbent.bootstrap == mode \
                and incumbent.initialized:
            return incumbent
        raise OSError("notification bootstrap was not preserved")

    async def bootstrap_current(self):
        return await self._bootstrap(BOOTSTRAP_CURRENT)

    async def bootstrap_backfill(self):
        return await self._bootstrap(BOOTSTRAP_BACKFILL)

    async def _candidate(self, cursor):
        prefix = head_slot_prefix(self.workspace)
        after = None
        while True:
            page = await self.repository_store.list_page(
                prefix, after, PAGE_BATCH)
            opened = await asyncio.gather(*(
                self.repository_store.read_versioned(key)
                for key in page.keys), return_exceptions=True)
            devices = []
            slots = []
            for key, value in zip(page.keys, opened):
                if isinstance(value, BaseException):
                    raise value
                if not isinstance(value, Versioned):
                    raise ValueError("listed writer slot disappeared")
                slot = decode_slot_at(key, value.value)
                devices.append(slot.device)
                slots.append(slot)
            acknowledged = await self._map_points(
                "heads", cursor.heads, devices)
            rejected = await self._map_points(
                "rejected", cursor.rejected, devices)
            for slot in slots:
                base = acknowledged[slot.device]
                if base == slot.head or rejected[slot.device] == slot.head:
                    continue
                return Scan(
                    slot.device, slot.head, slot.removal_root)
            if page.cursor is None:
                return None
            after = page.cursor

    async def _pending_body(self, cursor):
        raw = await self._get(
            self.cursor_store, "obj/" + cursor.pending.oid,
            MAX_HINT_BYTES)
        if not isinstance(raw, bytes) or h(raw) != cursor.pending.oid:
            raise ValueError("notification pending body")
        reference = decode_hint(raw)
        base = (await self._map_points(
            "heads", cursor.heads, (cursor.scan.device,))
        )[cursor.scan.device]
        if reference.workspace != cursor.workspace \
                or reference.owner != cursor.owner \
                or reference.generation != cursor.generation \
                or reference.device != cursor.scan.device \
                or reference.base_head != base \
                or reference.head != cursor.scan.head:
            raise ValueError("notification pending identity")
        return raw

    async def _publish(self, raw):
        accepted = await self.carrier.publish(raw)
        if not isinstance(accepted, CarrierAccepted):
            raise TypeError("notification carrier did not accept hint")

    async def _clear_stale_scan(self, cursor, token):
        desired = replace(cursor, scan=None)
        if await self._cas_exact(token, desired) is None:
            return DiscoveryResult("raced", cursor.scan.head)
        return DiscoveryResult("stale", cursor.scan.head)

    async def _reject_scan(self, cursor, token):
        rejected = await self._map_update(
            "rejected", cursor.rejected,
            ((cursor.scan.device, cursor.scan.head),))
        desired = replace(cursor, rejected=rejected, scan=None)
        if await self._cas_exact(token, desired) is None:
            return DiscoveryResult("raced", cursor.scan.head)
        return DiscoveryResult("invalid", cursor.scan.head)

    async def _scan(self, cursor, token):
        scan = cursor.scan
        base = (await self._map_points(
            "heads", cursor.heads, (scan.device,))
        )[scan.device]
        state = _CollectState({scan.device: base})
        target = _ScanStore(
            self.repository_store, self.workspace, scan, base)
        result = await RepositoryMirror(
            self.workspace, target,
            claimed_writer_binding, FactConsumer(self.workspace, state),
        ).sync_from(_PinnedSource(
            self.repository_store, self.workspace, scan))
        if result.errors:
            return await self._reject_scan(cursor, token)
        if state.projected_head(scan.device) != scan.head:
            return await self._clear_stale_scan(cursor, token)

        rows = await self._unseen(
            cursor.seen, self._trigger_rows(state))
        page = rows[:self.page_rows]
        if page:
            events = []
            for fid, oid, raw in page:
                await self._ensure_object(raw, MAX_FACT_BYTES)
                events.append(EventRef(fid, oid))
            hint = NotificationHint(
                self.workspace, self.owner, cursor.generation,
                scan.device, base, scan.head, tuple(events))
            raw = encode_hint(hint)
            oid = await self._ensure_object(raw, MAX_HINT_BYTES)
            seen = await self._map_update(
                "seen", cursor.seen,
                tuple((event.fid, event.oid) for event in events))
            pending = Pending(oid, cursor.heads, seen)
            desired = replace(cursor, pending=pending)
            if await self._cas_exact(token, desired) is None:
                return DiscoveryResult("raced", scan.head)
            await self._publish(raw)
            return DiscoveryResult(
                "published", scan.head, None, oid)

        heads = await self._map_update(
            "heads", cursor.heads, ((scan.device, scan.head),))
        desired = replace(cursor, heads=heads, scan=None)
        if await self._cas_exact(token, desired) is None:
            return DiscoveryResult("raced", scan.head)
        return DiscoveryResult("advanced", scan.head)

    async def run_once(self):
        cursor, token = await self._read_cursor()
        if cursor.pending is not None:
            raw = await self._pending_body(cursor)
            await self._publish(raw)
            return DiscoveryResult(
                "republished", cursor.scan.head, None,
                cursor.pending.oid)
        if cursor.scan is None:
            candidate = await self._candidate(cursor)
            if candidate is None:
                return DiscoveryResult("idle")
            desired = replace(cursor, scan=candidate)
            next_token = await self._cas_exact(token, desired)
            if next_token is None:
                return DiscoveryResult("raced", candidate.head)
            cursor, token = desired, next_token
        return await self._scan(cursor, token)


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
    "Scan",
    "decode_cursor",
    "empty_descriptor",
    "encode_cursor",
)
