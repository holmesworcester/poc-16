"""Durable notification discovery over validated per-writer head diffs.

The operational cursor owns three small authenticated maps: acknowledged head
OID by writer, exact rejected head OID by writer, and already-emitted trigger
FID by fact-object OID. One scan is pinned to one exact signed writer slot and
persists authenticated history/suffix continuation. FactConsumer performs the
same pile-signature, closure, and fact validation as ordinary mirroring. No
workspace content root is read, written, or retained here.
"""
import asyncio
from dataclasses import dataclass, field, replace
import secrets

import facts

from core import merkle_map
from core.crypto import h
from core.fact import canon, decode
from core.limits import (
    MAX_FACT_BYTES,
    MAX_HEAD_CONTROL_PILES,
    MAX_MERKLE_PAGE_BYTES,
    MAX_OBJECT_BYTES,
    MAX_SEMANTIC_PILE_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
    decode_json,
)
from core.object_store import (
    ABSENT,
    STALE,
    Applied,
    OutcomeUnknown,
    OPERATIONAL_CURSOR_KEY,
    Versioned,
    async_store,
    ensure_object_async,
    store_namespace,
)
from core.shape import valid_fid
from core.writer_head import (
    MAX_WRITER_HEAD_BYTES,
    decode_head,
    decode_slot_at,
    head_slot_prefix,
    require_bound_head,
    validate_advance,
)
from core.writer_repository import (
    FactConsumer,
    RepositoryMirror,
    ValidatedBatch,
)
from core.writer_tree import (
    EMPTY_TREE,
    LEAF_PREFIX,
    MAX_WRITER_SEQUENCE,
    leaf_key,
    parse_leaf_key,
    tree_reader,
    validate_extension_awaited,
)

from .carrier import CarrierAccepted
from .forest import MemoryStore, closure_writer_binding
from .hints import (
    EventRef,
    MAX_HINT_BYTES,
    MAX_HINT_EVENTS,
    NotificationHint,
    decode_hint,
    encode_hint,
)


CURSOR_FORMAT = "notification-writer-cursor-v2"
MAX_CURSOR_BYTES = 16 * 1024
MAX_SCAN_PILES_PER_TURN = 1
SCAN_PHASES = frozenset(("base", "suffix", "emit", "complete"))
BOOTSTRAP_CURRENT = "current"
BOOTSTRAP_BACKFILL = "backfill"
REBOOTSTRAP_CURRENT = "rebootstrap-current"
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


class CursorRebootstrapRequired(RuntimeError):
    """Retained pending bytes have no reader in the current hard-cut build."""


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
    phase: str = "base"
    after: str | None = None
    sequence: int = 0
    controls: dict = field(default_factory=empty_descriptor)
    events: dict = field(default_factory=empty_descriptor)

    def __post_init__(self):
        after_ok = self.after is None
        if self.after is not None and isinstance(self.after, str):
            try:
                after_ok = valid_fid(self.after) if self.phase == "emit" \
                    else parse_leaf_key(self.after) >= 1
            except ValueError:
                after_ok = False
        if not all(valid_fid(value) for value in (
                self.device, self.head, self.removal_root)) \
                or self.phase not in SCAN_PHASES \
                or not after_ok \
                or self.phase == "complete" and self.after is not None \
                or type(self.sequence) is not int \
                or not 0 <= self.sequence <= MAX_WRITER_SEQUENCE:
            raise ValueError("notification scan")
        object.__setattr__(self, "controls", _descriptor(self.controls))
        object.__setattr__(self, "events", _descriptor(self.events))
        if self.controls["count"] > MAX_HEAD_CONTROL_PILES \
                or self.phase == "emit" and not self.events["count"]:
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
    directory_after: str | None = None

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.owner) \
                or not valid_fid(self.generation) \
                or self.bootstrap not in {
                    BOOTSTRAP_CURRENT, BOOTSTRAP_BACKFILL,
                    REBOOTSTRAP_CURRENT} \
                or not isinstance(self.initialized, bool) \
                or self.scan is not None and not isinstance(self.scan, Scan) \
                or self.pending is not None and (
                    not isinstance(self.pending, Pending)
                    or self.scan is None) \
                or self.directory_after is not None and not isinstance(
                    self.directory_after, str) \
                or self.directory_after == "":
            raise ValueError("notification cursor")
        object.__setattr__(self, "heads", _descriptor(self.heads))
        object.__setattr__(self, "rejected", _descriptor(self.rejected))
        object.__setattr__(self, "seen", _descriptor(self.seen))
        if not self.initialized and (
                self.heads != empty_descriptor()
                or self.rejected != empty_descriptor()
                or self.seen != empty_descriptor()
                or self.scan is not None or self.pending is not None
                or self.directory_after is not None):
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
            self.scan, None, self.directory_after,
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
        "after": value.after,
        "controls": _descriptor_body(value.controls),
        "device": value.device,
        "events": _descriptor_body(value.events),
        "head": value.head,
        "phase": value.phase,
        "removal_root": value.removal_root,
        "sequence": value.sequence,
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
        "directory_after": cursor.directory_after,
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
            "directory_after", "owner", "pending", "rejected", "scan",
            "seen", "workspace"} \
            or value.get("format") != CURSOR_FORMAT:
        raise ValueError("notification cursor shape")
    raw_scan = value.get("scan")
    raw_pending = value.get("pending")
    if raw_scan is not None and (
            not isinstance(raw_scan, dict) or set(raw_scan) != {
                "after", "controls", "device", "events", "head", "phase",
                "removal_root", "sequence"}):
        raise ValueError("notification scan shape")
    if raw_pending is not None and (
            not isinstance(raw_pending, dict) or set(raw_pending) != {
                "heads", "oid", "seen"}):
        raise ValueError("notification pending shape")
    scan = None if raw_scan is None else Scan(
        raw_scan.get("device"), raw_scan.get("head"),
        raw_scan.get("removal_root"), raw_scan.get("phase"),
        raw_scan.get("after"), raw_scan.get("sequence"),
        raw_scan.get("controls"), raw_scan.get("events"))
    pending = None if raw_pending is None else Pending(
        raw_pending.get("oid"), raw_pending.get("heads"),
        raw_pending.get("seen"))
    cursor = Cursor(
        value.get("workspace"), value.get("owner"),
        value.get("generation"), value.get("bootstrap"),
        value.get("initialized"), value.get("heads"),
        value.get("rejected"), value.get("seen"), scan, pending,
        value.get("directory_after"))
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

    async def _map_page(self, name, descriptor, after, limit):
        """Read one bounded page from an authenticated cursor map."""
        seed = self._seed(name)
        remote = merkle_map.Reader(
            descriptor["root"], seed, self._map_fetch,
            max_page_depth=descriptor["depth"],
            expected_count=descriptor["count"],
            expected_depth=descriptor["depth"],
        )
        empty = merkle_map.Reader(
            "", seed, self._map_fetch,
            max_page_depth=0, expected_count=0, expected_depth=0,
        )
        page = await remote.diff_page_awaited(
            empty, after=after, limit=limit)
        if page.rows != page.differing or len(page.rows) > limit:
            raise ValueError("notification cursor map page")
        return page.rows, page.cursor

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
        if mode in {BOOTSTRAP_CURRENT, REBOOTSTRAP_CURRENT}:
            state = _CollectState()
            result = await RepositoryMirror(
                self.workspace, MemoryStore(),
                closure_writer_binding, FactConsumer(self.workspace, state),
                observe_controls=True,
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

    async def rebootstrap_current(self):
        """Explicitly replace retained progress, then acknowledge current state.

        Operators invoke this only with delivery disabled.  The fresh random
        generation fences every old carrier body, and current bootstrap marks
        all presently valid triggers seen instead of replaying pre-cut work.
        A crash after the reset CAS leaves an ordinary resumable, uninitialized
        current bootstrap.
        """
        cursor, token = await self._read_cursor(initialized=False)
        if cursor.bootstrap == REBOOTSTRAP_CURRENT:
            return await self._bootstrap(REBOOTSTRAP_CURRENT)
        if not cursor.initialized:
            raise CursorNotInitialized(
                "notification rebootstrap source is not initialized")
        generation = self.generation_factory()
        if not valid_fid(generation) or generation == cursor.generation:
            raise ValueError("notification rebootstrap generation")
        reset = Cursor(
            self.workspace, self.owner, generation,
            REBOOTSTRAP_CURRENT, False,
            empty_descriptor(), empty_descriptor(), empty_descriptor())
        if await self._cas_exact(token, reset) is None:
            raise OSError("notification rebootstrap raced")
        return await self._bootstrap(REBOOTSTRAP_CURRENT)

    async def _candidate(self, cursor):
        """Inspect at most one directory page and return durable progress."""
        prefix = head_slot_prefix(self.workspace)
        page = await self.repository_store.list_page(
            prefix, cursor.directory_after, PAGE_BATCH)
        if len(page.keys) > PAGE_BATCH:
            raise ValueError("notification directory page overflow")
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
                slot.device, slot.head, slot.removal_root), None
        return None, page.cursor

    async def _repository_object(self, oid, maximum):
        raw = await self._get(
            self.repository_store, "obj/" + oid, maximum)
        if not isinstance(raw, bytes) or h(raw) != oid:
            raise ValueError("notification repository object")
        return raw

    async def _tree_object(self, oid):
        return await self._repository_object(oid, MAX_OBJECT_BYTES)

    async def _head(self, oid, scan):
        raw = await self._repository_object(oid, MAX_WRITER_HEAD_BYTES)
        candidate = decode_head(raw)
        binding = closure_writer_binding(
            self.workspace, scan.device, scan.removal_root, candidate)
        return require_bound_head(candidate, binding)

    async def _pile(self, oid):
        value = bytearray()
        copied = await self.repository_store.copy_pile_object(
            oid, MAX_SEMANTIC_PILE_BYTES, value.extend)
        raw = bytes(value)
        if copied is None or copied != len(raw) or h(raw) != oid:
            raise ValueError("notification scan pile")
        return raw

    async def _scan_context(self, cursor):
        scan = cursor.scan
        base_oid = (await self._map_points(
            "heads", cursor.heads, (scan.device,)))[scan.device]
        candidate = await self._head(scan.head, scan)
        accepted = None if base_oid is None else await self._head(
            base_oid, scan)
        if accepted is not None:
            validate_advance(accepted, candidate, closure_writer_binding(
                self.workspace, scan.device, scan.removal_root, candidate))
        accepted_control = EMPTY_TREE if accepted is None else accepted.control
        control_delta = candidate.control.count - accepted_control.count
        if not 0 <= control_delta <= MAX_HEAD_CONTROL_PILES:
            raise PayloadTooLarge("notification control delta")
        controls = frozenset(
            oid for _key, oid in await validate_extension_awaited(
                accepted_control,
                candidate.control,
                self.workspace,
                scan.device,
                self._tree_object,
                self._tree_object,
            )
        )
        return base_oid, accepted, candidate, controls

    async def _scan_page(self, cursor):
        """Validate at most one tree-diff page and one closed pile."""
        scan = cursor.scan
        base_oid, accepted, candidate, controls = await self._scan_context(
            cursor)
        accepted_tree = EMPTY_TREE if accepted is None else accepted.tree
        if scan.phase not in {"base", "suffix"}:
            raise ValueError("notification scan validation phase")

        if scan.phase == "base":
            if accepted_tree != EMPTY_TREE:
                page = await tree_reader(
                    accepted_tree,
                    self.workspace,
                    scan.device,
                    self._tree_object,
                ).diff_page_awaited(
                    tree_reader(
                        candidate.tree,
                        self.workspace,
                        scan.device,
                        self._tree_object,
                    ),
                    after=scan.after,
                    # This pass compares authenticated metadata only; pile
                    # bodies remain subject to MAX_SCAN_PILES_PER_TURN below.
                    limit=PAGE_BATCH,
                )
                if page.differing:
                    raise ValueError("notification writer rewrote history")
                if page.cursor is not None:
                    return (
                        base_oid, candidate, controls,
                        replace(scan, after=page.cursor), None, False,
                    )
            scan = replace(
                scan,
                phase="suffix",
                after=None,
                sequence=accepted_tree.count,
            )

        page = await tree_reader(
            candidate.tree,
            self.workspace,
            scan.device,
            self._tree_object,
        ).diff_page_awaited(
            tree_reader(
                accepted_tree,
                self.workspace,
                scan.device,
                self._tree_object,
            ),
            start=leaf_key(accepted_tree.count + 1),
            stop=LEAF_PREFIX + "\uffff",
            after=scan.after,
            limit=MAX_SCAN_PILES_PER_TURN,
        )
        if len(page.differing) > MAX_SCAN_PILES_PER_TURN:
            raise ValueError("notification scan pile page")
        state = None
        sequence = scan.sequence
        if page.differing:
            key, pile_oid = page.differing[0]
            if key != leaf_key(sequence + 1):
                raise ValueError("notification writer noncontiguous suffix")
            raw = await self._pile(pile_oid)
            state = _CollectState()
            consumer = FactConsumer(self.workspace, state)
            batch = consumer.prepare_batch(
                ((raw, scan.device),), owner=candidate.owner)
            consumer.commit(batch, device=scan.device, head=scan.head)
            actual_controls = set(batch.control_piles)
            if actual_controls - controls:
                raise ValueError("notification undeclared control pile")
            sequence += 1
        complete = page.cursor is None
        if complete and sequence != candidate.sequence:
            raise ValueError("notification writer suffix coverage")
        next_scan = replace(
            scan,
            phase="complete" if complete else "suffix",
            after=None if complete else page.cursor,
            sequence=sequence,
        )
        processed = None if state is None else (
            state, tuple(batch.control_piles))
        return (
            base_oid, candidate, controls, next_scan, processed, complete)

    async def _pending_body(self, cursor):
        raw = await self._get(
            self.cursor_store, "obj/" + cursor.pending.oid,
            MAX_HINT_BYTES)
        if not isinstance(raw, bytes) or h(raw) != cursor.pending.oid:
            raise ValueError("notification pending body")
        try:
            reference = decode_hint(raw)
        except ValueError as error:
            raise CursorRebootstrapRequired(
                "disable delivery and rebootstrap current notification state"
            ) from error
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

    async def _reject_scan(self, cursor, token):
        rejected = await self._map_update(
            "rejected", cursor.rejected,
            ((cursor.scan.device, cursor.scan.head),))
        desired = replace(cursor, rejected=rejected, scan=None)
        if await self._cas_exact(token, desired) is None:
            return DiscoveryResult("raced", cursor.scan.head)
        return DiscoveryResult("invalid", cursor.scan.head)

    async def _emit(self, cursor, token):
        """Publish one page only after the complete pinned head validated."""
        scan = cursor.scan
        rows, continuation = await self._map_page(
            "scan-events", scan.events, scan.after, self.page_rows)
        if not rows:
            raise ValueError("notification staged event page")
        events = []
        for fid, oid in rows:
            if not valid_fid(fid) or not valid_fid(oid):
                raise ValueError("notification staged event")
            raw = await self._get(
                self.cursor_store, "obj/" + oid, MAX_FACT_BYTES)
            if not isinstance(raw, bytes) or h(raw) != oid:
                raise ValueError("notification staged event")
            events.append(EventRef(fid, oid))
        base = (await self._map_points(
            "heads", cursor.heads, (scan.device,)))[scan.device]
        hint = NotificationHint(
            self.workspace, self.owner, cursor.generation,
            scan.device, base, scan.head, tuple(events))
        raw = encode_hint(hint)
        oid = await self._ensure_object(raw, MAX_HINT_BYTES)
        seen = await self._map_update(
            "seen", cursor.seen,
            tuple((event.fid, event.oid) for event in events))
        successor = replace(
            scan,
            phase="complete" if continuation is None else "emit",
            after=continuation,
        )
        pending = Pending(oid, cursor.heads, seen)
        desired = replace(cursor, scan=successor, pending=pending)
        if await self._cas_exact(token, desired) is None:
            return DiscoveryResult("raced", scan.head)
        await self._publish(raw)
        return DiscoveryResult("published", scan.head, None, oid)

    async def _scan(self, cursor, token):
        scan = cursor.scan
        if scan.phase == "emit":
            return await self._emit(cursor, token)
        if scan.phase == "complete":
            heads = await self._map_update(
                "heads", cursor.heads, ((scan.device, scan.head),))
            desired = replace(cursor, heads=heads, scan=None)
            if await self._cas_exact(token, desired) is None:
                return DiscoveryResult("raced", scan.head)
            return DiscoveryResult("advanced", scan.head)
        try:
            _base, _candidate, controls, next_scan, processed, complete = \
                await self._scan_page(cursor)
        except ValueError:
            return await self._reject_scan(cursor, token)

        if processed is not None:
            state, actual_controls = processed
            if actual_controls:
                next_controls = await self._map_update(
                    "scan-controls",
                    next_scan.controls,
                    tuple((oid, oid) for oid in actual_controls),
                )
                next_scan = replace(next_scan, controls=next_controls)
            rows = await self._unseen(
                cursor.seen, self._trigger_rows(state))
            if rows:
                staged = []
                for fid, oid, raw in rows:
                    if await self._ensure_object(raw, MAX_FACT_BYTES) != oid:
                        raise ValueError("notification staged event")
                    staged.append((fid, oid))
                event_map = await self._map_update(
                    "scan-events", next_scan.events, tuple(staged))
                next_scan = replace(next_scan, events=event_map)

        if complete and next_scan.controls["count"] != len(controls):
            return await self._reject_scan(cursor, token)
        if complete:
            next_scan = replace(
                next_scan,
                phase="emit" if next_scan.events["count"] else "complete",
                after=None,
            )
        desired = replace(cursor, scan=next_scan)
        next_token = await self._cas_exact(token, desired)
        if next_token is None:
            return DiscoveryResult("raced", scan.head)
        if next_scan.phase == "emit":
            return await self._emit(desired, next_token)
        if next_scan.phase == "complete":
            return await self._scan(desired, next_token)
        return DiscoveryResult(
            "continued", scan.head, next_scan.after)

    async def run_once(self):
        cursor, token = await self._read_cursor()
        if cursor.pending is not None:
            raw = await self._pending_body(cursor)
            await self._publish(raw)
            return DiscoveryResult(
                "republished", cursor.scan.head, None,
                cursor.pending.oid)
        if cursor.scan is None:
            candidate, continuation = await self._candidate(cursor)
            if candidate is None:
                if continuation == cursor.directory_after:
                    return DiscoveryResult("idle")
                desired = replace(
                    cursor, directory_after=continuation)
                next_token = await self._cas_exact(token, desired)
                if next_token is None:
                    return DiscoveryResult("raced")
                return DiscoveryResult(
                    "continued" if continuation is not None else "idle",
                    continuation=continuation,
                )
            desired = replace(
                cursor,
                scan=candidate,
                directory_after=continuation,
            )
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
    "CursorRebootstrapRequired",
    "DiscoveryResult",
    "NotificationDiscovery",
    "NotificationState",
    "PENDING_CURRENT",
    "PENDING_NONCURRENT",
    "PENDING_RETRY",
    "REBOOTSTRAP_CURRENT",
    "Pending",
    "Scan",
    "decode_cursor",
    "empty_descriptor",
    "encode_cursor",
)
