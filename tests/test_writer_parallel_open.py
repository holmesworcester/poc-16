"""Deterministic schedules for bounded parallel writer-top opening.

Only remote slot reads overlap.  Candidate traversal, local slot CAS, and the
consumer commit remain one serialized acceptance stream.
"""
import asyncio
from dataclasses import dataclass

from core.crypto import h, keypair
from core.object_store import ABSENT, Applied, Versioned, VersionToken
from core.store import FsStore
from core.writer_head import (
    HeadSlot,
    WriterBinding,
    decode_slot_at,
    encode_slot,
    head_slot_key,
)
from core.writer_repository import FactConsumer, RepositoryMirror, WriterLog
from facts.auth.device import device as device_fact
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact


def run(awaitable):
    return asyncio.run(awaitable)


@dataclass
class Forest:
    workspace: str
    source: FsStore
    closure: tuple
    devices: tuple
    logs: dict
    bindings: dict
    slots: dict
    authority: str

    def resolve(self, workspace, device, _authority):
        if workspace != self.workspace:
            return None
        return self.bindings.get(device)


async def make_forest(path, count=3, published=None):
    """Build independent device logs with one realistic shared authority."""
    identities = tuple(keypair() for _ in range(count))
    founder_secret, founder = identities[0]
    root = workspace_fact(founder_secret, founder, "workspace", 1)
    primary = device_fact(root.fid, founder, "primary", 2)
    primary_signature = signature_fact(
        founder_secret, founder, primary, 2)
    closure = [root, primary_signature, primary]
    for ordinal, (_secret, public) in enumerate(identities[1:], 3):
        grant = device_invite(
            root.fid,
            founder,
            founder,
            public,
            f"device-{ordinal}",
            ordinal,
        )
        closure.extend((
            signature_fact(founder_secret, founder, grant, ordinal),
            grant,
        ))

    source = FsStore(str(path))
    authority = h(b"parallel-open-authority")
    logs, bindings, slots = {}, {}, {}
    for ordinal, (secret, public) in enumerate(identities):
        store_binding = h(f"writer-store-{ordinal}".encode())
        binding = WriterBinding(
            root.fid, public, founder, store_binding)
        log = WriterLog(
            root.fid,
            public,
            founder,
            store_binding,
            secret,
            source,
        )
        update = await log.prepare((tuple(closure),))
        await log.establish(update)
        logs[public] = log
        bindings[public] = binding
        slots[public] = encode_slot(HeadSlot(
            root.fid, public, update.head_oid, authority))

    devices = tuple(sorted(logs))
    if published is None:
        published = count
    for public in devices[:published]:
        result = source.cas(
            head_slot_key(root.fid, public), ABSENT, slots[public])
        assert isinstance(result, Applied)
    return Forest(
        root.fid,
        source,
        tuple(closure),
        devices,
        logs,
        bindings,
        slots,
        authority,
    )


async def staged_append(forest, device):
    update = await forest.logs[device].prepare((forest.closure,))
    await forest.logs[device].establish(update)
    return update, encode_slot(HeadSlot(
        forest.workspace,
        device,
        update.head_oid,
        forest.authority,
    ))


class AsyncStoreProxy:
    """Awaited façade whose subclasses can place exact scheduling points."""

    def __init__(self, backing):
        self.backing = backing

    async def get_bounded(self, key, maximum):
        return self.backing.get_bounded(key, maximum)

    async def read_versioned(self, key):
        return self.backing.read_versioned(key)

    async def put_if_absent(self, key, value):
        return self.backing.put_if_absent(key, value)

    async def cas(self, key, token, value):
        return self.backing.cas(key, token, value)

    async def list_page(self, prefix, cursor=None, limit=256):
        return self.backing.list_page(prefix, cursor, limit)


class TopReadWave(AsyncStoreProxy):
    """Release a page only if every exact slot read is already suspended."""

    def __init__(self, backing, keys, before_release=None):
        super().__init__(backing)
        self.keys = frozenset(keys)
        self.before_release = before_release
        self.snapshots = {}
        self.entered = []
        self.released_with = ()
        self.failure = None
        self.release = asyncio.Event()

    def _end_scheduler_turn(self):
        self.released_with = tuple(self.entered)
        if set(self.entered) != self.keys:
            self.failure = AssertionError(
                "a writer slot was released before its page peers opened")
        elif self.before_release is not None:
            self.before_release()
        self.release.set()

    async def read_versioned(self, key):
        if key not in self.keys:
            return await super().read_versioned(key)
        if key in self.snapshots:
            raise AssertionError("the prefetched writer slot was read twice")
        self.snapshots[key] = self.backing.read_versioned(key)
        self.entered.append(key)
        if len(self.entered) == 1:
            # gather()/TaskGroup creates the page's tasks before any one task
            # blocks. call_soon therefore runs after those tasks have reached
            # this barrier. A sequential loop deterministically fails here;
            # there is no wall-clock timeout or scheduler race in the test.
            asyncio.get_running_loop().call_soon(
                self._end_scheduler_turn)
        await self.release.wait()
        if self.failure is not None:
            raise self.failure
        return self.snapshots[key]


class SerialLocalStore(AsyncStoreProxy):
    """Make an overlapping local slot-CAS phase observable and invalid."""

    def __init__(self, backing, events):
        super().__init__(backing)
        self.events = events
        self.active = None

    async def cas(self, key, token, value):
        if not key.startswith("heads/"):
            return await super().cas(key, token, value)
        if self.active is not None:
            raise AssertionError(
                f"slot applications overlapped: {self.active}, {key}")
        self.active = key
        self.events.append(("cas-start", key))
        try:
            await asyncio.sleep(0)
            result = self.backing.cas(key, token, value)
            self.events.append(("cas-end", key))
            return result
        finally:
            self.active = None


class RecordingConsumer(FactConsumer):
    def __init__(self, workspace, events):
        super().__init__(workspace)
        self.events = events

    def commit(self, batch, *, device, head):
        self.events.append((
            "commit", head_slot_key(self.workspace, device)))
        return super().commit(batch, device=device, head=head)


def test_page_tops_open_together_but_slot_projection_stays_serial(tmp_path):
    async def scenario():
        forest = await make_forest(tmp_path / "source")
        keys = tuple(
            head_slot_key(forest.workspace, device)
            for device in forest.devices)
        source = TopReadWave(forest.source, keys)
        events = []
        local = SerialLocalStore(FsStore(str(tmp_path / "local")), events)
        consumer = RecordingConsumer(forest.workspace, events)
        mirror = RepositoryMirror(
            forest.workspace, local, forest.resolve, consumer)

        result = await mirror.sync_from(source, page_limit=len(keys))

        assert result.errors == ()
        assert result.listed == result.changed == result.piles == len(keys)
        assert set(source.released_with) == set(keys)
        assert len(source.snapshots) == len(keys)
        assert len(events) == 3 * len(keys)
        for offset in range(0, len(events), 3):
            start, end, commit = events[offset:offset + 3]
            assert start[0] == "cas-start"
            assert end == ("cas-end", start[1])
            assert commit == ("commit", start[1])

    run(scenario())


def test_slot_advance_during_top_wave_is_complete_then_catches_up(tmp_path):
    async def scenario():
        forest = await make_forest(tmp_path / "source")
        selected = forest.devices[0]
        key = head_slot_key(forest.workspace, selected)
        old_opened = forest.source.read_versioned(key)
        old_slot = old_opened.value
        old_head = decode_slot_at(key, old_slot).head
        update, new_slot = await staged_append(forest, selected)

        def advance():
            result = forest.source.cas(key, old_opened.token, new_slot)
            assert isinstance(result, Applied)

        keys = tuple(
            head_slot_key(forest.workspace, device)
            for device in forest.devices)
        source = TopReadWave(forest.source, keys, advance)
        local = FsStore(str(tmp_path / "local"))
        consumer = FactConsumer(forest.workspace)
        mirror = RepositoryMirror(
            forest.workspace, local, forest.resolve, consumer)

        first = await mirror.sync_from(source)
        assert first.errors == ()
        assert set(source.released_with) == set(keys)
        # Every page top was pinned before the source advanced and released
        # the wave. The receiver may not combine the new slot with the old
        # head/tree.
        assert local.get(key) == old_slot
        assert consumer.projected_head(selected) == old_head
        assert local.get("obj/" + old_head) is not None

        caught_up = await mirror.sync_from(forest.source)
        assert caught_up.errors == ()
        assert caught_up.changed == caught_up.piles == 1
        assert local.get(key) == new_slot
        assert consumer.projected_head(selected) == update.head_oid
        assert local.get("obj/" + update.head_oid) is not None

    run(scenario())


class InsertAfterListSnapshot(AsyncStoreProxy):
    def __init__(self, backing, insert):
        super().__init__(backing)
        self.insert = insert
        self.inserted = False

    async def list_page(self, prefix, cursor=None, limit=256):
        page = self.backing.list_page(prefix, cursor, limit)
        if not self.inserted:
            self.inserted = True
            self.insert()
        return page


def test_key_created_after_list_snapshot_waits_for_next_scan(tmp_path):
    async def scenario():
        forest = await make_forest(
            tmp_path / "source", published=2)
        late = forest.devices[2]
        late_key = head_slot_key(forest.workspace, late)

        def insert():
            result = forest.source.cas(
                late_key, ABSENT, forest.slots[late])
            assert isinstance(result, Applied)

        local = FsStore(str(tmp_path / "local"))
        consumer = FactConsumer(forest.workspace)
        mirror = RepositoryMirror(
            forest.workspace, local, forest.resolve, consumer)

        first = await mirror.sync_from(
            InsertAfterListSnapshot(forest.source, insert), page_limit=10)
        assert first.errors == ()
        assert first.listed == first.changed == 2
        assert local.get(late_key) is None
        assert consumer.projected_head(late) is None

        repaired = await mirror.sync_from(forest.source, page_limit=10)
        assert repaired.errors == ()
        assert repaired.listed == 3
        assert repaired.changed == repaired.piles == 1
        assert local.get(late_key) == forest.slots[late]
        assert consumer.projected_head(late) == decode_slot_at(
            late_key, forest.slots[late]).head

    run(scenario())


class PinnedSlotSource(AsyncStoreProxy):
    def __init__(self, backing, key, raw):
        super().__init__(backing)
        self.key = key
        self.raw = raw

    async def read_versioned(self, key):
        if key == self.key:
            return Versioned(self.raw, VersionToken(h(self.raw)))
        return await super().read_versioned(key)


class CompetingLocalReads(AsyncStoreProxy):
    """Give two mirror turns the same atomic local-slot observation."""

    def __init__(self, backing, key):
        super().__init__(backing)
        self.key = key
        self.snapshots = []
        self.release = asyncio.Event()
        self.failure = None

    def _end_scheduler_turn(self):
        if len(self.snapshots) != 2:
            self.failure = AssertionError(
                "competing mirrors did not overlap at the local slot")
        self.release.set()

    async def read_versioned(self, key):
        if key != self.key or self.release.is_set():
            return await super().read_versioned(key)
        opened = self.backing.read_versioned(key)
        self.snapshots.append(opened)
        if len(self.snapshots) == 1:
            asyncio.get_running_loop().call_soon(
                self._end_scheduler_turn)
        await self.release.wait()
        if self.failure is not None:
            raise self.failure
        return opened


def test_competing_syncs_for_one_local_slot_cannot_corrupt_it(tmp_path):
    async def scenario():
        forest = await make_forest(
            tmp_path / "source", count=1)
        device = forest.devices[0]
        key = head_slot_key(forest.workspace, device)
        old_slot = forest.slots[device]
        old_head = decode_slot_at(key, old_slot).head
        opened = forest.source.read_versioned(key)
        update, new_slot = await staged_append(forest, device)
        assert isinstance(forest.source.cas(
            key, opened.token, new_slot), Applied)

        local = CompetingLocalReads(
            FsStore(str(tmp_path / "local")), key)
        consumer = FactConsumer(forest.workspace)
        mirror = RepositoryMirror(
            forest.workspace, local, forest.resolve, consumer)
        old_source = PinnedSlotSource(
            forest.source, key, old_slot)

        results = await asyncio.gather(
            mirror.sync_from(old_source),
            mirror.sync_from(forest.source),
        )
        assert all(snapshot is ABSENT for snapshot in local.snapshots)
        assert sum(result.changed for result in results) == 1
        errors = tuple(
            error
            for result in results
            for error in result.errors)
        assert len(errors) == 1
        assert errors[0] == (key, "concurrent local writer-slot update")

        accepted = decode_slot_at(key, local.backing.get(key)).head
        assert accepted in {old_head, update.head_oid}
        assert consumer.projected_head(device) == accepted

        repaired = await mirror.sync_from(forest.source)
        assert repaired.errors == ()
        assert local.backing.get(key) == new_slot
        assert consumer.projected_head(device) == update.head_oid

    run(scenario())
