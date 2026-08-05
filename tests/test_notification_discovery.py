"""Crash, bootstrap, and race coverage for per-writer notification cursors."""
import asyncio
from dataclasses import dataclass

import pytest

import facts
from adapters.s3 import S3Config, S3Store
from core.crypto import h, keypair
from core.fact import canon, encode
from core.object_store import OutcomeUnknown
from core.store import FsStore
from core.writer_head import (
    HeadSlot,
    decode_head,
    decode_slot_at,
    encode_head,
    encode_slot,
    head_oid,
    head_slot_key,
    make_head,
    require_bound_head,
    writer_store_binding,
)
from core.writer_tree import leaf_key, tree_reader
from facts.auth.device import bind
from facts.content import delete, message
from full_peer.node import FullPeer
from notifications.carrier import CarrierAccepted
from notifications.discovery import (
    BOOTSTRAP_BACKFILL,
    BOOTSTRAP_CURRENT,
    Cursor,
    CursorNotInitialized,
    NotificationDiscovery,
    NotificationState,
    PENDING_CURRENT,
    PENDING_NONCURRENT,
    Pending,
    Scan,
    decode_cursor,
    empty_descriptor,
    encode_cursor,
)
from notifications.hints import (
    EventRef,
    MAX_HINT_BYTES,
    MAX_HINT_EVENTS,
    NotificationHint,
    decode_hint,
    encode_hint,
    materialize_hint,
)
from notifications.forest import closure_writer_binding
from tests.util import add_member


OWNER = "c" * 64
GENERATION = "e" * 64


@dataclass
class MemoryCarrier:
    payloads: list

    async def publish(self, payload):
        self.payloads.append(payload)
        return CarrierAccepted(h(payload))


class RejectCarrier:
    async def publish(self, _payload):
        raise RuntimeError("carrier unavailable")


class BarrierCarrier(MemoryCarrier):
    def __init__(self):
        super().__init__([])
        self.barrier = asyncio.Barrier(2)

    async def publish(self, payload):
        self.payloads.append(payload)
        await self.barrier.wait()
        return CarrierAccepted(h(payload))


class DelegateStore:
    def __init__(self, store):
        self.store = store

    def __getattr__(self, name):
        return getattr(self.store, name)


class UnknownNextCas(DelegateStore):
    """Commit one selected CAS but lose its response."""

    def __init__(self, store):
        super().__init__(store)
        self.unknown = False

    def cas(self, key, token, value):
        result = self.store.cas(key, token, value)
        if self.unknown:
            self.unknown = False
            raise OutcomeUnknown("lost CAS response")
        return result


class SimulatedCrash(BaseException):
    pass


class CrashBeforeSecondCas(DelegateStore):
    """Crash after validation but before pending notification progress."""

    def __init__(self, store):
        super().__init__(store)
        self.remaining = None

    def arm(self):
        # run_once first pins Scan, then attempts to persist Pending.
        self.remaining = 2

    def cas(self, key, token, value):
        if self.remaining is not None:
            self.remaining -= 1
            if self.remaining == 0:
                self.remaining = None
                raise SimulatedCrash()
        return self.store.cas(key, token, value)


class CrashAfterNextCas(DelegateStore):
    """Preserve one cursor CAS, then lose the process before scan work."""

    def __init__(self, store):
        super().__init__(store)
        self.armed = False

    def cas(self, key, token, value):
        result = self.store.cas(key, token, value)
        if self.armed:
            self.armed = False
            raise SimulatedCrash()
        return result


class AwaitedStore:
    """Actually-async object-store fake, including writer-list operations."""

    def __init__(self, store):
        self.store = store
        self.calls = []

    async def get_bounded(self, key, maximum):
        self.calls.append(("get", key))
        await asyncio.sleep(0)
        return self.store.get_bounded(key, maximum)

    async def copy_pile_object(self, oid, maximum, write):
        self.calls.append(("copy", oid))
        await asyncio.sleep(0)
        return self.store.copy_pile_object(oid, maximum, write)

    async def read_versioned(self, key):
        self.calls.append(("read", key))
        await asyncio.sleep(0)
        return self.store.read_versioned(key)

    async def put_if_absent(self, key, value):
        self.calls.append(("create", key))
        await asyncio.sleep(0)
        return self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        self.calls.append(("cas", key))
        await asyncio.sleep(0)
        return self.store.cas(key, token, value)

    async def list_page(self, prefix, cursor=None, limit=256):
        self.calls.append(("list", prefix))
        await asyncio.sleep(0)
        return self.store.list_page(prefix, cursor, limit)


def _world(tmp_path):
    node = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    return node, workspace


def _forest(tmp_path):
    alice_secret, _alice_public = keypair()
    bob_secret, bob_public = keypair()
    alice = FullPeer(str(tmp_path / "alice"), initial_secret=alice_secret)
    workspace = facts.auth.workspace.create(alice, "alice", ts=1)
    _secret, _public, bob_join = add_member(
        alice,
        workspace,
        "bob",
        ts=10,
        member_identity=(bob_secret, bob_public),
        invite_identity=keypair(),
    )
    authority = alice.sender(workspace).close((bob_join,), {})
    bob = FullPeer(str(tmp_path / "bob"), initial_secret=bob_secret)
    bob.add_workspace(workspace, "bob", peers=[])
    bob.publish_closed(workspace, (authority,))
    return alice, bob, workspace


def _discovery(node, workspace, cursor, carrier, **kwargs):
    return NotificationDiscovery(
        node.store(workspace), cursor, workspace, carrier,
        owner=OWNER, generation_factory=lambda: GENERATION, **kwargs)


def _cursor(store):
    store = getattr(store, "store", store)
    return decode_cursor(store.read_versioned("cursor").value)


def _slot(node, workspace, device=None):
    device = node.identity_id(workspace) if device is None else device
    key = head_slot_key(workspace, device)
    return decode_slot_at(key, node.store(workspace).get(key))


def _replace_head_claim(node, anchored_workspace, **changes):
    """Install one device-signed hostile head over the genuine tree."""
    secret, device = node.identity(anchored_workspace)
    store = node.store(anchored_workspace)
    key = head_slot_key(anchored_workspace, device)
    opened = store.read_versioned(key)
    slot = decode_slot_at(key, opened.value)
    current = decode_head(store.get("obj/" + slot.head))
    candidate = make_head(
        secret,
        changes.get("workspace", current.workspace),
        device,
        changes.get("owner", current.owner),
        current.sequence,
        current.tree,
        changes.get("store", current.store),
        current.control,
    )
    raw = encode_head(candidate)
    oid = head_oid(raw)
    store.put_if_absent("obj/" + oid, raw)
    store.cas(
        key,
        opened.token,
        encode_slot(HeadSlot(
            anchored_workspace, device, oid, slot.removal_root)),
    )
    return oid


async def _pending_body(discovery):
    pending = _cursor(discovery.cursor_store).pending
    return await discovery.state.get_bounded(
        "obj/" + pending.oid, MAX_HINT_BYTES)


async def _complete(discovery, raw):
    return await discovery.state.complete(h(raw))


async def _drain(discovery, maximum=100):
    results = []
    for _ in range(maximum):
        result = await discovery.run_once()
        results.append(result)
        if result.status in {"published", "republished"}:
            raw = await _pending_body(discovery)
            assert await _complete(discovery, raw) == PENDING_NONCURRENT
        if result.status == "idle":
            return results
    raise AssertionError("notification discovery did not become idle")


def test_run_requires_explicit_bootstrap(tmp_path):
    node, workspace = _world(tmp_path)
    discovery = _discovery(
        node, workspace, FsStore(str(tmp_path / "cursor")),
        MemoryCarrier([]))

    with pytest.raises(CursorNotInitialized, match="cursor is absent"):
        asyncio.run(discovery.run_once())


def test_backfill_validates_writer_head_and_materializes_exact_event(tmp_path):
    node, workspace = _world(tmp_path)
    event = message.post(node, workspace, "general", "hello", ts=3)
    carrier = MemoryCarrier([])
    discovery = _discovery(
        node, workspace, FsStore(str(tmp_path / "cursor")), carrier)

    first = asyncio.run(discovery.bootstrap_backfill())
    assert first.bootstrap == BOOTSTRAP_BACKFILL
    assert asyncio.run(discovery.bootstrap_backfill()) == first
    asyncio.run(_drain(discovery))

    reference, = map(decode_hint, carrier.payloads)
    slot = _slot(node, workspace)
    assert reference.workspace == workspace
    assert reference.owner == OWNER
    assert reference.generation == GENERATION
    assert reference.device == node.identity_id(workspace)
    assert reference.base_head is None
    assert reference.head == slot.head
    assert reference.facts == (event,)
    event_raw = discovery.cursor_store.store.get(
        "obj/" + reference.events[0].oid)
    assert materialize_hint(reference, (event_raw,)).facts == (event,)
    assert not discovery.cursor_store.store.list(f"heads/{workspace}")


def test_closure_binding_uses_proved_owner_and_canonical_writer_store(
        tmp_path):
    node, workspace = _world(tmp_path)
    slot = _slot(node, workspace)
    head = decode_head(node.store(workspace).get("obj/" + slot.head))

    binding = closure_writer_binding(
        workspace, head.device, slot.removal_root, head)

    assert binding.owner == head.owner
    assert binding.store == writer_store_binding(workspace, head.device)
    assert require_bound_head(head, binding) == head


@pytest.mark.parametrize("field", ("owner", "store", "workspace"))
def test_notification_scan_rejects_signed_cross_boundary_head_claim(
        tmp_path, field):
    node, workspace = _world(tmp_path)
    event = message.post(node, workspace, "general", "hostile", ts=3)
    _replace_head_claim(node, workspace, **{field: h(field.encode())})
    carrier = MemoryCarrier([])
    discovery = _discovery(
        node, workspace, FsStore(str(tmp_path / "cursor")), carrier)
    asyncio.run(discovery.bootstrap_backfill())

    result = asyncio.run(discovery.run_once())

    assert result.status == "invalid"
    assert carrier.payloads == []
    assert event not in {
        fid for raw in carrier.payloads for fid in decode_hint(raw).facts}


def test_current_bootstrap_skips_history_but_finds_later_facts(tmp_path):
    node, workspace = _world(tmp_path)
    old = message.post(node, workspace, "general", "old", ts=3)
    carrier = MemoryCarrier([])
    discovery = _discovery(
        node, workspace, FsStore(str(tmp_path / "cursor")), carrier)

    cursor = asyncio.run(discovery.bootstrap_current())
    assert cursor.bootstrap == BOOTSTRAP_CURRENT
    assert asyncio.run(discovery.run_once()).status == "idle"
    new = message.post(node, workspace, "general", "new", ts=4)
    asyncio.run(_drain(discovery))

    found = {fid for raw in carrier.payloads for fid in decode_hint(raw).facts}
    assert found == {new}
    assert old not in found


def test_two_writer_heads_are_acknowledged_independently(tmp_path):
    alice, bob, workspace = _forest(tmp_path)
    alice_event = message.post(
        alice, workspace, "general", "from alice", ts=30)
    bob_event = message.post(bob, workspace, "general", "from bob", ts=31)
    mirrored = asyncio.run(
        alice.mirror(workspace).sync_from(bob.store(workspace)))
    assert mirrored.errors == ()
    carrier = MemoryCarrier([])
    discovery = _discovery(
        alice, workspace, FsStore(str(tmp_path / "cursor")), carrier)
    asyncio.run(discovery.bootstrap_backfill())

    asyncio.run(_drain(discovery))

    references = tuple(map(decode_hint, carrier.payloads))
    assert {fid for row in references for fid in row.facts} >= {
        alice_event, bob_event}
    assert {row.device for row in references} == {
        alice.identity_id(workspace), bob.identity_id(workspace)}
    assert asyncio.run(discovery.run_once()).status == "idle"


def test_unknown_bootstrap_cas_reconciles_by_reread(tmp_path):
    node, workspace = _world(tmp_path)
    store = UnknownNextCas(FsStore(str(tmp_path / "cursor")))
    store.unknown = True
    discovery = _discovery(node, workspace, store, MemoryCarrier([]))

    cursor = asyncio.run(discovery.bootstrap_current())

    assert cursor == _cursor(store)
    assert asyncio.run(discovery.bootstrap_current()) == cursor


def test_bootstrap_mode_owner_and_state_loss_fail_closed(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    discovery = _discovery(node, workspace, store, MemoryCarrier([]))
    asyncio.run(discovery.bootstrap_current())

    with pytest.raises(ValueError, match="bootstrap conflict"):
        asyncio.run(discovery.bootstrap_backfill())
    foreign = NotificationDiscovery(
        node.store(workspace), store, workspace, MemoryCarrier([]),
        owner="d" * 64)
    with pytest.raises(ValueError, match="bootstrap conflict"):
        asyncio.run(foreign.bootstrap_current())
    store._delete("cursor")
    with pytest.raises(CursorNotInitialized):
        asyncio.run(discovery.run_once())


def test_carrier_failure_and_dropped_wake_republish_exact_body(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    bootstrap = _discovery(node, workspace, store, MemoryCarrier([]))
    asyncio.run(bootstrap.bootstrap_current())
    event = message.post(node, workspace, "general", "retry", ts=3)

    with pytest.raises(RuntimeError, match="carrier unavailable"):
        asyncio.run(_discovery(
            node, workspace, store, RejectCarrier()).run_once())
    pending = _cursor(store).pending
    raw = store.get("obj/" + pending.oid)
    assert decode_hint(raw).facts == (event,)

    carrier = MemoryCarrier([])
    retry = _discovery(node, workspace, store, carrier)
    assert asyncio.run(retry.run_once()).status == "republished"
    carrier.payloads.clear()  # simulate an expired carrier wake
    assert asyncio.run(retry.run_once()).status == "republished"
    assert carrier.payloads == [raw]
    assert _cursor(store).pending == pending


def test_concurrent_scanners_republish_one_pending_body(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    discovery = _discovery(node, workspace, store, MemoryCarrier([]))
    asyncio.run(discovery.bootstrap_current())
    event = message.post(node, workspace, "general", "race", ts=3)
    with pytest.raises(RuntimeError):
        asyncio.run(_discovery(
            node, workspace, store, RejectCarrier()).run_once())

    carrier = BarrierCarrier()

    async def race():
        return await asyncio.gather(*(
            _discovery(node, workspace, store, carrier).run_once()
            for _ in range(2)))

    results = asyncio.run(race())
    assert [row.status for row in results] == ["republished", "republished"]
    assert carrier.payloads[0] == carrier.payloads[1]
    assert decode_hint(carrier.payloads[0]).facts == (event,)
    assert _cursor(store).pending.oid == h(carrier.payloads[0])


def test_crash_after_mirror_before_cursor_cas_replays_unacked_head(tmp_path):
    node, workspace = _world(tmp_path)
    base = FsStore(str(tmp_path / "cursor"))
    fault = CrashBeforeSecondCas(base)
    discovery = _discovery(node, workspace, fault, MemoryCarrier([]))
    asyncio.run(discovery.bootstrap_current())
    event = message.post(node, workspace, "general", "unacked", ts=3)
    fault.arm()

    with pytest.raises(SimulatedCrash):
        asyncio.run(discovery.run_once())
    crashed = _cursor(base)
    assert crashed.scan is not None and crashed.pending is None
    assert not base.list(f"heads/{workspace}")

    carrier = MemoryCarrier([])
    retry = _discovery(node, workspace, base, carrier)
    assert asyncio.run(retry.run_once()).status == "published"
    assert decode_hint(carrier.payloads[0]).facts == (event,)


def test_completion_unknown_and_concurrent_completion_are_safe(tmp_path):
    node, workspace = _world(tmp_path)
    base = FsStore(str(tmp_path / "cursor"))
    fault = UnknownNextCas(base)
    discovery = _discovery(node, workspace, fault, MemoryCarrier([]))
    asyncio.run(discovery.bootstrap_current())
    message.post(node, workspace, "general", "accepted", ts=3)
    asyncio.run(discovery.run_once())
    raw = base.get("obj/" + _cursor(base).pending.oid)
    fault.unknown = True

    assert asyncio.run(discovery.state.complete(h(raw))) == PENDING_NONCURRENT
    assert asyncio.run(discovery.state.complete(h(raw))) == PENDING_NONCURRENT
    assert _cursor(base).pending is None


def test_scan_stays_on_exact_head_when_writer_advances_mid_page(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(
        node, workspace, store, carrier, page_rows=1)
    asyncio.run(discovery.bootstrap_current())
    first = message.post(node, workspace, "general", "first", ts=10)
    second = message.post(node, workspace, "general", "second", ts=11)
    pinned = _slot(node, workspace).head

    assert asyncio.run(discovery.run_once()).status == "published"
    first_body = carrier.payloads[-1]
    assert decode_hint(first_body).head == pinned
    asyncio.run(_complete(discovery, first_body))
    later = message.post(node, workspace, "general", "later", ts=12)
    latest = _slot(node, workspace).head
    assert latest != pinned
    asyncio.run(_drain(discovery))

    heads_by_fact = {
        fid: reference.head
        for raw in carrier.payloads
        for reference in (decode_hint(raw),)
        for fid in reference.facts
    }
    assert heads_by_fact[first] == heads_by_fact[second] == pinned
    assert heads_by_fact[later] == latest


def test_malformed_writer_is_quarantined_without_blocking_other_heads(
        tmp_path):
    node, other, workspace = _forest(tmp_path)
    mirrored = asyncio.run(
        node.mirror(workspace).sync_from(other.store(workspace)))
    assert mirrored.errors == ()
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(node, workspace, store, carrier)
    asyncio.run(discovery.bootstrap_current())
    bad = message.post(node, workspace, "general", "corrupt", ts=30)
    good = message.post(other, workspace, "general", "valid", ts=31)
    mirrored = asyncio.run(
        node.mirror(workspace).sync_from(other.store(workspace)))
    assert mirrored.errors == ()

    slot = _slot(node, workspace)
    head = decode_head(node.store(workspace).get("obj/" + slot.head))
    reader = tree_reader(
        head.tree,
        workspace,
        head.device,
        lambda oid: node.store(workspace).get("obj/" + oid),
    )
    pile_oid = reader.get(leaf_key(head.sequence))
    node.store(workspace)._delete("obj/" + pile_oid)

    results = asyncio.run(_drain(discovery))
    cursor = _cursor(store)
    rejected = asyncio.run(discovery._map_points(
        "rejected", cursor.rejected, (slot.device,)))
    found = {
        fid for raw in carrier.payloads for fid in decode_hint(raw).facts}
    assert "invalid" in {result.status for result in results}
    assert rejected[slot.device] == slot.head
    assert cursor.scan is cursor.pending is None
    assert good in found and bad not in found
    assert asyncio.run(discovery.run_once()).status == "idle"


def test_current_suppression_does_not_erase_historical_discovery(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(node, workspace, store, carrier)
    asyncio.run(discovery.bootstrap_current())
    event = message.post(node, workspace, "general", "removed", ts=10)
    delete.remove(node, workspace, event, ts=11)
    assert node.sql(workspace).fact_active(event) is False

    asyncio.run(_drain(discovery))

    assert event in {
        fid for raw in carrier.payloads for fid in decode_hint(raw).facts}


def test_current_member_removal_does_not_rewrite_historical_writer_event(
        tmp_path):
    alice, bob, workspace = _forest(tmp_path)
    mirrored = asyncio.run(
        alice.mirror(workspace).sync_from(bob.store(workspace)))
    assert mirrored.errors == ()
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(alice, workspace, store, carrier)
    asyncio.run(discovery.bootstrap_current())
    event = message.post(bob, workspace, "general", "before removal", ts=30)
    mirrored = asyncio.run(
        alice.mirror(workspace).sync_from(bob.store(workspace)))
    assert mirrored.errors == ()
    facts.auth.removal.evict(alice, workspace, bob.pk)

    asyncio.run(_drain(discovery))

    assert next(
        row for row in facts.auth.user.members(alice, workspace)
        if row["pk"] == bob.pk)["evicted"] is True
    assert event in {
        fid for raw in carrier.payloads for fid in decode_hint(raw).facts}


def test_scan_retry_replays_exact_slot_recorded_removal_root(tmp_path):
    node, workspace = _world(tmp_path)
    base = FsStore(str(tmp_path / "cursor"))
    fault = CrashAfterNextCas(base)
    discovery = _discovery(node, workspace, fault, MemoryCarrier([]))
    asyncio.run(discovery.bootstrap_current())
    event = message.post(node, workspace, "general", "pinned root", ts=10)
    pinned = _slot(node, workspace)
    fault.armed = True

    with pytest.raises(SimulatedCrash):
        asyncio.run(discovery.run_once())
    crashed = _cursor(base)
    assert crashed.scan == Scan(
        pinned.device, pinned.head, pinned.removal_root)

    add_member(node, workspace, "later member", ts=20)
    current = _slot(node, workspace)
    assert current.head != pinned.head
    assert current.removal_root != pinned.removal_root

    carrier = MemoryCarrier([])
    retry = _discovery(node, workspace, base, carrier)
    assert asyncio.run(retry.run_once()).status == "published"
    reference = decode_hint(carrier.payloads[0])
    assert reference.head == pinned.head
    assert reference.facts == (event,)


def test_actual_async_stores_preserve_writer_cursor_protocol(tmp_path):
    node, workspace = _world(tmp_path)
    repository = AwaitedStore(node.store(workspace))
    state = AwaitedStore(FsStore(str(tmp_path / "cursor")))
    carrier = MemoryCarrier([])
    discovery = NotificationDiscovery(
        repository, state, workspace, carrier, owner=OWNER,
        generation_factory=lambda: GENERATION)
    asyncio.run(discovery.bootstrap_current())
    message.post(node, workspace, "general", "async", ts=3)
    asyncio.run(discovery.run_once())

    assert _cursor(state).pending is not None
    assert {name for name, _key in repository.calls} >= {
        "copy", "get", "list", "read"}
    assert {name for name, _key in state.calls} >= {
        "get", "read", "create", "cas"}


def test_rebootstrap_generation_makes_old_delivery_noncurrent(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    old = _discovery(node, workspace, store, carrier)
    asyncio.run(old.bootstrap_current())
    event = message.post(node, workspace, "general", "old wake", ts=3)
    assert asyncio.run(old.run_once()).status == "published"
    old_raw = carrier.payloads[-1]
    old_reference = decode_hint(old_raw)
    assert old_reference.facts == (event,)
    assert asyncio.run(old.state.pending(h(old_raw))) == PENDING_CURRENT

    store._delete("cursor")
    fresh_carrier = MemoryCarrier([])
    fresh = NotificationDiscovery(
        node.store(workspace), store, workspace, fresh_carrier,
        owner=OWNER, generation_factory=lambda: "f" * 64)
    asyncio.run(fresh.bootstrap_backfill())
    assert asyncio.run(fresh.run_once()).status == "published"
    new_raw, = fresh_carrier.payloads
    new_reference = decode_hint(new_raw)
    assert new_reference.head == old_reference.head
    assert new_reference.facts == old_reference.facts
    assert new_reference.generation != old_reference.generation
    assert h(new_raw) != h(old_raw)

    assert asyncio.run(fresh.state.pending(h(old_raw))) == PENDING_NONCURRENT
    assert asyncio.run(old.state.complete(h(old_raw))) == PENDING_NONCURRENT


def test_hint_and_cursor_codecs_are_canonical_and_reject_old_shape():
    events = tuple(
        EventRef(
            h(number.to_bytes(4, "big")),
            h(b"event" + number.to_bytes(4, "big")),
        )
        for number in range(MAX_HINT_EVENTS)
    )
    events = tuple(sorted(events))
    hint = NotificationHint(
        "a" * 64, "b" * 64, "c" * 64, "d" * 64,
        None, "e" * 64, events)
    raw = encode_hint(hint)
    assert len(raw) < MAX_HINT_BYTES
    assert decode_hint(raw) == hint
    with pytest.raises(ValueError, match="notification hint"):
        NotificationHint(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64,
            None, "e" * 64, events + (EventRef("f" * 64, "f" * 64),))

    empty = empty_descriptor()
    cursor = Cursor(
        "a" * 64, "b" * 64, "c" * 64, BOOTSTRAP_BACKFILL,
        True, empty, empty, empty,
        Scan("d" * 64, "e" * 64, "f" * 64))
    encoded_cursor = encode_cursor(cursor)
    assert b'"removal_root"' in encoded_cursor
    assert b'"authority_root"' not in encoded_cursor
    assert decode_cursor(encoded_cursor) == cursor
    with pytest.raises(ValueError, match="cursor shape"):
        decode_cursor(canon({"format": "notification-cursor-v3"}))

    changed = {"root": h(b"map"), "count": 1, "depth": 1}
    with pytest.raises(ValueError, match="pending successor"):
        Cursor(
            cursor.workspace, cursor.owner, cursor.generation,
            cursor.bootstrap, True, empty, empty, empty, cursor.scan,
            Pending("f" * 64, changed, empty))


def test_discovery_rejects_one_namespace_and_page_over_limit(tmp_path):
    root = tmp_path / "same"
    root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="notification discovery"):
        NotificationDiscovery(
            FsStore(str(root)), FsStore(str(alias)), "a" * 64,
            MemoryCarrier([]), owner=OWNER)

    first = S3Store(
        S3Config(bucket="same-bucket", prefix="same/prefix"),
        client=object())
    second = S3Store(
        S3Config(bucket="same-bucket", prefix="same/prefix"),
        client=object())
    with pytest.raises(ValueError, match="notification discovery"):
        NotificationDiscovery(
            first, second, "a" * 64, MemoryCarrier([]), owner=OWNER)
    with pytest.raises(ValueError, match="notification discovery"):
        NotificationDiscovery(
            object(), object(), "a" * 64, MemoryCarrier([]), owner=OWNER,
            page_rows=MAX_HINT_EVENTS + 1)
