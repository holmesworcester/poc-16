"""Crash/race coverage for durable post-publication discovery."""
import asyncio
from dataclasses import dataclass

import pytest

import facts
from core import merkle_map
from core.crypto import h
from core.limits import MAX_PILE_FACTS, PayloadTooLarge
from core.object_store import OutcomeUnknown
from core.store import FsStore
from facts.auth.device import bind
from facts.content import delete, message
from full_peer.node import FullPeer
from notifications.carrier import CarrierAccepted
from notifications.discovery import (
    Cursor,
    NotificationDiscovery,
    decode_cursor,
    encode_cursor,
)
from notifications.hints import (
    MAX_HINT_BYTES,
    NotificationHint,
    decode_hint,
    encode_hint,
    hint_id,
    materialize_hint,
)


@dataclass
class MemoryCarrier:
    payloads: list

    async def publish(self, payload):
        self.payloads.append(payload)
        return CarrierAccepted(h(payload))


class DelegateStore:
    def __init__(self, store):
        self.store = store

    def __getattr__(self, name):
        return getattr(self.store, name)


class FailSecondCas(DelegateStore):
    """Crash after durable carrier acceptance but before progress CAS."""

    def __init__(self, store):
        super().__init__(store)
        self.calls = 0

    def cas(self, key, token, value):
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("crash before cursor CAS")
        return self.store.cas(key, token, value)


class UnknownAfterSecondCas(DelegateStore):
    """Lose the response after progress was durably committed."""

    def __init__(self, store):
        super().__init__(store)
        self.calls = 0

    def cas(self, key, token, value):
        self.calls += 1
        result = self.store.cas(key, token, value)
        if self.calls == 2:
            raise OutcomeUnknown("lost cursor response")
        return result


class RejectCarrier:
    async def publish(self, _payload):
        raise RuntimeError("carrier unavailable")


class BarrierCarrier(MemoryCarrier):
    def __init__(self):
        super().__init__([])
        self.barrier = asyncio.Barrier(2)
        self.lock = asyncio.Lock()

    async def publish(self, payload):
        async with self.lock:
            self.payloads.append(payload)
        await self.barrier.wait()
        return CarrierAccepted(h(payload))


class AwaitedStore:
    """Actually-async object-store fake, not the synchronous adapter."""

    def __init__(self, store):
        self.store = store
        self.calls = []

    async def get_bounded(self, key, maximum):
        self.calls.append(("get", key))
        await asyncio.sleep(0)
        return self.store.get_bounded(key, maximum)

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


def _world(tmp_path):
    node = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    return node, workspace


def _discovery(node, workspace, cursor, carrier, **kwargs):
    return NotificationDiscovery(
        node.store(workspace), cursor, workspace, carrier, **kwargs)


async def _drain(discovery, maximum=100):
    results = []
    for _ in range(maximum):
        result = await discovery.run_once()
        results.append(result)
        if result.status == "idle":
            return results
    raise AssertionError("notification discovery did not become idle")


def _cursor(store):
    store = getattr(store, "store", store)
    return decode_cursor(store.read_versioned("root").value)


def test_first_activation_backfills_historical_triggers(tmp_path):
    node, workspace = _world(tmp_path)
    event = message.post(node, workspace, "general", "hello", ts=3)
    root = node.reader(workspace).root_bytes
    carrier, cursor = MemoryCarrier([]), FsStore(str(tmp_path / "cursor"))

    asyncio.run(_drain(_discovery(node, workspace, cursor, carrier)))

    hint, = (decode_hint(raw) for raw in carrier.payloads)
    assert hint.workspace == workspace
    assert hint.root_oid == h(root)
    assert hint.facts == (event,)
    assert materialize_hint(hint, root).root == root
    assert encode_hint(hint) == carrier.payloads[0]
    assert hint_id(decode_hint(encode_hint(hint))) == hint_id(hint)
    assert _cursor(cursor) == Cursor(workspace, h(root))


def test_maximum_hint_fits_cloudflare_queue_body_limit():
    fids = tuple(sorted(
        h(number.to_bytes(4, "big")) for number in range(MAX_PILE_FACTS)))
    raw = encode_hint(NotificationHint("a" * 64, "b" * 64, fids))

    assert len(raw) < MAX_HINT_BYTES == 128_000
    assert decode_hint(raw).facts == fids


def test_hint_and_page_limits_accept_exact_and_reject_one_over():
    fids = tuple(sorted(
        h(number.to_bytes(4, "big")) for number in range(MAX_PILE_FACTS)))
    hint = NotificationHint("a" * 64, "b" * 64, fids)
    assert len(encode_hint(hint)) < MAX_HINT_BYTES
    with pytest.raises(PayloadTooLarge, match="notification hint too large"):
        decode_hint(b"x" * (MAX_HINT_BYTES + 1))

    repository, cursor = object(), object()
    NotificationDiscovery(
        repository, cursor, "a" * 64, MemoryCarrier([]),
        page_rows=merkle_map.MAX_RANGE_ROWS)
    with pytest.raises(ValueError, match="notification discovery"):
        NotificationDiscovery(
            repository, cursor, "a" * 64, MemoryCarrier([]),
            page_rows=merkle_map.MAX_RANGE_ROWS + 1)


def test_dropped_wakes_use_actual_async_stores_and_latest_root(tmp_path):
    node, workspace = _world(tmp_path)
    carrier = MemoryCarrier([])
    repository = AwaitedStore(node.store(workspace))
    cursor = AwaitedStore(FsStore(str(tmp_path / "cursor")))
    discovery = NotificationDiscovery(
        repository, cursor, workspace, carrier)
    asyncio.run(_drain(discovery))
    carrier.payloads.clear()

    first = message.post(node, workspace, "general", "one", ts=10)
    second = message.post(node, workspace, "general", "two", ts=11)
    latest = node.reader(workspace).root_bytes
    asyncio.run(_drain(discovery))

    hints = [decode_hint(raw) for raw in carrier.payloads]
    assert {fid for hint in hints for fid in hint.facts} == {first, second}
    assert {hint.root_oid for hint in hints} == {h(latest)}
    assert _cursor(cursor).target is None
    assert {name for name, _key in repository.calls} >= {"get", "read"}
    assert {name for name, _key in cursor.calls} >= {
        "get", "read", "create", "cas"}


def test_discovery_reports_residence_without_current_authority(
        tmp_path):
    node, workspace = _world(tmp_path)
    carrier, cursor = MemoryCarrier([]), FsStore(str(tmp_path / "cursor"))
    discovery = _discovery(node, workspace, cursor, carrier)
    asyncio.run(_drain(discovery))
    carrier.payloads.clear()

    event = message.post(node, workspace, "general", "removed", ts=10)
    delete.remove(node, workspace, event, ts=11)
    assert node.reader(workspace).worker().fact_active(event) is False
    asyncio.run(_drain(discovery))

    assert event in {
        fid for raw in carrier.payloads for fid in decode_hint(raw).facts
    }


def test_target_stays_pinned_while_page_continuation_exists(tmp_path):
    node, workspace = _world(tmp_path)
    carrier, cursor = MemoryCarrier([]), FsStore(str(tmp_path / "cursor"))
    discovery = _discovery(
        node, workspace, cursor, carrier, page_rows=1)
    asyncio.run(_drain(discovery))
    carrier.payloads.clear()

    late = message.post(node, workspace, "general", "late", ts=100)
    first_target = node.reader(workspace).root_bytes
    first = asyncio.run(discovery.run_once())
    assert first.continuation is not None
    pinned = _cursor(cursor).target

    early = message.post(node, workspace, "general", "early", ts=10)
    newest = node.reader(workspace).root_bytes
    assert newest != first_target
    while _cursor(cursor).base != h(first_target):
        asyncio.run(discovery.run_once())
        assert _cursor(cursor).target in {pinned, None}
    asyncio.run(_drain(discovery))

    hints = [decode_hint(raw) for raw in carrier.payloads]
    by_fact = {
        fid: hint.root_oid for hint in hints for fid in hint.facts
    }
    assert by_fact[late] == h(first_target)
    assert by_fact[early] == h(newest)


def test_crash_before_progress_cas_republishes_exact_hint(tmp_path):
    node, workspace = _world(tmp_path)
    carrier, cursor = MemoryCarrier([]), FsStore(str(tmp_path / "cursor"))
    asyncio.run(_drain(_discovery(node, workspace, cursor, carrier)))
    carrier.payloads.clear()
    event = message.post(node, workspace, "general", "retry", ts=10)

    crashing = _discovery(
        node, workspace, FailSecondCas(cursor), carrier)
    with pytest.raises(RuntimeError, match="before cursor CAS"):
        asyncio.run(crashing.run_once())
    assert _cursor(cursor).target is not None

    asyncio.run(_drain(_discovery(node, workspace, cursor, carrier)))
    assert len(carrier.payloads) == 2
    assert carrier.payloads[0] == carrier.payloads[1]
    assert decode_hint(carrier.payloads[0]).facts == (event,)


def test_lost_progress_cas_response_does_not_lose_handoff(tmp_path):
    node, workspace = _world(tmp_path)
    carrier, cursor = MemoryCarrier([]), FsStore(str(tmp_path / "cursor"))
    asyncio.run(_drain(_discovery(node, workspace, cursor, carrier)))
    carrier.payloads.clear()
    event = message.post(node, workspace, "general", "accepted", ts=10)

    with pytest.raises(OutcomeUnknown, match="lost cursor response"):
        asyncio.run(_discovery(
            node, workspace, UnknownAfterSecondCas(cursor), carrier
        ).run_once())
    asyncio.run(_drain(_discovery(
        node, workspace, cursor, carrier)))

    assert len(carrier.payloads) == 1
    assert decode_hint(carrier.payloads[0]).facts == (event,)


def test_malformed_cursor_fails_before_repository_or_carrier_work(
        tmp_path):
    node, workspace = _world(tmp_path)
    cursor, carrier = FsStore(str(tmp_path / "cursor")), MemoryCarrier([])
    discovery = _discovery(node, workspace, cursor, carrier)
    asyncio.run(_drain(discovery))
    carrier.payloads.clear()
    version = cursor.read_versioned("root")
    cursor.cas("root", version.token, b"{}")

    with pytest.raises(ValueError, match="notification cursor shape"):
        asyncio.run(discovery.run_once())

    assert carrier.payloads == []


def test_substituted_root_from_another_workspace_fails_closed(tmp_path):
    node, workspace = _world(tmp_path)
    cursor, carrier = FsStore(str(tmp_path / "cursor")), MemoryCarrier([])
    discovery = _discovery(node, workspace, cursor, carrier)
    asyncio.run(_drain(discovery))

    other = FullPeer(str(tmp_path / "other-peer"))
    other_workspace = facts.auth.workspace.create(other, "mallory", ts=20)
    other_root = other.reader(other_workspace).root_bytes
    other_oid = h(other_root)
    cursor.put_if_absent("obj/" + other_oid, other_root)
    version = cursor.read_versioned("root")
    current = decode_cursor(version.value)
    cursor.cas("root", version.token, encode_cursor(Cursor(
        workspace, current.base, other_oid)))

    with pytest.raises(ValueError, match="repository reader workspace"):
        asyncio.run(discovery.run_once())

    assert carrier.payloads == []


def test_concurrent_workers_may_duplicate_but_one_advances(tmp_path):
    node, workspace = _world(tmp_path)
    cursor = FsStore(str(tmp_path / "cursor"))
    asyncio.run(_drain(_discovery(
        node, workspace, cursor, MemoryCarrier([]))))
    event = message.post(node, workspace, "general", "race", ts=10)

    # Pin the target, then fail before accepting work so both workers start
    # from the exact same durable cursor version.
    with pytest.raises(RuntimeError, match="carrier unavailable"):
        asyncio.run(_discovery(
            node, workspace, cursor, RejectCarrier()).run_once())
    carrier = BarrierCarrier()

    async def race():
        return await asyncio.gather(*(
            _discovery(node, workspace, cursor, carrier).run_once()
            for _ in range(2)
        ))

    results = asyncio.run(race())

    assert sorted(result.status for result in results) \
        == ["published", "raced"]
    assert len(carrier.payloads) == 2
    assert carrier.payloads[0] == carrier.payloads[1]
    assert decode_hint(carrier.payloads[0]).facts == (event,)
    result = asyncio.run(_discovery(
        node, workspace, cursor, MemoryCarrier([])).run_once())
    assert result.status == "idle"
