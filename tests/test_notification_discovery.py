"""Crash, bootstrap, and race coverage for durable notification discovery."""
import asyncio
from dataclasses import dataclass

import pytest

import facts
from adapters.s3 import S3Config, S3Store
from core import merkle_map
from core.crypto import h
from core.fact import encode
from core.limits import MAX_PILE_FACTS, PayloadTooLarge
from core.object_store import OutcomeUnknown
from core.store import FsStore
from facts.auth.device import bind
from facts import _bao
from facts.content import delete, file_slice, message
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
    decode_cursor,
    encode_cursor,
)
from notifications.hints import (
    MAX_HINT_BYTES,
    NotificationHint,
    decode_hint,
    encode_hint,
    materialize_hint,
)
from tests.util import send_bytes


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
        node.store(workspace), cursor, workspace, carrier,
        owner=OWNER, generation_factory=lambda: GENERATION, **kwargs)


def _cursor(store):
    store = getattr(store, "store", store)
    return decode_cursor(store.read_versioned("root").value)


async def _complete(discovery, raw):
    return await discovery.state.complete(h(raw))


async def _drain(discovery, maximum=100):
    results = []
    for _ in range(maximum):
        result = await discovery.run_once()
        results.append(result)
        if result.status in {"published", "republished"}:
            raw = await discovery.state.get_bounded(
                "obj/" + _cursor(discovery.cursor_store).pending.oid,
                MAX_HINT_BYTES)
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


def test_backfill_bootstrap_includes_history_and_is_idempotent(tmp_path):
    node, workspace = _world(tmp_path)
    event = message.post(node, workspace, "general", "hello", ts=3)
    root = node.reader(workspace).root_bytes
    carrier = MemoryCarrier([])
    discovery = _discovery(
        node, workspace, FsStore(str(tmp_path / "cursor")), carrier)

    first = asyncio.run(discovery.bootstrap_backfill())
    assert first.bootstrap == BOOTSTRAP_BACKFILL
    assert asyncio.run(discovery.bootstrap_backfill()) == first
    asyncio.run(_drain(discovery))

    reference, = map(decode_hint, carrier.payloads)
    assert reference.workspace == workspace
    assert reference.owner == OWNER
    assert reference.generation == GENERATION
    assert reference.root_oid == h(root)
    assert reference.facts == (event,)
    assert materialize_hint(reference, root).root == root
    assert _cursor(discovery.cursor_store).base == h(root)


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


def test_unknown_bootstrap_cas_reconciles_by_reread(tmp_path):
    node, workspace = _world(tmp_path)
    store = UnknownNextCas(FsStore(str(tmp_path / "cursor")))
    store.unknown = True
    discovery = _discovery(node, workspace, store, MemoryCarrier([]))

    cursor = asyncio.run(discovery.bootstrap_current())

    assert cursor == _cursor(store)
    assert asyncio.run(discovery.bootstrap_current()) == cursor


def test_bootstrap_mode_and_owner_are_persistent(tmp_path):
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


def test_state_loss_never_silently_reinitializes(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    discovery = _discovery(node, workspace, store, MemoryCarrier([]))
    asyncio.run(discovery.bootstrap_current())
    store._delete("root")

    with pytest.raises(CursorNotInitialized):
        asyncio.run(discovery.run_once())


def test_rebootstrap_generation_makes_old_delivery_noncurrent(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    old = _discovery(node, workspace, store, carrier)
    asyncio.run(old.bootstrap_current())
    event = message.post(node, workspace, "general", "old wake", ts=3)
    assert asyncio.run(old.run_once()).status == "published"
    raw = carrier.payloads[-1]
    reference = decode_hint(raw)
    assert reference.facts == (event,)
    assert asyncio.run(old.state.pending(h(raw))) == PENDING_CURRENT

    store._delete("root")
    fresh_carrier = MemoryCarrier([])
    fresh = NotificationDiscovery(
        node.store(workspace), store, workspace, fresh_carrier,
        owner=OWNER, generation_factory=lambda: "f" * 64)
    current = asyncio.run(fresh.bootstrap_backfill())
    assert asyncio.run(fresh.run_once()).status == "published"
    new_raw, = fresh_carrier.payloads
    new_reference = decode_hint(new_raw)
    assert new_reference.root_oid == reference.root_oid
    assert new_reference.facts == reference.facts
    assert h(new_raw) != h(raw)
    before = store.read_versioned("root")

    assert asyncio.run(fresh.state.pending(h(raw))) == PENDING_NONCURRENT
    assert asyncio.run(old.state.complete(h(raw))) == PENDING_NONCURRENT
    assert store.read_versioned("root") == before
    assert current.generation != reference.generation


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
    carrier.payloads.clear()  # simulate an expired carrier message/dropped wake
    assert asyncio.run(retry.run_once()).status == "republished"
    assert carrier.payloads == [raw]
    assert _cursor(store).pending == pending


def test_crash_after_publish_before_completion_republishes(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(node, workspace, store, carrier)
    asyncio.run(discovery.bootstrap_current())
    message.post(node, workspace, "general", "published", ts=3)

    assert asyncio.run(discovery.run_once()).status == "published"
    assert asyncio.run(discovery.run_once()).status == "republished"
    assert carrier.payloads[0] == carrier.payloads[1]


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


def test_completion_unknown_and_concurrent_completion_are_safe(tmp_path):
    node, workspace = _world(tmp_path)
    base = FsStore(str(tmp_path / "cursor"))
    fault = UnknownNextCas(base)
    discovery = _discovery(node, workspace, fault, MemoryCarrier([]))
    asyncio.run(discovery.bootstrap_current())
    message.post(node, workspace, "general", "accepted", ts=3)
    asyncio.run(discovery.run_once())
    current = _cursor(base)
    raw = base.get("obj/" + current.pending.oid)
    args = (h(raw),)
    fault.unknown = True

    assert asyncio.run(discovery.state.complete(*args)) == PENDING_NONCURRENT
    assert asyncio.run(discovery.state.complete(*args)) == PENDING_NONCURRENT
    assert _cursor(base).pending is None


def test_actual_async_stores_preserve_pending_protocol(tmp_path):
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
    assert {name for name, _key in repository.calls} >= {"get", "read"}
    assert {name for name, _key in state.calls} >= {
        "get", "read", "create", "cas"}


def test_type_range_emits_new_resident_trigger_in_one_turn(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(
        node, workspace, store, carrier,
        page_rows=merkle_map.LEAF_MAX_ROWS)
    asyncio.run(discovery.bootstrap_current())
    event = message.post(node, workspace, "general", "one turn", ts=3)

    result = asyncio.run(discovery.run_once())

    assert result.status == "published"
    assert decode_hint(carrier.payloads[0]).facts == (event,)
    assert _cursor(store).pending is not None


def test_target_stays_pinned_when_repository_advances_mid_page(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(
        node, workspace, store, carrier, page_rows=1)
    asyncio.run(discovery.bootstrap_current())
    late = message.post(node, workspace, "general", "late", ts=100)
    first_root = node.reader(workspace).root_bytes

    for _ in range(100):
        result = asyncio.run(discovery.run_once())
        if result.status == "published":
            asyncio.run(_complete(discovery, carrier.payloads[-1]))
        current = _cursor(store)
        if current.target == h(first_root) and current.after is not None:
            break
    else:
        raise AssertionError("first target did not expose a continuation")

    early = message.post(node, workspace, "general", "early", ts=10)
    latest_root = node.reader(workspace).root_bytes
    assert latest_root != first_root
    asyncio.run(_drain(discovery))

    by_fact = {
        fid: reference.root_oid
        for raw in carrier.payloads
        for reference in (decode_hint(raw),)
        for fid in reference.facts
    }
    assert by_fact[late] == h(first_root)
    assert by_fact[early] == h(latest_root)


def test_large_bao_fact_is_classified_without_fetching_its_blob(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    initial = _discovery(node, workspace, store, MemoryCarrier([]))
    asyncio.run(initial.bootstrap_current())
    send_bytes(
        node, workspace, "large.bin", b"x" * (_bao.WIDTH + 1), ts=10)
    slice_fact = max(
        node.by_type(workspace, file_slice.TAG),
        key=lambda fact: len(encode(fact)))
    slice_raw = encode(slice_fact)
    assert len(slice_raw) > _bao.WIDTH

    repository = AwaitedStore(node.store(workspace))
    carrier = MemoryCarrier([])
    discovery = NotificationDiscovery(
        repository, store, workspace, carrier, owner=OWNER,
        generation_factory=lambda: GENERATION)
    asyncio.run(_drain(discovery))

    assert carrier.payloads == []
    assert ("get", "obj/" + h(slice_raw)) not in repository.calls


def test_discovery_reports_residence_after_current_suppression(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(node, workspace, store, carrier)
    asyncio.run(discovery.bootstrap_current())
    event = message.post(node, workspace, "general", "removed", ts=10)
    delete.remove(node, workspace, event, ts=11)
    assert node.reader(workspace).worker().fact_active(event) is False

    asyncio.run(_drain(discovery))

    assert event in {
        fid for raw in carrier.payloads for fid in decode_hint(raw).facts}


def test_substituted_cross_workspace_root_fails_closed(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(node, workspace, store, carrier)
    asyncio.run(discovery.bootstrap_current())

    other = FullPeer(str(tmp_path / "other-peer"))
    other_workspace = facts.auth.workspace.create(other, "mallory", ts=20)
    other_root = other.reader(other_workspace).root_bytes
    other_oid = h(other_root)
    store.put_if_absent("obj/" + other_oid, other_root)
    version = store.read_versioned("root")
    current = decode_cursor(version.value)
    substituted = Cursor(
        current.workspace, current.owner, current.generation,
        current.bootstrap, current.base, other_oid)
    store.cas("root", version.token, encode_cursor(substituted))

    with pytest.raises(ValueError, match="repository reader workspace"):
        asyncio.run(discovery.run_once())
    assert carrier.payloads == []


def test_malformed_cursor_fails_before_carrier_work(tmp_path):
    node, workspace = _world(tmp_path)
    store = FsStore(str(tmp_path / "cursor"))
    carrier = MemoryCarrier([])
    discovery = _discovery(node, workspace, store, carrier)
    asyncio.run(discovery.bootstrap_current())
    version = store.read_versioned("root")
    store.cas("root", version.token, b"{}")

    with pytest.raises(ValueError, match="notification cursor shape"):
        asyncio.run(discovery.run_once())
    assert carrier.payloads == []


def test_maximum_hint_and_generation_bounds_are_canonical():
    fids = tuple(sorted(
        h(number.to_bytes(4, "big")) for number in range(MAX_PILE_FACTS)))
    hint = NotificationHint(
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, fids)
    raw = encode_hint(hint)
    assert len(raw) < MAX_HINT_BYTES == 128_000
    assert decode_hint(raw) == hint
    with pytest.raises(ValueError, match="notification hint"):
        NotificationHint(
            "a" * 64, "b" * 64, "not-a-generation", "d" * 64, ())
    with pytest.raises(PayloadTooLarge, match="notification hint too large"):
        decode_hint(b"x" * (MAX_HINT_BYTES + 1))


def test_pending_codec_rejects_nonforward_successor():
    pending = Pending(
        "d" * 64, "f" * 64, "a" * 64, "k")
    cursor = Cursor(
        "a" * 64, "b" * 64, "c" * 64, BOOTSTRAP_BACKFILL,
        base="f" * 64, target="a" * 64, after="z")
    with pytest.raises(ValueError, match="pending successor"):
        Cursor(
            cursor.workspace, cursor.owner, cursor.generation,
            cursor.bootstrap, cursor.base, cursor.target,
            cursor.after, pending)


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
            page_rows=merkle_map.MAX_RANGE_ROWS + 1)
