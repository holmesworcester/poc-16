"""A durable pending hint enters the provider-neutral worker path."""
import asyncio

import facts

from core.crypto import h, keypair
from core.limits import PayloadTooLarge
from core.writer_head import decode_slot_at, head_slot_key
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.content import message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.carrier import ACK, RETRY, CarrierDelivery
from notifications.delivery import (
    PushAccepted,
    PushUnregistered,
    seal_target,
)
from notifications.discovery import (
    NotificationDiscovery,
    NotificationState,
    PENDING_CURRENT,
    PENDING_NONCURRENT,
)
from notifications.hints import decode_hint
from notifications.forest import current_repository
from notifications.worker import NotificationWorker, handle_carrier_delivery
from tests.notification_carrier import FaultCarrier


OWNER = "c" * 64
GENERATION = "e" * 64


class MemoryCarrier:
    def __init__(self):
        self.payloads = []

    async def publish(self, payload):
        from notifications.carrier import CarrierAccepted
        self.payloads.append(payload)
        return CarrierAccepted(h(payload))


class AsyncPush:
    def __init__(self, error=None):
        self.requests = []
        self.error = error

    async def send(self, request):
        await asyncio.sleep(0)
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return PushAccepted("provider-accepted")


class StateProxy:
    def __init__(self, state):
        self.state = state
        self.owner = state.owner

    def __getattr__(self, name):
        return getattr(self.state, name)


class FailCompleteOnce(StateProxy):
    def __init__(self, state):
        super().__init__(state)
        self.failed = False

    async def complete(self, *args):
        if not self.failed:
            self.failed = True
            raise OSError("crash before completion CAS")
        return await self.state.complete(*args)


class PausingComplete(StateProxy):
    def __init__(self, state):
        super().__init__(state)
        self.entered = asyncio.Event()
        self.resume = asyncio.Event()

    async def complete(self, *args):
        self.entered.set()
        await self.resume.wait()
        return await self.state.complete(*args)


class EventFault(StateProxy):
    def __init__(self, state, value=None, error=None):
        super().__init__(state)
        self.value = value
        self.error = error

    async def get_bounded(self, _key, _maximum):
        if self.error is not None:
            raise self.error
        return self.value


class CountingState:
    owner = OWNER

    def __init__(self):
        self.calls = []

    async def get_bounded(self, *args):
        self.calls.append(("get", args))

    async def pending(self, *args):
        self.calls.append(("pending", args))

    async def complete(self, *args):
        self.calls.append(("complete", args))


def _world(tmp_path, provider=None):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    push_secret, push_node = keypair()
    push_endpoint.register(
        node, workspace, h(b"installation"), push_node, "android",
        "poc16.mobile", "production",
        seal_target(push_node, "firebase-installation-id"), ts=2)
    preference.set_global(node, workspace, preference.ALL, ts=3)

    cursor_store = node.__class__.__module__  # keep construction below clear
    from core.store import FsStore
    cursor_store = FsStore(str(tmp_path / "notification-state"))
    carrier = MemoryCarrier()
    discovery = NotificationDiscovery(
        node.store(workspace), cursor_store, workspace, carrier,
        owner=OWNER, generation_factory=lambda: GENERATION)
    asyncio.run(discovery.bootstrap_current())
    event = message.post(node, workspace, "general", "hello", ts=4)
    assert asyncio.run(discovery.run_once()).status == "published"
    body, = carrier.payloads
    reference = decode_hint(body)
    state = NotificationState(cursor_store, workspace, OWNER)
    provider = provider or AsyncPush()

    async def current(selected):
        await asyncio.sleep(0)
        return await current_repository(node.store(selected), selected)

    async def now_ms():
        await asyncio.sleep(0)
        return 10

    worker = NotificationWorker(
        current, push_secret, provider, now_ms)
    return (
        node, workspace, event, body, reference, state, provider, worker)


async def _deliver(body, workspace, state, worker):
    carrier = FaultCarrier()
    accepted = await carrier.publish(body)

    async def handler(delivery):
        return await handle_carrier_delivery(
            delivery, workspace, state, worker)

    result = await carrier.deliver((0,), handler)
    return carrier, accepted, result


def test_current_body_is_acked_only_after_provider_and_progress(tmp_path):
    (_node, workspace, _event, body, _reference,
     state, provider, worker) = _world(tmp_path)

    carrier, accepted, result = asyncio.run(_deliver(
        body, workspace, state, worker))

    assert result == ((accepted.message_id, ACK),)
    assert len(provider.requests) == 1
    assert carrier.pending == ()
    assert asyncio.run(state.pending(h(body))) == PENDING_NONCURRENT


def test_crash_after_fcm_acceptance_retries_until_progress_cas(tmp_path):
    (_node, workspace, _event, body, _reference,
     state, provider, worker) = _world(tmp_path)
    crashing = FailCompleteOnce(state)

    first_carrier, first, result = asyncio.run(_deliver(
        body, workspace, crashing, worker))
    assert result == ((first.message_id, RETRY),)
    assert first_carrier.pending == (first.message_id,)
    assert len(provider.requests) == 1

    second_carrier, second, result = asyncio.run(_deliver(
        body, workspace, state, worker))
    assert result == ((second.message_id, ACK),)
    assert second_carrier.pending == ()
    assert len(provider.requests) == 2


def test_delayed_mute_is_checked_at_current_authority(tmp_path):
    (node, workspace, _event, body, _reference,
     state, provider, worker) = _world(tmp_path)
    preference.set_global(node, workspace, preference.NONE, ts=5)

    _carrier, accepted, result = asyncio.run(_deliver(
        body, workspace, state, worker))

    assert result == ((accepted.message_id, ACK),)
    assert provider.requests == []


def test_invalid_endpoint_is_terminal_and_advances(tmp_path):
    provider = AsyncPush(PushUnregistered("gone"))
    (_node, workspace, _event, body, _reference,
     state, _provider, worker) = _world(tmp_path, provider)

    _carrier, accepted, result = asyncio.run(_deliver(
        body, workspace, state, worker))

    assert result == ((accepted.message_id, ACK),)
    assert len(provider.requests) == 1


def test_concurrent_workers_may_duplicate_but_cannot_double_advance(tmp_path):
    (_node, workspace, _event, body, _reference,
     state, provider, worker) = _world(tmp_path)

    async def race():
        deliveries = (
            CarrierDelivery(body, "worker-a", 1),
            CarrierDelivery(body, "worker-b", 1),
        )
        return await asyncio.gather(*(
            handle_carrier_delivery(row, workspace, state, worker)
            for row in deliveries))

    assert asyncio.run(race()) == [ACK, ACK]
    assert len(provider.requests) == 2


def test_stale_duplicate_acks_without_second_provider_call(tmp_path):
    (_node, workspace, _event, body, _reference,
     state, provider, worker) = _world(tmp_path)
    assert asyncio.run(_deliver(body, workspace, state, worker))[2][0][1] \
        is ACK
    assert asyncio.run(_deliver(body, workspace, state, worker))[2][0][1] \
        is ACK
    assert len(provider.requests) == 1


def test_rebootstrap_generation_prevents_paused_muted_worker_aba(tmp_path):
    (node, workspace, _event, initial_body, _reference,
     state, provider, worker) = _world(tmp_path)
    store = state.store.store
    assert asyncio.run(state.complete(h(initial_body))) == PENDING_NONCURRENT
    preference.set_global(node, workspace, preference.NONE, ts=5)

    store._delete("cursor")
    old_carrier = MemoryCarrier()
    old_scanner = NotificationDiscovery(
        node.store(workspace), store, workspace, old_carrier,
        owner=OWNER, generation_factory=lambda: GENERATION)
    asyncio.run(old_scanner.bootstrap_backfill())
    assert asyncio.run(old_scanner.run_once()).status == "published"
    old_body, = old_carrier.payloads
    paused = PausingComplete(old_scanner.state)

    async def scenario():
        old_task = asyncio.create_task(handle_carrier_delivery(
            CarrierDelivery(old_body, "old-muted", 1),
            workspace, paused, worker))
        await paused.entered.wait()
        assert provider.requests == []

        store._delete("cursor")
        fresh_carrier = MemoryCarrier()
        fresh_scanner = NotificationDiscovery(
            node.store(workspace), store, workspace, fresh_carrier,
            owner=OWNER, generation_factory=lambda: "f" * 64)
        await fresh_scanner.bootstrap_backfill()
        assert (await fresh_scanner.run_once()).status == "published"
        new_body, = fresh_carrier.payloads
        old_reference, new_reference = map(
            decode_hint, (old_body, new_body))
        assert old_reference.head == new_reference.head
        assert old_reference.facts == new_reference.facts
        assert old_reference.generation != new_reference.generation
        assert h(old_body) != h(new_body)

        await asyncio.to_thread(
            preference.set_global,
            node, workspace, preference.ALL, 6)
        paused.resume.set()
        assert await old_task is ACK
        assert await fresh_scanner.state.pending(
            h(new_body)) == PENDING_CURRENT
        assert await handle_carrier_delivery(
            CarrierDelivery(new_body, "new-unmuted", 1),
            workspace, fresh_scanner.state, worker) is ACK
        assert await fresh_scanner.state.pending(
            h(new_body)) == PENDING_NONCURRENT

    asyncio.run(scenario())
    assert len(provider.requests) == 1


def test_pending_event_missing_corrupt_or_oversized_always_retries(tmp_path):
    (_node, workspace, _event, body, _reference,
     state, provider, worker) = _world(tmp_path)
    faults = (
        EventFault(state),
        EventFault(state, b"substituted"),
        EventFault(state, error=PayloadTooLarge("oversized")),
        EventFault(state, error=OSError("temporarily down")),
    )
    for fault in faults:
        carrier, accepted, result = asyncio.run(_deliver(
            body, workspace, fault, worker))
        assert result == ((accepted.message_id, RETRY),)
        assert carrier.pending == (accepted.message_id,)
    assert provider.requests == []


def test_malformed_current_writer_forest_retries_without_completion(tmp_path):
    (node, workspace, _event, body, _reference,
     state, provider, worker) = _world(tmp_path)
    device = node.identity_id(workspace)
    key = head_slot_key(workspace, device)
    slot = decode_slot_at(key, node.store(workspace).get(key))
    node.store(workspace)._delete("obj/" + slot.head)

    carrier, accepted, result = asyncio.run(_deliver(
        body, workspace, state, worker))

    assert result == ((accepted.message_id, RETRY),)
    assert carrier.pending == (accepted.message_id,)
    assert provider.requests == []


def test_malformed_and_foreign_bodies_ack_before_state_or_provider(tmp_path):
    (_node, workspace, _event, body, reference,
     _state, provider, worker) = _world(tmp_path)
    state = CountingState()

    _carrier, accepted, result = asyncio.run(_deliver(
        b"not a canonical notification hint", workspace, state, worker))
    assert result == ((accepted.message_id, ACK),)

    _carrier, accepted, result = asyncio.run(_deliver(
        body, h(b"another workspace"), state, worker))
    assert result == ((accepted.message_id, ACK),)
    assert reference.workspace == workspace
    assert state.calls == []
    assert provider.requests == []
