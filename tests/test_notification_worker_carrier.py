"""The provider-neutral carrier body enters the awaited worker once."""
import asyncio

import facts

from core.crypto import h, keypair
from core.limits import MAX_ROOT_BYTES, PayloadTooLarge
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.content import message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.carrier import ACK, RETRY
from notifications.delivery import PushAccepted, seal_target
from notifications.hints import NotificationHint, encode_hint
from notifications.worker import NotificationWorker, handle_carrier_delivery
from tests.notification_carrier import FaultCarrier


class AsyncState:
    def __init__(self, values=(), error=None):
        self.values = dict(values)
        self.error = error
        self.calls = []

    async def get_bounded(self, key, maximum):
        await asyncio.sleep(0)
        self.calls.append((key, maximum))
        if self.error is not None:
            raise self.error
        value = self.values.get(key)
        if isinstance(value, bytes) and len(value) > maximum:
            raise PayloadTooLarge("notification state")
        return value


class AsyncPush:
    def __init__(self):
        self.requests = []

    async def send(self, request):
        await asyncio.sleep(0)
        self.requests.append(request)
        return PushAccepted("provider-accepted")


def _world(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    push_secret, push_node = keypair()
    push_endpoint.register(
        node,
        workspace,
        h(b"installation"),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        seal_target(push_node, "firebase-installation-id"),
        ts=2,
    )
    preference.set_global(node, workspace, preference.ALL, ts=3)
    event = message.post(node, workspace, "general", "hello", ts=4)
    root = node.reader(workspace).root_bytes
    reference = NotificationHint(workspace, h(root), (event,))
    provider = AsyncPush()

    async def current_root(selected):
        await asyncio.sleep(0)
        return node.reader(selected).root_bytes

    async def fetch(selected, oid):
        await asyncio.sleep(0)
        return node.store(selected).get("obj/" + oid)

    async def now_ms():
        await asyncio.sleep(0)
        return 10

    worker = NotificationWorker(
        current_root, fetch, push_secret, provider, now_ms)
    return node, workspace, root, reference, provider, worker


async def _deliver(body, workspace, state, worker):
    carrier = FaultCarrier()
    accepted = await carrier.publish(body)

    async def handler(delivery):
        return await handle_carrier_delivery(
            delivery, workspace, state, worker)

    result = await carrier.deliver((0,), handler)
    return carrier, accepted, result


def test_canonical_body_fetches_bounded_root_and_awaits_worker(tmp_path):
    _node, workspace, root, reference, provider, worker = _world(tmp_path)
    state = AsyncState({"obj/" + reference.root_oid: root})

    carrier, accepted, result = asyncio.run(_deliver(
        encode_hint(reference), workspace, state, worker))

    assert result == ((accepted.message_id, ACK),)
    assert state.calls == [
        ("obj/" + reference.root_oid, MAX_ROOT_BYTES),
    ]
    assert len(provider.requests) == 1
    assert carrier.pending == ()


def test_malformed_body_is_terminal_poison_before_state_read(tmp_path):
    _node, workspace, _root, _reference, provider, worker = _world(tmp_path)
    state = AsyncState()

    carrier, accepted, result = asyncio.run(_deliver(
        b"not a canonical notification hint", workspace, state, worker))

    assert result == ((accepted.message_id, ACK),)
    assert state.calls == []
    assert provider.requests == []
    assert carrier.pending == ()


def test_missing_or_transient_root_retries_without_provider_call(tmp_path):
    _node, workspace, _root, reference, provider, worker = _world(tmp_path)
    body = encode_hint(reference)
    for state in (AsyncState(), AsyncState(error=OSError("temporarily down"))):
        carrier, accepted, result = asyncio.run(_deliver(
            body, workspace, state, worker))

        assert result == ((accepted.message_id, RETRY),)
        assert carrier.pending == (accepted.message_id,)
    assert provider.requests == []


def test_substituted_root_is_terminal_poison(tmp_path):
    _node, workspace, _root, reference, provider, worker = _world(tmp_path)
    state = AsyncState({"obj/" + reference.root_oid: b"substituted"})

    carrier, accepted, result = asyncio.run(_deliver(
        encode_hint(reference), workspace, state, worker))

    assert result == ((accepted.message_id, ACK),)
    assert provider.requests == []
    assert carrier.pending == ()


def test_trusted_workspace_mismatch_is_terminal_before_state_read(tmp_path):
    _node, _workspace, _root, reference, provider, worker = _world(tmp_path)
    state = AsyncState()

    carrier, accepted, result = asyncio.run(_deliver(
        encode_hint(reference), h(b"another workspace"), state, worker))

    assert result == ((accepted.message_id, ACK),)
    assert state.calls == []
    assert provider.requests == []
    assert carrier.pending == ()


def test_oversized_root_is_terminal_poison(tmp_path):
    _node, workspace, _root, reference, provider, worker = _world(tmp_path)
    state = AsyncState({
        "obj/" + reference.root_oid: b"x" * (MAX_ROOT_BYTES + 1),
    })

    carrier, accepted, result = asyncio.run(_deliver(
        encode_hint(reference), workspace, state, worker))

    assert result == ((accepted.message_id, ACK),)
    assert provider.requests == []
    assert carrier.pending == ()
