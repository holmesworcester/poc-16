"""Provider-neutral carrier vocabulary and deterministic fault schedule."""
import asyncio
from enum import Enum
import json

import pytest

from core.fact import canon
from notifications.carrier import (
    ACK,
    RETRY,
    CarrierAccepted,
    CarrierDelivery,
    MAX_CARRIER_BYTES,
    PublishOutcomeUnknown,
    checked_body,
    delivery_disposition,
)
from tests.notification_carrier import FaultCarrier


pytestmark = pytest.mark.unit


def _body(event="e", delivery="d"):
    return canon({
        "delivery_id": delivery * 64,
        "event_id": event * 64,
        "format": "notification-hint-test-v1",
    })


def _publish(carrier, body):
    return asyncio.run(carrier.publish(body))


def _deliver(carrier, indexes, handler, **kwargs):
    return asyncio.run(carrier.deliver(indexes, handler, **kwargs))


def test_publish_requires_typed_durable_acceptance_and_preserves_bytes():
    carrier, body = FaultCarrier(), _body()
    carrier.lose_next_publish_response = True

    with pytest.raises(PublishOutcomeUnknown, match="response loss"):
        _publish(carrier, body)
    accepted = _publish(carrier, body)

    assert isinstance(accepted, CarrierAccepted)
    assert accepted.message_id == "message-0002"
    assert [record.body for record in carrier.records] == [body, body]
    assert carrier.records[0].message_id != carrier.records[1].message_id


def test_retry_redelivers_stable_body_message_and_embedded_ids():
    carrier, seen = FaultCarrier(), []
    body = _body("a", "b")
    accepted = _publish(carrier, body)

    async def handler(delivery):
        seen.append(delivery)
        return RETRY if len(seen) == 1 else ACK

    assert _deliver(carrier, (0,), handler) == (
        (accepted.message_id, RETRY),)
    assert _deliver(carrier, (0,), handler) == (
        (accepted.message_id, ACK),)

    assert [(item.body, item.message_id, item.attempt) for item in seen] == [
        (body, accepted.message_id, 1),
        (body, accepted.message_id, 2),
    ]
    assert json.loads(seen[0].body) == json.loads(seen[1].body)
    assert carrier.pending == ()


def test_reordered_delayed_poison_and_partial_batch_map_independently():
    carrier = FaultCarrier()
    accepted = [
        _publish(carrier, _body("a", "a")),
        _publish(carrier, b"not a canonical hint"),
        _publish(carrier, _body("r", "r")),
        _publish(carrier, _body("d", "d")),
    ]
    observed = []

    async def handler(delivery):
        observed.append(delivery.message_id)
        try:
            event = json.loads(delivery.body)["event_id"]
        except (KeyError, TypeError, ValueError):
            return ACK  # Typed terminal poison result.
        return RETRY if event == "r" * 64 else ACK

    batch = _deliver(carrier, (2, 0, 1), handler)

    assert observed == [
        accepted[2].message_id,
        accepted[0].message_id,
        accepted[1].message_id,
    ]
    assert batch == (
        (accepted[2].message_id, RETRY),
        (accepted[0].message_id, ACK),
        (accepted[1].message_id, ACK),
    )
    assert carrier.pending == (
        accepted[2].message_id, accepted[3].message_id)

    assert _deliver(carrier, (3,), handler) == (
        (accepted[3].message_id, ACK),)
    assert carrier.pending == (accepted[2].message_id,)


@pytest.mark.parametrize("fault", ["ack_loss", "crash_after"])
def test_ack_loss_or_crash_after_completion_can_duplicate(fault):
    carrier, completed = FaultCarrier(), []
    accepted = _publish(carrier, _body())

    async def handler(delivery):
        completed.append((delivery.message_id, delivery.body))
        return ACK

    _deliver(carrier, (0,), handler, **{fault: (0,)})
    assert carrier.pending == (accepted.message_id,)
    _deliver(carrier, (0,), handler)

    assert completed == [
        (accepted.message_id, _body()),
        (accepted.message_id, _body()),
    ]
    assert carrier.pending == ()


class _WrongDisposition(Enum):
    ACK = "ack"


@pytest.mark.parametrize(
    "handler",
    [
        lambda _delivery: asyncio.sleep(0, result=None),
        lambda _delivery: asyncio.sleep(0, result="ack"),
        lambda _delivery: asyncio.sleep(0, result=_WrongDisposition.ACK),
        lambda _delivery: (_ for _ in ()).throw(RuntimeError("crash")),
    ],
)
def test_unknown_or_failed_handler_result_retries(handler):
    delivery = CarrierDelivery(_body(), "provider-id", 1)
    assert asyncio.run(delivery_disposition(delivery, handler)) is RETRY


def test_only_explicit_typed_ack_acknowledges():
    delivery = CarrierDelivery(_body(), "provider-id", None)

    async def acknowledge(_item):
        return ACK

    async def retry(_item):
        return RETRY

    assert asyncio.run(delivery_disposition(delivery, acknowledge)) is ACK
    assert asyncio.run(delivery_disposition(delivery, retry)) is RETRY


def test_body_and_attempt_metadata_are_bounded_before_provider_work():
    assert checked_body(b"x" * MAX_CARRIER_BYTES) == (
        b"x" * MAX_CARRIER_BYTES)
    with pytest.raises(ValueError, match="carrier body"):
        checked_body(b"")
    with pytest.raises(ValueError, match="carrier body"):
        checked_body(b"x" * (MAX_CARRIER_BYTES + 1))
    with pytest.raises(TypeError, match="carrier body"):
        checked_body("bytes required")

    for attempt in (False, 0, -1, 1 << 31):
        with pytest.raises(ValueError, match="delivery attempt"):
            CarrierDelivery(b"x", "message", attempt)
    assert CarrierDelivery(b"x", "message", 1).attempt == 1
