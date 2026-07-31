"""Small provider-neutral boundary for durable notification hints.

The carrier moves opaque canonical bytes.  Provider glue may receive work by
pull, push, or a native batch callback; it exposes each item to the worker as
one ``CarrierDelivery`` and maps the worker's explicit ACK/RETRY disposition
back to that provider's native result.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from core.limits import valid_bounded_text


# Cloudflare Queues is the narrowest initial provider envelope.  Keep the
# decimal provider limit here and let hint codecs choose an equal or smaller
# bound.
MAX_CARRIER_BYTES = 128_000
MAX_CARRIER_ID_BYTES = 4_096
MAX_DELIVERY_ATTEMPT = (1 << 31) - 1


class CarrierError(OSError):
    """A carrier operation did not complete normally."""


class PublishOutcomeUnknown(CarrierError):
    """The body may be durable, but no acceptance response was received."""


def checked_body(body):
    if not isinstance(body, bytes):
        raise TypeError("carrier body")
    if not 0 < len(body) <= MAX_CARRIER_BYTES:
        raise ValueError("carrier body")
    return body


def _checked_id(value, label):
    if not valid_bounded_text(value, MAX_CARRIER_ID_BYTES):
        raise ValueError(label)
    return value


@dataclass(frozen=True, slots=True)
class CarrierAccepted:
    """Evidence that the exact call's body is durable for later delivery."""

    message_id: str

    def __post_init__(self):
        _checked_id(self.message_id, "carrier acceptance id")


class Carrier(Protocol):
    """Publish one opaque body without imposing receive mechanics."""

    async def publish(self, body: bytes) -> CarrierAccepted:
        """Return acceptance only for this call's exact ``body`` bytes."""
        ...


@dataclass(frozen=True, slots=True)
class CarrierDelivery:
    """One provider delivery; metadata is advisory and carries no authority."""

    body: bytes
    message_id: str
    attempt: int | None = None

    def __post_init__(self):
        checked_body(self.body)
        _checked_id(self.message_id, "carrier message id")
        if self.attempt is not None and (
                type(self.attempt) is not int
                or not 1 <= self.attempt <= MAX_DELIVERY_ATTEMPT):
            raise ValueError("carrier delivery attempt")


class DeliveryDisposition(Enum):
    ACK = "ack"
    RETRY = "retry"


ACK = DeliveryDisposition.ACK
RETRY = DeliveryDisposition.RETRY


class DeliveryHandler(Protocol):
    async def __call__(self, delivery: CarrierDelivery) \
            -> DeliveryDisposition: ...


async def delivery_disposition(delivery, handler):
    """Fail closed: only an explicit typed ACK lets provider glue acknowledge."""
    if not isinstance(delivery, CarrierDelivery) or not callable(handler):
        raise TypeError("carrier delivery handler")
    try:
        result = await handler(delivery)
    except Exception:
        return RETRY
    return result if isinstance(result, DeliveryDisposition) else RETRY


__all__ = (
    "ACK",
    "Carrier",
    "CarrierAccepted",
    "CarrierDelivery",
    "CarrierError",
    "DeliveryDisposition",
    "DeliveryHandler",
    "MAX_CARRIER_BYTES",
    "PublishOutcomeUnknown",
    "RETRY",
    "checked_body",
    "delivery_disposition",
)
