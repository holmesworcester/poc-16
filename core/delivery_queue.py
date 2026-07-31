"""Bounded provider-neutral at-least-once delivery queue vocabulary."""
from dataclasses import dataclass
from itertools import islice
from typing import Protocol


MAX_QUEUE_MESSAGE_BYTES = 128 * 1024
MAX_PULL_MESSAGES = 10
MAX_LEASE_BATCH = 100
MIN_LEASE_SECONDS = 10
MAX_LEASE_SECONDS = 600
MAX_OPAQUE_ID_BYTES = 4096


class QueueError(OSError):
    pass


class RetryableQueueError(QueueError):
    pass


class PublishOutcomeUnknown(RetryableQueueError):
    """A publish may have committed without returning its acceptance id."""


class QueueProtocolError(QueueError):
    pass


def _opaque_text(value, label):
    if not isinstance(value, str) or not value or not value.isascii() \
            or len(value.encode("ascii")) > MAX_OPAQUE_ID_BYTES \
            or any(ord(character) < 0x21 or ord(character) > 0x7e
                   for character in value):
        raise ValueError(label)
    return value


def validate_message_body(body):
    if not isinstance(body, bytes):
        raise TypeError("queue message body")
    if not body or len(body) > MAX_QUEUE_MESSAGE_BYTES:
        raise ValueError("queue message body")
    return body


def validate_pull(max_messages, lease_seconds):
    if type(max_messages) is not int \
            or not 1 <= max_messages <= MAX_PULL_MESSAGES:
        raise ValueError("queue pull count")
    if type(lease_seconds) is not int \
            or not MIN_LEASE_SECONDS <= lease_seconds <= MAX_LEASE_SECONDS:
        raise ValueError("queue lease seconds")
    return max_messages, lease_seconds


def validate_defer_seconds(delay_seconds):
    if type(delay_seconds) is not int or not (
            delay_seconds == 0
            or MIN_LEASE_SECONDS <= delay_seconds <= MAX_LEASE_SECONDS):
        raise ValueError("queue defer seconds")
    return delay_seconds


@dataclass(frozen=True)
class Published:
    message_id: str

    def __post_init__(self):
        _opaque_text(self.message_id, "queue message id")


@dataclass(frozen=True)
class QueueLease:
    binding: str
    token: str

    def __post_init__(self):
        _opaque_text(self.binding, "queue lease binding")
        _opaque_text(self.token, "queue lease token")


@dataclass(frozen=True)
class LeasedMessage:
    body: bytes
    message_id: str
    lease: QueueLease
    delivery_attempt: int | None = None

    def __post_init__(self):
        validate_message_body(self.body)
        _opaque_text(self.message_id, "queue message id")
        if not isinstance(self.lease, QueueLease):
            raise TypeError("queue lease")
        if self.delivery_attempt is not None and (
                type(self.delivery_attempt) is not int
                or self.delivery_attempt < 1):
            raise ValueError("queue delivery attempt")


def validate_leases(leases, binding):
    _opaque_text(binding, "queue lease binding")
    try:
        values = tuple(islice(iter(leases), MAX_LEASE_BATCH + 1))
    except TypeError as error:
        raise TypeError("queue leases") from error
    if len(values) > MAX_LEASE_BATCH:
        raise ValueError("queue lease batch")
    if any(not isinstance(lease, QueueLease) for lease in values):
        raise TypeError("queue lease")
    if any(lease.binding != binding for lease in values):
        raise ValueError("queue lease binding")
    if len({lease.token for lease in values}) != len(values):
        raise ValueError("duplicate queue lease")
    return values


class DeliveryQueue(Protocol):
    def publish(self, body: bytes) -> Published: ...

    def pull(
            self, *, max_messages: int = 1,
            lease_seconds: int = 60) -> tuple[LeasedMessage, ...]: ...

    def ack(self, leases) -> None: ...

    def defer(self, leases, *, delay_seconds: int = 0) -> None: ...


__all__ = (
    "DeliveryQueue",
    "LeasedMessage",
    "MAX_LEASE_BATCH",
    "MAX_LEASE_SECONDS",
    "MAX_PULL_MESSAGES",
    "MAX_QUEUE_MESSAGE_BYTES",
    "MIN_LEASE_SECONDS",
    "Published",
    "PublishOutcomeUnknown",
    "QueueError",
    "QueueLease",
    "QueueProtocolError",
    "RetryableQueueError",
    "validate_defer_seconds",
    "validate_leases",
    "validate_message_body",
    "validate_pull",
)
