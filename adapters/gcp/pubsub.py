"""Google Cloud Pub/Sub implementation of the delivery-queue contract."""
from dataclasses import dataclass
import importlib
from itertools import islice
import math
import re

from core.delivery_queue import (
    LeasedMessage,
    Published,
    PublishOutcomeUnknown,
    QueueError,
    QueueLease,
    QueueProtocolError,
    RetryableQueueError,
    validate_defer_seconds,
    validate_leases,
    validate_message_body,
    validate_pull,
)


_PROJECT_RE = re.compile(
    r"^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,30})$")
_RESOURCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$")
_PERMANENT_ERRORS = frozenset({
    "AlreadyExists",
    "FailedPrecondition",
    "Forbidden",
    "InvalidArgument",
    "NotFound",
    "PermissionDenied",
    "Unauthenticated",
})


def _resource_id(value, label):
    if not isinstance(value, str) or _RESOURCE_RE.fullmatch(value) is None \
            or value.lower().startswith("goog"):
        raise ValueError(label)
    return value


def _timeout(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or not 0 < value <= 300:
        raise ValueError(label)
    return float(value)


def _label(operation, error):
    return f"Pub/Sub {operation} failed: {type(error).__name__}"


def _permanent(error):
    return type(error).__name__ in _PERMANENT_ERRORS


def _raise_operation(operation, error):
    if _permanent(error):
        raise QueueError(_label(operation, error)) from error
    raise RetryableQueueError(_label(operation, error)) from error


def _raise_publish(error):
    if _permanent(error):
        raise QueueError(_label("publish", error)) from error
    raise PublishOutcomeUnknown(_label("publish", error)) from error


@dataclass(frozen=True)
class PubSubQueueConfig:
    project_id: str
    topic_id: str
    subscription_id: str
    publish_timeout: float = 30.0
    pull_timeout: float = 5.0
    rpc_timeout: float = 10.0

    def __post_init__(self):
        if not isinstance(self.project_id, str) \
                or _PROJECT_RE.fullmatch(self.project_id) is None:
            raise ValueError("Pub/Sub project id")
        _resource_id(self.topic_id, "Pub/Sub topic id")
        _resource_id(self.subscription_id, "Pub/Sub subscription id")
        _timeout(self.publish_timeout, "Pub/Sub publish timeout")
        _timeout(self.pull_timeout, "Pub/Sub pull timeout")
        _timeout(self.rpc_timeout, "Pub/Sub RPC timeout")

    @property
    def topic_path(self):
        return f"projects/{self.project_id}/topics/{self.topic_id}"

    @property
    def subscription_path(self):
        return (
            f"projects/{self.project_id}/subscriptions/"
            f"{self.subscription_id}"
        )


class PubSubQueue:
    """Unary-pull Pub/Sub adapter with explicit receipt control."""

    def __init__(self, config, *, producer=None, subscriber=None):
        if not isinstance(config, PubSubQueueConfig):
            raise TypeError("Pub/Sub queue config")
        if (producer is None) != (subscriber is None):
            raise ValueError("inject both Pub/Sub clients or neither")
        self.config = config
        self._owns_clients = producer is None
        if producer is None:
            producer, subscriber = self._sdk_clients()
        self._producer = producer
        self._subscriber = subscriber

    @staticmethod
    def _sdk_clients():
        try:
            pubsub = importlib.import_module("google.cloud.pubsub_v1")
        except ImportError as error:
            raise RuntimeError(
                "google-cloud-pubsub is required unless clients are injected"
            ) from error
        return pubsub.PublisherClient(), pubsub.SubscriberClient()

    @property
    def binding(self):
        return self.config.subscription_path

    def publish(self, body):
        body = validate_message_body(body)
        try:
            future = self._producer.publish(self.config.topic_path, body)
            message_id = future.result(
                timeout=self.config.publish_timeout)
        except Exception as error:
            _raise_publish(error)
        try:
            return Published(message_id)
        except (TypeError, ValueError) as error:
            raise PublishOutcomeUnknown(
                "Pub/Sub publish returned no valid acceptance id") from error

    def pull(self, *, max_messages=1, lease_seconds=60):
        max_messages, lease_seconds = validate_pull(
            max_messages, lease_seconds)
        try:
            response = self._subscriber.pull(
                request={
                    "subscription": self.binding,
                    "max_messages": max_messages,
                },
                timeout=self.config.pull_timeout,
            )
        except Exception as error:
            _raise_operation("pull", error)
        received = getattr(response, "received_messages", None)
        try:
            received = tuple(islice(iter(received), max_messages + 1))
        except TypeError as error:
            raise QueueProtocolError(
                "Pub/Sub pull response has no message sequence") from error
        if len(received) > max_messages:
            raise QueueProtocolError(
                "Pub/Sub pull exceeded the requested message count")

        deliveries = []
        try:
            for item in received:
                message = item.message
                attempt = getattr(item, "delivery_attempt", None)
                if attempt == 0:
                    attempt = None
                deliveries.append(LeasedMessage(
                    body=message.data,
                    message_id=message.message_id,
                    lease=QueueLease(self.binding, item.ack_id),
                    delivery_attempt=attempt,
                ))
        except (AttributeError, TypeError, ValueError) as error:
            raise QueueProtocolError(
                "Pub/Sub returned an invalid delivery") from error
        if deliveries:
            self._modify(
                tuple(delivery.lease for delivery in deliveries),
                lease_seconds,
                "lease",
            )
        return tuple(deliveries)

    def _modify(self, leases, seconds, operation):
        if not leases:
            return
        try:
            self._subscriber.modify_ack_deadline(
                request={
                    "subscription": self.binding,
                    "ack_ids": [lease.token for lease in leases],
                    "ack_deadline_seconds": seconds,
                },
                timeout=self.config.rpc_timeout,
            )
        except Exception as error:
            _raise_operation(operation, error)

    def ack(self, leases):
        leases = validate_leases(leases, self.binding)
        if not leases:
            return
        try:
            self._subscriber.acknowledge(
                request={
                    "subscription": self.binding,
                    "ack_ids": [lease.token for lease in leases],
                },
                timeout=self.config.rpc_timeout,
            )
        except Exception as error:
            _raise_operation("acknowledge", error)

    def defer(self, leases, *, delay_seconds=0):
        leases = validate_leases(leases, self.binding)
        delay_seconds = validate_defer_seconds(delay_seconds)
        self._modify(leases, delay_seconds, "defer")

    def close(self):
        if not self._owns_clients:
            return
        for client in (self._producer, self._subscriber):
            close = getattr(client, "close", None)
            if callable(close):
                close()


__all__ = ("PubSubQueue", "PubSubQueueConfig")
