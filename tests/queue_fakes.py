"""Deterministic queue and injected Pub/Sub clients for conformance tests."""
from dataclasses import dataclass
import threading
import time

from core.delivery_queue import (
    LeasedMessage,
    Published,
    QueueLease,
    validate_defer_seconds,
    validate_leases,
    validate_message_body,
    validate_pull,
)


@dataclass
class _Record:
    message_id: str
    body: bytes
    visible_at: float
    lease_token: str | None = None
    acknowledged: bool = False
    delivery_attempt: int = 0


class MemoryQueueService:
    def __init__(self, binding="memory/poc16-conformance"):
        self.binding = binding
        self.records = []
        self.message_counter = 0
        self.lease_counter = 0
        self.lock = threading.Lock()
        self.history = []

    def handle(self):
        return MemoryDeliveryQueue(self)


class MemoryDeliveryQueue:
    def __init__(self, service):
        self.service = service

    @property
    def binding(self):
        return self.service.binding

    def publish(self, body):
        body = validate_message_body(body)
        with self.service.lock:
            self.service.message_counter += 1
            message_id = (
                f"memory-message-{self.service.message_counter:08d}")
            self.service.records.append(_Record(
                message_id, body, time.monotonic()))
            self.service.history.append(("publish", message_id))
        return Published(message_id)

    def pull(self, *, max_messages=1, lease_seconds=60):
        max_messages, lease_seconds = validate_pull(
            max_messages, lease_seconds)
        now = time.monotonic()
        deliveries = []
        with self.service.lock:
            for record in self.service.records:
                if len(deliveries) == max_messages:
                    break
                if record.acknowledged or record.visible_at > now:
                    continue
                self.service.lease_counter += 1
                record.lease_token = (
                    f"memory-lease-{self.service.lease_counter:08d}")
                record.visible_at = now + lease_seconds
                record.delivery_attempt += 1
                deliveries.append(LeasedMessage(
                    body=record.body,
                    message_id=record.message_id,
                    lease=QueueLease(
                        self.binding, record.lease_token),
                    delivery_attempt=record.delivery_attempt,
                ))
            self.service.history.append((
                "pull", tuple(item.message_id for item in deliveries)))
        return tuple(deliveries)

    def _records_for(self, leases):
        leases = validate_leases(leases, self.binding)
        by_token = {
            record.lease_token: record
            for record in self.service.records
            if not record.acknowledged and record.lease_token is not None
        }
        return leases, by_token

    def ack(self, leases):
        with self.service.lock:
            leases, by_token = self._records_for(leases)
            for lease in leases:
                record = by_token.get(lease.token)
                if record is not None:
                    record.acknowledged = True
            self.service.history.append((
                "ack", tuple(lease.token for lease in leases)))

    def defer(self, leases, *, delay_seconds=0):
        delay_seconds = validate_defer_seconds(delay_seconds)
        with self.service.lock:
            leases, by_token = self._records_for(leases)
            now = time.monotonic()
            for lease in leases:
                record = by_token.get(lease.token)
                if record is not None:
                    record.visible_at = now + delay_seconds
            self.service.history.append((
                "defer",
                tuple(lease.token for lease in leases),
                delay_seconds,
            ))


class FakeFuture:
    def __init__(self, result, error=None):
        self._result = result
        self._error = error
        self.timeouts = []

    def result(self, timeout=None):
        self.timeouts.append(timeout)
        if self._error is not None:
            raise self._error
        return self._result


class FakePubSubPublisher:
    def __init__(self, service):
        self.service = service
        self.call_error = None
        self.result_error = None
        self.result_override = None
        self.last_future = None
        self.history = []

    def publish(self, topic, data, **attributes):
        self.history.append((topic, bytes(data), dict(attributes)))
        if self.call_error is not None:
            raise self.call_error
        receipt = self.service.queue.handle().publish(bytes(data))
        result = receipt.message_id if self.result_override is None \
            else self.result_override
        self.last_future = FakeFuture(result, self.result_error)
        return self.last_future


@dataclass
class FakePubSubMessage:
    data: bytes
    message_id: str


@dataclass
class FakeReceivedMessage:
    ack_id: str
    message: FakePubSubMessage
    delivery_attempt: int = 0


@dataclass
class FakePullResponse:
    received_messages: tuple


class FakePubSubSubscriber:
    def __init__(self, service):
        self.service = service
        self.pull_error = None
        self.ack_error = None
        self.modify_error = None
        self.response_override = None
        self.history = []

    def pull(self, *, request, timeout):
        self.history.append(("pull", request, timeout))
        if self.pull_error is not None:
            raise self.pull_error
        if self.response_override is not None:
            return self.response_override
        deliveries = self.service.queue.handle().pull(
            max_messages=request["max_messages"], lease_seconds=10)
        return FakePullResponse(tuple(
            FakeReceivedMessage(
                item.lease.token,
                FakePubSubMessage(item.body, item.message_id),
                item.delivery_attempt or 0,
            )
            for item in deliveries
        ))

    def acknowledge(self, *, request, timeout):
        self.history.append(("acknowledge", request, timeout))
        if self.ack_error is not None:
            raise self.ack_error
        self.service.queue.handle().ack(tuple(
            QueueLease(self.service.subscription_path, token)
            for token in request["ack_ids"]
        ))

    def modify_ack_deadline(self, *, request, timeout):
        self.history.append(("modify_ack_deadline", request, timeout))
        if self.modify_error is not None:
            raise self.modify_error
        self.service.queue.handle().defer(
            tuple(
                QueueLease(self.service.subscription_path, token)
                for token in request["ack_ids"]
            ),
            delay_seconds=request["ack_deadline_seconds"],
        )


class FakePubSubService:
    def __init__(self, config):
        self.topic_path = config.topic_path
        self.subscription_path = config.subscription_path
        self.queue = MemoryQueueService(self.subscription_path)
        self.publishers = []
        self.subscribers = []

    def clients(self):
        publisher = FakePubSubPublisher(self)
        subscriber = FakePubSubSubscriber(self)
        self.publishers.append(publisher)
        self.subscribers.append(subscriber)
        return publisher, subscriber


__all__ = (
    "FakePubSubMessage",
    "FakePubSubService",
    "FakePullResponse",
    "FakeReceivedMessage",
    "MemoryQueueService",
)
