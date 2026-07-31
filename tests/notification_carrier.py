"""Deterministic managed-carrier fake; provider receive mechanics stay here."""
from dataclasses import dataclass

from notifications.carrier import (
    ACK,
    CarrierAccepted,
    CarrierDelivery,
    PublishOutcomeUnknown,
    checked_body,
    delivery_disposition,
)


@dataclass(slots=True)
class _Record:
    message_id: str
    body: bytes
    attempt: int = 0
    acknowledged: bool = False


class FaultCarrier:
    """A push-shaped fake with deterministic publish and delivery faults."""

    def __init__(self):
        self.records = []
        self.history = []
        self.lose_next_publish_response = False

    async def publish(self, body):
        body = checked_body(body)
        message_id = f"message-{len(self.records) + 1:04d}"
        self.records.append(_Record(message_id, body))
        self.history.append(("published", message_id, body))
        if self.lose_next_publish_response:
            self.lose_next_publish_response = False
            self.history.append(("publish-response-lost", message_id))
            raise PublishOutcomeUnknown("scripted publish response loss")
        return CarrierAccepted(message_id)

    async def deliver(self, indexes, handler, *, ack_loss=(), crash_after=()):
        """Invoke one-message handling in provider-selected batch order."""
        results = []
        ack_loss, crash_after = set(ack_loss), set(crash_after)
        for index in indexes:
            record = self.records[index]
            if record.acknowledged:
                continue
            record.attempt += 1
            delivery = CarrierDelivery(
                record.body, record.message_id, record.attempt)
            disposition = await delivery_disposition(delivery, handler)
            results.append((record.message_id, disposition))
            self.history.append((
                "handled", record.message_id,
                record.attempt, disposition.value))
            if disposition is not ACK:
                continue
            if index in crash_after:
                self.history.append(("crash-before-ack", record.message_id))
            elif index in ack_loss:
                self.history.append(("ack-lost", record.message_id))
            else:
                record.acknowledged = True
                self.history.append(("acked", record.message_id))
        return tuple(results)

    @property
    def pending(self):
        return tuple(
            record.message_id for record in self.records
            if not record.acknowledged)


__all__ = ("FaultCarrier",)
