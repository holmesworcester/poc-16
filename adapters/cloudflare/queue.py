"""Exact notification-carrier translation for Cloudflare Queues."""

from core.crypto import h
from notifications.carrier import (
    CarrierAccepted,
    CarrierDelivery,
    PublishOutcomeUnknown,
    checked_body,
)


# Cloudflare counts roughly 100 bytes of internal metadata inside its decimal
# 128,000-byte limit.  Keep a full decimal kilobyte of provider-only headroom;
# the provider-neutral carrier may be used by transports without that tax.
MAX_CLOUDFLARE_QUEUE_BODY_BYTES = 127_000


class CloudflareQueueCarrier:
    """Publish canonical hint bytes as Queue ``text`` messages.

    Notification hints are canonical ASCII JSON.  ``text`` avoids V8-only
    serialization and Base64 expansion, so the protocol's 128,000-byte bound
    is the provider's actual message bound too.
    """

    __slots__ = ("queue",)

    def __init__(self, queue):
        if not callable(getattr(queue, "send", None)):
            raise TypeError("Cloudflare Queue producer binding")
        self.queue = queue

    async def publish(self, body):
        body = checked_body(body)
        if len(body) > MAX_CLOUDFLARE_QUEUE_BODY_BYTES:
            raise ValueError("Cloudflare Queue body")
        try:
            text = body.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("Cloudflare notification body is not ASCII") \
                from error
        try:
            await self.queue.send(text, contentType="text")
        except Exception as error:
            # A rejected/lost promise cannot prove that this exact body was
            # not written.  The cursor must stay put and safely duplicate it.
            raise PublishOutcomeUnknown(
                "Cloudflare Queue publish outcome unknown") from error
        return CarrierAccepted(h(body))


def delivery_from_message(message):
    """Decode only the exact ``text`` envelope emitted above.

    ``None`` means poison provider work and is terminal.  Queue metadata is
    advisory; malformed metadata never becomes repository authority.
    """
    body = getattr(message, "body", None)
    identifier = getattr(message, "id", None)
    attempts = getattr(message, "attempts", None)
    if not isinstance(body, str):
        return None
    try:
        raw = body.encode("ascii")
        if len(raw) > MAX_CLOUDFLARE_QUEUE_BODY_BYTES:
            return None
        return CarrierDelivery(raw, identifier, attempts)
    except (TypeError, ValueError, UnicodeEncodeError):
        return None


__all__ = (
    "CloudflareQueueCarrier",
    "MAX_CLOUDFLARE_QUEUE_BODY_BYTES",
    "delivery_from_message",
)
