"""One carrier-neutral, post-publication notification attempt.

A managed carrier durably owns redelivery.  It decodes a ``PublicationHint``,
awaits :meth:`NotificationWorker.process`, acknowledges ``ACK`` and
``TERMINAL``, and redelivers ``RETRY``.  The worker never mutates repository
state and never treats the carrier as authority.
"""
from dataclasses import dataclass
from enum import Enum
from inspect import isawaitable

from core.shape import FACT_TS_MAX, valid_fid

from .carrier import ACK as CARRIER_ACK
from .carrier import RETRY as CARRIER_RETRY
from .delivery import (
    DeliveryResult,
    InvalidPublicationHint,
    PublicationHint,
    PushAccepted,
    PushInvalidEndpoint,
    PushUnregistered,
    derive_awaited,
    request_for,
)


class NotificationAction(Enum):
    ACK = "ack"
    RETRY = "retry"
    TERMINAL = "terminal"


ACK = NotificationAction.ACK
RETRY = NotificationAction.RETRY
TERMINAL = NotificationAction.TERMINAL


@dataclass(frozen=True, slots=True)
class WorkerResult:
    """The only decision a managed carrier needs from one attempt."""

    action: NotificationAction
    deliveries: tuple[DeliveryResult, ...] = ()
    reason: str = ""

    def __post_init__(self):
        if not isinstance(self.action, NotificationAction) \
                or not isinstance(self.deliveries, tuple) \
                or not all(isinstance(row, DeliveryResult)
                           for row in self.deliveries) \
                or not isinstance(self.reason, str):
            raise TypeError("notification worker result")


def carrier_disposition(result):
    """Map only this worker's typed result into the carrier vocabulary."""
    if not isinstance(result, WorkerResult):
        return CARRIER_RETRY
    return CARRIER_RETRY if result.action is RETRY else CARRIER_ACK


class NotificationWorker:
    """Derive current recipients and attempt FCM for one historical hint.

    ``current_root(workspace)`` and ``fetch(workspace, oid)`` are deliberately
    read-only.  A deployment adapter may bind them to S3, R2, or a full peer;
    no SQL projection or RepositoryApplier callback is involved.
    """

    def __init__(
            self, current_root, fetch, push_node_secret, provider, now_ms):
        if not callable(current_root) or not callable(fetch) \
                or not callable(getattr(provider, "send", None)) \
                or not callable(now_ms):
            raise TypeError("notification worker dependency")
        try:
            public = push_node_secret.verify_key.encode().hex()
        except Exception as error:
            raise TypeError("push node secret key") from error
        if not valid_fid(public):
            raise ValueError("push node secret key")
        self.current_root = current_root
        self.fetch = fetch
        self.secret = push_node_secret
        self.provider = provider
        self.now_ms = now_ms
        self.push_node = public

    @staticmethod
    async def _resolve(value):
        return await value if isawaitable(value) else value

    async def process(self, hint):
        """Return an ack decision; never acknowledge a retryable failure."""
        if not isinstance(hint, PublicationHint):
            return WorkerResult(TERMINAL, reason="invalid-hint")
        try:
            root = await self._resolve(self.current_root(hint.workspace))
            now = await self._resolve(self.now_ms())
            if type(now) is not int or not 0 <= now <= FACT_TS_MAX:
                raise ValueError("notification clock")
            intents = await derive_awaited(
                hint,
                lambda oid: self.fetch(hint.workspace, oid),
                root,
                push_node=self.push_node,
            )
        except InvalidPublicationHint:
            return WorkerResult(TERMINAL, reason="invalid-hint")
        except Exception:
            return WorkerResult(RETRY, reason="repository-unavailable")

        outcomes = []
        retry = False
        for intent in intents:
            try:
                request = request_for(intent, self.secret, now)
                accepted = await self._resolve(self.provider.send(request))
                if not isinstance(accepted, PushAccepted):
                    raise OSError("push provider returned no acceptance")
            except PushUnregistered:
                outcomes.append(DeliveryResult(
                    intent.delivery_id, "unregistered"))
            except PushInvalidEndpoint:
                outcomes.append(DeliveryResult(
                    intent.delivery_id, "invalid-endpoint"))
            except Exception:
                retry = True
                outcomes.append(DeliveryResult(
                    intent.delivery_id, "retry"))
            else:
                outcomes.append(DeliveryResult(
                    intent.delivery_id, "accepted", accepted.message_id))
        return WorkerResult(
            RETRY if retry else ACK,
            tuple(outcomes),
            "provider-retry" if retry else "",
        )


__all__ = (
    "ACK",
    "NotificationAction",
    "NotificationWorker",
    "RETRY",
    "TERMINAL",
    "WorkerResult",
    "carrier_disposition",
)
