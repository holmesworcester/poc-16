"""One carrier-neutral, post-publication notification attempt.

The notification cursor durably owns one pending body. A managed carrier is a
disposable wake that may expire or duplicate it. The handler advances only the
exact pending body after :meth:`NotificationWorker.process` succeeds; every
fair scanner run republishes work that remains pending.
"""
from dataclasses import dataclass
from enum import Enum
from inspect import isawaitable

from core.crypto import h
from core.limits import MAX_FACT_BYTES, PayloadTooLarge
from core.shape import FACT_TS_MAX, valid_fid

from .carrier import ACK as CARRIER_ACK
from .carrier import RETRY as CARRIER_RETRY
from .carrier import CarrierDelivery
from .delivery import (
    DeliveryResult,
    InvalidPublicationHint,
    PublicationHint,
    PushAccepted,
    PushInvalidEndpoint,
    PushUnregistered,
    derive,
    request_for,
)
from .hints import decode_hint, materialize_hint
from .forest import CurrentRepository
from .discovery import (
    PENDING_CURRENT,
    PENDING_NONCURRENT,
)


class NotificationAction(Enum):
    ACK = "ack"
    RETRY = "retry"
    TERMINAL = "terminal"


ACK = NotificationAction.ACK
RETRY = NotificationAction.RETRY
TERMINAL = NotificationAction.TERMINAL


async def _resolve(value):
    return await value if isawaitable(value) else value


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

    ``current_repository(workspace)`` reconstructs one ephemeral validated
    view from current writer heads. A deployment may bind its reads to S3,
    R2, or a full peer; no SQL projection or global content root is involved.
    """

    def __init__(
            self, current_repository, push_node_secret, provider, now_ms):
        if not callable(current_repository) \
                or not callable(getattr(provider, "send", None)) \
                or not callable(now_ms):
            raise TypeError("notification worker dependency")
        try:
            public = push_node_secret.verify_key.encode().hex()
        except Exception as error:
            raise TypeError("push node secret key") from error
        if not valid_fid(public):
            raise ValueError("push node secret key")
        self.current_repository = current_repository
        self.secret = push_node_secret
        self.provider = provider
        self.now_ms = now_ms
        self.push_node = public

    async def process(self, hint):
        """Return an ack decision; never acknowledge a retryable failure."""
        if not isinstance(hint, PublicationHint):
            return WorkerResult(TERMINAL, reason="invalid-hint")
        try:
            current = await _resolve(
                self.current_repository(hint.workspace))
            if not isinstance(current, CurrentRepository):
                raise TypeError("notification current repository")
            now = await _resolve(self.now_ms())
            if type(now) is not int or not 0 <= now <= FACT_TS_MAX:
                raise ValueError("notification clock")
            intents = derive(
                hint, current.view, push_node=self.push_node)
        except InvalidPublicationHint:
            return WorkerResult(TERMINAL, reason="invalid-hint")
        except Exception:
            return WorkerResult(RETRY, reason="repository-unavailable")

        outcomes = []
        retry = False
        for intent in intents:
            try:
                request = request_for(intent, self.secret, now)
                accepted = await _resolve(self.provider.send(request))
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


def _reference(delivery, workspace, owner):
    try:
        reference = decode_hint(delivery.body)
    except (TypeError, ValueError):
        return None, "invalid-carrier-hint"
    if reference.workspace != workspace or reference.owner != owner:
        return None, "foreign-authority"
    return reference, ""


async def _process(reference, notification_state, worker):
    read = getattr(notification_state, "get_bounded", None)
    if not callable(read):
        raise TypeError("notification carrier handler")
    try:
        raws = []
        for event in reference.events:
            raw = await _resolve(read(
                "obj/" + event.oid, MAX_FACT_BYTES))
            if raw is None or not isinstance(raw, bytes):
                return WorkerResult(RETRY, reason="state-event-missing")
            raws.append(raw)
    except PayloadTooLarge:
        return WorkerResult(RETRY, reason="oversized-state-event")
    except Exception:
        return WorkerResult(RETRY, reason="state-unavailable")
    try:
        hint = materialize_hint(reference, raws)
    except (TypeError, ValueError):
        return WorkerResult(RETRY, reason="invalid-state-event")
    return await worker.process(hint)


async def process_carrier_delivery(
        delivery, workspace, notification_state, worker):
    """Evaluate one body without advancing durable discovery state."""
    read = getattr(notification_state, "get_bounded", None)
    owner = getattr(notification_state, "owner", None)
    if not isinstance(delivery, CarrierDelivery) \
            or not valid_fid(workspace) \
            or not callable(read) \
            or not valid_fid(owner) \
            or not isinstance(worker, NotificationWorker):
        raise TypeError("notification carrier handler")
    reference, reason = _reference(delivery, workspace, owner)
    if reference is None:
        return WorkerResult(TERMINAL, reason=reason)
    return await _process(reference, notification_state, worker)


async def handle_carrier_delivery(
        delivery, workspace, notification_state, worker, *, wake=None):
    """Evaluate and complete only the exact durable pending body."""
    read = getattr(notification_state, "get_bounded", None)
    pending = getattr(notification_state, "pending", None)
    complete = getattr(notification_state, "complete", None)
    owner = getattr(notification_state, "owner", None)
    if not isinstance(delivery, CarrierDelivery) \
            or not valid_fid(workspace) \
            or not callable(read) \
            or not callable(pending) \
            or not callable(complete) \
            or not valid_fid(owner) \
            or not isinstance(worker, NotificationWorker) \
            or wake is not None and not callable(wake):
        raise TypeError("notification carrier handler")
    reference, _reason = _reference(delivery, workspace, owner)
    if reference is None:
        return CARRIER_ACK
    body_oid = h(delivery.body)
    try:
        status = await _resolve(pending(body_oid))
    except Exception:
        return CARRIER_RETRY
    if status == PENDING_NONCURRENT:
        return CARRIER_ACK
    if status != PENDING_CURRENT:
        return CARRIER_RETRY
    result = await _process(reference, notification_state, worker)
    if not isinstance(result, WorkerResult) \
            or result.action is RETRY \
            or result.reason == "invalid-hint":
        return CARRIER_RETRY
    try:
        status = await _resolve(complete(body_oid))
    except Exception:
        return CARRIER_RETRY
    if status != PENDING_NONCURRENT:
        return CARRIER_RETRY
    if wake is not None:
        try:
            await _resolve(wake())
        except Exception:
            # Completion is already durable. The ordinary fair cadence repairs
            # a dropped optimization wake without replaying accepted FCM work.
            pass
    return CARRIER_ACK


__all__ = (
    "ACK",
    "NotificationAction",
    "NotificationWorker",
    "RETRY",
    "TERMINAL",
    "WorkerResult",
    "carrier_disposition",
    "handle_carrier_delivery",
    "process_carrier_delivery",
)
