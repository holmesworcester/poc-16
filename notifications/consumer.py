"""Consume managed-queue jobs and discharge them through FCM."""
from dataclasses import dataclass

from core.crypto import h
from core.delivery_queue import LeasedMessage
from core.fact import canon
from core.limits import decode_json
from core.object_store import CREATED, EXISTS, OutcomeUnknown
from core.shape import valid_fid
from .job import MAX_PUSH_JOB_BYTES, decode as decode_job, encode as encode_job
from .provider import (
    FcmAccepted,
    FcmPermanent,
    FcmRequest,
    FcmRetryable,
    FcmUnregistered,
    MAX_FCM_TTL_SECONDS,
)
from .target import InvalidSealedTarget, open_target


DONE_SCHEMA = "poc16-push-delivery-result-v1"
FAILED_SCHEMA = "poc16-push-provider-failure-v1"
INVALIDATION_SCHEMA = "poc16-push-endpoint-invalidation-v1"
MAX_CONSUMER_RECORD_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class ConsumeItem:
    message_id: str
    status: str
    delivery_id: str | None = None
    error: str | None = None


def _get(store, key, maximum):
    raw = store.get_bounded(key, maximum)
    if raw is not None and (
            not isinstance(raw, bytes) or len(raw) > maximum):
        raise ValueError("push consumer read")
    return raw


def _put_exact(store, key, raw, compatible=None):
    unknown = None
    for _ in range(2):
        try:
            outcome = store.put_if_absent(key, raw)
        except OutcomeUnknown as error:
            unknown = error
        else:
            if outcome not in {CREATED, EXISTS}:
                raise TypeError("push consumer create result")
        incumbent = _get(store, key, MAX_CONSUMER_RECORD_BYTES)
        if incumbent == raw or incumbent is not None \
                and compatible is not None and compatible(incumbent):
            return incumbent
        if incumbent is not None:
            raise ValueError("push consumer evidence conflict")
    raise unknown or OSError("push consumer evidence was not preserved")


def _decode_done(raw):
    value = decode_json(raw, MAX_CONSUMER_RECORD_BYTES, "push result")
    if not isinstance(value, dict) or set(value) != {
            "delivery_id", "endpoint", "job", "message_id", "schema",
            "status"} or value.get("schema") != DONE_SCHEMA \
            or value.get("status") not in {
                "accepted", "expired", "unregistered"} \
            or not all(valid_fid(value.get(field)) for field in (
                "delivery_id", "endpoint", "job")) \
            or not isinstance(value.get("message_id"), str) \
            or canon(value) != raw:
        raise ValueError("push result")
    return value


def _done(store, job):
    raw = _get(
        store,
        "push/done/" + job.delivery_id,
        MAX_CONSUMER_RECORD_BYTES,
    )
    if raw is None:
        return None
    value = _decode_done(raw)
    if value["delivery_id"] != job.delivery_id \
            or value["endpoint"] != job.endpoint \
            or value["job"] != h(encode_job(job)):
        raise ValueError("push result binding")
    return value


def _record_done(store, job, status, message_id=""):
    raw = canon({
        "delivery_id": job.delivery_id,
        "endpoint": job.endpoint,
        "job": h(encode_job(job)),
        "message_id": message_id,
        "schema": DONE_SCHEMA,
        "status": status,
    })

    def compatible(incumbent):
        try:
            value = _decode_done(incumbent)
        except ValueError:
            return False
        return value["delivery_id"] == job.delivery_id \
            and value["endpoint"] == job.endpoint \
            and value["job"] == h(encode_job(job))

    preserved = _put_exact(
        store, "push/done/" + job.delivery_id, raw, compatible)
    return _decode_done(preserved)


def _record_invalidation(store, job):
    raw = canon({
        "delivery_id": job.delivery_id,
        "endpoint": job.endpoint,
        "job": h(encode_job(job)),
        "reason": "unregistered",
        "schema": INVALIDATION_SCHEMA,
        "workspace": job.workspace,
    })
    key = f"push/invalidation/{job.endpoint}/{job.delivery_id}"
    _put_exact(store, key, raw)


def _record_failed(store, message, classification, job=None):
    record = {
        "classification": classification,
        "message": h(message.message_id.encode("utf-8")),
        "schema": FAILED_SCHEMA,
    }
    if job is not None:
        record.update({
            "delivery_id": job.delivery_id,
            "job": h(encode_job(job)),
        })
    raw = canon(record)
    _put_exact(store, "push/provider-failed/" + h(raw), raw)


def _payload(job):
    value = decode_json(job.payload, len(job.payload), "push payload")
    if not isinstance(value, dict) or set(value) != {
            "channel", "event", "kind", "workspace"} \
            or value.get("event") != job.event \
            or value.get("workspace") != job.workspace \
            or value.get("kind") not in {"mention", "message"} \
            or not isinstance(value.get("channel"), str) \
            or not value["channel"] \
            or canon(value) != job.payload:
        raise ValueError("push payload")
    return value


def _retry_delay(job, attempt):
    attempt = 1 if attempt is None else min(attempt, 16)
    base = min(480, 10 * (2 ** (attempt - 1)))
    jitter = int(h(canon([job.delivery_id, attempt]))[:8], 16) \
        % max(1, base // 4)
    return min(600, base + jitter)


class PushConsumer:
    """One push-node key, one queue subscription, one terminal store."""

    def __init__(self, store, queue, provider, push_node_secret, now_ms):
        if not callable(now_ms) or not callable(getattr(
                provider, "send", None)):
            raise TypeError("push consumer dependency")
        try:
            public = push_node_secret.verify_key.encode().hex()
        except Exception as error:
            raise TypeError("push node secret key") from error
        if not valid_fid(public):
            raise ValueError("push node secret key")
        self.store = store
        self.queue = queue
        self.provider = provider
        self.secret = push_node_secret
        self.push_node = public
        self.now_ms = now_ms

    def _terminal(self, message, job, status, message_id=""):
        result = _record_done(
            self.store, job, status, message_id)
        if result["status"] == "unregistered":
            _record_invalidation(self.store, job)
        self.queue.ack((message.lease,))
        return ConsumeItem(
            message.message_id, result["status"], job.delivery_id)

    def _one(self, message):
        if not isinstance(message, LeasedMessage):
            raise TypeError("push queue delivery")
        try:
            job = decode_job(message.body)
        except (TypeError, ValueError):
            _record_failed(self.store, message, "invalid-job")
            self.queue.ack((message.lease,))
            return ConsumeItem(
                message.message_id, "failed", error="invalid-job")

        terminal = _done(self.store, job)
        if terminal is not None:
            if terminal["status"] == "unregistered":
                _record_invalidation(self.store, job)
            self.queue.ack((message.lease,))
            return ConsumeItem(
                message.message_id,
                "already-done",
                job.delivery_id,
            )
        if job.push_node != self.push_node:
            _record_failed(self.store, message, "wrong-push-node", job)
            self.queue.ack((message.lease,))
            return ConsumeItem(
                message.message_id,
                "failed",
                job.delivery_id,
                "wrong-push-node",
            )

        now = self.now_ms()
        if type(now) is not int or now < 0:
            raise ValueError("push consumer clock")
        if now >= job.expires_at_ms:
            return self._terminal(message, job, "expired")
        try:
            target = open_target(self.secret, job.sealed_target)
            payload = _payload(job)
            ttl = min(
                MAX_FCM_TTL_SECONDS,
                max(0, (job.expires_at_ms - now + 999) // 1000),
            )
            outcome = self.provider.send(FcmRequest(
                application=job.application,
                environment=job.environment,
                platform=job.platform,
                target=target,
                payload=job.payload,
                delivery_id=job.delivery_id,
                expires_at_ms=job.expires_at_ms,
                ttl_seconds=ttl,
                kind=payload["kind"],
            ))
            if not isinstance(outcome, FcmAccepted):
                raise FcmRetryable("FCM returned no acceptance")
        except FcmUnregistered:
            return self._terminal(message, job, "unregistered")
        except (InvalidSealedTarget, ValueError, FcmPermanent) as error:
            classification = "invalid-target" \
                if isinstance(error, InvalidSealedTarget) \
                else "invalid-payload" if isinstance(error, ValueError) \
                else "permanent-provider-error"
            _record_failed(self.store, message, classification, job)
            self.queue.ack((message.lease,))
            return ConsumeItem(
                message.message_id,
                "failed",
                job.delivery_id,
                classification,
            )
        except (FcmRetryable, OSError, TimeoutError):
            self.queue.defer(
                (message.lease,),
                delay_seconds=_retry_delay(
                    job, message.delivery_attempt),
            )
            return ConsumeItem(
                message.message_id, "retry", job.delivery_id)
        return self._terminal(
            message, job, "accepted", outcome.message_id)

    def consume(self, *, max_messages=10, lease_seconds=60):
        messages = self.queue.pull(
            max_messages=max_messages, lease_seconds=lease_seconds)
        outcomes = []
        for message in messages:
            try:
                outcomes.append(self._one(message))
            except Exception as error:
                outcomes.append(ConsumeItem(
                    message.message_id,
                    "retry",
                    error=f"{type(error).__name__}: {error}",
                ))
        return tuple(outcomes)


__all__ = (
    "ConsumeItem",
    "DONE_SCHEMA",
    "FAILED_SCHEMA",
    "INVALIDATION_SCHEMA",
    "MAX_CONSUMER_RECORD_BYTES",
    "PushConsumer",
)
