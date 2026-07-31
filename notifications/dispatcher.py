"""Move durable push piles into an at-least-once managed queue."""
from dataclasses import dataclass

from core.crypto import h
from core.delivery_queue import Published
from core.fact import canon
from core.limits import PAGE_BATCH, PayloadTooLarge
from core.object_store import CREATED, EXISTS, OutcomeUnknown
from core.shape import valid_fid
from .job import MAX_PUSH_JOB_BYTES, decode as decode_job
from .queue_evidence import (
    MAX_QUEUE_EVIDENCE_BYTES,
    QUEUED_SCHEMA,
    decode_queue_acceptance,
    encode_queue_acceptance,
    pile_address,
    queue_acceptance_matches,
)


FAILED_SCHEMA = "poc16-push-dispatch-failure-v1"
MAX_DISPATCH_RECORD_BYTES = MAX_QUEUE_EVIDENCE_BYTES


@dataclass(frozen=True, slots=True)
class DispatchItem:
    pile: str
    status: str
    delivery_id: str | None = None
    message_id: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class DispatchPage:
    items: tuple[DispatchItem, ...]
    cursor: str | None


def _get(store, key, maximum):
    raw = store.get_bounded(key, maximum)
    if raw is not None and (
            not isinstance(raw, bytes) or len(raw) > maximum):
        raise ValueError("push dispatcher read")
    return raw


def _put_exact(store, key, raw):
    unknown = None
    for _ in range(2):
        try:
            outcome = store.put_if_absent(key, raw)
        except OutcomeUnknown as error:
            unknown = error
        else:
            if outcome not in {CREATED, EXISTS}:
                raise TypeError("push dispatcher create result")
        incumbent = _get(store, key, len(raw))
        if incumbent == raw:
            return
        if incumbent is not None:
            raise ValueError("push dispatcher evidence conflict")
    raise unknown or OSError("push dispatcher evidence was not preserved")


def encode_job(job):
    from .job import encode

    return encode(job)


def _accepted(store, job):
    raw = _get(
        store,
        "push/queued/" + job.delivery_id,
        MAX_DISPATCH_RECORD_BYTES,
    )
    if raw is None:
        return None
    value = decode_queue_acceptance(raw)
    if not queue_acceptance_matches(
            value,
            delivery_id=job.delivery_id,
            job_digest=h(encode_job(job)),
            push_node=job.push_node):
        raise ValueError("queue acceptance binding")
    return value


def _record_acceptance(store, job, pile, message_id):
    key = "push/queued/" + job.delivery_id
    raw = encode_queue_acceptance(job, pile, message_id)
    unknown = None
    for _ in range(2):
        try:
            outcome = store.put_if_absent(key, raw)
        except OutcomeUnknown as error:
            unknown = error
        else:
            if outcome not in {CREATED, EXISTS}:
                raise TypeError("queue acceptance create result")
        incumbent = _get(store, key, MAX_DISPATCH_RECORD_BYTES)
        if incumbent is not None:
            value = decode_queue_acceptance(incumbent)
            if queue_acceptance_matches(
                    value,
                    delivery_id=job.delivery_id,
                    job_digest=h(encode_job(job)),
                    push_node=job.push_node):
                return value
            raise ValueError("queue acceptance conflict")
    raise unknown or OSError("queue acceptance was not preserved")


def _poison(store, key, classification):
    record = canon({
        "classification": classification,
        "pile": key,
        "schema": FAILED_SCHEMA,
    })
    _put_exact(store, "push/failed/" + h(record), record)
    store.delete(key)
    return DispatchItem(key, "failed", error=classification)


def dispatch_one(store, queue, key, *, push_node):
    """Publish once unless durable acceptance already exists."""
    address_node, _generation, digest = pile_address(key)
    if address_node != push_node or not valid_fid(push_node):
        raise ValueError("push dispatcher node binding")
    try:
        raw = _get(store, key, MAX_PUSH_JOB_BYTES)
    except PayloadTooLarge:
        return _poison(store, key, "oversized-job")
    if raw is None:
        return DispatchItem(key, "missing")
    if h(raw) != digest:
        return _poison(store, key, "wrong-address")
    try:
        job = decode_job(raw)
    except (TypeError, ValueError):
        return _poison(store, key, "invalid-job")
    if job.push_node != push_node:
        return _poison(store, key, "wrong-push-node")

    accepted = _accepted(store, job)
    if accepted is None:
        receipt = queue.publish(raw)
        if not isinstance(receipt, Published):
            raise TypeError("queue publish receipt")
        accepted = _record_acceptance(
            store, job, key, receipt.message_id)
        status = "published"
    else:
        status = "already-published"
    store.delete(key)
    return DispatchItem(
        key,
        status,
        job.delivery_id,
        accepted["message_id"],
    )


def dispatch_page(
        store, queue, push_node, *, cursor=None, limit=PAGE_BATCH):
    """Drain one bounded discovery page while isolating retryable items."""
    if not valid_fid(push_node):
        raise ValueError("push dispatcher node")
    if type(limit) is not int or not 0 < limit <= PAGE_BATCH:
        raise ValueError("push dispatcher page limit")
    page = store.list_page(
        f"push/pile/{push_node}/", cursor, limit)
    outcomes = []
    for key in page.keys:
        try:
            outcomes.append(dispatch_one(
                store, queue, key, push_node=push_node))
        except Exception as error:
            outcomes.append(DispatchItem(
                key,
                "retry",
                error=f"{type(error).__name__}: {error}",
            ))
    return DispatchPage(tuple(outcomes), page.cursor)


__all__ = (
    "DispatchItem",
    "DispatchPage",
    "FAILED_SCHEMA",
    "MAX_DISPATCH_RECORD_BYTES",
    "QUEUED_SCHEMA",
    "dispatch_one",
    "dispatch_page",
)
