"""Canonical evidence that a resolved push job reached a managed queue."""
from core.crypto import h
from core.fact import canon
from core.limits import decode_json
from core.shape import valid_fid
from .job import encode as encode_job


QUEUED_SCHEMA = "poc16-push-queue-acceptance-v1"
MAX_QUEUE_EVIDENCE_BYTES = 16 * 1024


def pile_address(key):
    try:
        prefix, kind, push_node, generation, digest = key.split("/")
    except (AttributeError, ValueError) as error:
        raise ValueError("push pile address") from error
    if (prefix, kind) != ("push", "pile") \
            or not all(valid_fid(value) for value in (
                push_node, generation, digest)):
        raise ValueError("push pile address")
    return push_node, generation, digest


def encode_queue_acceptance(job, pile, message_id):
    if not isinstance(message_id, str) or not message_id:
        raise ValueError("queue acceptance id")
    push_node, _generation, digest = pile_address(pile)
    raw_job = encode_job(job)
    if push_node != job.push_node or digest != h(raw_job):
        raise ValueError("queue acceptance pile binding")
    raw = canon({
        "delivery_id": job.delivery_id,
        "job": h(raw_job),
        "message_id": message_id,
        "pile": pile,
        "push_node": job.push_node,
        "schema": QUEUED_SCHEMA,
    })
    if len(raw) > MAX_QUEUE_EVIDENCE_BYTES:
        raise ValueError("queue acceptance size")
    return raw


def decode_queue_acceptance(raw):
    value = decode_json(
        raw, MAX_QUEUE_EVIDENCE_BYTES, "queue acceptance")
    if not isinstance(value, dict) or set(value) != {
            "delivery_id", "job", "message_id", "pile", "push_node",
            "schema"} or value.get("schema") != QUEUED_SCHEMA \
            or not all(valid_fid(value.get(field)) for field in (
                "delivery_id", "job", "push_node")) \
            or not isinstance(value.get("message_id"), str) \
            or not value["message_id"] \
            or canon(value) != raw:
        raise ValueError("queue acceptance")
    push_node, _generation, digest = pile_address(value["pile"])
    if push_node != value["push_node"] or digest != value["job"]:
        raise ValueError("queue acceptance binding")
    return value


def queue_acceptance_matches(
        value, *, delivery_id, job_digest, push_node):
    return isinstance(value, dict) \
        and value.get("delivery_id") == delivery_id \
        and value.get("job") == job_digest \
        and value.get("push_node") == push_node


__all__ = (
    "MAX_QUEUE_EVIDENCE_BYTES",
    "QUEUED_SCHEMA",
    "decode_queue_acceptance",
    "encode_queue_acceptance",
    "pile_address",
    "queue_acceptance_matches",
)
