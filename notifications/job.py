"""Canonical self-contained job consumed after managed-queue delivery."""
import base64
from dataclasses import dataclass
import re

from core.crypto import h
from core.fact import canon
from core.limits import PayloadTooLarge, decode_json
from core.shape import valid_fid, valid_timestamp


SCHEMA = "poc16-push-delivery-v2"
MAX_PUSH_JOB_BYTES = 16 * 1024
MAX_PUSH_PAYLOAD_BYTES = 4096
MAX_SEALED_TARGET_BYTES = 4096
MAX_APPLICATION_BYTES = 256
MAX_ENVIRONMENT_BYTES = 64
MAX_PAYLOAD_VERSION = 1_000_000
PLATFORMS = frozenset(("android", "apple"))
_APPLICATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_ENVIRONMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FIELDS = {
    "application",
    "delivery_id",
    "endpoint",
    "environment",
    "event",
    "expires_at_ms",
    "payload",
    "payload_version",
    "platform",
    "push_node",
    "schema",
    "sealed_target",
    "workspace",
}


class InvalidPushJob(ValueError):
    pass


def _invalid(error=None):
    failure = InvalidPushJob("invalid push delivery job")
    if error is None:
        raise failure
    raise failure from error


def _ascii(value, pattern, maximum):
    if not isinstance(value, str) or pattern.fullmatch(value) is None \
            or len(value.encode("ascii")) > maximum:
        _invalid()
    return value


def _bounded_bytes(value, maximum, label):
    if not isinstance(value, bytes):
        raise TypeError(label)
    if not value or len(value) > maximum:
        raise ValueError(label)
    return value


def _encode_b64(value, maximum, label):
    return base64.b64encode(
        _bounded_bytes(value, maximum, label)).decode("ascii")


def _decode_b64(value, maximum):
    if not isinstance(value, str) \
            or len(value) > 4 * ((maximum + 2) // 3):
        _invalid()
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        _invalid(error)
    if not raw or len(raw) > maximum \
            or base64.b64encode(raw).decode("ascii") != value:
        _invalid()
    return raw


def derive_delivery_id(
        workspace, event, endpoint, payload_version, payload):
    if not all(valid_fid(value) for value in (
            workspace, event, endpoint)):
        raise ValueError("push delivery id facts")
    if type(payload_version) is not int \
            or not 1 <= payload_version <= MAX_PAYLOAD_VERSION:
        raise ValueError("push payload version")
    payload = _bounded_bytes(
        payload, MAX_PUSH_PAYLOAD_BYTES, "push payload")
    return h(canon([
        SCHEMA,
        workspace,
        event,
        endpoint,
        payload_version,
        h(payload),
    ]))


@dataclass(frozen=True, slots=True)
class PushDeliveryJob:
    workspace: str
    event: str
    endpoint: str
    push_node: str
    platform: str
    application: str
    environment: str
    sealed_target: bytes
    payload: bytes
    payload_version: int
    expires_at_ms: int
    delivery_id: str

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.event, self.endpoint, self.push_node)):
            raise ValueError("push job fact id")
        if self.platform not in PLATFORMS:
            raise ValueError("push platform")
        _ascii(
            self.application, _APPLICATION_RE, MAX_APPLICATION_BYTES)
        _ascii(
            self.environment, _ENVIRONMENT_RE, MAX_ENVIRONMENT_BYTES)
        _bounded_bytes(
            self.sealed_target,
            MAX_SEALED_TARGET_BYTES,
            "sealed push target",
        )
        _bounded_bytes(self.payload, MAX_PUSH_PAYLOAD_BYTES, "push payload")
        if type(self.payload_version) is not int \
                or not 1 <= self.payload_version <= MAX_PAYLOAD_VERSION:
            raise ValueError("push payload version")
        if not valid_timestamp(self.expires_at_ms) \
                or self.expires_at_ms == 0:
            raise ValueError("push expiry")
        if self.delivery_id != derive_delivery_id(
                self.workspace,
                self.event,
                self.endpoint,
                self.payload_version,
                self.payload):
            raise ValueError("push delivery id")


def make_job(
        workspace, event, endpoint, push_node, platform, application,
        environment, sealed_target, payload, payload_version,
        expires_at_ms):
    return PushDeliveryJob(
        workspace,
        event,
        endpoint,
        push_node,
        platform,
        application,
        environment,
        sealed_target,
        payload,
        payload_version,
        expires_at_ms,
        derive_delivery_id(
            workspace, event, endpoint, payload_version, payload),
    )


def encode(job):
    if not isinstance(job, PushDeliveryJob):
        raise TypeError("push delivery job")
    raw = canon({
        "application": job.application,
        "delivery_id": job.delivery_id,
        "endpoint": job.endpoint,
        "environment": job.environment,
        "event": job.event,
        "expires_at_ms": job.expires_at_ms,
        "payload": _encode_b64(
            job.payload, MAX_PUSH_PAYLOAD_BYTES, "push payload"),
        "payload_version": job.payload_version,
        "platform": job.platform,
        "push_node": job.push_node,
        "schema": SCHEMA,
        "sealed_target": _encode_b64(
            job.sealed_target,
            MAX_SEALED_TARGET_BYTES,
            "sealed push target",
        ),
        "workspace": job.workspace,
    })
    if len(raw) > MAX_PUSH_JOB_BYTES:
        raise PayloadTooLarge("push delivery job too large")
    return raw


def decode(raw):
    try:
        value = decode_json(raw, MAX_PUSH_JOB_BYTES, "push delivery job")
        if not isinstance(value, dict) or set(value) != _FIELDS \
                or value.get("schema") != SCHEMA:
            _invalid()
        job = PushDeliveryJob(
            workspace=value["workspace"],
            event=value["event"],
            endpoint=value["endpoint"],
            push_node=value["push_node"],
            platform=value["platform"],
            application=_ascii(
                value["application"],
                _APPLICATION_RE,
                MAX_APPLICATION_BYTES,
            ),
            environment=_ascii(
                value["environment"],
                _ENVIRONMENT_RE,
                MAX_ENVIRONMENT_BYTES,
            ),
            sealed_target=_decode_b64(
                value["sealed_target"], MAX_SEALED_TARGET_BYTES),
            payload=_decode_b64(value["payload"], MAX_PUSH_PAYLOAD_BYTES),
            payload_version=value["payload_version"],
            expires_at_ms=value["expires_at_ms"],
            delivery_id=value["delivery_id"],
        )
    except PayloadTooLarge:
        raise
    except (KeyError, TypeError, ValueError) as error:
        _invalid(error)
    if encode(job) != raw:
        _invalid()
    return job


__all__ = (
    "InvalidPushJob",
    "MAX_PUSH_JOB_BYTES",
    "MAX_PUSH_PAYLOAD_BYTES",
    "MAX_SEALED_TARGET_BYTES",
    "PushDeliveryJob",
    "SCHEMA",
    "decode",
    "derive_delivery_id",
    "encode",
    "make_job",
)
