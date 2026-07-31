"""Provider-neutral FCM request and outcome seam."""
from dataclasses import dataclass
from typing import Protocol

from core.limits import MAX_ATOM_VALUE_BYTES, valid_bounded_text
from core.shape import valid_fid, valid_timestamp
from facts.auth.push_endpoint import MAX_SEALED_TARGET_BYTES, PLATFORMS
from .job import MAX_PUSH_PAYLOAD_BYTES


MAX_FCM_TARGET_BYTES = MAX_SEALED_TARGET_BYTES - 48
MAX_FCM_TTL_SECONDS = 28 * 24 * 60 * 60


class FcmError(OSError):
    pass


class FcmRetryable(FcmError):
    pass


class FcmPermanent(FcmError):
    pass


class FcmUnregistered(FcmPermanent):
    pass


def checked_target(value):
    if not isinstance(value, str) or not value.isascii() \
            or not value or len(value.encode("ascii")) > MAX_FCM_TARGET_BYTES \
            or any(ord(character) < 0x21 or ord(character) > 0x7e
                   for character in value):
        raise ValueError("FCM installation target")
    return value


@dataclass(frozen=True, slots=True)
class FcmRequest:
    application: str
    environment: str
    platform: str
    target: str
    payload: bytes
    delivery_id: str
    expires_at_ms: int
    ttl_seconds: int
    kind: str

    def __post_init__(self):
        if not valid_bounded_text(
                self.application, MAX_ATOM_VALUE_BYTES) \
                or not valid_bounded_text(
                    self.environment, MAX_ATOM_VALUE_BYTES):
            raise ValueError("FCM application mapping")
        if self.platform not in PLATFORMS:
            raise ValueError("FCM platform")
        checked_target(self.target)
        if not isinstance(self.payload, bytes) or not self.payload \
                or len(self.payload) > MAX_PUSH_PAYLOAD_BYTES:
            raise ValueError("FCM payload")
        if not valid_fid(self.delivery_id):
            raise ValueError("FCM delivery id")
        if not valid_timestamp(self.expires_at_ms) \
                or self.expires_at_ms == 0:
            raise ValueError("FCM expiration")
        if type(self.ttl_seconds) is not int \
                or not 0 <= self.ttl_seconds <= MAX_FCM_TTL_SECONDS:
            raise ValueError("FCM TTL")
        if self.kind not in {"mention", "message"}:
            raise ValueError("FCM notification kind")


@dataclass(frozen=True, slots=True)
class FcmAccepted:
    message_id: str

    def __post_init__(self):
        if not isinstance(self.message_id, str) or not self.message_id \
                or len(self.message_id.encode("utf-8")) > 4096:
            raise ValueError("FCM message id")


class FcmClient(Protocol):
    def send(self, request: FcmRequest) -> FcmAccepted: ...


__all__ = (
    "FcmAccepted",
    "FcmClient",
    "FcmError",
    "FcmPermanent",
    "FcmRequest",
    "FcmRetryable",
    "FcmUnregistered",
    "MAX_FCM_TARGET_BYTES",
    "MAX_FCM_TTL_SECONDS",
    "checked_target",
)
