"""Canonical metadata wire for one exact-pile direct upload.

Pile bytes travel straight from the client to S3/R2.  This wire carries only
the current authorization proof, exact digest/size, fixed lease, and final
application result.
"""
import base64
from dataclasses import dataclass, field

from core.fact import canon
from core.limits import MAX_MINT_REQUEST_BYTES, PayloadTooLarge, decode_json
from deploy.upload_session import UploadLeaf, valid_cursor, valid_leaf


OPEN_REQUEST_SCHEMA = "poc16-upload-open-request-v2"
FINALIZE_REQUEST_SCHEMA = "poc16-upload-finalize-request-v2"
OPEN_RESPONSE_SCHEMA = "poc16-upload-open-v2"
FINALIZE_RESPONSE_SCHEMA = "poc16-upload-finalize-v2"
UPLOAD_CONTENT_TYPE = "application/octet-stream"

MAX_OPEN_REQUEST_BYTES = 4 * ((MAX_MINT_REQUEST_BYTES + 2) // 3) + 1_024
MAX_OPEN_RESPONSE_BYTES = 8 * 1_024
MAX_FINALIZE_REQUEST_BYTES = 4 * 1_024
MAX_FINALIZE_RESPONSE_BYTES = 1_024
FINAL_STATUSES = frozenset(("applied", "noop", "rejected", "retryable"))


class InvalidUploadWire(ValueError):
    """A request is not the one canonical upload protocol document."""


@dataclass(frozen=True, slots=True)
class UploadCapability:
    method: str
    url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    expires_at_ms: int


@dataclass(frozen=True, slots=True)
class GrantedUpload:
    leaf: UploadLeaf
    capability: UploadCapability


@dataclass(frozen=True, slots=True)
class OpenedUpload:
    session: str
    cursor: str
    pile: GrantedUpload
    expires_at_ms: int


@dataclass(frozen=True, slots=True)
class FinalizedUpload:
    status: str

    def __post_init__(self):
        if self.status not in FINAL_STATUSES:
            raise ValueError("upload final status")


def _invalid(label, error=None):
    failure = InvalidUploadWire(f"invalid {label}")
    if error is None:
        raise failure
    raise failure from error


def _encode_b64(raw, maximum, label):
    if not isinstance(raw, bytes):
        _invalid(label)
    if len(raw) > maximum:
        raise PayloadTooLarge(f"{label} too large")
    return base64.b64encode(raw).decode("ascii")


def _decode_b64(value, maximum, label):
    if not isinstance(value, str):
        _invalid(label)
    if len(value) > 4 * ((maximum + 2) // 3):
        raise PayloadTooLarge(f"{label} too large")
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        _invalid(label, error)
    if len(raw) > maximum:
        raise PayloadTooLarge(f"{label} too large")
    if base64.b64encode(raw).decode("ascii") != value:
        _invalid(label)
    return raw


def _leaf_document(leaf):
    if not valid_leaf(leaf):
        _invalid("upload leaf")
    return {"digest": leaf.digest, "size": leaf.size}


def _decode_leaf(value):
    if not isinstance(value, dict) or set(value) != {"digest", "size"}:
        _invalid("upload leaf")
    try:
        leaf = UploadLeaf(value["digest"], value["size"])
    except (KeyError, TypeError, ValueError) as error:
        _invalid("upload leaf", error)
    if not valid_leaf(leaf):
        _invalid("upload leaf")
    return leaf


def _request(raw, maximum, fields, schema, label):
    try:
        value = decode_json(raw, maximum, label)
        if canon(value) != raw or not isinstance(value, dict) \
                or set(value) != fields or value.get("schema") != schema:
            raise ValueError
        return value
    except PayloadTooLarge:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        _invalid(label, error)


def _encoded(value, maximum, label):
    try:
        raw = canon(value)
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        _invalid(label, error)
    if len(raw) > maximum:
        raise PayloadTooLarge(f"{label} too large")
    return raw


def encode_open_request(proof, pile):
    return _encoded({
        "pile": _leaf_document(pile),
        "proof": _encode_b64(
            proof, MAX_MINT_REQUEST_BYTES, "upload proof"),
        "schema": OPEN_REQUEST_SCHEMA,
    }, MAX_OPEN_REQUEST_BYTES, "upload OPEN request")


def decode_open_request(raw):
    value = _request(
        raw,
        MAX_OPEN_REQUEST_BYTES,
        {"pile", "proof", "schema"},
        OPEN_REQUEST_SCHEMA,
        "upload OPEN request",
    )
    return (
        _decode_b64(
            value["proof"], MAX_MINT_REQUEST_BYTES, "upload proof"),
        _decode_leaf(value["pile"]),
    )


def encode_finalize_request(cursor):
    if not valid_cursor(cursor):
        _invalid("upload cursor")
    return _encoded({
        "cursor": cursor,
        "schema": FINALIZE_REQUEST_SCHEMA,
    }, MAX_FINALIZE_REQUEST_BYTES, "upload FINALIZE request")


def decode_finalize_request(raw):
    value = _request(
        raw,
        MAX_FINALIZE_REQUEST_BYTES,
        {"cursor", "schema"},
        FINALIZE_REQUEST_SCHEMA,
        "upload FINALIZE request",
    )
    cursor = value["cursor"]
    if not valid_cursor(cursor):
        _invalid("upload cursor")
    return cursor


__all__ = (
    "FINALIZE_REQUEST_SCHEMA",
    "FINALIZE_RESPONSE_SCHEMA",
    "FINAL_STATUSES",
    "FinalizedUpload",
    "GrantedUpload",
    "InvalidUploadWire",
    "MAX_FINALIZE_REQUEST_BYTES",
    "MAX_FINALIZE_RESPONSE_BYTES",
    "MAX_OPEN_REQUEST_BYTES",
    "MAX_OPEN_RESPONSE_BYTES",
    "OPEN_REQUEST_SCHEMA",
    "OPEN_RESPONSE_SCHEMA",
    "OpenedUpload",
    "UPLOAD_CONTENT_TYPE",
    "UploadCapability",
    "decode_finalize_request",
    "decode_open_request",
    "encode_finalize_request",
    "encode_open_request",
)
