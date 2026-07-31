"""Canonical request codec for the direct-upload HTTP protocol.

This module is the one agreement between upload clients and broker endpoints.
It carries only bounded metadata: authorization proofs, Merkle descriptors,
and authenticated cursors. Provider bodies and credentials never cross it.
"""
import base64
from dataclasses import dataclass, field
from itertools import islice

from core.fact import canon
from core.limits import (
    MAX_MINT_REQUEST_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
    decode_json,
)
from deploy.upload_session import (
    MAX_RANGE_PROOF_BYTES,
    MAX_SESSION_OBJECTS,
    TOKEN_BYTES,
    UploadLeaf,
    UploadManifest,
    valid_leaf,
    valid_manifest,
)


OPEN_REQUEST_SCHEMA = "poc16-upload-open-request-v1"
ISSUE_REQUEST_SCHEMA = "poc16-upload-issue-request-v1"
FINALIZE_REQUEST_SCHEMA = "poc16-upload-finalize-request-v1"
UPLOAD_CONTENT_TYPE = "application/octet-stream"

MAX_OPEN_RESPONSE_BYTES = 2_048
MAX_ISSUE_RESPONSE_BYTES = 512 * 1024
MAX_FINALIZE_RESPONSE_BYTES = 4_096

# Base64 expands the largest accepted mint proof by 4/3. Keep the HTTP
# envelope from silently imposing a smaller authorization-proof limit than
# UploadBroker itself.
MAX_OPEN_REQUEST_BYTES = (
    4 * ((MAX_MINT_REQUEST_BYTES + 2) // 3) + 4_096
)
MAX_ISSUE_REQUEST_BYTES = 128 * 1024
MAX_FINALIZE_REQUEST_BYTES = 16 * 1024


class InvalidUploadWire(ValueError):
    """A request is not the one canonical upload protocol document."""


@dataclass(frozen=True)
class UploadCapability:
    """One exact provider request issued by the broker to the client."""

    method: str
    url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    expires_at_ms: int


@dataclass(frozen=True)
class GrantedUpload:
    leaf: UploadLeaf
    capability: UploadCapability


@dataclass(frozen=True)
class OpenedUpload:
    session: str
    cursor: str
    expires_at_ms: int


@dataclass(frozen=True)
class IssuedUpload:
    cursor: str
    next_index: int
    objects: tuple[GrantedUpload, ...]
    expires_at_ms: int


@dataclass(frozen=True)
class FinalizedUpload:
    cursor: str
    pile: GrantedUpload
    expires_at_ms: int


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
    if not isinstance(value, dict) \
            or set(value) != {"digest", "size"}:
        _invalid("upload leaf")
    try:
        leaf = UploadLeaf(value["digest"], value["size"])
    except (KeyError, TypeError, ValueError) as error:
        _invalid("upload leaf", error)
    if not valid_leaf(leaf):
        _invalid("upload leaf")
    return leaf


def _manifest_document(value):
    if not valid_manifest(value):
        _invalid("upload manifest")
    return {
        "count": value.count,
        "root": value.root,
        "total_bytes": value.total_bytes,
    }


def _decode_manifest(value):
    if not isinstance(value, dict) \
            or set(value) != {"count", "root", "total_bytes"}:
        _invalid("upload manifest")
    try:
        manifest = UploadManifest(
            value["root"], value["count"], value["total_bytes"])
    except (KeyError, TypeError, ValueError) as error:
        _invalid("upload manifest", error)
    if not valid_manifest(manifest):
        _invalid("upload manifest")
    return manifest


def _cursor(value):
    if not isinstance(value, str) or len(value) != TOKEN_BYTES \
            or not value.isascii():
        _invalid("upload cursor")
    return value


def _request(raw, maximum, fields, schema, label):
    try:
        value = decode_json(raw, maximum, label)
    except PayloadTooLarge:
        raise
    except ValueError as error:
        _invalid(label, error)
    try:
        canonical = canon(value)
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        _invalid(label, error)
    if canonical != raw or not isinstance(value, dict) \
            or set(value) != fields or value.get("schema") != schema:
        _invalid(label)
    return value


def _encoded(value, maximum, label):
    try:
        raw = canon(value)
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        _invalid(label, error)
    if len(raw) > maximum:
        raise PayloadTooLarge(f"{label} too large")
    return raw


def encode_open_request(proof, manifest, pile):
    return _encoded(
        {
            "manifest": _manifest_document(manifest),
            "pile": _leaf_document(pile),
            "proof": _encode_b64(
                proof, MAX_MINT_REQUEST_BYTES, "upload proof"),
            "schema": OPEN_REQUEST_SCHEMA,
        },
        MAX_OPEN_REQUEST_BYTES,
        "upload OPEN request",
    )


def decode_open_request(raw):
    value = _request(
        raw,
        MAX_OPEN_REQUEST_BYTES,
        {"manifest", "pile", "proof", "schema"},
        OPEN_REQUEST_SCHEMA,
        "upload OPEN request",
    )
    return (
        _decode_b64(
            value["proof"], MAX_MINT_REQUEST_BYTES, "upload proof"),
        _decode_manifest(value["manifest"]),
        _decode_leaf(value["pile"]),
    )


def _bounded_leaves(values):
    try:
        leaves = tuple(islice(iter(values), PAGE_BATCH + 1))
    except (TypeError, ValueError) as error:
        _invalid("upload ISSUE leaves", error)
    if not leaves or len(leaves) > PAGE_BATCH:
        _invalid("upload ISSUE leaves")
    return leaves


def encode_issue_request(cursor, start_index, leaves, proof):
    leaves = _bounded_leaves(leaves)
    if type(start_index) is not int \
            or not 0 <= start_index < MAX_SESSION_OBJECTS:
        _invalid("upload ISSUE start index")
    return _encoded(
        {
            "cursor": _cursor(cursor),
            "leaves": [_leaf_document(leaf) for leaf in leaves],
            "proof": _encode_b64(
                proof, MAX_RANGE_PROOF_BYTES, "upload range proof"),
            "schema": ISSUE_REQUEST_SCHEMA,
            "start_index": start_index,
        },
        MAX_ISSUE_REQUEST_BYTES,
        "upload ISSUE request",
    )


def decode_issue_request(raw):
    value = _request(
        raw,
        MAX_ISSUE_REQUEST_BYTES,
        {"cursor", "leaves", "proof", "schema", "start_index"},
        ISSUE_REQUEST_SCHEMA,
        "upload ISSUE request",
    )
    start_index = value["start_index"]
    if type(start_index) is not int \
            or not 0 <= start_index < MAX_SESSION_OBJECTS \
            or not isinstance(value["leaves"], list):
        _invalid("upload ISSUE request")
    leaves = _bounded_leaves(
        _decode_leaf(item) for item in value["leaves"])
    return (
        _cursor(value["cursor"]),
        start_index,
        leaves,
        _decode_b64(
            value["proof"],
            MAX_RANGE_PROOF_BYTES,
            "upload range proof",
        ),
    )


def encode_finalize_request(cursor):
    return _encoded(
        {
            "cursor": _cursor(cursor),
            "schema": FINALIZE_REQUEST_SCHEMA,
        },
        MAX_FINALIZE_REQUEST_BYTES,
        "upload FINALIZE request",
    )


def decode_finalize_request(raw):
    value = _request(
        raw,
        MAX_FINALIZE_REQUEST_BYTES,
        {"cursor", "schema"},
        FINALIZE_REQUEST_SCHEMA,
        "upload FINALIZE request",
    )
    return _cursor(value["cursor"])


__all__ = (
    "FINALIZE_REQUEST_SCHEMA",
    "FinalizedUpload",
    "GrantedUpload",
    "ISSUE_REQUEST_SCHEMA",
    "InvalidUploadWire",
    "MAX_FINALIZE_REQUEST_BYTES",
    "MAX_FINALIZE_RESPONSE_BYTES",
    "MAX_ISSUE_REQUEST_BYTES",
    "MAX_ISSUE_RESPONSE_BYTES",
    "MAX_OPEN_REQUEST_BYTES",
    "MAX_OPEN_RESPONSE_BYTES",
    "OPEN_REQUEST_SCHEMA",
    "OpenedUpload",
    "IssuedUpload",
    "UPLOAD_CONTENT_TYPE",
    "UploadCapability",
    "decode_finalize_request",
    "decode_issue_request",
    "decode_open_request",
    "encode_finalize_request",
    "encode_issue_request",
    "encode_open_request",
)
