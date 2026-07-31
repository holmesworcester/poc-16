"""Canonical private broker-to-RepositoryApplier documents."""
from core.shape import valid_fid


APPLY_REQUEST_SCHEMA = "poc16-repository-apply-v1"
APPLY_RESULT_SCHEMA = "poc16-repository-apply-result-v1"
MAX_APPLY_KEY_BYTES = 1024
_PUBLIC_STATUSES = frozenset({
    "applied", "noop", "rejected", "retryable"})
_RESULT_STATUSES = {
    "admitted": "applied",
    "applied": "applied",
    "confirmed": "applied",
    "noop": "noop",
    "rootless": "noop",
    "rejected": "rejected",
    "retryable": "retryable",
}


def encode_apply_request(workspace, key, digest):
    """Build one exact, bounded private invocation value."""
    try:
        key_bytes = key.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        key_bytes = b""
    if not valid_fid(workspace) or not isinstance(key, str) or not key \
            or not key_bytes or len(key_bytes) > MAX_APPLY_KEY_BYTES \
            or not valid_fid(digest):
        raise ValueError("repository apply request")
    return {
        "schema": APPLY_REQUEST_SCHEMA,
        "workspace": workspace,
        "key": key,
        "digest": digest,
    }


def decode_apply_request(value):
    """Return ``(workspace, key, digest)`` from the exact request shape."""
    if not isinstance(value, dict) or set(value) != {
            "schema", "workspace", "key", "digest"} \
            or value.get("schema") != APPLY_REQUEST_SCHEMA:
        raise ValueError("repository apply request")
    return tuple(encode_apply_request(
        value["workspace"], value["key"], value["digest"],
    )[name] for name in ("workspace", "key", "digest"))


def encode_apply_result(result):
    """Hide internal outcomes behind the four-result provider contract."""
    status = _RESULT_STATUSES.get(getattr(result, "status", None))
    if status is None:
        raise ValueError("repository apply result")
    return {"schema": APPLY_RESULT_SCHEMA, "status": status}


def decode_apply_result(value):
    """Return one exact public status from a provider response."""
    if not isinstance(value, dict) \
            or set(value) != {"schema", "status"} \
            or value.get("schema") != APPLY_RESULT_SCHEMA \
            or value.get("status") not in _PUBLIC_STATUSES:
        raise ValueError("repository apply result")
    return value["status"]


__all__ = (
    "APPLY_REQUEST_SCHEMA",
    "APPLY_RESULT_SCHEMA",
    "MAX_APPLY_KEY_BYTES",
    "decode_apply_request",
    "decode_apply_result",
    "encode_apply_request",
    "encode_apply_result",
)
