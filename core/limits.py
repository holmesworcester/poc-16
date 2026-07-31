"""One set of byte and count limits for the sync wire protocol.

Deployments may choose stricter front-door limits, but they must not silently
accept more than these core bounds.  ``PayloadTooLarge`` remains a
``ValueError`` so the pure codecs keep their total "value or ValueError"
contract while HTTP adapters can translate the condition to status 413.
"""
import json

MIB = 1024 * 1024

PAGE_BATCH = 256
MAX_ROOT_BYTES = MIB
MAX_PILE_BYTES = 64 * MIB
MAX_OBJECT_BYTES = 64 * MIB
MAX_CONTROL_BYTES = MIB
MAX_MINT_REQUEST_BYTES = 512 * 1024
MAX_MINT_FETCHES = 128
MAX_MINT_FETCH_BYTES = 4 * MIB
MAX_PAGE_REQUEST_BYTES = 64 * 1024
MAX_PAGE_BATCH_BYTES = 4 * MIB
MAX_REJECTION_RECORD_BYTES = 4 * 1024
MAX_REJECTION_DIAGNOSTIC_BYTES = 512

# Every database-free hosted Reader must be able to return canonical facts and
# public invite envelopes admitted by the shared engine. Detached file objects
# use their own direct-upload/completion path and retain MAX_OBJECT_BYTES.
MAX_FACT_BYTES = MAX_PAGE_BATCH_BYTES
MAX_INVITE_BYTES = MAX_PAGE_BATCH_BYTES
MAX_REPOSITORY_OBJECT_BYTES = MAX_FACT_BYTES

# One immutable closed pile. These are protocol limits, not merely
# implementation budgets: every receiving engine enforces the same boundary.
MAX_PILE_FACTS = 4_096
MAX_CLOSURE_FACTS = 256
MAX_RESOLVED_EDGES = 64

# Clear-envelope names become authenticated index vocabulary; values may
# become authenticated map keys. Bound both before family dispatch so malformed
# atoms cannot escape as retryable program failures or unbounded index rows.
MAX_ATOM_NAME_BYTES = 128
MAX_ATOM_VALUE_BYTES = 384


class PayloadTooLarge(ValueError):
    """A bounded protocol value exceeded its declared byte budget."""


class InvalidEncoding(ValueError):
    """Bytes violate an immutable protocol shape or integrity rule."""


def valid_bounded_text(value, maximum, *, allow_empty=False):
    """Whether one protocol string has canonical bounded UTF-8 bytes."""
    if not isinstance(value, str):
        return False
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        return False
    return size <= maximum and (allow_empty or size > 0)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InvalidEncoding("duplicate JSON key")
        value[key] = item
    return value


def _reject_nonfinite(_value):
    raise InvalidEncoding("non-finite JSON number")


def decode_json(raw, limit, label):
    """Decode bounded JSON and expose every parser failure as ``ValueError``."""
    if not isinstance(raw, bytes):
        raise InvalidEncoding(f"{label} bytes")
    if len(raw) > limit:
        raise PayloadTooLarge(f"{label} too large")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (TypeError, ValueError, RecursionError, UnicodeError) as error:
        raise InvalidEncoding(f"{label} encoding") from error
