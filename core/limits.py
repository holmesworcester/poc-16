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
MAX_CONTROL_BYTES = MIB
MAX_MINT_REQUEST_BYTES = 512 * 1024
MAX_MINT_FETCHES = 128
MAX_MINT_FETCH_BYTES = 4 * MIB
MAX_PAGE_REQUEST_BYTES = 64 * 1024
MAX_PAGE_BATCH_BYTES = 4 * MIB
MAX_OBJECT_BYTES = MAX_PAGE_BATCH_BYTES
# Shared authenticated-map geometry.
MAX_MERKLE_PAGE_BYTES = 48 * 1024
MAX_MERKLE_PAGE_DEPTH = 512

# Inline facts stay small; detached Bao objects carry large content.  This
# makes the complete 256-fact closure fit one pile by construction instead of
# relying on every present and future family to invent a second size system.
MAX_FACT_BYTES = 16 * 1024
MAX_INVITE_BYTES = MAX_PAGE_BATCH_BYTES
MAX_REPOSITORY_OBJECT_BYTES = max(
    MAX_FACT_BYTES, MAX_MERKLE_PAGE_BYTES)

# One immutable closed pile. These are protocol limits, not merely
# implementation budgets: every receiving engine enforces the same boundary.
MAX_CLOSURE_FACTS = 256
MAX_PILE_FACTS = MAX_CLOSURE_FACTS
MAX_PILE_BYTES = 5 * MIB
MAX_STORE_READ_BYTES = max(MAX_OBJECT_BYTES, MAX_PILE_BYTES)
MAX_PILE_JSON_VALUES = 48 * MAX_PILE_FACTS + 16
# device_invite is the current maximum: FactOrder + Fact residence + ten
# mechanical postings + five current suppression slots.
MAX_REGISTERED_FACT_ROUTES = 17
MAX_REGISTERED_FACT_ROWS = 11
MAX_REGISTERED_SUPPRESSION_ROUTES = 5
MAX_RESOLVED_EDGES = 64

# A 512-page adversarial path is accepted; a deeper canonical map is outside
# the protocol even though a 384-byte key could theoretically select more
# five-bit radix boundaries.

# Executable conservative deployment envelope for the smallest receiver. This
# function runs before json.loads. Counts and Merkle geometry are protocol
# facts; per-object coefficients and the fixed warm-runtime reserve are
# deliberately generous implementation allowances, ratcheted in tests and
# still subject to live workerd/Pyodide conformance.
MIN_HOSTED_MEMORY_BYTES = 128_000_000
APPLIER_RUNTIME_RESERVE_BYTES = 64 * MIB
_PILE_BUFFER_COPIES = 5
_JSON_VALUE_BYTES = 256
_FACT_DECODE_BYTES = 1024
_FACT_ROUTE_BYTES = 512
_FACT_COMPILE_BYTES = (
    MAX_REGISTERED_FACT_ROUTES * _FACT_ROUTE_BYTES)
_MERKLE_FRONTIER_BYTES = (
    MAX_MERKLE_PAGE_DEPTH * MAX_MERKLE_PAGE_BYTES)
_SUPPRESSION_EVIDENCE_BYTES = (
    MAX_PILE_FACTS
    * MAX_REGISTERED_SUPPRESSION_ROUTES
    * (2 + MAX_REGISTERED_SUPPRESSION_ROUTES)
    * _FACT_ROUTE_BYTES
)


def closure_bitset_bound(fact_count):
    """Bytes for all transitive integer bitsets plus one object per fact."""
    if type(fact_count) is not int or fact_count < 0:
        raise ValueError("closure bitset count")
    bits = fact_count * (fact_count + 1) // 2
    return (bits + 7) // 8 + 64 * fact_count


def applier_peak_bound(pile_bytes, json_values, fact_count):
    """Conservative live-byte ceiling for one RepositoryApplier pile turn."""
    if not all(
            type(value) is int and value >= 0
            for value in (pile_bytes, json_values, fact_count)):
        raise ValueError("applier memory inputs")
    decode = (
        APPLIER_RUNTIME_RESERVE_BYTES
        + _PILE_BUFFER_COPIES * pile_bytes
        + _JSON_VALUE_BYTES * json_values
        + _FACT_DECODE_BYTES * fact_count
        + closure_bitset_bound(fact_count)
    )
    compile_ = (
        APPLIER_RUNTIME_RESERVE_BYTES
        + 2 * pile_bytes
        + _JSON_VALUE_BYTES * json_values
        + _FACT_COMPILE_BYTES * fact_count
        + _FACT_DECODE_BYTES * fact_count
        + closure_bitset_bound(fact_count)
        + _MERKLE_FRONTIER_BYTES
        + _SUPPRESSION_EVIDENCE_BYTES
    )
    return max(decode, compile_)


# Worst-case provider calls for one accepted hosted pile. Multi-point reads
# visit at most one union of bounded paths; the intentionally smaller updater
# charges one complete path per logical change. Immutable Ensure is charged
# twice (conditional PUT plus collision GET).
MAX_APPLIER_ROUTE_CHANGES = (
    MAX_PILE_FACTS * MAX_REGISTERED_FACT_ROUTES)
MAX_APPLIER_SUPPRESSION_POINTS = (
    MAX_PILE_FACTS * MAX_REGISTERED_SUPPRESSION_ROUTES)
MAX_APPLIER_PAGE_READS = (
    MAX_PILE_FACTS
    + 2 * MAX_APPLIER_SUPPRESSION_POINTS
    + MAX_APPLIER_ROUTE_CHANGES
) * MAX_MERKLE_PAGE_DEPTH
MAX_APPLIER_PAGE_WRITES = (
    MAX_APPLIER_ROUTE_CHANGES * MAX_MERKLE_PAGE_DEPTH)
MAX_APPLIER_SUBREQUESTS = (
    MAX_APPLIER_PAGE_READS
    + 2 * MAX_APPLIER_PAGE_WRITES
    + 4 * MAX_PILE_FACTS
    + 10_000
)
# Per exact hosted invocation. Provider adapters may choose a lower limit.
MAX_HOSTED_CPU_MS = 30_000
MAX_HOSTED_SUBREQUESTS = 10_000_000

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
