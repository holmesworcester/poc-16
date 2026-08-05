"""One set of byte and count limits for the sync wire protocol.

Deployments may choose stricter front-door limits, but they must not silently
accept more than these core bounds.  ``PayloadTooLarge`` remains a
``ValueError`` so the pure codecs keep their total "value or ValueError"
contract while HTTP adapters can translate the condition to status 413.
"""
import json

MIB = 1024 * 1024

# Physical pack/object transfer is independent of semantic pile evaluation.
# Packs may concatenate several complete piles up to this streamed ceiling;
# none of the pack, direct-object, or provider paths may imply that one value
# of this size can be decoded in a hosted evaluator turn.
MAX_FACT_BYTES = 4 * MIB
MAX_WRITER_PACK_BYTES = 95 * MIB

# Discarded access proofs and the remaining buffered pile door use the same
# deliberately small budget. Content pull is the only path that needs the full
# writer-pile ceiling, and it must use the direct data plane.
MAX_BUFFERED_PILE_BYTES = 5 * MIB
MAX_CONTROL_PILE_BYTES = MAX_BUFFERED_PILE_BYTES
PAGE_BATCH = 256
# One control-bearing head may collect several small independently closed
# piles, but the complete semantic turn must still fit the ordinary discarded
# control budget.  The count independently bounds framing and repeated
# evaluator setup for a head made from many tiny piles.
MAX_HEAD_CONTROL_PILES = PAGE_BATCH
MAX_HEAD_CONTROL_BYTES = MAX_CONTROL_PILE_BYTES
MAX_HEAD_PERMIT_BYTES = 32 * 1024

# Writer-log physical layout and streaming bounds. Keep these provider-neutral
# so codecs, stores, FullPeer, Lambda, R2, and benchmarks cannot drift by
# repeating the same numeric ceiling.
WRITER_LAYOUT_WINDOW_PILES = 16_384
DIRECT_STREAM_CHUNK_BYTES = 64 * 1024
MAX_DIRECT_STREAM_FRAGMENTS = 4_096

MAX_ROOT_BYTES = MIB
MAX_CONTROL_BYTES = MIB
MAX_MINT_REQUEST_BYTES = 512 * 1024
MAX_MINT_FETCHES = 128
MAX_MINT_FETCH_BYTES = 4 * MIB
MAX_PAGE_REQUEST_BYTES = 64 * 1024
MAX_PAGE_BATCH_BYTES = 4 * MIB
# Shared authenticated-map geometry.
MAX_MERKLE_PAGE_BYTES = 48 * 1024
MAX_MERKLE_PAGE_DEPTH = 512

# Private removal proof geometry. Logical keys are SHA-256
# digests, so a compressed binary Patricia path has at most one branch for
# each digest bit. Proofs carry only one target value and opaque sibling
# commitments; they never carry a dense leaf or neighboring logical keys.
MAX_REMOVAL_PROOF_STEPS = 256
MAX_REMOVAL_NODE_BYTES = 1024
# The private judgment pin is fetched whole so a cold gate never walks one
# provider object per Patricia branch. Hashed rows fit the same bounded 1 MiB
# control-response envelope; immutable nodes remain for path commitments.
MAX_REMOVAL_ROOT_BYTES = MAX_ROOT_BYTES
MAX_REMOVAL_PROOF_BYTES = 32 * 1024

MAX_INVITE_BYTES = MAX_PAGE_BATCH_BYTES
# QR version 40-L carries at most 2,953 byte-mode bytes. Compact ordinary
# invites fit that transport, while deeper authority chains remain usable as
# links inside the local 1 MiB control envelope. Reserve 64 KiB there for the
# command document, member display name, and encoding overhead.
MAX_INVITE_QR_BYTES = 2_953
MAX_INVITE_LINK_BYTES = MAX_CONTROL_BYTES - 64 * 1024
MAX_INVITE_ARTIFACT_BYTES = (MAX_INVITE_LINK_BYTES // 4) * 3
# Facts and authenticated-map pages use the ordinary buffered object path.
# Large signed piles share the ``obj/`` address space but require the direct
# streaming data plane and therefore must not widen this semantic-object bound.
MAX_REPOSITORY_OBJECT_BYTES = max(
    MAX_FACT_BYTES, MAX_MERKLE_PAGE_BYTES)
MAX_OBJECT_BYTES = MAX_REPOSITORY_OBJECT_BYTES
MAX_DIRECT_OBJECT_BYTES = max(
    MAX_REPOSITORY_OBJECT_BYTES, MAX_WRITER_PACK_BYTES)

# One immutable closed pile. These are protocol limits, not merely
# implementation budgets: every receiving engine enforces the same boundary.
MAX_CLOSURE_FACTS = 256
MAX_PILE_FACTS = MAX_CLOSURE_FACTS
MAX_STORE_READ_BYTES = max(
    MAX_REPOSITORY_OBJECT_BYTES, MAX_BUFFERED_PILE_BYTES)
MAX_PILE_JSON_VALUES = 48 * MAX_PILE_FACTS + 16
# push_endpoint is the current maximum: FactOrder + Fact residence, seven
# mechanical postings, and three current suppression slots.
MAX_REGISTERED_FACT_ROUTES = 11
MAX_REGISTERED_FACT_ROWS = 7
MAX_REGISTERED_SUPPRESSION_ROUTES = 3
MAX_RESOLVED_EDGES = 64
# Recipient removal state advances once per state-affecting fact, never once
# per whole pile. One fact cannot contribute more than this many slots.
MAX_REMOVAL_UPDATES = MAX_REGISTERED_SUPPRESSION_ROUTES
# A live request proves one direct-member provider and, for a secondary
# device, one owner-signed device provider. Each may carry the full declared
# suppression-route ceiling.
MAX_REMOVAL_PATH_SCOPES = 2 * MAX_REGISTERED_SUPPRESSION_ROUTES
MAX_REMOVAL_PATH_BYTES = MAX_MINT_REQUEST_BYTES

# A control head may carry several independently closed semantic mutations,
# but their complete turn is no larger than one ordinary closure. Dependency
# facts count even when repeated because each supplied pile is evaluated. The
# sink rows then ACI-join into one private-root CAS turn.
MAX_HEAD_CONTROL_FACTS = MAX_PILE_FACTS
MAX_HEAD_REMOVAL_UPDATES = MAX_REMOVAL_PATH_SCOPES
# A control commit may absorb one concurrent removal-root winner after its
# issue-time root was proved current. Further contention returns a bounded
# retryable result to the caller instead of multiplying provider work.
MAX_CONTROL_APPLY_ATTEMPTS = 2
# One exact permit is retained only for a bounded active publication turn.
MAX_OWNER_CONTROL_COMMIT_ATTEMPTS = 4

# Worst-case object-store calls for one self-contained control permit commit.
# A 256-bit Patricia walk reads at most D+1 nodes per update. Each reachable
# path-copy node gets one conditional PUT and, only for an unknown outcome,
# one exact reconciliation GET. The fixed terms cover root pin/CAS/reconcile,
# the result pin, proposed-head existence, and the single writer-slot CAS with
# an exact reread.
_REMOVAL_DEPTH = MAX_REMOVAL_PROOF_STEPS
_HEAD_APPLY_SUBREQUESTS = (
    5
    + MAX_HEAD_REMOVAL_UPDATES * (
        (_REMOVAL_DEPTH + 1) + 2 * (_REMOVAL_DEPTH + 2))
)
_HEAD_RECOVERY_SUBREQUESTS = (
    MAX_HEAD_REMOVAL_UPDATES * (_REMOVAL_DEPTH + 1)
    + _HEAD_APPLY_SUBREQUESTS
)
MAX_HEAD_COMMIT_SUBREQUESTS = (
    2
    + max(
        MAX_CONTROL_APPLY_ATTEMPTS * _HEAD_APPLY_SUBREQUESTS,
        _HEAD_RECOVERY_SUBREQUESTS,
    )
    + 4
)
CLOUDFLARE_SUBREQUEST_LIMIT = 10_000
if MAX_HEAD_COMMIT_SUBREQUESTS > CLOUDFLARE_SUBREQUEST_LIMIT:
    raise RuntimeError("control-head provider-call envelope")

# A 512-page adversarial path is accepted; a deeper canonical map is outside
# the protocol even though a 384-byte key could theoretically select more
# five-bit radix boundaries.

# Executable conservative deployment envelope for the smallest receiver. This
# function runs before json.loads. Counts and Merkle geometry are protocol
# facts; per-object coefficients and the fixed warm-runtime reserve are
# deliberately generous implementation allowances, ratcheted in tests and
# still subject to live workerd/Pyodide conformance.
MIN_HOSTED_MEMORY_BYTES = 128_000_000
EVALUATOR_RUNTIME_RESERVE_BYTES = 64 * MIB
_PILE_BUFFER_COPIES = 5
_JSON_VALUE_BYTES = 256
_FACT_DECODE_BYTES = 1024


def closure_bitset_bound(fact_count):
    """Bytes for all transitive integer bitsets plus one object per fact."""
    if type(fact_count) is not int or fact_count < 0:
        raise ValueError("closure bitset count")
    bits = fact_count * (fact_count + 1) // 2
    return (bits + 7) // 8 + 64 * fact_count


def evaluator_peak_bound(pile_bytes, json_values, fact_count):
    """Conservative live-byte ceiling for one closed-pile evaluation."""
    if not all(
            type(value) is int and value >= 0
            for value in (pile_bytes, json_values, fact_count)):
        raise ValueError("evaluator memory inputs")
    return (
        EVALUATOR_RUNTIME_RESERVE_BYTES
        + _PILE_BUFFER_COPIES * pile_bytes
        + _JSON_VALUE_BYTES * json_values
        + _FACT_DECODE_BYTES * fact_count
        + closure_bitset_bound(fact_count)
    )


def evaluator_pile_byte_bound(memory_bytes, json_values, fact_count):
    """Largest pile byte count admitted by one evaluator memory envelope."""
    if type(memory_bytes) is not int or memory_bytes < 0:
        raise ValueError("evaluator memory limit")
    fixed = evaluator_peak_bound(0, json_values, fact_count)
    return max(0, (memory_bytes - fixed) // _PILE_BUFFER_COPIES)


# One immutable semantic pile. This is derived for the worst legal JSON and
# fact counts, so the byte ceiling alone proves that every admitted canonical
# pile fits the smallest hosted evaluator. It is intentionally smaller than
# the physical streamed-object/pack ceiling above.
MAX_SEMANTIC_PILE_BYTES = evaluator_pile_byte_bound(
    MIN_HOSTED_MEMORY_BYTES,
    MAX_PILE_JSON_VALUES,
    MAX_PILE_FACTS,
)

# Clear-envelope names become authenticated index vocabulary; values may
# become authenticated map keys. Bound both before family dispatch so malformed
# atoms cannot escape as retryable program failures or unbounded index rows.
MAX_ATOM_NAME_BYTES = 128
MAX_ATOM_VALUE_BYTES = 384
MAX_SUPPRESSION_ID_BYTES = (
    MAX_ATOM_NAME_BYTES + 1 + MAX_ATOM_VALUE_BYTES)


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
