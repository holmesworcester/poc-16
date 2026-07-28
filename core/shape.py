"""The pure key discipline of the one store.

Everything a reader or writer needs to know about WHERE a fact lives —
canonical key format, content-derived chunk boundaries, range fingerprint —
and nothing about what a fact means. Leaf piles (manifest.build) and manifest
shards (manifest.encode) both cut on ``boundary``; there is no second
chunking rule. docs/CUTOVER.md §3.
"""
import re

from .crypto import h

CUT = 64  # home-leaf density: the knee where a whole fetch goes
          # bandwidth-bound (docs/COSTS.md §6)
FACT_TS_MIN = 0
FACT_TS_MAX = 999_999_999_999_999
FID_BYTES = 64
FACT_KEY_BYTES = 15 + 1 + FID_BYTES
_FID = re.compile(r"^[0-9a-f]{64}$")
_FACT_KEY = re.compile(r"^[0-9]{15}:[0-9a-f]{64}$")


def valid_timestamp(ts):
    """Whether ``ts`` has the one canonical on-disk representation.

    ``bool`` is deliberately excluded even though it is an ``int`` subclass:
    accepting it would give the same logical timestamp two JSON spellings.
    """
    return type(ts) is int and FACT_TS_MIN <= ts <= FACT_TS_MAX


def valid_fid(fid):
    """A content id is exactly 32 lowercase hexadecimal bytes."""
    return isinstance(fid, str) and _FID.fullmatch(fid) is not None


def parse_key(value):
    """Parse the exact 80-byte ``<15 decimal digits>:<64 lowercase hex>`` key.

    This is the single address door used by manifests, removal indexes and
    sync.  It intentionally rejects signs, whitespace, wider timestamps,
    Unicode digits, uppercase hex and extra colons.
    """
    if not isinstance(value, str) or len(value.encode("utf-8")) != FACT_KEY_BYTES \
            or _FACT_KEY.fullmatch(value) is None:
        raise ValueError("fact address")
    ts = int(value[:15])
    if not valid_timestamp(ts) or f"{ts:015d}" != value[:15]:
        raise ValueError("fact address")
    return ts, value[16:]


def is_key(value):
    try:
        parse_key(value)
    except (TypeError, ValueError, UnicodeError):
        return False
    return True


def key(fact):
    """Canonical sort key "<ts:015d>:<fid>"."""
    return key_parts(fact.ts, fact.fid)


def key_parts(ts, fid):
    """Canonical key from an index row, without loading the fact body."""
    if not valid_timestamp(ts) or not valid_fid(fid):
        raise ValueError("fact address")
    value = f"{ts:015d}:{fid}"
    if len(value.encode("ascii")) != FACT_KEY_BYTES:
        raise ValueError("fact address")
    return value


def fid_of(k):
    """Inverse projection: the fid inside a key."""
    return parse_key(k)[1]


def boundary(fid):
    """A key ends a chunk iff its own hash mod CUT == 0.
    Reads only the key's own hash => history independence."""
    return int(fid[:8], 16) % CUT == 0


def stable_cut_positions(fids):
    """Monotone content cuts: adding keys never removes a boundary, so a
    settle rebuilds only the touched leaf and shard."""
    return [
        index + 1
        for index, fid in enumerate(fids)
        if boundary(fid)
    ]


def fingerprint(keys):
    """fp over sorted keys only — the set identity the removal index
    publishes beside its pile oid (docs/REMOVALS.md I4)."""
    return h("|".join(keys).encode())
