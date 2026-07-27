"""The pure key discipline of the one store.

Everything a reader or writer needs to know about WHERE a fact lives —
canonical key format, content-derived chunk boundaries, range fingerprint —
and nothing about what a fact means. Leaf piles (manifest.build) and manifest
shards (manifest.encode) both cut on ``boundary``; there is no second
chunking rule. docs/CUTOVER.md §3.
"""
from .crypto import h

CUT = 64  # home-leaf density: the knee where a whole fetch goes
          # bandwidth-bound (docs/COSTS.md §6)


def key(fact):
    """Canonical sort key "<ts:015d>:<fid>"."""
    return key_parts(fact.ts, fact.fid)


def key_parts(ts, fid):
    """Canonical key from an index row, without loading the fact body."""
    return f"{ts:015d}:{fid}"


def fid_of(k):
    """Inverse projection: the fid inside a key."""
    return k.rsplit(":", 1)[1]


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
