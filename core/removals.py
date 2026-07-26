"""Grow-only removal index: range-kill head + target-keyed points.

One entry per removal fact, spanning the fact-tree keys its victims occupy:
a single-target deletion spans its victim's exact key and sorts to the
victim's position; a channel kill spans ``("", "~")`` and sorts to the head.
Spans are routing only — over-approximation is safe, under-approximation is
the one forbidden failure — and ``applies`` decides actual matches. Readers
take the head plus the slice for their range; the index syncs whole while
small and never shrinks. Plan of record: docs/REMOVALS.md.
"""
import json
from bisect import bisect_left, bisect_right
from typing import NamedTuple

from . import shape
from .crypto import h
from .fact import canon
from .suppression import TARGET, is_deletion, suppkey

HEAD = ("", "~")

# The join byte ranks below every character a fact key can hold (digits, ':',
# hex), so the empty ``lo`` of a head entry sorts first. A literal '|' (0x7C)
# would sort it last — the format, not the order, gives way (REMOVALS.md §2).
JOIN = "\0"


class Entry(NamedTuple):
    """One removal's routing span over fact-tree target keys, closed."""
    lo: str
    hi: str
    fid: str


def _target(removal):
    """The single explicit victim ref, or None for a kill (or an ambiguous
    multi-target removal, whose honest span is then the head)."""
    targets = [fid for name, fid in removal.refs() if name == TARGET]
    return targets[0] if len(targets) == 1 else None


def entry(fact, key_of):
    """Derive the canonical entry for one removal fact (author-side only).

    Point removals span exactly ``key_of(target)``; kills span ``HEAD``.
    Raises for non-deletions, which by ``_marker`` includes a fact carrying
    0 or 2+ death markers — the I3 admission rule, not a silent collapse.
    """
    if not is_deletion(fact):
        raise ValueError("not a removal")
    target = _target(fact)
    if target is None:
        return Entry(*HEAD, fact.fid)
    key = key_of(target)
    return Entry(key, key, fact.fid)


def entry_key(e):
    """Total sort order ``"<lo>" + JOIN + "<fid>"``; head entries sort
    first (REMOVALS.md §2 writes the join as '|', which would sort them
    last — the format gives way, the order does not)."""
    return f"{e.lo}{JOIN}{e.fid}"


def overlapping(entries, lo, hi):
    """Head plus the point slice for the closed target range ``[lo, hi]``."""
    # Sorting normalizes any caller's table (linear on decode's, already in
    # order); the answer is then one contiguous run, never a per-key probe.
    ordered = sorted(entries, key=entry_key)
    los = [e.lo for e in ordered]
    head = bisect_right(los, HEAD[0])
    start = max(bisect_left(los, lo), head)
    return tuple(ordered[:head]) + tuple(ordered[start:bisect_right(los, hi)])


def applies(removal, fact):
    """Whether ``removal`` suppresses ``fact``; never True for removals (I2).

    A point removal matches its target fid and nothing else; only a kill
    matches a whole suppression group. The gate is what keeps the victim set
    inside the span ``entry`` derives: a point span is one key, so a
    group-matching point removal would under-approximate — the one forbidden
    failure (I6), and suppression would then depend on where the leaf cut
    fell. REMOVALS.md §2's one-line formula omits the gate; §2's own point
    spans, I6, §3.3 and node.apply_removals all require it.
    """
    if is_deletion(fact):
        return False
    target = _target(removal)
    if target is not None:
        return target == fact.fid
    group = suppkey(fact)
    return group is not None and group == suppkey(removal)


def admit(e, removal):
    """Per-entry admission: span integrity (I6), one death marker (I3)."""
    if not is_deletion(removal) or e.fid != removal.fid:
        return False
    if (e.lo, e.hi) == HEAD:
        return True
    target = _target(removal)
    return (e.lo == e.hi and ":" in e.lo and target is not None
            and shape.fid_of(e.lo) == target)


def encode(entries, facts, emit):
    """Settle the index: sorted entry table plus the removal closures' fact
    keys, sorted and deduplicated — refs, never an inlined pile (I3).

    The ref is a ``shape.key``, not a body oid: a fact's bytes live once, in
    its home leaf's pile, and every cross-leaf need is a ref by key (CUTOVER
    §1, §3's address-form row), so the reader resolves a ref through
    ``manifest.locate``/``fetch_plan`` — the same two-wave path closure
    siblings use. The index object is the only object this emits.
    """
    raw = canon({
        "entries": [list(e) for e in sorted(entries, key=entry_key)],
        "refs": sorted({shape.key(fact) for fact in facts}),
    })
    emit(raw)
    return h(raw)


def decode(raw):
    """Read back ``(entries, refs)`` with integrity checks."""
    obj = json.loads(raw)
    if not isinstance(obj, dict) or set(obj) != {"entries", "refs"}:
        raise ValueError("removal index shape")
    rows, refs = obj["entries"], obj["refs"]
    if not isinstance(rows, list) or not isinstance(refs, list) \
            or not all(isinstance(ref, str) and ref for ref in refs) \
            or sorted(set(refs)) != refs \
            or not all(
                isinstance(row, list) and len(row) == 3
                and all(isinstance(part, str) for part in row)
                and row[0] <= row[1] for row in rows):
        raise ValueError("removal index shape")
    entries = tuple(Entry(*row) for row in rows)
    keys = [entry_key(e) for e in entries]
    if keys != sorted(keys) or len(set(keys)) != len(entries) \
            or len({e.fid for e in entries}) != len(entries):
        raise ValueError("removal index order")
    return entries, tuple(refs)


def fingerprint(entries):
    """Set identity over sorted entry keys, published beside the oid (I4)."""
    return shape.fingerprint(sorted(entry_key(e) for e in entries))
