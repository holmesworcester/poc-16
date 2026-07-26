"""Grow-only removal index: range-kill head + target-keyed points.

One entry per removal fact, spanning the fact-tree keys its victims occupy:
a single-target deletion spans its victim's exact key and sorts to the
victim's position; a channel kill spans ``("", "~")`` and sorts to the head.
Spans are routing only — over-approximation is safe, under-approximation is
the one forbidden failure — and ``applies`` decides actual matches. Readers
take the head plus the slice for their range; the index syncs whole while
small and never shrinks. Plan of record: docs/REMOVALS.md.
"""
from typing import NamedTuple

from .suppression import TARGET, is_deletion, suppkey

HEAD = ("", "~")


class Entry(NamedTuple):
    """One removal's routing span over fact-tree target keys, closed."""
    lo: str
    hi: str
    fid: str


def entry(fact, key_of):
    """Derive the canonical entry for one removal fact (author-side only).

    Point removals span exactly ``key_of(target)``; kills span ``HEAD``.
    Raises for non-deletions and for facts without exactly one death marker.
    """
    raise NotImplementedError


def entry_key(e):
    """Total sort order ``"<lo>|<fid>"``; head entries sort first."""
    raise NotImplementedError


def overlapping(entries, lo, hi):
    """Head plus the point slice for the closed target range ``[lo, hi]``."""
    raise NotImplementedError


def applies(removal, fact):
    """Whether ``removal`` suppresses ``fact``; never True for removals (I2)."""
    raise NotImplementedError


def admit(e, removal):
    """Per-entry admission: span integrity (I6), one death marker (I3)."""
    raise NotImplementedError


def encode(entries, facts, emit):
    """Settle the index: sorted entry table, removal closures by ref (I3)."""
    raise NotImplementedError


def decode(raw):
    """Read back ``(entries, refs)`` with integrity checks."""
    raise NotImplementedError


def fingerprint(entries):
    """Set identity over sorted entry keys, published beside the oid (I4)."""
    raise NotImplementedError
