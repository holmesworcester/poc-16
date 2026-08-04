"""Coverage honesty: fingerprint only what you fully hold.

A peer declares half-open ts-ranges it fully holds. Fingerprinting an
unheld range lies to the counterparty and silently breaks convergence,
so the walk refuses it by construction — islands are excluded from
fingerprinting and exchanged as exact sets instead.
"""
from dataclasses import dataclass

from core.shape import FACT_TS_MAX, FACT_TS_MIN


TS_STOP = FACT_TS_MAX + 1


@dataclass(frozen=True)
class Coverage:
    """Canonical disjoint half-open timestamp ranges held completely."""

    ranges: tuple[tuple[int, int], ...]

    def __post_init__(self):
        previous_hi = None
        for item in self.ranges:
            if not (isinstance(item, tuple) and len(item) == 2):
                raise ValueError("coverage range")
            lo, hi = item
            if not (_valid_bound(lo) and _valid_bound(hi) and lo < hi):
                raise ValueError("coverage range")
            # Adjacent intervals have one canonical representation: merged.
            if previous_hi is not None and lo <= previous_hi:
                raise ValueError("coverage order")
            previous_hi = hi


def _valid_bound(value):
    return type(value) is int and FACT_TS_MIN <= value <= TS_STOP


def _append(ranges, lo, hi):
    if ranges and ranges[-1][1] == lo:
        ranges[-1] = (ranges[-1][0], hi)
    else:
        ranges.append((lo, hi))


def intersect(a: Coverage, b: Coverage) -> Coverage:
    """Return the canonical intersection without widening either claim."""
    if not isinstance(a, Coverage) or not isinstance(b, Coverage):
        raise ValueError("coverage")
    out = []
    ai = bi = 0
    while ai < len(a.ranges) and bi < len(b.ranges):
        alo, ahi = a.ranges[ai]
        blo, bhi = b.ranges[bi]
        lo, hi = max(alo, blo), min(ahi, bhi)
        if lo < hi:
            _append(out, lo, hi)
        if ahi <= bhi:
            ai += 1
        if bhi <= ahi:
            bi += 1
    return Coverage(tuple(out))


def allows(cov: Coverage, lo: int, hi: int) -> bool:
    """True iff [lo, hi) lies entirely inside declared coverage."""
    if not isinstance(cov, Coverage) \
            or not (_valid_bound(lo) and _valid_bound(hi) and lo < hi):
        return False
    return any(start <= lo and hi <= stop for start, stop in cov.ranges)
