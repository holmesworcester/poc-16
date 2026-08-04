"""Coverage honesty: fingerprint only what you fully hold.

A peer declares closed ts-ranges it fully holds. Fingerprinting an
unheld range lies to the counterparty and silently breaks convergence,
so the walk refuses it by construction — islands are excluded from
fingerprinting and exchanged as exact sets instead.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Coverage:
    ranges: tuple[tuple[int, int], ...]  # disjoint, sorted, closed ts-ranges


def intersect(a: Coverage, b: Coverage) -> Coverage:
    raise NotImplementedError


def allows(cov: Coverage, lo: int, hi: int) -> bool:
    """True iff [lo, hi) lies entirely inside declared coverage."""
    raise NotImplementedError
