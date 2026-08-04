"""Per-writer seq tree: verification and time cuts.

Deterministic pages summarize (seq range, ts-min, ts-max, hash); the
root is what a head signs. The ts rows allow one-sided time-window
cuts without interpreting ts. In phase 2 the frozen pages ride in
object footers; here they are what inclusion proofs traverse.
"""
from .log import Head, WriterLog


def root(log: WriterLog) -> bytes:
    raise NotImplementedError


def pages(log: WriterLog) -> tuple[bytes, ...]:
    """Deterministic page encoding for the current log."""
    raise NotImplementedError


def inclusion(log: WriterLog, seq: int) -> tuple[bytes, ...]:
    """Sibling-hash path proving the fact at seq against root(log)."""
    raise NotImplementedError


def verify_inclusion(head: Head, seq: int, fact_bytes: bytes,
                     path: tuple[bytes, ...]) -> bool:
    raise NotImplementedError


def ts_cut(page_bytes: tuple[bytes, ...], t0: int, t1: int) -> tuple[tuple[int, int], ...]:
    """Seq intervals whose ts summaries intersect [t0, t1)."""
    raise NotImplementedError
