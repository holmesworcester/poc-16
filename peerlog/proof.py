"""Runs: contiguous writer-seq slices with amortized authentication.

One signed head plus boundary inclusion paths authenticate an entire
run; a single carried fact is the degenerate run (~0.7 KB). Verify is
all-or-nothing — one tampered byte rejects the whole run. A run proved
against an older head stays valid: logs are append-only, and a seq
whose bytes differ under two heads is writer equivocation (ingest.py).
"""
from dataclasses import dataclass

from .log import Head, WriterLog


@dataclass(frozen=True)
class Run:
    writer: bytes
    lo: int
    hi: int
    facts: bytes  # canonical slice bytes for [lo, hi)
    head: Head    # any signed head with head.seq >= hi - 1
    paths: tuple[tuple[bytes, ...], ...]  # boundary inclusion paths


def prove_run(log: WriterLog, lo: int, hi: int) -> Run:
    raise NotImplementedError


def verify_run(run: Run) -> bool:
    raise NotImplementedError


def carry(log: WriterLog, seq: int) -> Run:
    """Single-fact run, the universal carry format (Rule 2, thread
    roots, P2P scatter transfer)."""
    raise NotImplementedError
