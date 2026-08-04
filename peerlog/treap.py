"""Peer-local (ts, fid) treap over resident facts.

Derived state, never shared or stored remotely: the shared-manifest
contention that killed the original walk on the passive store cannot
recur here. History-independent shape — identical resident sets yield
identical fingerprints regardless of arrival order — so two honest
peers with equal coverage prune in one comparison.
"""


class Treap:
    def insert(self, ts: int, f: bytes) -> None:
        raise NotImplementedError

    def fingerprint(self, lo: int, hi: int) -> bytes:
        """Range fingerprint over (ts, fid) in [lo, hi). The caller
        must hold full coverage of the range (coverage.allows); the
        walk enforces it, this asserts it."""
        raise NotImplementedError

    def split_points(self, lo: int, hi: int, k: int) -> tuple[int, ...]:
        """Deterministic k-way subdivision of [lo, hi) for recursion."""
        raise NotImplementedError

    def members(self, lo: int, hi: int) -> tuple[tuple[int, bytes], ...]:
        """Exact (ts, fid) set of a range — the leaf exchange."""
        raise NotImplementedError
