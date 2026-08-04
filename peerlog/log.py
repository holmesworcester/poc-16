"""One dense append-only canonical stream per writer.

Density is the availability contract: a head at seq h promises every
seq <= h exists, so slices have no holes and located refs below a
stored head cannot fail to resolve. A local WriterLog may be a dense
suffix (one's own log), or islands (a foreign writer hydrated by chase
or RBSR); coverage() is the honest statement of which.
"""
from dataclasses import dataclass

from .fact import Fact


@dataclass(frozen=True)
class Head:
    writer: bytes
    seq: int
    root: bytes          # seq-tree root over the whole log (tree.py)
    control_root: bytes  # control-subsequence tree root
    sig: bytes


class WriterLog:
    def append(self, fact: Fact) -> int:
        """Own-log only; returns the assigned seq."""
        raise NotImplementedError

    def slice(self, lo: int, hi: int) -> bytes:
        """Canonical bytes for seqs [lo, hi); raises on any gap."""
        raise NotImplementedError

    def coverage(self) -> tuple[tuple[int, int], ...]:
        """Contiguous (lo, hi) seq intervals held locally."""
        raise NotImplementedError

    def head(self) -> Head:
        """Latest signed head observed (own log: latest published)."""
        raise NotImplementedError
