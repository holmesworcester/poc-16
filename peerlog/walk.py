"""Two-sided closed-range RBSR over GET/PUT.

The b9af34f one-sided walk, symmetric between live peers: conditional
GET of the counterparty's root, prune equal fingerprints, recurse into
unequal ranges, pull missing facts as closed runs, push news the same
way. Diff runs only inside the coverage intersection. A peer that only
serves (never walks) is indistinguishable from the passive store —
clients reuse the same recipes against either.
"""
from typing import Protocol

from .coverage import Coverage
from .proof import Run
from .treap import Treap


class Store(Protocol):
    """The whole transport. Both peers and the cloud expose it."""

    def get(self, key: str, rng: tuple[int, int] | None = None) -> bytes: ...

    def put(self, key: str, val: bytes) -> None: ...


def diff(local: Treap, cov: Coverage, remote: Store) -> tuple[tuple[int, int], ...]:
    """ts-ranges where the sets differ, within the coverage
    intersection; identical sets return () after one conditional GET."""
    raise NotImplementedError


def pull(remote: Store, ranges: tuple[tuple[int, int], ...]) -> tuple[Run, ...]:
    """Fetch missing facts as closed runs, coalesced per writer."""
    raise NotImplementedError


def push(remote: Store, runs: tuple[Run, ...]) -> None:
    """Publish news the counterparty lacks, as closed runs."""
    raise NotImplementedError


def sync(local_state, remote: Store) -> dict:
    """diff -> pull -> ingest -> push; returns a round/byte report the
    bench harness consumes (bench/writer_p2p_cost.py)."""
    raise NotImplementedError
