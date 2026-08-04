"""One-sided closed-range RBSR over GET/PUT: driver and server.

The b9af34f walk between live peers. The DRIVER — the session
initiator; simultaneous dials collapse to one session, lower endpoint
id drives — walks the responder's served pages: conditional GET of the
root, prune equal fingerprints, recurse unequal ranges, and read the
symmetric difference off the leaf pages, which tells it both what it
lacks (pull) and what the responder lacks (push). One session moves
news both ways; the responder runs zero walk logic. It serves stable
self-addressed treap pages (maintained incrementally at its own ingest
time) and verifies pushed runs — indistinguishable from the passive
store except that it maintains its own pages, which the passive cloud
cannot (hence the cloud path is seq-diff). Diff runs only inside the
coverage intersection.
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
    """Driver side, one session: diff -> pull -> ingest -> push;
    returns a round/byte report the bench harness consumes
    (bench/writer_p2p_cost.py). The remote never walks."""
    raise NotImplementedError
