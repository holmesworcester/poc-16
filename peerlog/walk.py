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
cannot (hence the cloud path is seq-diff). Covered ranges use Merkle
pruning only when the driver holds them completely; all other resident
islands are enumerated exactly.
"""
from dataclasses import dataclass
from typing import Protocol

from core.limits import (
    MAX_MERKLE_PAGE_BYTES,
    MAX_MERKLE_PAGE_DEPTH,
    MAX_ROOT_BYTES,
)

from .coverage import Coverage, allows
from .proof import Run
from .treap import (
    EMPTY,
    Treap,
    _root_hash,
    decode_exact,
    decode_node,
    decode_root,
    snapshot,
)


ROOT_KEY = "peerlog/treap/root"
OBJECT_PREFIX = "peerlog/treap/obj/"


class Store(Protocol):
    """The whole transport. Both peers and the cloud expose it."""

    def get(self, key: str, rng: tuple[int, int] | None = None) -> bytes | None: ...

    def put(self, key: str, val: bytes) -> None: ...


@dataclass(frozen=True)
class Difference:
    """Exact result learned by the sole walker, plus measured wire cost."""

    remote_only: tuple[tuple[int, bytes], ...]
    local_only: tuple[tuple[int, bytes], ...]
    gets: int
    received_bytes: int


class _Reader:
    def __init__(self, store):
        self.store = store
        self.gets = 0
        self.received_bytes = 0

    def get(self, key, maximum):
        raw = self.store.get(key)
        self.gets += 1
        if not isinstance(raw, bytes):
            raise ValueError("missing treap object")
        if len(raw) > maximum:
            raise ValueError("oversized treap object")
        self.received_bytes += len(raw)
        return raw


def publish(local: Treap, cov: Coverage, store: Store) -> bytes:
    """PUT immutable pages first, then replace the responder's root.

    Page PUTs are idempotent because their key is the digest of their bytes.
    A responder can therefore rebuild after a crash without a mutable page
    manifest, and a root reader never observes references that were not sent.
    """
    built = snapshot(local, cov)
    for oid, raw in built.objects:
        store.put(OBJECT_PREFIX + oid.hex(), raw)
    store.put(ROOT_KEY, built.root)
    return built.root


def diff_entries(local: Treap, cov: Coverage, remote: Store) -> Difference:
    """Run the one-sided page walk and return the symmetric difference."""
    if not isinstance(local, Treap) or not isinstance(cov, Coverage):
        raise ValueError("treap diff")
    reader = _Reader(remote)
    remote_root = decode_root(reader.get(ROOT_KEY, MAX_ROOT_BYTES))
    remote_only = set()
    local_only = set()

    for lo, hi, oid in remote_root.covered:
        local_rows = local.members(lo, hi)
        if allows(cov, lo, hi):
            _walk(
                reader, oid, local_rows, remote_only, local_only, set(),
                (lo, b""), (hi, b""), 0,
            )
        else:
            remote_rows = set(_read_all(
                reader, oid, set(), (lo, b""), (hi, b""), 0))
            local_rows = set(local_rows)
            remote_only.update(remote_rows - local_rows)
            local_only.update(local_rows - remote_rows)

    # The responder's coverage and exact islands partition its whole set.
    # Compare the complement exactly, regardless of the driver's own claim.
    remote_islands = set()
    previous = None
    for oid in remote_root.islands:
        raw = reader.get(OBJECT_PREFIX + oid.hex(), MAX_MERKLE_PAGE_BYTES)
        rows = decode_exact(raw, oid)
        if previous is not None and rows[0] <= previous \
                or any(
                    lo <= ts < hi
                    for ts, _ in rows
                    for lo, hi in remote_root.coverage.ranges):
            raise ValueError("treap island partition")
        previous = rows[-1]
        remote_islands.update(rows)
    local_islands = {
        row for row in local.entries()
        if not any(lo <= row[0] < hi for lo, hi in remote_root.coverage.ranges)
    }
    remote_only.update(remote_islands - local_islands)
    local_only.update(local_islands - remote_islands)

    return Difference(
        tuple(sorted(remote_only)),
        tuple(sorted(local_only)),
        reader.gets,
        reader.received_bytes,
    )


def _walk(
        reader, oid, local_rows, remote_only, local_only, seen,
        lower, upper, depth):
    local_oid = _root_hash(local_rows)
    if oid == local_oid:
        return
    if oid == EMPTY:
        local_only.update(local_rows)
        return
    if oid in seen:
        raise ValueError("treap page cycle")
    if depth >= MAX_MERKLE_PAGE_DEPTH:
        raise ValueError("treap page depth")
    seen.add(oid)
    raw = reader.get(OBJECT_PREFIX + oid.hex(), MAX_MERKLE_PAGE_BYTES)
    ts, fact_id, left, right = decode_node(raw, oid)
    key = (ts, fact_id)
    if not lower < key < upper:
        raise ValueError("treap page order")
    before = tuple(row for row in local_rows if row < key)
    after = tuple(row for row in local_rows if row > key)
    if key not in local_rows:
        remote_only.add(key)
    _walk(
        reader, left, before, remote_only, local_only, seen,
        lower, key, depth + 1,
    )
    _walk(
        reader, right, after, remote_only, local_only, seen,
        key, upper, depth + 1,
    )


def _read_all(reader, oid, seen, lower, upper, depth):
    if oid == EMPTY:
        return ()
    if oid in seen:
        raise ValueError("treap page cycle")
    if depth >= MAX_MERKLE_PAGE_DEPTH:
        raise ValueError("treap page depth")
    seen.add(oid)
    raw = reader.get(OBJECT_PREFIX + oid.hex(), MAX_MERKLE_PAGE_BYTES)
    ts, fact_id, left, right = decode_node(raw, oid)
    key = (ts, fact_id)
    if not lower < key < upper:
        raise ValueError("treap page order")
    return (
        *_read_all(reader, left, seen, lower, key, depth + 1),
        key,
        *_read_all(reader, right, seen, key, upper, depth + 1),
    )


def diff(local: Treap, cov: Coverage, remote: Store) -> tuple[tuple[int, int], ...]:
    """Timestamp windows containing either side of the exact difference.

    Fully covered remote intervals use fingerprints; intervals the driver
    does not fully cover and all responder islands are exchanged exactly.
    Equal roots return after the single current-root GET.
    """
    result = diff_entries(local, cov, remote)
    changed = {
        ts for ts, _ in (
            *result.remote_only,
            *result.local_only,
        )
    }
    ranges = []
    for ts in sorted(changed):
        if ranges and ranges[-1][1] == ts:
            ranges[-1] = (ranges[-1][0], ts + 1)
        else:
            ranges.append((ts, ts + 1))
    return tuple(ranges)


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
