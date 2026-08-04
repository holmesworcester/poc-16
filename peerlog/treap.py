"""Peer-local (ts, fid) treap over resident facts.

Derived state, never shared or stored remotely: the shared-manifest
contention that killed the original walk on the passive store cannot
recur here. History-independent shape — identical resident sets yield
identical fingerprints regardless of arrival order — so two honest
peers with equal coverage prune in one comparison.
"""
import hashlib
from dataclasses import dataclass

from core.limits import PAGE_BATCH
from core.shape import FACT_TS_MAX, FACT_TS_MIN, valid_fid

from .coverage import Coverage, allows


_EMPTY = hashlib.sha256(b"peerlog/treap/empty/v1").digest()


def _valid_ts(value):
    return type(value) is int and FACT_TS_MIN <= value <= FACT_TS_MAX


def _valid_fid_bytes(value):
    if not isinstance(value, bytes):
        return False
    try:
        return valid_fid(value.decode("ascii"))
    except UnicodeError:
        return False


def _entry_bytes(ts, fact_id):
    return ts.to_bytes(8, "big") + fact_id


@dataclass
class _Node:
    ts: int
    fact_id: bytes
    priority: bytes
    left: "_Node | None" = None
    right: "_Node | None" = None


def _root_hash(entries):
    """Merkle root of the canonical Cartesian treap for sorted entries.

    This is the reusable core of the pre-forest treap: content-derived
    priority makes the shape independent of insertion order. Rebuilding this
    small in-memory view is intentional for the first phase; stable page
    persistence can use the same node hash without changing the fingerprint.
    """
    if not entries:
        return _EMPTY
    stack = []
    for ts, fact_id in entries:
        encoded = _entry_bytes(ts, fact_id)
        node = _Node(
            ts,
            fact_id,
            hashlib.sha256(b"peerlog/treap/priority/v1" + encoded).digest(),
        )
        previous = None
        while stack and (stack[-1].priority, stack[-1].ts,
                         stack[-1].fact_id) < (node.priority, ts, fact_id):
            previous = stack.pop()
        node.left = previous
        if stack:
            stack[-1].right = node
        stack.append(node)
    root = stack[0]

    hashes = {}
    todo = [(root, False)]
    while todo:
        node, visited = todo.pop()
        if not visited:
            todo.append((node, True))
            if node.right is not None:
                todo.append((node.right, False))
            if node.left is not None:
                todo.append((node.left, False))
            continue
        left = _EMPTY if node.left is None else hashes[id(node.left)]
        right = _EMPTY if node.right is None else hashes[id(node.right)]
        hashes[id(node)] = hashlib.sha256(
            b"peerlog/treap/node/v1"
            + _entry_bytes(node.ts, node.fact_id)
            + left
            + right
        ).digest()
    return hashes[id(root)]


class Treap:
    def __init__(self):
        self._by_fid = {}

    def insert(self, ts: int, f: bytes) -> None:
        if not _valid_ts(ts) or not _valid_fid_bytes(f):
            raise ValueError("treap fact")
        existing = self._by_fid.get(f)
        if existing is not None and existing != ts:
            raise ValueError("treap fid timestamp")
        self._by_fid[f] = ts

    def fingerprint(self, lo: int, hi: int, coverage: Coverage) -> bytes:
        """Range fingerprint over (ts, fid) in [lo, hi).

        The explicit coverage capability prevents callers from accidentally
        advertising an unheld interval. The walk checks the same claim before
        choosing fingerprint reconciliation; this assertion is the last door.
        """
        if not allows(coverage, lo, hi):
            raise ValueError("uncovered fingerprint")
        return _root_hash(self.members(lo, hi))

    def split_points(self, lo: int, hi: int, k: int) -> tuple[int, ...]:
        """Deterministic member-quantile subdivision of [lo, hi)."""
        if not (_valid_ts(lo) and type(hi) is int
                and lo < hi <= FACT_TS_MAX + 1
                and type(k) is int and 2 <= k <= PAGE_BATCH):
            raise ValueError("treap split")
        timestamps = sorted({ts for ts, _ in self.members(lo, hi)})
        if len(timestamps) < 2:
            return ()
        parts = min(k, len(timestamps))
        points = []
        for part in range(1, parts):
            candidate = timestamps[(part * len(timestamps)) // parts]
            if lo < candidate < hi and (not points or points[-1] != candidate):
                points.append(candidate)
        return tuple(points)

    def members(self, lo: int, hi: int) -> tuple[tuple[int, bytes], ...]:
        """Exact (ts, fid) set of a range — the leaf exchange."""
        if not (_valid_ts(lo) and type(hi) is int
                and lo < hi <= FACT_TS_MAX + 1):
            raise ValueError("treap range")
        return tuple(sorted(
            (ts, fact_id)
            for fact_id, ts in self._by_fid.items()
            if lo <= ts < hi
        ))

    def __len__(self):
        return len(self._by_fid)
