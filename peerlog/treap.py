"""Peer-local (ts, fid) treap over resident facts.

Derived state, never shared or stored remotely: the shared-manifest
contention that killed the original walk on the passive store cannot
recur here. History-independent shape — identical resident sets yield
identical fingerprints regardless of arrival order — so two honest
peers with equal coverage prune in one comparison.
"""
import hashlib
from dataclasses import dataclass

from core.fact import canon
from core.limits import (
    MAX_MERKLE_PAGE_BYTES,
    MAX_ROOT_BYTES,
    PAGE_BATCH,
    decode_json,
)
from core.shape import FACT_TS_MAX, FACT_TS_MIN, valid_fid

from .coverage import Coverage, allows


EMPTY = hashlib.sha256(b"peerlog/treap/empty/v1").digest()
NODE_FORMAT = "peerlog-treap-node-v1"
EXACT_FORMAT = "peerlog-treap-exact-v1"
ROOT_FORMAT = "peerlog-treap-root-v1"


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


@dataclass(frozen=True)
class Snapshot:
    """One immutable page set plus the current-root document that names it."""

    root: bytes
    objects: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class Root:
    coverage: Coverage
    covered: tuple[tuple[int, int, bytes], ...]
    islands: tuple[bytes, ...]


def _node_bytes(node, left, right):
    return canon([
        NODE_FORMAT,
        node.ts,
        node.fact_id.decode("ascii"),
        left.hex(),
        right.hex(),
    ])


def _page_tree(entries):
    """Return (root, immutable pages) for one sorted entry interval.

    This is the reusable core of the pre-forest treap: content-derived
    priority makes the shape independent of insertion order. Rebuilding this
    in-memory view does not rewrite stable pages: every node's canonical bytes
    are addressed by their own digest, so unchanged subtrees retain identity.
    """
    if not entries:
        return EMPTY, {}
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
    objects = {}
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
        left = EMPTY if node.left is None else hashes[id(node.left)]
        right = EMPTY if node.right is None else hashes[id(node.right)]
        raw = _node_bytes(node, left, right)
        if len(raw) > MAX_MERKLE_PAGE_BYTES:
            raise ValueError("treap node too large")
        oid = hashlib.sha256(raw).digest()
        hashes[id(node)] = oid
        objects[oid] = raw
    return hashes[id(root)], objects


def _root_hash(entries):
    return _page_tree(entries)[0]


def _exact_bytes(entries):
    raw = canon([
        EXACT_FORMAT,
        [[ts, fact_id.decode("ascii")] for ts, fact_id in entries],
    ])
    if len(raw) > MAX_MERKLE_PAGE_BYTES:
        raise ValueError("treap exact page too large")
    return raw


def _in_coverage(coverage, ts):
    return any(lo <= ts < hi for lo, hi in coverage.ranges)


def snapshot(tree, coverage):
    """Build the stable served view for one ingest snapshot.

    Covered intervals receive independently fingerprintable treap roots.
    Resident rows outside those claims are paged as exact islands; their
    absence is never summarized by a fingerprint.
    """
    if not isinstance(tree, Treap) or not isinstance(coverage, Coverage):
        raise ValueError("treap snapshot")
    objects = {}
    covered = []
    for lo, hi in coverage.ranges:
        oid, pages = _page_tree(tree.members(lo, hi))
        objects.update(pages)
        covered.append([lo, hi, oid.hex()])

    island_rows = tuple(
        row for row in tree.entries()
        if not _in_coverage(coverage, row[0])
    )
    islands = []
    for offset in range(0, len(island_rows), PAGE_BATCH):
        raw = _exact_bytes(island_rows[offset:offset + PAGE_BATCH])
        oid = hashlib.sha256(raw).digest()
        objects[oid] = raw
        islands.append(oid.hex())
    root = canon({
        "covered": covered,
        "format": ROOT_FORMAT,
        "islands": islands,
    })
    if len(root) > MAX_ROOT_BYTES:
        raise ValueError("treap root too large")
    return Snapshot(root, tuple(sorted(objects.items())))


def decode_root(raw):
    value = decode_json(raw, MAX_ROOT_BYTES, "treap root")
    if not isinstance(value, dict) or set(value) != {
            "covered", "format", "islands"} \
            or value.get("format") != ROOT_FORMAT or canon(value) != raw \
            or not isinstance(value.get("covered"), list) \
            or not isinstance(value.get("islands"), list):
        raise ValueError("treap root")
    ranges = []
    covered = []
    for item in value["covered"]:
        if not isinstance(item, list) or len(item) != 3:
            raise ValueError("treap root")
        lo, hi, encoded = item
        oid = _decode_oid(encoded)
        ranges.append((lo, hi))
        covered.append((lo, hi, oid))
    coverage = Coverage(tuple(ranges))
    islands = tuple(_decode_oid(item) for item in value["islands"])
    if len(set(islands)) != len(islands):
        raise ValueError("treap root")
    return Root(coverage, tuple(covered), islands)


def decode_node(raw, oid):
    _verify_object(raw, oid, "treap node")
    value = decode_json(raw, MAX_MERKLE_PAGE_BYTES, "treap node")
    if not isinstance(value, list) or len(value) != 5 \
            or value[0] != NODE_FORMAT or canon(value) != raw \
            or not _valid_ts(value[1]):
        raise ValueError("treap node")
    try:
        fact_id = value[2].encode("ascii")
    except (AttributeError, UnicodeError):
        raise ValueError("treap node") from None
    if not _valid_fid_bytes(fact_id):
        raise ValueError("treap node")
    return value[1], fact_id, _decode_oid(value[3]), _decode_oid(value[4])


def decode_exact(raw, oid):
    _verify_object(raw, oid, "treap exact page")
    value = decode_json(raw, MAX_MERKLE_PAGE_BYTES, "treap exact page")
    if not isinstance(value, list) or len(value) != 2 \
            or value[0] != EXACT_FORMAT or canon(value) != raw \
            or not isinstance(value[1], list) \
            or len(value[1]) > PAGE_BATCH:
        raise ValueError("treap exact page")
    rows = []
    for item in value[1]:
        if not isinstance(item, list) or len(item) != 2 \
                or not _valid_ts(item[0]):
            raise ValueError("treap exact page")
        try:
            fact_id = item[1].encode("ascii")
        except (AttributeError, UnicodeError):
            raise ValueError("treap exact page") from None
        if not _valid_fid_bytes(fact_id):
            raise ValueError("treap exact page")
        rows.append((item[0], fact_id))
    rows = tuple(rows)
    if not rows or tuple(sorted(set(rows))) != rows:
        raise ValueError("treap exact page")
    return rows


def _decode_oid(value):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("treap object id")
    try:
        oid = bytes.fromhex(value)
    except ValueError:
        raise ValueError("treap object id") from None
    if value != oid.hex():
        raise ValueError("treap object id")
    return oid


def _verify_object(raw, oid, label):
    if not isinstance(raw, bytes) or not isinstance(oid, bytes) \
            or len(oid) != 32 or hashlib.sha256(raw).digest() != oid:
        raise ValueError(f"{label} integrity")


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

    def entries(self) -> tuple[tuple[int, bytes], ...]:
        """The exact resident set, in reconciliation-key order."""
        return tuple(sorted((ts, fact_id) for fact_id, ts in self._by_fid.items()))

    def __len__(self):
        return len(self._by_fid)
