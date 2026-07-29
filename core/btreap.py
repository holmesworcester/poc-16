"""Canonical persistent Merkle treap with bounded authenticated lookup.

Each immutable page stores one logical row and two child object ids. Priority
is a pure hash of ``(layout_seed, key)``, so the same map has one tree and one
root regardless of insertion order. Updates rewrite only the search/rotation
path; Workers fetch at most one object per binary level and never rebuild a
database or enumerate the tree.
"""
import json
from dataclasses import dataclass

from .crypto import h
from .fact import canon
from .shape import valid_fid

FORMAT = "btreap-v2"
MAX_PAGE_DEPTH = 128
MAX_VALUE_BYTES = 4 * 1024
MAX_PAGE_BYTES = 8 * 1024


@dataclass
class _Node:
    key: str
    value: object
    priority: str
    left: object = None
    right: object = None


@dataclass(frozen=True)
class Built:
    root: str
    count: int
    page_depth: int
    pages: int


def priority(seed, key):
    if not valid_fid(seed) or not isinstance(key, str):
        raise ValueError("btreap priority input")
    return h(canon([FORMAT, seed, key]))


def _logical(rows, seed):
    ordered = sorted(rows, key=lambda row: row[0])
    if any(
            not isinstance(row, tuple) or len(row) != 2
            or not isinstance(row[0], str) or not row[0]
            for row in ordered):
        raise ValueError("btreap row")
    if any(a[0] >= b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("duplicate btreap key")
    nodes, stack = [], []
    for key, value in ordered:
        if len(canon(value)) > MAX_VALUE_BYTES:
            raise ValueError("btreap value too large")
        node = _Node(key, value, priority(seed, key))
        last = None
        while stack and (node.priority, node.key) < (
                stack[-1].priority, stack[-1].key):
            last = stack.pop()
        node.left = last
        if stack:
            stack[-1].right = node
        stack.append(node)
        nodes.append(node)
    return (stack[0] if stack else None), len(nodes)


def _binary_depth(root):
    depth, stack = 0, [(root, 1)] if root else []
    while stack:
        node, at = stack.pop()
        depth = max(depth, at)
        if node.left:
            stack.append((node.left, at + 1))
        if node.right:
            stack.append((node.right, at + 1))
    return depth


def _raw(key, value, claimed, left, right, count, depth):
    raw = canon({
        "count": count,
        "depth": depth,
        "format": FORMAT,
        "key": key,
        "left": left,
        "priority": claimed,
        "right": right,
        "value": value,
    })
    if len(raw) > MAX_PAGE_BYTES:
        raise ValueError("btreap page too large")
    return raw


def build(rows, seed, emit, *, max_page_depth=MAX_PAGE_DEPTH):
    """Bulk-build the unique tree; every logical node is one immutable page."""
    root, count = _logical(tuple(rows), seed)
    if root is None:
        return Built("", 0, 0, 0)
    depth = _binary_depth(root)
    if depth > max_page_depth:
        raise ValueError("btreap depth budget")
    pages = 0

    def store(node):
        nonlocal pages
        if node is None:
            return "", 0, 0
        left, left_count, left_depth = store(node.left)
        right, right_count, right_depth = store(node.right)
        node_count = 1 + left_count + right_count
        node_depth = 1 + max(left_depth, right_depth)
        raw = _raw(
            node.key, node.value, node.priority, left, right,
            node_count, node_depth)
        oid = h(raw)
        emitted = emit(raw)
        if emitted is not None and emitted != oid:
            raise ValueError("btreap emitter changed object identity")
        pages += 1
        return oid, node_count, node_depth

    root_oid, stored_count, stored_depth = store(root)
    if stored_count != count or stored_depth != depth:
        raise AssertionError("btreap metadata")
    return Built(root_oid, count, depth, pages)


def _decode(raw, oid, seed):
    if raw is None or h(raw) != oid:
        raise ValueError("btreap page integrity")
    try:
        page = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("btreap page shape") from exc
    if canon(page) != raw or not isinstance(page, dict) or set(page) != {
            "count", "depth", "format", "key", "left", "priority", "right",
            "value"} or page["format"] != FORMAT:
        raise ValueError("btreap page shape")
    key = page["key"]
    if not isinstance(key, str) or not key \
            or page["priority"] != priority(seed, key) \
            or not all(
                child == "" or valid_fid(child)
                for child in (page["left"], page["right"])) \
            or type(page["count"]) is not int or page["count"] < 1 \
            or type(page["depth"]) is not int \
            or not 1 <= page["depth"] <= MAX_PAGE_DEPTH \
            or len(canon(page["value"])) > MAX_VALUE_BYTES \
            or len(raw) > MAX_PAGE_BYTES:
        raise ValueError("btreap page shape")
    return page


class Reader:
    """Hash-verifying exact reads; ``items`` is maintenance-only."""

    def __init__(
            self, root, seed, fetch, *, max_page_depth=MAX_PAGE_DEPTH):
        if root and not valid_fid(root):
            raise ValueError("btreap root")
        if not valid_fid(seed) or not 0 <= max_page_depth <= MAX_PAGE_DEPTH:
            raise ValueError("btreap read budget")
        self.root = root
        self.seed = seed
        self.fetch = fetch
        self.max_page_depth = max_page_depth
        self.pages_read = 0
        self._page_budget = max_page_depth

    def _page(self, oid):
        if not valid_fid(oid):
            raise ValueError("btreap page ref")
        self.pages_read += 1
        if self.pages_read > self._page_budget:
            raise ValueError("btreap read budget")
        return _decode(self.fetch(oid), oid, self.seed)

    @staticmethod
    def _ordered(page, lo, hi, parent_priority):
        key = page["key"]
        rank = (page["priority"], key)
        if (lo is not None and key <= lo) \
                or (hi is not None and key >= hi) \
                or (parent_priority is not None and rank < parent_priority):
            raise ValueError("btreap global order")
        return rank

    def get(self, key):
        before, _ = self.neighbors(key)
        return before[1] if before is not None and before[0] == key else None

    def neighbors(self, key):
        """Authenticated rows immediately at/before and at/after ``key``.

        This is the ordered counterpart to ``get``: it follows one bounded
        search path and never enumerates the logical map.
        """
        if not isinstance(key, str) or not key:
            raise ValueError("btreap lookup key")
        self.pages_read = 0
        self._page_budget = self.max_page_depth
        oid, lo, hi, parent = self.root, None, None, None
        before = after = None
        while oid:
            page = self._page(oid)
            rank = self._ordered(page, lo, hi, parent)
            row = (page["key"], page["value"])
            if key == page["key"]:
                return row, row
            if key < page["key"]:
                after = row
                oid, hi = page["left"], page["key"]
            else:
                before = row
                oid, lo = page["right"], page["key"]
            parent = rank
        return before, after

    def items(self, known=None, *, max_pages=None):
        """The complete map, sourcing shared pages from ``known`` locally."""
        known = known or {}
        if not self.root:
            return ()
        self.pages_read = 0
        self._page_budget = max_pages or 1_000_000
        seen, out = set(), []

        def walk(oid, lo, hi, parent, shared=False):
            if not oid:
                return 0, 0
            if oid in seen:
                raise ValueError("repeated btreap page")
            seen.add(oid)
            shared = shared or oid in known
            if shared and oid not in known:
                raise ValueError("incomplete known btreap subtree")
            page = _decode(known[oid], oid, self.seed) \
                if shared else self._page(oid)
            rank = self._ordered(page, lo, hi, parent)
            left_count, left_depth = walk(
                page["left"], lo, page["key"], rank, shared)
            out.append((page["key"], page["value"]))
            right_count, right_depth = walk(
                page["right"], page["key"], hi, rank, shared)
            count = 1 + left_count + right_count
            depth = 1 + max(left_depth, right_depth)
            if page["count"] != count or page["depth"] != depth:
                raise ValueError("btreap page metadata")
            return count, depth

        walk(self.root, None, None, None)
        return tuple(out)


def update(root, seed, changes, fetch, emit):
    """Apply map changes by persistent treap path-copying."""
    cache = {}
    writes = 0

    def load(oid):
        if not oid:
            return None
        if oid not in cache:
            cache[oid] = _decode(fetch(oid), oid, seed)
        return cache[oid]

    def meta(oid):
        page = load(oid)
        return (0, 0) if page is None else (page["count"], page["depth"])

    def store(key, value, left, right):
        nonlocal writes
        left_count, left_depth = meta(left)
        right_count, right_depth = meta(right)
        count = 1 + left_count + right_count
        depth = 1 + max(left_depth, right_depth)
        if depth > MAX_PAGE_DEPTH:
            raise ValueError("btreap depth budget")
        raw = _raw(
            key, value, priority(seed, key), left, right, count, depth)
        oid = h(raw)
        emitted = emit(raw)
        if emitted is not None and emitted != oid:
            raise ValueError("btreap emitter changed object identity")
        cache[oid] = json.loads(raw)
        writes += 1
        return oid

    def split(oid, key):
        if not oid:
            return "", ""
        page = load(oid)
        if key < page["key"]:
            left, middle = split(page["left"], key)
            return left, store(
                page["key"], page["value"], middle, page["right"])
        middle, right = split(page["right"], key)
        return store(
            page["key"], page["value"], page["left"], middle), right

    def merge(left, right):
        if not left:
            return right
        if not right:
            return left
        a, b = load(left), load(right)
        if (a["priority"], a["key"]) < (b["priority"], b["key"]):
            return store(
                a["key"], a["value"], a["left"],
                merge(a["right"], right))
        return store(
            b["key"], b["value"], merge(left, b["left"]), b["right"])

    def insert(oid, key, value):
        if not oid:
            return store(key, value, "", "")
        page = load(oid)
        if key == page["key"]:
            if value == page["value"]:
                return oid
            return store(key, value, page["left"], page["right"])
        if (priority(seed, key), key) < (page["priority"], page["key"]):
            left, right = split(oid, key)
            return store(key, value, left, right)
        if key < page["key"]:
            child = insert(page["left"], key, value)
            if child == page["left"]:
                return oid
            return store(
                page["key"], page["value"], child, page["right"])
        child = insert(page["right"], key, value)
        if child == page["right"]:
            return oid
        return store(page["key"], page["value"], page["left"], child)

    def delete(oid, key):
        if not oid:
            return ""
        page = load(oid)
        if key == page["key"]:
            return merge(page["left"], page["right"])
        if key < page["key"]:
            child = delete(page["left"], key)
            if child == page["left"]:
                return oid
            return store(
                page["key"], page["value"], child, page["right"])
        child = delete(page["right"], key)
        if child == page["right"]:
            return oid
        return store(page["key"], page["value"], page["left"], child)

    current = root
    for key, value in changes:
        if not isinstance(key, str) or not key:
            raise ValueError("btreap row")
        if value is None:
            current = delete(current, key)
        else:
            if len(canon(value)) > MAX_VALUE_BYTES:
                raise ValueError("btreap value too large")
            current = insert(current, key, value)
    if not current:
        return Built("", 0, 0, writes)
    page = load(current)
    return Built(current, page["count"], page["depth"], writes)
