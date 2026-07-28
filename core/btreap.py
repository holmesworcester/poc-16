"""Canonical immutable B-treap pages with bounded authenticated lookup.

Logical rows form the unique Cartesian treap induced by
``priority(layout_seed, key)``.  Four binary treap levels are packed into one
immutable page (at most fifteen rows), so a read authenticates a bounded page
path while equal logical maps always produce byte-identical pages regardless
of insertion history.

This module knows nothing about facts, suppression, or authority.  Those are
three schemas over this one codec.
"""
import json
from dataclasses import dataclass

from .crypto import h
from .fact import canon
from .shape import valid_fid

FORMAT = "btreap-v1"
PAGE_LEVELS = 4
MAX_PAGE_DEPTH = 17
MAX_VALUE_BYTES = 4 * 1024
MAX_PAGE_BYTES = 64 * 1024


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
    return stack[0] if stack else None, len(nodes)


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


def build(rows, seed, emit, *, max_page_depth=MAX_PAGE_DEPTH):
    """Bulk-build the unique tree and emit canonical content-addressed pages."""
    root, count = _logical(tuple(rows), seed)
    if root is None:
        return Built("", 0, 0, 0)
    binary_depth = _binary_depth(root)
    page_depth = (binary_depth + PAGE_LEVELS - 1) // PAGE_LEVELS
    if page_depth > max_page_depth:
        raise ValueError("btreap depth budget")
    pages = 0

    def page(node):
        nonlocal pages

        def inline(item, level):
            if item is None:
                return None
            if level == PAGE_LEVELS:
                return {"page": page(item)}
            return [
                item.key,
                item.value,
                item.priority,
                inline(item.left, level + 1),
                inline(item.right, level + 1),
            ]

        raw = canon({"format": FORMAT, "tree": inline(node, 0)})
        if len(raw) > MAX_PAGE_BYTES:
            raise ValueError("btreap page too large")
        oid = h(raw)
        emitted = emit(raw)
        if emitted is not None and emitted != oid:
            raise ValueError("btreap emitter changed object identity")
        pages += 1
        return oid

    return Built(page(root), count, page_depth, pages)


class Reader:
    """Hash-verifying exact reads; ``items`` is an off-request maintenance API."""

    def __init__(
            self, root, seed, fetch, *, max_page_depth=MAX_PAGE_DEPTH):
        if root and not valid_fid(root):
            raise ValueError("btreap root")
        if not valid_fid(seed):
            raise ValueError("btreap seed")
        self.root = root
        self.seed = seed
        self.fetch = fetch
        self.max_page_depth = max_page_depth
        self.pages_read = 0

    def _page(self, oid):
        if not valid_fid(oid):
            raise ValueError("btreap page ref")
        raw = self.fetch(oid)
        if raw is None or h(raw) != oid:
            raise ValueError("btreap page integrity")
        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("btreap page shape") from exc
        if canon(value) != raw or not isinstance(value, dict) \
                or value.get("format") != FORMAT \
                or set(value) != {"format", "tree"}:
            raise ValueError("btreap page shape")
        self.pages_read += 1
        if self.pages_read > self.max_page_depth:
            raise ValueError("btreap read budget")
        self._validate_inline(value["tree"], None, None, 0)
        return value["tree"]

    def _validate_inline(self, node, lo, hi, level):
        if node is None:
            return
        if level == PAGE_LEVELS:
            if not isinstance(node, dict) or set(node) != {"page"} \
                    or not valid_fid(node["page"]):
                raise ValueError("btreap child ref")
            return
        if not isinstance(node, list) or len(node) != 5:
            raise ValueError("btreap node")
        key, value, claimed, left, right = node
        if not isinstance(key, str) or not key \
                or lo is not None and key <= lo \
                or hi is not None and key >= hi \
                or claimed != priority(self.seed, key) \
                or len(canon(value)) > MAX_VALUE_BYTES:
            raise ValueError("btreap node")
        self._validate_inline(left, lo, key, level + 1)
        self._validate_inline(right, key, hi, level + 1)

    def get(self, key):
        if not isinstance(key, str) or not key:
            raise ValueError("btreap lookup key")
        self.pages_read = 0
        node = self._page(self.root) if self.root else None
        level = 0
        while node is not None:
            if level == PAGE_LEVELS:
                node = self._page(node["page"])
                level = 0
                continue
            row_key, value, _, left, right = node
            if key == row_key:
                return value
            node = left if key < row_key else right
            level += 1
        return None

    def items(self, *, max_pages=None):
        """Decode the full logical map for certification/migration, never Worker."""
        if not self.root:
            return ()
        old_budget = self.max_page_depth
        self.max_page_depth = max_pages or 1_000_000
        self.pages_read = 0
        seen, out = set(), []

        def walk_page(oid):
            if oid in seen:
                raise ValueError("repeated btreap page")
            seen.add(oid)
            walk_inline(self._page(oid), 0)

        def walk_inline(node, level):
            if node is None:
                return
            if level == PAGE_LEVELS:
                walk_page(node["page"])
                return
            key, value, _, left, right = node
            walk_inline(left, level + 1)
            out.append((key, value))
            walk_inline(right, level + 1)

        try:
            walk_page(self.root)
            if any(a[0] >= b[0] for a, b in zip(out, out[1:])):
                raise ValueError("btreap global order")
            return tuple(out)
        finally:
            self.max_page_depth = old_budget


def update(root, seed, changes, fetch, emit):
    """Canonical maintenance update; unchanged page bytes deduplicate at emit."""
    rows = dict(Reader(root, seed, fetch).items()) if root else {}
    for key, value in changes:
        if value is None:
            rows.pop(key, None)
        else:
            rows[key] = value
    return build(tuple(rows.items()), seed, emit)
