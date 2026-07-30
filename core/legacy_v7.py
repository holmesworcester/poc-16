"""Read-only decoder for the one v7 B-treap cutover.

No current root, Worker, publisher, or query may import this module.  It
exists only so the explicit v7 -> current rebuild can recover old RangeTree
rows before republishing them through :mod:`core.merkle_map`.  In particular
there is deliberately no legacy build or update implementation.
"""
import json

from .crypto import h
from .fact import canon
from .shape import valid_fid

FORMAT = "btreap-v2"
MAX_PAGE_DEPTH = 128
MAX_VALUE_BYTES = 4 * 1024
MAX_PAGE_BYTES = 8 * 1024


def _priority(seed, key):
    if not valid_fid(seed) or not isinstance(key, str):
        raise ValueError("legacy v7 priority input")
    return h(canon([FORMAT, seed, key]))


def _decode(raw, oid, seed):
    if not isinstance(raw, bytes) or len(raw) > MAX_PAGE_BYTES \
            or h(raw) != oid:
        raise ValueError("legacy v7 page integrity")
    try:
        page = json.loads(raw)
        if canon(page) != raw or not isinstance(page, dict) or set(page) != {
                "count", "depth", "format", "key", "left", "priority",
                "right", "value"} or page["format"] != FORMAT:
            raise ValueError("legacy v7 page shape")
        key = page["key"]
        if not isinstance(key, str) or not key \
                or page["priority"] != _priority(seed, key) \
                or not all(
                    child == "" or valid_fid(child)
                    for child in (page["left"], page["right"])) \
                or type(page["count"]) is not int or page["count"] < 1 \
                or type(page["depth"]) is not int \
                or not 1 <= page["depth"] <= MAX_PAGE_DEPTH \
                or len(canon(page["value"])) > MAX_VALUE_BYTES:
            raise ValueError("legacy v7 page shape")
        return page
    except (TypeError, ValueError, RecursionError) as error:
        if isinstance(error, ValueError) \
                and str(error).startswith("legacy v7"):
            raise
        raise ValueError("legacy v7 page shape") from error


class Reader:
    """Strict finite decoder used only by the format-cutover coordinator."""

    def __init__(self, root, seed, fetch, *, max_pages):
        if not valid_fid(root) or not valid_fid(seed) \
                or type(max_pages) is not int or max_pages < 1:
            raise ValueError("legacy v7 read budget")
        self.root = root
        self.seed = seed
        self.fetch = fetch
        self.max_pages = max_pages
        self.pages_read = 0

    def _page(self, oid):
        if not valid_fid(oid):
            raise ValueError("legacy v7 page ref")
        self.pages_read += 1
        if self.pages_read > self.max_pages:
            raise ValueError("legacy v7 read budget")
        return _decode(self.fetch(oid), oid, self.seed)

    @staticmethod
    def _ordered(page, lo, hi, parent_priority):
        key = page["key"]
        rank = (page["priority"], key)
        if (lo is not None and key <= lo) \
                or (hi is not None and key >= hi) \
                or (parent_priority is not None and rank < parent_priority):
            raise ValueError("legacy v7 global order")
        return rank

    def items(self):
        seen, out = set(), []

        def walk(oid, lo, hi, parent):
            if not oid:
                return 0, 0
            if oid in seen:
                raise ValueError("repeated legacy v7 page")
            seen.add(oid)
            page = self._page(oid)
            rank = self._ordered(page, lo, hi, parent)
            left_count, left_depth = walk(
                page["left"], lo, page["key"], rank)
            out.append((page["key"], page["value"]))
            right_count, right_depth = walk(
                page["right"], page["key"], hi, rank)
            count = 1 + left_count + right_count
            depth = 1 + max(left_depth, right_depth)
            if page["count"] != count or page["depth"] != depth:
                raise ValueError("legacy v7 page metadata")
            return count, depth

        walk(self.root, None, None, None)
        return tuple(out)
