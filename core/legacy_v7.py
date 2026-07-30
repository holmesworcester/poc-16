"""Read-only decoder for the one v7 B-treap cutover.

No current root, Worker, publisher, or query may import this module.  It
exists only so the explicit v7 -> current rebuild can recover old RangeTree
rows before republishing them through :mod:`core.merkle_map`.  In particular
there is deliberately no legacy build or update implementation.
"""
import json
from typing import NamedTuple

from .crypto import h
from .fact import canon
from .limits import MAX_ROOT_BYTES, decode_json
from .shape import is_key, valid_fid

FORMAT = "btreap-v2"
LAYOUT = "composite-btreap-v7-generic-candidate-index"
MAX_PAGE_DEPTH = 128
MAX_VALUE_BYTES = 4 * 1024
MAX_PAGE_BYTES = 8 * 1024
MAX_ROWS = 1_000_000
TREE_NAMES = ("fact", "supp", "authority")
RANGE_SEED = h(canon(["range-tree-v1"]))
CUT = 64


class Root(NamedTuple):
    anchor: str
    manifest: str
    layout_seed: str
    trees: dict
    action_etag: str


class RangeEntry(NamedTuple):
    sep: str
    leaf: str
    closure: str


def _trees_ok(trees):
    return isinstance(trees, dict) and set(trees) == set(TREE_NAMES) \
        and all(
            isinstance(value, dict)
            and set(value) == {"root", "count", "depth"}
            and isinstance(value["root"], str)
            and (not value["root"] or valid_fid(value["root"]))
            and type(value["count"]) is int and value["count"] >= 0
            and type(value["depth"]) is int
            and 0 <= value["depth"] <= MAX_PAGE_DEPTH
            and bool(value["root"]) == bool(value["count"])
            for value in trees.values()
        )


def decode_root(raw):
    """Decode only the immediately preceding production root format."""
    value = decode_json(raw, MAX_ROOT_BYTES, "legacy v7 root")
    if not isinstance(value, dict) or set(value) != {
            "action_etag", "anchor", "layout_seed", "manifest", "stamp",
            "trees"} \
            or value.get("stamp") != LAYOUT \
            or not valid_fid(value.get("action_etag")) \
            or not valid_fid(value.get("anchor")) \
            or not valid_fid(value.get("layout_seed")) \
            or not isinstance(value.get("manifest"), str) \
            or value["manifest"] and not valid_fid(value["manifest"]) \
            or not _trees_ok(value.get("trees")):
        raise ValueError("legacy v7 root shape")
    return Root(
        value["anchor"],
        value["manifest"],
        value["layout_seed"],
        {name: dict(value["trees"][name]) for name in TREE_NAMES},
        value["action_etag"],
    )


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


def items(root, seed, fetch):
    """Traverse one legacy map under its authenticated root count budget."""
    if not root:
        return ()
    first = _decode(fetch(root), root, seed)
    if first["count"] > MAX_ROWS:
        raise ValueError("legacy v7 read budget")
    return Reader(
        root, seed, fetch, max_pages=first["count"]).items()


def range_entries(root, seed, fetch):
    """Strict old RangeTree rows for the one v7-to-current rebuild."""
    out = []
    for sep, value in items(root, seed, fetch):
        if not is_key(sep) or not isinstance(value, list) or len(value) != 2 \
                or not valid_fid(value[0]) \
                or not isinstance(value[1], str) \
                or value[1] and not valid_fid(value[1]):
            raise ValueError("legacy v7 RangeTree row")
        out.append(RangeEntry(sep, value[0], value[1]))
    return tuple(out)


def stable_cut_positions(fids):
    """The removed v7 content-cut rule, retained only for migration checks."""
    return [
        index + 1
        for index, fid in enumerate(fids)
        if int(fid[:8], 16) % CUT == 0
    ]
