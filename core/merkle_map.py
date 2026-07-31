"""Canonical, adversarially bounded persistent Merkle map.

The map geometry depends only on the bytes of its ordered keys.  A subtree is
one sorted leaf exactly while all of its rows fit both :data:`LEAF_MAX_ROWS`
and :data:`LEAF_MAX_BYTES`.  Otherwise it is a Patricia branch at the first
byte that distinguishes its first and last key.  Branches have no unary
nodes, so an author's choice of key cannot create a probabilistically deep
tree or move an unrelated downstream boundary.

Values are opaque canonical-JSON values.  In particular this codec knows
nothing about facts, piles, or closures; a FactOrderMap may store
``fact.key -> raw_oid`` without teaching the generic map a fact-body format.
"""
import base64
import bisect
import json
from dataclasses import dataclass

from .crypto import h
from .fact import canon
from .limits import MAX_MERKLE_PAGE_BYTES, MAX_MERKLE_PAGE_DEPTH
from .shape import valid_fid

FORMAT = "merkle-map-v1"

# Logical authenticated keys are provider-neutral ASCII.  Current callers
# derive them from fixed fact keys, typed suppression ids, canonical JSON, or
# base64url components. The family-side pre-admission ratchet for every
# future family remains tracked by poc-16-x1p.17.12; this boundary ensures the
# map itself never emits an unbounded page.
MAX_KEY_BYTES = 384
MAX_VALUE_BYTES = 4 * 1024

LEAF_MAX_ROWS = 32
LEAF_MAX_BYTES = 8 * 1024

# Each ASCII byte is represented by two order-preserving five-bit digits.
# A branch therefore has at most 32 digit children plus the terminal symbol.
# This leaves room for authenticated child bounds without a wide page.
MAX_FANOUT = 32
MAX_PAGE_BYTES = MAX_MERKLE_PAGE_BYTES

# The wire protocol accepts at most this many authenticated pages on a path.
# It is deliberately below the theoretical two-radix-digits-per-byte ceiling:
# serviceable work, not key length alone, defines a valid repository map.
MAX_PAGE_DEPTH = MAX_MERKLE_PAGE_DEPTH
MAX_RANGE_ROWS = 256

_TERMINAL = -1
_DIGITS = "0123456789abcdefghijklmnopqrstuv"


@dataclass(frozen=True)
class Built:
    root: str
    count: int
    page_depth: int
    pages: int


@dataclass(frozen=True, slots=True)
class _Read:
    oid: str


@dataclass(frozen=True, slots=True)
class _Write:
    raw: bytes


@dataclass(frozen=True)
class RangePage:
    """One bounded authenticated half-open range page."""

    rows: tuple
    cursor: str | None


@dataclass(frozen=True)
class DiffPage:
    """Rows in remote-only page objects, plus exact logical differences.

    ``rows`` includes every row from a non-shared leaf reached during this
    turn.  ``differing`` keeps only rows whose value differs from the supplied
    local reader.  A caller runs the operation in both directions when it
    needs deletions as well as remote additions/changes.
    """

    rows: tuple
    differing: tuple
    cursor: str | None


@dataclass(frozen=True)
class _Summary:
    oid: str
    count: int
    items: int
    depth: int
    first: str
    last: str


def _stored_key(key):
    if not isinstance(key, str) or not key:
        raise ValueError("merkle map key")
    try:
        raw = key.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("merkle map key") from error
    if len(raw) > MAX_KEY_BYTES:
        raise ValueError("merkle map key too large")
    return raw


def _query_key(key):
    if not isinstance(key, str) or not key:
        raise ValueError("merkle map lookup key")
    try:
        raw = key.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("merkle map lookup key") from error
    if len(raw) > MAX_KEY_BYTES + 4:
        raise ValueError("merkle map lookup key")
    return raw


def _row_item(key, value):
    key_bytes = _stored_key(key)
    if value is None:
        raise ValueError("merkle map null value")
    value_bytes = canon(value)
    if len(value_bytes) > MAX_VALUE_BYTES:
        raise ValueError("merkle map value too large")
    item = canon([key, value])
    # A single accepted row must always fit a leaf.  Keeping this check here
    # makes both bulk and incremental entry paths reject before any emit.
    if _leaf_size(1, len(item)) > LEAF_MAX_BYTES:
        raise ValueError("merkle map row too large")
    return key_bytes, len(item)


def _leaf_size(count, items):
    empty = len(canon({
        "count": count,
        "depth": 1,
        "format": FORMAT,
        "items": items,
        "kind": "leaf",
        "rows": [],
        "seed": "0" * 64,
    }))
    return empty + items + max(0, count - 1)


def _fits_leaf(count, items):
    return count <= LEAF_MAX_ROWS \
        and _leaf_size(count, items) <= LEAF_MAX_BYTES


def _byte_tokens(raw):
    out = []
    for byte in raw:
        out.extend((byte >> 5, byte & 31))
    out.append(_TERMINAL)
    return tuple(out)


def _tokens(key):
    return _byte_tokens(_stored_key(key))


def _query_tokens(key):
    return _byte_tokens(_query_key(key))


def _label(tokens, prefix_len):
    return tokens[prefix_len]


def _matches_route(key, prefix, label):
    tokens = _tokens(key)
    return len(tokens) > len(prefix) \
        and tokens[:len(prefix)] == prefix \
        and tokens[len(prefix)] == label


def _common_prefix(first, last):
    a, b = _tokens(first), _tokens(last)
    at = 0
    stop = min(len(a), len(b))
    while at < stop and a[at] == b[at]:
        at += 1
    # Distinct keys cannot share a terminal token.
    return a[:at]


def _prefix_text(prefix):
    return "".join(_DIGITS[digit] for digit in prefix)


def _decode_prefix(value):
    if not isinstance(value, str):
        raise ValueError("merkle map page shape")
    try:
        prefix = tuple(_DIGITS.index(char) for char in value)
    except ValueError as error:
        raise ValueError("merkle map page shape") from error
    return prefix


def _bound_text(key):
    return base64.urlsafe_b64encode(
        _stored_key(key)).decode("ascii").rstrip("=")


def _decode_bound(value):
    try:
        if not isinstance(value, str):
            raise ValueError("merkle map page shape")
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_", validate=True)
        key = raw.decode("ascii")
        if _bound_text(key) != value:
            raise ValueError("merkle map page shape")
        return key
    except (UnicodeError, ValueError) as error:
        if isinstance(error, ValueError) \
                and str(error).startswith("merkle map"):
            raise
        raise ValueError("merkle map page shape") from error


def _leaf_raw(rows, seed):
    items = sum(len(canon([key, value])) for key, value in rows)
    raw = canon({
        "count": len(rows),
        "depth": 1,
        "format": FORMAT,
        "items": items,
        "kind": "leaf",
        "rows": [[key, value] for key, value in rows],
        "seed": seed,
    })
    if len(raw) > LEAF_MAX_BYTES:
        raise ValueError("merkle map leaf too large")
    return raw


def _child_row(label, child):
    return [
        label, child.oid, child.count, child.items, child.depth,
        _bound_text(child.first), _bound_text(child.last),
    ]


def _branch_raw(prefix, children, first, last, seed):
    count = sum(child.count for child in children.values())
    items = sum(child.items for child in children.values())
    depth = 1 + max(child.depth for child in children.values())
    raw = canon({
        "children": [
            _child_row(label, child)
            for label, child in sorted(children.items())
        ],
        "count": count,
        "depth": depth,
        "first": _bound_text(first),
        "format": FORMAT,
        "items": items,
        "kind": "branch",
        "last": _bound_text(last),
        "prefix": _prefix_text(prefix),
        "seed": seed,
    })
    if len(raw) > MAX_PAGE_BYTES:
        raise ValueError("merkle map branch too large")
    return raw


def _validate_seed(seed):
    if not valid_fid(seed):
        raise ValueError("merkle map seed")


def _checked_rows(rows):
    ordered = sorted(rows, key=lambda row: row[0])
    checked = []
    for row in ordered:
        if not isinstance(row, tuple) or len(row) != 2:
            raise ValueError("merkle map row")
        key, value = row
        _, size = _row_item(key, value)
        checked.append((key, value, size))
    if any(a[0] >= b[0] for a, b in zip(checked, checked[1:])):
        raise ValueError("duplicate merkle map key")
    return tuple(checked)


def _emit(raw, emit):
    oid = h(raw)
    answer = emit(raw)
    if answer is not None and answer != oid:
        raise ValueError("merkle map emitter changed object identity")
    return oid


def _build_rows(checked, seed, emit):
    """Build the unique recursive partition for already checked rows."""
    if not checked:
        return None
    count = len(checked)
    items = sum(row[2] for row in checked)
    if _fits_leaf(count, items):
        rows = tuple((key, value) for key, value, _ in checked)
        raw = _leaf_raw(rows, seed)
        oid = _emit(raw, emit)
        return _Summary(
            oid, count, items, 1, checked[0][0], checked[-1][0])

    prefix = _common_prefix(checked[0][0], checked[-1][0])
    groups = {}
    for row in checked:
        groups.setdefault(
            _label(_tokens(row[0]), len(prefix)), []).append(row)
    if not 2 <= len(groups) <= MAX_FANOUT:
        raise ValueError("merkle map branch fanout")
    children = {
        label: _build_rows(tuple(group), seed, emit)
        for label, group in sorted(groups.items())
    }
    raw = _branch_raw(
        prefix, children, checked[0][0], checked[-1][0], seed)
    oid = _emit(raw, emit)
    depth = 1 + max(child.depth for child in children.values())
    if depth > MAX_PAGE_DEPTH:
        raise ValueError("merkle map depth budget")
    return _Summary(
        oid, count, items, depth, checked[0][0], checked[-1][0])


def build(rows, seed, emit, *, max_page_depth=MAX_PAGE_DEPTH):
    """Bulk-build the canonical map, rejecting every row before first emit."""
    _validate_seed(seed)
    if type(max_page_depth) is not int \
            or not 0 <= max_page_depth <= MAX_PAGE_DEPTH:
        raise ValueError("merkle map depth budget")
    checked = _checked_rows(tuple(rows))
    if not checked:
        return Built("", 0, 0, 0)
    # Build into memory first: a late depth/page error must not partially emit.
    pending = {}

    def stage(raw):
        oid = h(raw)
        pending[oid] = raw
        return oid

    root = _build_rows(checked, seed, stage)
    if root.depth > max_page_depth:
        raise ValueError("merkle map depth budget")
    for raw in pending.values():
        _emit(raw, emit)
    return Built(root.oid, root.count, root.depth, len(pending))


def _descriptor(child):
    return (
        child.oid, child.count, child.items, child.depth,
        child.first, child.last,
    )


def _decode(raw, oid, seed):
    if not isinstance(raw, bytes) or len(raw) > MAX_PAGE_BYTES \
            or h(raw) != oid:
        raise ValueError("merkle map page integrity")
    try:
        page = json.loads(raw)
        if canon(page) != raw or not isinstance(page, dict) \
                or page.get("format") != FORMAT \
                or page.get("seed") != seed:
            raise ValueError("merkle map page shape")
        kind = page.get("kind")
        if kind == "leaf":
            if set(page) != {
                    "count", "depth", "format", "items", "kind", "rows",
                    "seed"} \
                    or not isinstance(page["rows"], list) \
                    or not page["rows"] \
                    or len(page["rows"]) > LEAF_MAX_ROWS \
                    or len(raw) > LEAF_MAX_BYTES:
                raise ValueError("merkle map page shape")
            checked = []
            for row in page["rows"]:
                if not isinstance(row, list) or len(row) != 2:
                    raise ValueError("merkle map page shape")
                key, value = row
                _, size = _row_item(key, value)
                checked.append((key, value, size))
            if any(a[0] >= b[0] for a, b in zip(checked, checked[1:])):
                raise ValueError("merkle map global order")
            count = len(checked)
            items = sum(row[2] for row in checked)
            if page["count"] != count or page["depth"] != 1 \
                    or page["items"] != items \
                    or not _fits_leaf(count, items):
                raise ValueError("merkle map noncanonical leaf")
            return page, _Summary(
                oid, count, items, 1, checked[0][0], checked[-1][0])

        if kind != "branch" or set(page) != {
                "children", "count", "depth", "first", "format", "items",
                "kind", "last", "prefix", "seed"}:
            raise ValueError("merkle map page shape")
        children = page["children"]
        first = _decode_bound(page["first"])
        last = _decode_bound(page["last"])
        prefix = _decode_prefix(page["prefix"])
        if first >= last or prefix != _common_prefix(first, last) \
                or not isinstance(children, list) \
                or not 2 <= len(children) <= MAX_FANOUT:
            raise ValueError("merkle map page shape")
        labels, count, items, depths, bounds = [], 0, 0, [], []
        for child in children:
            if not isinstance(child, list) or len(child) != 7:
                raise ValueError("merkle map page shape")
            (label, child_oid, child_count, child_items, child_depth,
             child_first_text, child_last_text) = child
            child_first = _decode_bound(child_first_text)
            child_last = _decode_bound(child_last_text)
            if type(label) is not int \
                    or not _TERMINAL <= label <= 31 \
                    or not valid_fid(child_oid) \
                    or type(child_count) is not int or child_count < 1 \
                    or type(child_items) is not int or child_items < 1 \
                    or type(child_depth) is not int \
                    or not 1 <= child_depth < MAX_PAGE_DEPTH \
                    or child_first > child_last \
                    or not _matches_route(child_first, prefix, label) \
                    or not _matches_route(child_last, prefix, label):
                raise ValueError("merkle map page shape")
            labels.append(label)
            bounds.append((child_first, child_last))
            count += child_count
            items += child_items
            depths.append(child_depth)
        if labels != sorted(set(labels)) \
                or any(a[1] >= b[0] for a, b in zip(bounds, bounds[1:])) \
                or first != bounds[0][0] or last != bounds[-1][1] \
                or labels[0] != _label(_tokens(first), len(prefix)) \
                or labels[-1] != _label(_tokens(last), len(prefix)) \
                or page["count"] != count \
                or page["items"] != items \
                or page["depth"] != 1 + max(depths) \
                or not 2 <= page["depth"] <= MAX_PAGE_DEPTH \
                or _fits_leaf(count, items):
            raise ValueError("merkle map page metadata")
        return page, _Summary(
            oid, count, items, page["depth"], first, last)
    except (AttributeError, TypeError, UnicodeError, ValueError,
            RecursionError) as error:
        if isinstance(error, ValueError) \
                and str(error).startswith("merkle map"):
            raise
        raise ValueError("merkle map page shape") from error


def _children(page):
    return {
        row[0]: _summary_row(row)
        for row in page["children"]
    }


def _summary_row(row):
    return _Summary(
        row[1], row[2], row[3], row[4],
        _decode_bound(row[5]), _decode_bound(row[6]))


def _expected_metadata(root, count, depth, max_depth):
    if count is None or depth is None:
        if count is not None or depth is not None:
            raise ValueError("merkle map expected metadata")
        return None
    if type(count) is not int or count < 0 \
            or type(depth) is not int or not 0 <= depth <= max_depth \
            or bool(root) != bool(count) \
            or bool(root) != bool(depth):
        raise ValueError("merkle map expected metadata")
    return count, depth


def _get_many_program(
        root, seed, keys, *,
        max_page_depth=MAX_PAGE_DEPTH,
        expected_count=None, expected_depth=None):
    """Yield each page in the union of sorted authenticated lookup paths."""
    if root and not valid_fid(root):
        raise ValueError("merkle map root")
    _validate_seed(seed)
    if type(max_page_depth) is not int \
            or not 0 <= max_page_depth <= MAX_PAGE_DEPTH:
        raise ValueError("merkle map read budget")
    expected_root = _expected_metadata(
        root, expected_count, expected_depth, max_page_depth)
    checked = tuple(sorted(keys))
    for key in checked:
        _query_key(key)
    if any(a == b for a, b in zip(checked, checked[1:])):
        raise ValueError("duplicate merkle map lookup")
    answers = {key: None for key in checked}
    if not root or not checked:
        return answers, 0

    # Iterative DFS matters here: recursive parent frames would retain one
    # copy of the whole requested-key set at every hostile radix depth.
    stack = [(root, None, None, checked)]
    seen, pages = set(), 0
    while stack:
        oid, expected, route, selected = stack.pop()
        if oid in seen or not valid_fid(oid):
            raise ValueError("repeated merkle map page")
        seen.add(oid)
        pages += 1
        if pages > len(checked) * max_page_depth:
            raise ValueError("merkle map read budget")
        page, summary = _decode((yield _Read(oid)), oid, seed)
        if oid == root and expected_root is not None \
                and (summary.count, summary.depth) != expected_root:
            raise ValueError("merkle map root metadata")
        if expected is not None and _descriptor(summary) != expected:
            raise ValueError("merkle map child metadata")
        if route is not None:
            prefix, label = route
            if any(
                    not _matches_route(edge, prefix, label)
                    for edge in (summary.first, summary.last)):
                raise ValueError("merkle map child route")
        selected = tuple(
            key for key in selected
            if summary.first <= key <= summary.last)
        if not selected:
            continue
        if page["kind"] == "leaf":
            rows = {row[0]: row[1] for row in page["rows"]}
            answers.update(
                (key, rows[key]) for key in selected if key in rows)
            continue

        prefix = _decode_prefix(page["prefix"])
        groups = {}
        for key in selected:
            tokens = _query_tokens(key)
            if tokens[:len(prefix)] == prefix:
                groups.setdefault(
                    _label(tokens, len(prefix)), []).append(key)
        children = {
            row[0]: _summary_row(row)
            for row in page["children"]
        }
        for label in sorted(groups, reverse=True):
            child = children.get(label)
            if child is not None:
                stack.append((
                    child.oid,
                    _descriptor(child),
                    (prefix, label),
                    tuple(groups[label]),
                ))
    return answers, pages


def _drive_get_many(program, fetch):
    try:
        operation = next(program)
        while True:
            if not isinstance(operation, _Read):
                raise TypeError("merkle map lookup operation")
            operation = program.send(fetch(operation.oid))
    except StopIteration as done:
        return done.value
    finally:
        program.close()


def get_many(
        root, seed, keys, fetch, *,
        max_page_depth=MAX_PAGE_DEPTH,
        expected_count=None, expected_depth=None):
    """Read one sorted union of paths without retaining a page corpus."""
    return _drive_get_many(
        _get_many_program(
            root,
            seed,
            keys,
            max_page_depth=max_page_depth,
            expected_count=expected_count,
            expected_depth=expected_depth,
        ),
        fetch,
    )


async def get_many_awaited(
        root, seed, keys, fetch, *,
        max_page_depth=MAX_PAGE_DEPTH,
        expected_count=None, expected_depth=None):
    """Await the same exact multi-point traversal one page at a time."""
    program = _get_many_program(
        root,
        seed,
        keys,
        max_page_depth=max_page_depth,
        expected_count=expected_count,
        expected_depth=expected_depth,
    )
    try:
        operation = next(program)
        while True:
            if not isinstance(operation, _Read):
                raise TypeError("merkle map lookup operation")
            operation = program.send(await fetch(operation.oid))
    except StopIteration as done:
        return done.value
    finally:
        program.close()


class Reader:
    """Hash-verifying exact, neighbor, range, and resumable diff reads."""

    def __init__(
            self, root, seed, fetch, *, max_page_depth=MAX_PAGE_DEPTH,
            expected_count=None, expected_depth=None):
        if root and not valid_fid(root):
            raise ValueError("merkle map root")
        _validate_seed(seed)
        if type(max_page_depth) is not int \
                or not 0 <= max_page_depth <= MAX_PAGE_DEPTH:
            raise ValueError("merkle map read budget")
        self.root = root
        self.seed = seed
        self.fetch = fetch
        self.max_page_depth = max_page_depth
        self.expected_root = _expected_metadata(
            root, expected_count, expected_depth, max_page_depth)
        self.pages_read = 0
        self._page_budget = max_page_depth

    def _check_root(self, summary):
        if self.expected_root is not None \
                and (summary.count, summary.depth) != self.expected_root:
            raise ValueError("merkle map root metadata")

    def _decode_page(self, raw, oid):
        page, summary = _decode(raw, oid, self.seed)
        if oid == self.root:
            self._check_root(summary)
        return page, summary

    def _page(self, oid, expected=None, route=None):
        if not valid_fid(oid):
            raise ValueError("merkle map page ref")
        self.pages_read += 1
        if self.pages_read > self._page_budget:
            raise ValueError("merkle map read budget")
        page, summary = self._decode_page(self.fetch(oid), oid)
        if expected is not None and _descriptor(summary) != expected:
            raise ValueError("merkle map child metadata")
        if route is not None:
            prefix, label = route
            for edge in (summary.first, summary.last):
                if not _matches_route(edge, prefix, label):
                    raise ValueError("merkle map child route")
        return page, summary

    @staticmethod
    def _child(page, label):
        rows = page["children"]
        labels = [row[0] for row in rows]
        at = bisect.bisect_left(labels, label)
        if at == len(rows) or rows[at][0] != label:
            return None, at
        return _summary_row(rows[at]), at

    def _root(self):
        if not self.root:
            return None, None
        return self._page(self.root)

    def get(self, key):
        key_tokens = _query_tokens(key)
        self.pages_read = 0
        self._page_budget = self.max_page_depth
        oid, expected, route = self.root, None, None
        while oid:
            page, summary = self._page(oid, expected, route)
            if not summary.first <= key <= summary.last:
                return None
            if page["kind"] == "leaf":
                keys = [row[0] for row in page["rows"]]
                at = bisect.bisect_left(keys, key)
                return page["rows"][at][1] \
                    if at < len(keys) and keys[at] == key else None
            prefix = _decode_prefix(page["prefix"])
            if key_tokens[:len(prefix)] != prefix:
                return None
            label = _label(key_tokens, len(prefix))
            child, _ = self._child(page, label)
            if child is None:
                return None
            oid, expected, route = (
                child.oid, _descriptor(child), (prefix, label))
        return None

    def _edge(self, child, first, route):
        oid, expected = child.oid, _descriptor(child)
        while oid:
            page, summary = self._page(oid, expected, route)
            if page["kind"] == "leaf":
                row = page["rows"][0 if first else -1]
                return row[0], row[1]
            selected = page["children"][0 if first else -1]
            child = _summary_row(selected)
            prefix = _decode_prefix(page["prefix"])
            route = (prefix, selected[0])
            oid, expected = child.oid, _descriptor(child)
        return None

    def neighbors(self, key):
        """Rows immediately at/before and at/after ``key``.

        One search path plus at most two boundary paths are read.  This is a
        hard ``3 * descriptor depth`` bound independent of map cardinality.
        """
        key_tokens = _query_tokens(key)
        self.pages_read = 0
        self._page_budget = 3 * self.max_page_depth
        if not self.root:
            return None, None
        oid, expected, route = self.root, None, None
        before_child = after_child = None
        before_route = after_route = None

        def loaded_edge(page, first):
            if page["kind"] == "leaf":
                row = page["rows"][0 if first else -1]
                return row[0], row[1]
            row = page["children"][0 if first else -1]
            return self._edge(
                _summary_row(row), first,
                (_decode_prefix(page["prefix"]), row[0]))

        while oid:
            page, summary = self._page(oid, expected, route)
            if key < summary.first:
                before = self._edge(
                    before_child, False, before_route
                ) if before_child is not None else None
                return before, loaded_edge(page, True)
            if key > summary.last:
                after = self._edge(
                    after_child, True, after_route
                ) if after_child is not None else None
                return loaded_edge(page, False), after
            if page["kind"] == "leaf":
                keys = [row[0] for row in page["rows"]]
                at = bisect.bisect_left(keys, key)
                before = tuple(page["rows"][at - 1]) if at else None
                after = tuple(page["rows"][at]) \
                    if at < len(keys) else None
                if after is not None and after[0] == key:
                    return after, after
                if before is None and before_child is not None:
                    before = self._edge(
                        before_child, False, before_route)
                if after is None and after_child is not None:
                    after = self._edge(after_child, True, after_route)
                return before, after

            prefix = _decode_prefix(page["prefix"])
            if key_tokens[:len(prefix)] != prefix:
                # Being inside [first,last] implies the shared prefix for
                # a well-formed radix interval. Treat contradiction as shape.
                raise ValueError("merkle map global order")
            label = _label(key_tokens, len(prefix))
            children = page["children"]
            labels = [row[0] for row in children]
            at = bisect.bisect_left(labels, label)
            if at and (at == len(labels) or labels[at] != label):
                row = children[at - 1]
                before_child = _summary_row(row)
                before_route = (prefix, row[0])
            if at < len(labels) and labels[at] != label:
                row = children[at]
                after_child = _summary_row(row)
                after_route = (prefix, row[0])
            if at == len(labels) or labels[at] != label:
                before = self._edge(
                    before_child, False, before_route) \
                    if before_child is not None else None
                after = self._edge(after_child, True, after_route) \
                    if after_child is not None else None
                return before, after
            if at:
                row = children[at - 1]
                before_child = _summary_row(row)
                before_route = (prefix, row[0])
            if at + 1 < len(children):
                row = children[at + 1]
                after_child = _summary_row(row)
                after_route = (prefix, row[0])
            row = children[at]
            child = _summary_row(row)
            oid, expected, route = (
                child.oid, _descriptor(child), (prefix, label))
        return None, None

    def _range_rows(self, start, stop, after, limit):
        found = []
        stack = [(self.root, None, None)] if self.root else []
        while stack and len(found) <= limit:
            oid, expected, route = stack.pop()
            page, summary = self._page(oid, expected, route)
            if summary.last < start or summary.first >= stop \
                    or after is not None and summary.last <= after:
                continue
            if page["kind"] == "leaf":
                for key, value in page["rows"]:
                    if start <= key < stop \
                            and (after is None or key > after):
                        found.append((key, value))
                        if len(found) > limit:
                            break
                continue
            prefix = _decode_prefix(page["prefix"])
            for row in reversed(page["children"]):
                child = _summary_row(row)
                if child.last < start or child.first >= stop \
                        or after is not None and child.last <= after:
                    continue
                stack.append((
                    child.oid, _descriptor(child), (prefix, row[0])))
        return found

    def range_page(self, start, stop, *, after=None, limit=MAX_RANGE_ROWS):
        if not isinstance(start, str) or not start \
                or not isinstance(stop, str) or start >= stop \
                or after is not None and (
                    not isinstance(after, str) or not after
                    or after < start or after >= stop
                ) \
                or type(limit) is not int \
                or not 1 <= limit <= MAX_RANGE_ROWS:
            raise ValueError("merkle map range")
        _query_key(start)
        _query_key(stop)
        if after is not None:
            _query_key(after)
        self.pages_read = 0
        self._page_budget = (
            2 * self.max_page_depth + 2 * (limit + 1))
        found = self._range_rows(start, stop, after, limit)
        more = len(found) > limit
        rows = tuple(found[:limit])
        return RangePage(rows, rows[-1][0] if more else None)

    def diff_page(self, local, *, after=None, limit=MAX_RANGE_ROWS):
        """Return one resumable oid-pruned page of a remote map.

        Pruning compares subtrees reachable from the two supplied *current
        roots*.  Merely possessing an oid is not a reachability witness:
        immutable stores retain stale pages from old roots.  Rewritten leaves
        are small by construction, so unchanged neighbors in such a leaf are
        returned alongside the exact ``differing`` rows.  Run the operation in
        both directions to discover deletions.
        """
        if not isinstance(local, Reader) or local.seed != self.seed \
                or after is not None and (
                    not isinstance(after, str) or not after):
            raise ValueError("merkle map diff")
        if after is not None:
            _query_key(after)
        if type(limit) is not int or not 1 <= limit <= MAX_RANGE_ROWS:
            raise ValueError("merkle map diff")
        self.pages_read = 0
        self._page_budget = (
            2 * self.max_page_depth + 2 * (limit + 1))
        local_pages = 0

        def local_page(ref):
            nonlocal local_pages
            oid, expected, route = ref
            local_pages += 1
            page, summary = local._decode_page(local.fetch(oid), oid)
            if expected is not None and _descriptor(summary) != expected:
                raise ValueError("merkle map child metadata")
            if route is not None:
                prefix, label = route
                if any(
                        not _matches_route(edge, prefix, label)
                        for edge in (summary.first, summary.last)):
                    raise ValueError("merkle map child route")
            return page, summary

        remote_root = (self.root, None, None) if self.root else None
        local_root = (local.root, None, None) if local.root else None
        if remote_root is not None and remote_root == local_root and (
                self.expected_root is not None
                or local.expected_root is not None):
            _, summary = self._page(self.root)
            local._check_root(summary)
        stack = [(remote_root, local_root)] if remote_root else []
        rows = []
        while stack and len(rows) <= limit:
            remote_ref, local_ref = stack.pop()
            oid, expected, route = remote_ref
            # Equal content hashes authenticate equality only when the two
            # current parents also authenticate the same descriptor and route.
            # A hostile parent may reuse a genuine child oid beside forged
            # bounds/counts; that child must be opened and rejected.
            if local_ref is not None and remote_ref == local_ref:
                continue
            page, summary = self._page(oid, expected, route)
            if after is not None and summary.last <= after:
                continue
            if page["kind"] == "leaf":
                for key, value in page["rows"]:
                    if after is None or key > after:
                        rows.append((key, value))
                        if len(rows) > limit:
                            break
                continue

            local_children = {}
            if local_ref is not None:
                local_node, _ = local_page(local_ref)
                if local_node["kind"] == "branch" \
                        and local_node["prefix"] == page["prefix"]:
                    local_children = {
                        row[0]: (
                            row[1],
                            _descriptor(_summary_row(row)),
                            (_decode_prefix(local_node["prefix"]), row[0]),
                        )
                        for row in local_node["children"]
                    }
            prefix = _decode_prefix(page["prefix"])
            for row in reversed(page["children"]):
                child = _summary_row(row)
                if after is not None and child.last <= after:
                    continue
                stack.append((
                    (
                        child.oid, _descriptor(child),
                        (prefix, row[0]),
                    ),
                    local_children.get(row[0]),
                ))

        more = len(rows) > limit
        selected = tuple(rows[:limit])
        differing = []
        lookup_pages = 0
        for row in selected:
            incumbent = local.get(row[0])
            lookup_pages += local.pages_read
            if incumbent != row[1]:
                differing.append(row)
        local.pages_read = local_pages + lookup_pages
        return DiffPage(
            selected,
            tuple(differing),
            selected[-1][0] if more else None,
        )

    def items(self, known=None, *, max_pages=None):
        """Decode the complete map for repair only.

        Normal remote reconciliation uses :meth:`diff_page`.  ``known`` may
        provide local raw pages; unlike diff, complete enumeration decodes
        those pages locally because the caller requested every logical row.
        """
        known = known or {}
        if not self.root:
            return ()
        self.pages_read = 0
        prefetched = {}
        if max_pages is None:
            if self.root in known:
                root_page, root_summary = self._decode_page(
                    known[self.root], self.root)
            else:
                self._page_budget = 1
                root_page, root_summary = self._page(self.root)
            max_pages = 2 * root_summary.count - 1
            prefetched[self.root] = (root_page, root_summary)
        if type(max_pages) is not int or max_pages < 1:
            raise ValueError("merkle map read budget")
        self._page_budget = max_pages
        seen, out = set(), []

        def walk(oid, expected=None, route=None):
            if oid in seen:
                raise ValueError("repeated merkle map page")
            seen.add(oid)
            if oid in prefetched:
                page, summary = prefetched[oid]
            elif oid in known:
                page, summary = self._decode_page(known[oid], oid)
                if expected is not None \
                        and _descriptor(summary) != expected:
                    raise ValueError("merkle map child metadata")
                if route is not None:
                    prefix, label = route
                    if any(
                            not _matches_route(edge, prefix, label)
                            for edge in (summary.first, summary.last)):
                        raise ValueError("merkle map child route")
            else:
                page, summary = self._page(oid, expected, route)
            if page["kind"] == "leaf":
                out.extend((row[0], row[1]) for row in page["rows"])
                return summary
            prefix = _decode_prefix(page["prefix"])
            children = []
            for row in page["children"]:
                child = _summary_row(row)
                children.append(walk(
                    child.oid, _descriptor(child), (prefix, row[0])))
            if summary.first != children[0].first \
                    or summary.last != children[-1].last:
                raise ValueError("merkle map page metadata")
            return summary

        walk(self.root)
        if any(a[0] >= b[0] for a, b in zip(out, out[1:])):
            raise ValueError("merkle map global order")
        return tuple(out)


def _update_program(
        root, seed, changes, *,
        expected_count=None, expected_depth=None):
    """Yield one bounded path-copy transition per sorted logical change.

    Each intermediate root is immutable and harmless: only the caller's final
    root is ever installed in the repository register.  Establishing one
    changed path before starting the next bounds the live decoded graph
    without retaining a replay corpus or a final-tree publication planner.
    """
    _validate_seed(seed)
    expected_root = _expected_metadata(
        root, expected_count, expected_depth, MAX_PAGE_DEPTH)
    checked_changes = []
    for change in changes:
        if not isinstance(change, tuple) or len(change) != 2:
            raise ValueError("merkle map row")
        key, value = change
        _stored_key(key)
        if value is not None:
            _row_item(key, value)
        checked_changes.append((key, value))
    checked_changes.sort(key=lambda row: row[0])
    if any(a[0] == b[0]
           for a, b in zip(checked_changes, checked_changes[1:])):
        raise ValueError("duplicate merkle map change")

    cache, pending = {}, {}
    written = 0

    def load(summary, route=None):
        if summary.oid in cache:
            page, actual = cache[summary.oid]
        else:
            raw = pending.get(summary.oid)
            if raw is None:
                raw = yield _Read(summary.oid)
            page, actual = _decode(raw, summary.oid, seed)
            cache[summary.oid] = (page, actual)
        if summary.first and _descriptor(actual) != _descriptor(summary):
            raise ValueError("merkle map child metadata")
        if route is not None:
            prefix, label = route
            if any(
                    not _matches_route(edge, prefix, label)
                    for edge in (actual.first, actual.last)):
                raise ValueError("merkle map child route")
        return page, actual

    def stage_raw(raw):
        oid = h(raw)
        incumbent = pending.setdefault(oid, raw)
        if incumbent != raw:
            raise ValueError("merkle map object hash collision")
        if oid not in cache:
            cache[oid] = _decode(raw, oid, seed)
        return oid

    def build_local(rows):
        checked = _checked_rows(tuple(rows))
        return _build_rows(checked, seed, stage_raw)

    def store_branch(prefix, children):
        ordered = dict(sorted(children.items()))
        if len(ordered) == 1:
            return next(iter(ordered.values()))
        first = next(iter(ordered.values())).first
        last = next(reversed(ordered.values())).last
        actual_prefix = _common_prefix(first, last)
        if actual_prefix != prefix:
            raise ValueError("merkle map branch prefix")
        raw = _branch_raw(prefix, ordered, first, last, seed)
        oid = stage_raw(raw)
        return cache[oid][1]

    def forget(summary):
        """Keep only the compact authenticated summary while unwinding."""
        if summary.oid not in pending:
            cache.pop(summary.oid, None)

    def collect(summary, route=None):
        page, actual = yield from load(summary, route)
        if page["kind"] == "leaf":
            return [(row[0], row[1]) for row in page["rows"]]
        prefix = _decode_prefix(page["prefix"])
        children = tuple(page["children"])
        forget(actual)
        page = None
        rows = []
        for row in children:
            child = _summary_row(row)
            rows.extend((yield from collect(
                child, (prefix, row[0]))))
            if len(rows) > LEAF_MAX_ROWS:
                raise ValueError("merkle map collapse budget")
        return rows

    def modify(summary, key, value, route=None):
        page, actual = yield from load(summary, route)
        if page["kind"] == "leaf":
            rows = [(row[0], row[1]) for row in page["rows"]]
            keys = [row[0] for row in rows]
            at = bisect.bisect_left(keys, key)
            if value is None:
                if at == len(rows) or rows[at][0] != key:
                    return actual
                rows.pop(at)
            elif at < len(rows) and rows[at][0] == key:
                if rows[at][1] == value:
                    return actual
                rows[at] = (key, value)
            else:
                rows.insert(at, (key, value))
            return build_local(rows) if rows else None

        prefix = _decode_prefix(page["prefix"])
        key_tokens = _tokens(key)
        if key_tokens[:len(prefix)] != prefix:
            if value is None:
                return actual
            one = build_local(((key, value),))
            new_prefix = _common_prefix(
                min(key, actual.first), max(key, actual.last))
            groups = {
                _label(_tokens(one.first), len(new_prefix)): one,
                _label(_tokens(actual.first), len(new_prefix)): actual,
            }
            if len(groups) != 2:
                raise ValueError("merkle map branch split")
            return store_branch(new_prefix, groups)

        label = _label(key_tokens, len(prefix))
        children = {}
        for row in page["children"]:
            children[row[0]] = _summary_row(row)
        forget(actual)
        page = None
        child = children.get(label)
        if child is None:
            if value is None:
                return actual
            children[label] = build_local(((key, value),))
        else:
            changed = yield from modify(
                child, key, value, (prefix, label))
            if changed is None:
                children.pop(label)
            else:
                children[label] = changed
        if not children:
            return None
        if len(children) == 1:
            survivor = next(iter(children.values()))
            _, survivor = yield from load(survivor)
            forget(survivor)
            return survivor
        count = sum(child.count for child in children.values())
        items = sum(child.items for child in children.values())
        if _fits_leaf(count, items):
            rows = []
            for child_label, child in sorted(children.items()):
                rows.extend((yield from collect(
                    child, (prefix, child_label))))
            return build_local(rows)
        # The authenticated parent already binds every unchanged child's hash,
        # bounds, count, and depth. Only the selected child path must be
        # fetched; rebuilding a parent must not hydrate unrelated siblings.
        return store_branch(prefix, children)

    try:
        if root:
            page, current = _decode((yield _Read(root)), root, seed)
            if expected_root is not None \
                    and (current.count, current.depth) != expected_root:
                raise ValueError("merkle map root metadata")
            cache[root] = (page, current)
        else:
            current = None
        for key, value in checked_changes:
            if current is None:
                if value is not None:
                    current = build_local(((key, value),))
            else:
                current = yield from modify(current, key, value)
            if current is not None and current.depth > MAX_PAGE_DEPTH:
                raise ValueError("merkle map depth budget")

            # _build_rows and store_branch stage children before parents.
            # Every value is immutable, and repository publication still
            # waits until the complete batch returns its final root.
            for raw in tuple(pending.values()):
                written += 1
                yield _Write(raw)
            pending.clear()
            cache.clear()
        if current is None:
            return Built("", 0, 0, written)
        return Built(
            current.oid, current.count, current.depth, written)
    finally:
        cache.clear()
        pending.clear()


def _drive_update(program, fetch, emit):
    try:
        operation = next(program)
        while True:
            if isinstance(operation, _Read):
                answer = fetch(operation.oid)
            elif isinstance(operation, _Write):
                answer = _emit(operation.raw, emit)
            else:
                raise TypeError("merkle map update operation")
            operation = program.send(answer)
    except StopIteration as done:
        return done.value
    finally:
        program.close()


def update(
        root, seed, changes, fetch, emit, *,
        expected_count=None, expected_depth=None):
    """Apply a canonical batch by path-copying only affected radix paths."""
    return _drive_update(
        _update_program(
            root, seed, changes,
            expected_count=expected_count,
            expected_depth=expected_depth,
        ),
        fetch,
        emit,
    )


async def update_awaited(
        root, seed, changes, fetch, emit, *,
        expected_count=None, expected_depth=None):
    """Await the same update program without retaining a replay cache."""
    program = _update_program(
        root, seed, changes,
        expected_count=expected_count,
        expected_depth=expected_depth,
    )
    try:
        operation = next(program)
        while True:
            if isinstance(operation, _Read):
                answer = await fetch(operation.oid)
            elif isinstance(operation, _Write):
                raw = operation.raw
                answer = await emit(raw)
                oid = h(raw)
                if answer is not None and answer != oid:
                    raise ValueError(
                        "merkle map emitter changed object identity")
                answer = oid
            else:
                raise TypeError("merkle map update operation")
            operation = program.send(answer)
    except StopIteration as done:
        return done.value
    finally:
        program.close()
