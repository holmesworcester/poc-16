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
import bisect
import json
from dataclasses import dataclass

from .crypto import h
from .fact import canon
from .shape import valid_fid

FORMAT = "merkle-map-v1"

# Logical authenticated keys are provider-neutral ASCII.  Current callers
# derive them from fixed fact keys, typed suppression ids, canonical JSON, or
# base64url components.  The catalog-side pre-admission ratchet for every
# future family remains tracked by poc-16-x1p.17.12; this boundary ensures the
# map itself never emits an unbounded page.
MAX_KEY_BYTES = 256
MAX_VALUE_BYTES = 4 * 1024

LEAF_MAX_ROWS = 32
LEAF_MAX_BYTES = 8 * 1024

# A byte branch has at most 128 ASCII children plus the terminal symbol.
# Child summaries make collapse decisions local.  The exact encoder check is
# authoritative; this ceiling includes the worst legal prefix and fanout.
MAX_FANOUT = 129
MAX_PAGE_BYTES = 32 * 1024

# A compressed Patricia path has at most one branch for each key byte, then a
# leaf.  The extra slot makes descriptor validation deliberately conservative.
MAX_PAGE_DEPTH = MAX_KEY_BYTES + 2
MAX_RANGE_ROWS = 256

_TERMINAL = -1


@dataclass(frozen=True)
class Built:
    root: str
    count: int
    page_depth: int
    pages: int


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
    # The seed is fixed-width, so the empty rows encoding is a constant.
    empty = len(canon({
        "format": FORMAT,
        "kind": "leaf",
        "rows": [],
        "seed": "0" * 64,
    }))
    return empty + items + max(0, count - 1)


def _fits_leaf(count, items):
    return count <= LEAF_MAX_ROWS \
        and _leaf_size(count, items) <= LEAF_MAX_BYTES


def _label(key_bytes, prefix_len):
    return _TERMINAL if prefix_len == len(key_bytes) \
        else key_bytes[prefix_len]


def _common_prefix(first, last):
    a, b = _stored_key(first), _stored_key(last)
    at = 0
    stop = min(len(a), len(b))
    while at < stop and a[at] == b[at]:
        at += 1
    return a[:at]


def _leaf_raw(rows, seed):
    raw = canon({
        "format": FORMAT,
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
        "first": first,
        "format": FORMAT,
        "items": items,
        "kind": "branch",
        "last": last,
        "prefix": prefix.decode("ascii"),
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
            _label(_stored_key(row[0]), len(prefix)), []).append(row)
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
    return child.oid, child.count, child.items, child.depth


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
            if set(page) != {"format", "kind", "rows", "seed"} \
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
            if not _fits_leaf(count, items):
                raise ValueError("merkle map noncanonical leaf")
            return page, _Summary(
                oid, count, items, 1, checked[0][0], checked[-1][0])

        if kind != "branch" or set(page) != {
                "children", "count", "depth", "first", "format", "items",
                "kind", "last", "prefix", "seed"}:
            raise ValueError("merkle map page shape")
        children = page["children"]
        first, last, prefix = page["first"], page["last"], page["prefix"]
        first_bytes, last_bytes = _stored_key(first), _stored_key(last)
        if first >= last or not isinstance(prefix, str) \
                or prefix.encode("ascii") != _common_prefix(first, last) \
                or not isinstance(children, list) \
                or not 2 <= len(children) <= MAX_FANOUT:
            raise ValueError("merkle map page shape")
        labels, count, items, depths = [], 0, 0, []
        for child in children:
            if not isinstance(child, list) or len(child) != 5:
                raise ValueError("merkle map page shape")
            label, child_oid, child_count, child_items, child_depth = child
            if type(label) is not int \
                    or not _TERMINAL <= label <= 127 \
                    or not valid_fid(child_oid) \
                    or type(child_count) is not int or child_count < 1 \
                    or type(child_items) is not int or child_items < 1 \
                    or type(child_depth) is not int \
                    or not 1 <= child_depth < MAX_PAGE_DEPTH:
                raise ValueError("merkle map page shape")
            labels.append(label)
            count += child_count
            items += child_items
            depths.append(child_depth)
        prefix_bytes = prefix.encode("ascii")
        if labels != sorted(set(labels)) \
                or labels[0] != _label(first_bytes, len(prefix_bytes)) \
                or labels[-1] != _label(last_bytes, len(prefix_bytes)) \
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
        row[0]: _Summary(row[1], row[2], row[3], row[4], "", "")
        for row in page["children"]
    }


class Reader:
    """Hash-verifying exact, neighbor, range, and resumable diff reads."""

    def __init__(
            self, root, seed, fetch, *, max_page_depth=MAX_PAGE_DEPTH):
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
        self.pages_read = 0
        self._page_budget = max_page_depth

    def _page(self, oid, expected=None, route=None):
        if not valid_fid(oid):
            raise ValueError("merkle map page ref")
        self.pages_read += 1
        if self.pages_read > self._page_budget:
            raise ValueError("merkle map read budget")
        page, summary = _decode(self.fetch(oid), oid, self.seed)
        if expected is not None and _descriptor(summary) != expected:
            raise ValueError("merkle map child metadata")
        if route is not None:
            prefix, label = route
            for edge in (summary.first, summary.last):
                raw = _stored_key(edge)
                if not raw.startswith(prefix) \
                        or _label(raw, len(prefix)) != label:
                    raise ValueError("merkle map child route")
        return page, summary

    @staticmethod
    def _child(page, label):
        rows = page["children"]
        labels = [row[0] for row in rows]
        at = bisect.bisect_left(labels, label)
        if at == len(rows) or rows[at][0] != label:
            return None, at
        row = rows[at]
        return _Summary(row[1], row[2], row[3], row[4], "", ""), at

    def _root(self):
        if not self.root:
            return None, None
        return self._page(self.root)

    def get(self, key):
        raw_key = _query_key(key)
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
            prefix = page["prefix"].encode("ascii")
            if not raw_key.startswith(prefix):
                return None
            label = _label(raw_key, len(prefix))
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
            child = _Summary(
                selected[1], selected[2], selected[3], selected[4], "", "")
            prefix = page["prefix"].encode("ascii")
            route = (prefix, selected[0])
            oid, expected = child.oid, _descriptor(child)
        return None

    def neighbors(self, key):
        """Rows immediately at/before and at/after ``key``.

        One search path plus at most two boundary paths are read.  This is a
        hard ``3 * descriptor depth`` bound independent of map cardinality.
        """
        raw_key = _query_key(key)
        self.pages_read = 0
        self._page_budget = 3 * self.max_page_depth
        if not self.root:
            return None, None
        oid, expected, route = self.root, None, None
        before_child = after_child = None
        before_route = after_route = None
        while oid:
            page, summary = self._page(oid, expected, route)
            if key < summary.first:
                if page["kind"] == "leaf":
                    row = page["rows"][0]
                    return None, (row[0], row[1])
                row = page["children"][0]
                child = _Summary(
                    row[1], row[2], row[3], row[4], "", "")
                return None, self._edge(
                    child, True,
                    (page["prefix"].encode("ascii"), row[0]))
            if key > summary.last:
                if page["kind"] == "leaf":
                    row = page["rows"][-1]
                    return (row[0], row[1]), None
                row = page["children"][-1]
                child = _Summary(
                    row[1], row[2], row[3], row[4], "", "")
                return self._edge(
                    child, False,
                    (page["prefix"].encode("ascii"), row[0])), None
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

            prefix = page["prefix"].encode("ascii")
            if not raw_key.startswith(prefix):
                # Being inside [first,last] implies the shared prefix for
                # well-formed UTF-8 order.  Treat any contradiction as shape.
                raise ValueError("merkle map global order")
            label = _label(raw_key, len(prefix))
            children = page["children"]
            labels = [row[0] for row in children]
            at = bisect.bisect_left(labels, label)
            if at and (at == len(labels) or labels[at] != label):
                row = children[at - 1]
                before_child = _Summary(
                    row[1], row[2], row[3], row[4], "", "")
                before_route = (prefix, row[0])
            if at < len(labels) and labels[at] != label:
                row = children[at]
                after_child = _Summary(
                    row[1], row[2], row[3], row[4], "", "")
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
                before_child = _Summary(
                    row[1], row[2], row[3], row[4], "", "")
                before_route = (prefix, row[0])
            if at + 1 < len(children):
                row = children[at + 1]
                after_child = _Summary(
                    row[1], row[2], row[3], row[4], "", "")
                after_route = (prefix, row[0])
            row = children[at]
            child = _Summary(row[1], row[2], row[3], row[4], "", "")
            oid, expected, route = (
                child.oid, _descriptor(child), (prefix, label))
        return None, None

    def _range_rows(self, start, stop, after, limit, known=None):
        found = []
        stack = [(self.root, None, None)] if self.root else []
        while stack and len(found) <= limit:
            oid, expected, route = stack.pop()
            if known is not None and oid in known:
                continue
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
            prefix = page["prefix"].encode("ascii")
            for row in reversed(page["children"]):
                child = _Summary(
                    row[1], row[2], row[3], row[4], "", "")
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

    def diff_page(
            self, known, *, local=None, after=None,
            limit=MAX_RANGE_ROWS):
        """Return one resumable oid-pruned page of a remote map.

        ``known`` is a set or mapping of locally held page oids.  Equal
        subtrees cost no fetch and yield no rows.  Rewritten leaves are small
        by construction, so unchanged neighbors in such a leaf are returned
        alongside changed rows; ``local`` optionally classifies the exact
        logical differences.  The cursor is the last returned key.
        """
        if not hasattr(known, "__contains__") \
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
        rows = self._range_rows(
            "", "\uffff", after, limit, known=known)
        more = len(rows) > limit
        selected = tuple(rows[:limit])
        differing = selected if local is None else tuple(
            row for row in selected if local.get(row[0]) != row[1])
        return DiffPage(
            selected,
            differing,
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
        self._page_budget = max_pages or 1_000_000
        seen, out = set(), []

        def walk(oid, expected=None, route=None):
            if oid in seen:
                raise ValueError("repeated merkle map page")
            seen.add(oid)
            if oid in known:
                page, summary = _decode(known[oid], oid, self.seed)
                if expected is not None \
                        and _descriptor(summary) != expected:
                    raise ValueError("merkle map child metadata")
                if route is not None:
                    prefix, label = route
                    if any(
                            not _stored_key(edge).startswith(prefix)
                            or _label(_stored_key(edge), len(prefix)) != label
                            for edge in (summary.first, summary.last)):
                        raise ValueError("merkle map child route")
            else:
                page, summary = self._page(oid, expected, route)
            if page["kind"] == "leaf":
                out.extend((row[0], row[1]) for row in page["rows"])
                return summary
            prefix = page["prefix"].encode("ascii")
            children = []
            for row in page["children"]:
                child = _Summary(
                    row[1], row[2], row[3], row[4], "", "")
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


def update(root, seed, changes, fetch, emit):
    """Apply a canonical batch by path-copying only affected radix paths."""
    _validate_seed(seed)
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

    def load(summary, route=None):
        if summary.oid in cache:
            page, actual = cache[summary.oid]
        else:
            raw = pending.get(summary.oid)
            if raw is None:
                raw = fetch(summary.oid)
            page, actual = _decode(raw, summary.oid, seed)
            cache[summary.oid] = (page, actual)
        if summary.first and _descriptor(actual) != _descriptor(summary):
            raise ValueError("merkle map child metadata")
        if route is not None:
            prefix, label = route
            if any(
                    not _stored_key(edge).startswith(prefix)
                    or _label(_stored_key(edge), len(prefix)) != label
                    for edge in (actual.first, actual.last)):
                raise ValueError("merkle map child route")
        return page, actual

    def stage_raw(raw):
        oid = h(raw)
        pending[oid] = raw
        page, summary = _decode(raw, oid, seed)
        cache[oid] = (page, summary)
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

    def collect(summary, route=None):
        page, actual = load(summary, route)
        if page["kind"] == "leaf":
            return [(row[0], row[1]) for row in page["rows"]]
        prefix = page["prefix"].encode("ascii")
        rows = []
        for row in page["children"]:
            child = _Summary(
                row[1], row[2], row[3], row[4], "", "")
            rows.extend(collect(child, (prefix, row[0])))
            if len(rows) > LEAF_MAX_ROWS:
                raise ValueError("merkle map collapse budget")
        return rows

    def modify(summary, key, value, route=None):
        page, actual = load(summary, route)
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

        prefix = page["prefix"].encode("ascii")
        key_bytes = _stored_key(key)
        if not key_bytes.startswith(prefix):
            if value is None:
                return actual
            one = build_local(((key, value),))
            new_prefix = _common_prefix(
                min(key, actual.first), max(key, actual.last))
            groups = {
                _label(_stored_key(one.first), len(new_prefix)): one,
                _label(_stored_key(actual.first), len(new_prefix)): actual,
            }
            if len(groups) != 2:
                raise ValueError("merkle map branch split")
            return store_branch(new_prefix, groups)

        label = _label(key_bytes, len(prefix))
        children = {}
        for row in page["children"]:
            children[row[0]] = _Summary(
                row[1], row[2], row[3], row[4], "", "")
        child = children.get(label)
        if child is None:
            if value is None:
                return actual
            children[label] = build_local(((key, value),))
        else:
            changed = modify(child, key, value, (prefix, label))
            if changed is None:
                children.pop(label)
            else:
                children[label] = changed
        if not children:
            return None
        if len(children) == 1:
            survivor = next(iter(children.values()))
            _, survivor = load(survivor)
            return survivor
        count = sum(child.count for child in children.values())
        items = sum(child.items for child in children.values())
        if _fits_leaf(count, items):
            rows = []
            for child_label, child in sorted(children.items()):
                rows.extend(collect(child, (prefix, child_label)))
            return build_local(rows)
        # The remaining labels still differ immediately after this absolute
        # prefix, so no sibling interval or downstream boundary can move.
        hydrated = {}
        for child_label, child in children.items():
            _, hydrated[child_label] = load(
                child, (prefix, child_label))
        return store_branch(prefix, hydrated)

    if root:
        page, current = _decode(fetch(root), root, seed)
        cache[root] = (page, current)
    else:
        current = None
    for key, value in checked_changes:
        if current is None:
            if value is not None:
                current = build_local(((key, value),))
            continue
        current = modify(current, key, value)
    if current is None:
        return Built("", 0, 0, 0)
    if current.depth > MAX_PAGE_DEPTH:
        raise ValueError("merkle map depth budget")

    # Intermediate split/collapse pages are content-addressed but need not be
    # published.  Walk only the final pending closure.
    emitted = set()

    def publish(oid):
        if oid in emitted or oid not in pending:
            return
        emitted.add(oid)
        page, _ = cache[oid]
        if page["kind"] == "branch":
            for row in page["children"]:
                publish(row[1])
        _emit(pending[oid], emit)

    publish(current.oid)
    return Built(
        current.oid, current.count, current.depth, len(emitted))
