"""Canonical RangeTree over closed home-leaf piles.

One entry maps a leaf's first opaque canonical key to its pile oid and closure
sibling oid. RangeTree uses the same persistent bounded Merkle map as the
Worker indexes: full build defines one history-independent root, while an
ordinary commit locates only the affected leaf windows through authenticated
neighbor reads and path-copies their tree paths. Equal RangeTree subtrees and
equal leaf piles have equal oids, so one-sided sync still prunes by oid.
"""
from bisect import bisect_right
from typing import NamedTuple

from . import merkle_map
from .merkle_map import MAX_PAGE_DEPTH as MAX_TREE_DEPTH
from .close import decode_pile, encode_pile
from .crypto import h
from .fact import canon
from .limits import MAX_ROOT_BYTES, decode_json
from .shape import boundary, fid_of, is_key, key, stable_cut_positions, valid_fid
from .object_store import verified_object

# The one format identity. Written into the root; checked by decode_root.
# A mismatch is a ValueError => the store rebuilds wholesale (no read-compat
# path exists. Replaces the pre-cutover tree configuration.
LAYOUT = "composite-merkle-map-v8-bounded-radix"
TREE_NAMES = ("fact", "supp", "authority")
RANGE_SEED = h(canon(["range-tree-v1"]))


class Entry(NamedTuple):
    """One home leaf: first key, pile oid, closure-sibling oid ("" if none)."""
    sep: str
    leaf: str
    closure: str


class RangeReplacement(NamedTuple):
    """Old leaf separators replaced by one canonical local key window."""

    old_seps: tuple[str, ...]
    keys: tuple[str, ...]


class Root(NamedTuple):
    """One fully checked published snapshot named by the mutable root key."""

    anchor: str
    manifest: str
    layout_seed: str
    trees: dict
    action_etag: str


def _chunks(items, fid):
    """The ONE cut: after any item whose fid is a boundary, tail included."""
    out, start = [], 0
    for stop in stable_cut_positions([fid(i) for i in items]) + [len(items)]:
        if stop > start:
            out.append(items[start:stop])
            start = stop
    return out


def _put(raw, emit):
    """Store one object; the oid is the bytes (emit's answer is advisory)."""
    emit(raw)
    return h(raw)


def _value(entry):
    return [entry.leaf, entry.closure]


def _entry(sep, value):
    if not is_key(sep) or not isinstance(value, list) or len(value) != 2 \
            or not valid_fid(value[0]) or not isinstance(value[1], str) \
            or value[1] and not valid_fid(value[1]):
        raise ValueError("manifest entry")
    return Entry(sep, *value)


def _range(keys, fact_of, deps_of, emit):
    members = []
    for wanted in keys:
        fact = fact_of(fid_of(wanted))
        if fact is None or key(fact) != wanted:
            raise ValueError("manifest member")
        members.append(fact)
    leaf = _put(encode_pile(members), emit)

    def key_of(fid):
        fact = fact_of(fid)
        if fact is None:
            raise ValueError("manifest closure")
        return key(fact)

    outside = closure_keys(members, deps_of, key_of)
    closure = _put(canon({"keys": outside}), emit) if outside else ""
    return Entry(keys[0], leaf, closure)


def range_members(entry, fetch, workspace):
    """Verify and decode one RangeTree row's canonical home-leaf pile."""
    held, blobs = decode_pile(
        verified_object(entry.leaf, fetch), workspace)
    keys = [key(fact) for fact in held]
    if blobs or not keys or keys != sorted(set(keys)) \
            or entry.sep != keys[0] \
            or len(_chunks(keys, fid_of)) != 1:
        raise ValueError("manifest range")
    return held


def build(keys, fact_of, deps_of, emit):
    """Full canonical rebuild; repair/cutover reference for ``update``."""
    entries = [
        _range(chunk, fact_of, deps_of, emit)
        for chunk in _chunks(sorted(set(keys)), fid_of)
    ]
    return entries, encode(entries, emit)


def changed_ranges(
        root, keys, fetch, workspace, *, removed=(), refreshed=()):
    """Return the authenticated local windows affected by one eligibility delta.

    ``keys`` are additions, ``removed`` are old resident keys, and
    ``refreshed`` keep their residence but require new fact/closure bytes.
    Removing a content-derived boundary joins only its leaf and immediate
    successor; every other transition touches one home leaf. Independent
    windows remain independent, so this never enumerates the RangeTree.
    """
    if not root:
        raise ValueError("missing RangeTree")
    supplied = tuple(keys)
    old = tuple(removed)
    refresh = tuple(refreshed)
    if any(
            not is_key(item)
            for item in (*supplied, *old, *refresh)):
        raise ValueError("changed range key")
    additions = tuple(sorted(set(supplied)))
    removals = tuple(sorted(set(old)))
    refreshes = tuple(sorted(set(refresh)))
    if set(additions) & set(removals) \
            or set(additions) & set(refreshes) \
            or set(removals) & set(refreshes):
        raise ValueError("overlapping range change")
    if not additions and not removals and not refreshes:
        return ()
    reader = merkle_map.Reader(root, RANGE_SEED, fetch)
    members = {}
    parent = {}
    assignments = []

    def member_keys(found):
        if found.sep not in members:
            members[found.sep] = tuple(
                key(fact) for fact in range_members(
                    found, fetch, workspace))
        return members[found.sep]

    def add_node(sep):
        parent.setdefault(sep, sep)
        return sep

    def find(sep):
        root_sep = sep
        while parent[root_sep] != root_sep:
            root_sep = parent[root_sep]
        while parent[sep] != sep:
            next_sep = parent[sep]
            parent[sep] = root_sep
            sep = next_sep
        return root_sep

    def join(left, right):
        left, right = find(add_node(left)), find(add_node(right))
        if left != right:
            parent[right] = left

    def checked_home(item):
        before_row, after_row = reader.neighbors(item)
        before = _entry(*before_row) if before_row else None
        after = _entry(*after_row) if after_row else None
        before_keys = member_keys(before) if before is not None else ()
        if before is None or item not in before_keys:
            raise ValueError("changed range is not resident")
        return before, after

    def successor(found):
        page = reader.range_page(
            found.sep, "\uffff", after=found.sep, limit=1)
        return _entry(*page.rows[0]) if page.rows else None

    for item in removals:
        home, after = checked_home(item)
        node = add_node(home.sep)
        assignments.append((node, (), (item,)))
        if boundary(fid_of(item)):
            if after is not None and after.sep == home.sep:
                after = successor(home)
            successor = after.sep if after is not None else None
            if after is not None:
                member_keys(after)
            join(node, successor)

    for item in refreshes:
        home, _ = checked_home(item)
        node = add_node(home.sep)
        assignments.append((node, (), ()))

    for item in additions:
        before_row, after_row = reader.neighbors(item)
        before = _entry(*before_row) if before_row else None
        after = _entry(*after_row) if after_row else None
        before_keys = member_keys(before) if before is not None else ()
        if before is not None and item in before_keys:
            raise ValueError("changed range already present")
        if before is None:
            home = after
        elif item <= before_keys[-1]:
            home = before
        elif after is not None:
            if not boundary(fid_of(before_keys[-1])):
                raise ValueError("manifest range boundary")
            home = after
        else:
            home = before \
                if not boundary(fid_of(before_keys[-1])) else None
        if home is not None:
            member_keys(home)
        node = add_node(home.sep if home else None)
        assignments.append((node, (item,), ()))

    groups = {}
    for sep in parent:
        group = groups.setdefault(
            find(sep), {"old": set(), "keys": set()})
        if sep is not None:
            group["old"].add(sep)
            group["keys"].update(members[sep])
    for node, added, removed_keys in assignments:
        group = groups[find(node)]
        if not set(removed_keys) <= group["keys"] \
                or set(added) & group["keys"]:
            raise ValueError("inconsistent range change")
        group["keys"].difference_update(removed_keys)
        group["keys"].update(added)

    replacements = [
        RangeReplacement(
            tuple(sorted(group["old"])),
            tuple(sorted(group["keys"])),
        )
        for group in groups.values()
    ]
    return tuple(sorted(
        replacements,
        key=lambda change: (
            change.old_seps[0] if change.old_seps
            else change.keys[0] if change.keys else "\uffff",
        ),
    ))


def update(root, ranges, fact_of, deps_of, fetch, emit):
    """Encode authenticated range replacements into the wire RangeTree."""
    if not root:
        raise ValueError("missing RangeTree")
    changes = {}
    replacements = tuple(ranges)
    if any(not isinstance(change, RangeReplacement)
           for change in replacements):
        raise ValueError("manifest replacement")
    old_seps = [
        sep for change in replacements for sep in change.old_seps]
    if len(old_seps) != len(set(old_seps)) \
            or any(not is_key(sep) for sep in old_seps):
        raise ValueError("manifest separator")
    for old_sep in old_seps:
        changes[old_sep] = None
    inserted = set()
    for replacement in replacements:
        keys = replacement.keys
        if tuple(sorted(set(keys))) != keys \
                or any(not is_key(item) for item in keys):
            raise ValueError("manifest replacement keys")
        for chunk in _chunks(keys, fid_of):
            entry = _range(chunk, fact_of, deps_of, emit)
            if entry.sep in inserted:
                raise ValueError("overlapping manifest replacement")
            inserted.add(entry.sep)
            changes[entry.sep] = _value(entry)
    return merkle_map.update(
        root, RANGE_SEED, sorted(changes.items()), fetch,
        lambda raw: _put(raw, emit)).root


def locate(entries, key):
    """The home-leaf entry for ``key`` (bisect on ``sep``); local, no I/O."""
    at = bisect_right(entries, key, key=lambda e: e.sep)
    return entries[at - 1] if at else None


def compare(mine, theirs, fetch):
    """Remote RangeTree rows and the exact mappings not held locally.

    The two current authenticated roots are diffed in bounded resumable pages;
    stale immutable pages outside the local root are never pruning evidence.
    This compatibility wrapper consumes the pages because the current sync
    turn still expects the complete entry vector.
    """
    held = {entry.sep: entry for entry in mine}
    local_objects = {}
    local_root = encode(
        mine,
        lambda raw: local_objects.setdefault(h(raw), raw),
    )
    local = merkle_map.Reader(local_root, RANGE_SEED, local_objects.get)
    remote_objects = {}

    def remote_fetch(oid):
        if oid not in remote_objects:
            remote_objects[oid] = fetch(oid)
        return remote_objects[oid]

    remote = merkle_map.Reader(theirs, RANGE_SEED, remote_fetch)

    def differing(reader, other):
        cursor, out = None, []
        while True:
            page = reader.diff_page(other, after=cursor)
            out.extend(page.differing)
            if page.cursor is None:
                return tuple(out)
            cursor = page.cursor

    remote_rows = differing(remote, local)
    local_rows = differing(local, remote)
    remote_changes = dict(remote_rows)
    rows = {
        sep: _value(entry)
        for sep, entry in held.items()
    }
    rows.update(remote_changes)
    for sep, _ in local_rows:
        if sep not in remote_changes:
            rows.pop(sep, None)
    entries = sorted(_entry(*row) for row in rows.items())
    return entries, [
        entry for entry in entries if held.get(entry.sep) != entry]


def closure_keys(members, deps_of, key_of):
    """Sorted transitive dependency keys not resident in this exact leaf."""
    inside = {fact.fid for fact in members}
    seen, stack = set(), [f.fid for f in members]
    while stack:
        fid = stack.pop()
        if fid in seen:
            continue
        seen.add(fid)
        stack.extend(deps_of(fid))
    return sorted(key_of(fid) for fid in seen - inside)


def fetch_plan(entries, missing_keys):
    """Group missing dep keys by home leaf: the second (final) wave of a
    cold-partial closure fetch, as ``{leaf_oid: [keys]}``."""
    plan = {}
    for k in sorted(set(missing_keys)):
        home = locate(entries, k)
        if home:
            plan.setdefault(home.leaf, []).append(k)
    return plan


def encode(entries, emit):
    """Bulk-build the canonical authenticated RangeTree."""
    checked = [_entry(entry.sep, _value(entry)) for entry in entries]
    rows = tuple((entry.sep, _value(entry)) for entry in checked)
    return merkle_map.build(
        rows, RANGE_SEED, lambda raw: _put(raw, emit)).root


def decode(raw, fetch):
    """Decode and validate every RangeTree entry."""
    root = h(raw)
    rooted = lambda oid: raw if oid == root else fetch(oid)
    return [
        _entry(*row) for row in
        merkle_map.Reader(root, RANGE_SEED, rooted).items()
    ]


def encode_root(
        anchor, manifest_oid, *, action_etag=None, layout_seed=None, trees=None):
    """The mutable root — the only non-content-addressed fact-layer key:

        canon({"anchor": ..., "manifest": <transport manifest oid or "">,
               "action_etag": <non-authoritative sync cache key>,
               "trees": {fact, supp, authority},
               "stamp": LAYOUT})

    Suppression and action evidence live in the authenticated logical trees;
    there is deliberately no duplicate summary or removal object."""
    layout_seed = layout_seed or h(canon(
        ["composite-layout-seed-v1", anchor]))
    trees = trees or {
        name: {"root": "", "count": 0, "depth": 0}
        for name in TREE_NAMES
    }
    action_etag = action_etag or h(canon(["active-actions-v1", []]))
    return canon({
        "action_etag": action_etag,
        "anchor": anchor,
        "layout_seed": layout_seed,
        "manifest": manifest_oid or "",
        "stamp": LAYOUT,
        "trees": trees,
    })


def decode_root(raw):
    """Decode and validate one published snapshot.

    Any malformed shape or foreign stamp is the wholesale-rebuild trigger;
    there is deliberately no compatibility path.
    """
    o = decode_json(raw, MAX_ROOT_BYTES, "root")
    if not isinstance(o, dict) or o.get("stamp") != LAYOUT:
        raise ValueError("root stamp")
    trees = o.get("trees")
    if not (set(o) == {
                "action_etag", "anchor", "layout_seed", "manifest", "stamp",
                "trees"}
            and valid_fid(o.get("action_etag"))
            and valid_fid(o.get("anchor"))
            and valid_fid(o.get("layout_seed"))
            and isinstance(o.get("manifest"), str)
            and (not o["manifest"] or valid_fid(o["manifest"]))
            and _trees_ok(trees)):
        raise ValueError("root shape")
    return Root(
        o["anchor"],
        o["manifest"],
        o["layout_seed"],
        {name: dict(trees[name]) for name in TREE_NAMES},
        o["action_etag"],
    )


def _trees_ok(trees):
    return isinstance(trees, dict) and set(trees) == set(TREE_NAMES) \
        and all(
            isinstance(value, dict)
            and set(value) == {"root", "count", "depth"}
            and isinstance(value["root"], str)
            and (not value["root"] or valid_fid(value["root"]))
            and type(value["count"]) is int and value["count"] >= 0
            and type(value["depth"]) is int
            and 0 <= value["depth"] <= MAX_TREE_DEPTH
            and bool(value["root"]) == bool(value["count"])
            for value in trees.values()
        )
