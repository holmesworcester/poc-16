"""Canonical RangeTree over closed home-leaf piles.

One entry maps a leaf's first opaque canonical key to its pile oid and closure
sibling oid. The RangeTree uses the same persistent authenticated treap as the
Worker indexes: full build defines one history-independent root, while an
additions-only commit encodes SQLite-selected ranges and path-copies only its
tree paths. Equal RangeTree subtrees and equal leaf piles have equal oids, so
one-sided sync still prunes by oid alone.
"""
import json
from bisect import bisect_right
from typing import NamedTuple

from . import btreap
from .btreap import MAX_PAGE_DEPTH as MAX_TREE_DEPTH
from .close import decode_pile, encode_pile
from .crypto import h
from .fact import canon
from .shape import fid_of, is_key, key, stable_cut_positions, valid_fid
from .store import verified_object

# The one format identity. Written into the root; checked by decode_root.
# A mismatch is a ValueError => the store rebuilds wholesale (no read-compat
# path exists. Replaces the pre-cutover tree configuration.
LAYOUT = "composite-btreap-v5"
TREE_NAMES = ("fact", "supp", "authority")
RANGE_SEED = h(canon(["range-tree-v1"]))


class Entry(NamedTuple):
    """One home leaf: first key, pile oid, closure-sibling oid ("" if none)."""
    sep: str
    leaf: str
    closure: str


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


def range_members(entry, fetch):
    """Verify and decode one RangeTree row's canonical home-leaf pile."""
    held, blobs = decode_pile(verified_object(entry.leaf, fetch))
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


def update(root, changed_ranges, fact_of, deps_of, fetch, emit):
    """Encode SQLite-selected range replacements into the wire RangeTree."""
    if not root:
        raise ValueError("missing RangeTree")
    changes = {}
    for old_sep, keys in changed_ranges:
        if old_sep is not None:
            if not is_key(old_sep):
                raise ValueError("manifest separator")
            changes[old_sep] = None
        for chunk in _chunks(tuple(keys), fid_of):
            entry = _range(chunk, fact_of, deps_of, emit)
            changes[entry.sep] = _value(entry)
    return btreap.update(
        root, RANGE_SEED, sorted(changes.items()), fetch,
        lambda raw: _put(raw, emit)).root


def locate(entries, key):
    """The home-leaf entry for ``key`` (bisect on ``sep``); local, no I/O."""
    at = bisect_right(entries, key, key=lambda e: e.sep)
    return entries[at - 1] if at else None


def compare(mine, theirs, fetch):
    """Remote RangeTree rows and the exact mappings not held locally.

    Shared authenticated pages are decoded from the local object map, so the
    complete logical remote map is available without fetching those pages.
    """
    held = {entry.sep: entry for entry in mine}
    known = {}
    encode(mine, lambda raw: known.setdefault(h(raw), raw))
    rows = btreap.Reader(
        theirs, RANGE_SEED, fetch).items(known)
    entries = sorted(_entry(*row) for row in rows)
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
    return btreap.build(
        rows, RANGE_SEED, lambda raw: _put(raw, emit)).root


def decode(raw, fetch):
    """Decode and validate every RangeTree entry."""
    root = h(raw)
    rooted = lambda oid: raw if oid == root else fetch(oid)
    return [
        _entry(*row) for row in
        btreap.Reader(root, RANGE_SEED, rooted).items()
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
    o = json.loads(raw)
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
