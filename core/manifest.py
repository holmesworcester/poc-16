"""Manifest spine: a content-addressed index of home-leaf piles.

One entry per leaf: ``(sep, leaf, closure)`` — the leaf's first key, the oid
of its pile (``encode_pile`` of the members, canonical key order: the same
codec the wire uses), and the oid of its closure sibling (the keys of the
members' transitive closure that fall outside the leaf's key range; ``""``
when empty). Entries shard into manifest objects by the same
``shape.boundary`` rule that cuts the leaves, giving depth 0-2 at any
realistic corpus. Equal content means equal oid (layout is canonical and
history-independent), so **oid comparison is the entire one-sided diff** —
no fingerprints, no n-counts, no per-node key arrays. The composite root and
cost posture are described in DESIGN.md.

Determinism contract: every function of the committed key set is a pure
function of that set. ``prev`` inputs only memoize — they may skip work,
never change an output byte (see ``build`` for the closure precondition
that makes the one memo sound).
"""
import json
from bisect import bisect_right
from typing import NamedTuple

from .btreap import MAX_PAGE_DEPTH as MAX_TREE_DEPTH
from .close import encode_pile
from .crypto import h
from .fact import canon
from .shape import fid_of, is_key, key, stable_cut_positions, valid_fid

# The one format identity. Written into the root; checked by decode_root.
# A mismatch is a ValueError => the store rebuilds wholesale (no read-compat
# path exists. Replaces the pre-cutover tree configuration.
LAYOUT = "composite-btreap-v3"
TREE_NAMES = ("fact", "supp", "authority")


class Entry(NamedTuple):
    """One home leaf: first key, pile oid, closure-sibling oid ("" if none)."""
    sep: str
    leaf: str
    closure: str


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


def build(keys, fact_of, deps_of, emit, prev=(), *, changed=None):
    """Settle the store: cut ``keys`` into leaves by ``shape.boundary``,
    emit each leaf pile (``close.encode_pile``, canonical key order) and its
    closure sibling, shard the entry list by the same rule, and return
    ``(entries, root_oid)``.

    ``prev`` is the previous commit's entries: a chunk whose pile oid is
    unchanged skips the closure walk and reuses its old ``closure`` oid. The
    pile is always re-encoded — that re-encoding is what proves the member
    set unchanged. Output is byte-identical with or without ``prev`` over a
    closed key set (every member's deps committed) — the only kind a store
    ever settles.
    """
    # Memo by pile oid: equal oid IS equal member set. Over a committed key
    # set the sibling is then a pure function of that set — closure keys are
    # committed keys and the chunks partition every committed key, so the
    # only thing a shifted ``lo`` can move across is a gap holding none.
    known = {e.leaf: e.closure for e in prev}
    previous = {e.sep: e for e in prev}
    changed = None if changed is None else set(changed)
    loaded, entries, lo = {}, [], ""
    key_of = lambda fid: key(loaded.get(fid) or fact_of(fid))
    for chunk in _chunks(sorted(set(keys)), fid_of):
        if changed is not None and not changed.intersection(chunk) \
                and chunk[0] in previous:
            entries.append(previous[chunk[0]])
            lo = chunk[-1]
            continue
        members = [fact_of(fid_of(k)) for k in chunk]
        loaded = {f.fid: f for f in members}
        leaf = _put(encode_pile(members), emit)
        if leaf in known:
            closure = known[leaf]
        else:
            out = closure_keys(members, deps_of, key_of, lo, chunk[-1])
            closure = _put(canon({"keys": out}), emit) if out else ""
        entries.append(Entry(chunk[0], leaf, closure))
        lo = chunk[-1]
    return entries, encode(entries, emit)


def locate(entries, key):
    """The home-leaf entry for ``key`` (bisect on ``sep``); local, no I/O."""
    at = bisect_right(entries, key, key=lambda e: e.sep)
    return entries[at - 1] if at else None


def diff(mine, theirs, fetch):
    """One-sided diff by oid: walk ``theirs`` top-down, prune subtrees whose
    oid we already hold, and return the entries whose leaf piles must be
    fetched (which includes leaves where only *we* have extra keys — the
    caller compares key sets for the push direction). Separator agreement is
    checked where it can be — in ``_rows``, over shards actually read; a
    pruned subtree is never fetched, so there is nothing to align it against.
    The walk is bounded by the objects the peer really serves: ``_shard``
    decodes each oid once."""
    held = {e.leaf for e in mine}
    encode(mine, lambda raw: held.add(h(raw)))  # our own shard oids
    out, stack, seen = [], [theirs], set()
    while stack:
        oid = stack.pop()
        if not oid or oid in held:  # equal content, equal oid: prune
            continue
        shard = _shard(oid, fetch, seen)
        if "shards" in shard:
            stack += [child for _, child in _list(shard, "shards", 2)]
        else:
            out += [e for e in _rows(shard, fetch, seen)
                    if e.leaf not in held]
    return sorted(out)


def closure_keys(members, deps_of, key_of, lo, hi):
    """Sorted keys of the members' transitive closure outside ``(lo, hi]`` —
    everything a reader of this range must fetch from elsewhere. Transitive,
    so a fetch plan over these keys never needs a third wave."""
    seen, stack = set(), [f.fid for f in members]
    while stack:
        fid = stack.pop()
        if fid in seen:
            continue
        seen.add(fid)
        stack.extend(deps_of(fid))
    return sorted(k for k in map(key_of, seen) if not lo < k <= hi)


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
    """Canonical manifest bytes: ``canon({"entries": [[sep, leaf, closure],
    ...]})`` per shard, ``canon({"shards": [[sep, oid], ...]})`` per branch
    level, sharded when ``shape.boundary`` says so; emits shard objects and
    returns the root shard's oid."""
    level = [
        (chunk[0].sep if chunk else "",
         _put(canon({"entries": [list(e) for e in chunk]}), emit))
        for chunk in _chunks(entries, lambda e: fid_of(e.sep)) or [[]]
    ]
    while len(level) > 1:
        groups = _chunks(level, lambda s: fid_of(s[0]))
        if len(groups) == len(level):  # every sep a boundary: one root
            groups = [level]
        level = [
            (g[0][0], _put(canon({"shards": [list(s) for s in g]}), emit))
            for g in groups
        ]
    return level[0][1]


def _shard(oid, fetch, seen):
    """One manifest object, hash-verified at the door and decoded at most
    once: a canonical manifest never repeats a shard (separators are unique,
    so equal content cannot occur twice), and a repeat is how a handful of
    hostile objects would otherwise expand into an unbounded walk."""
    if not valid_fid(oid):
        raise ValueError("manifest integrity")
    raw = fetch(oid)
    if raw is None or h(raw) != oid or oid in seen:
        raise ValueError("manifest integrity")
    seen.add(oid)
    return json.loads(raw)


def _list(shard, name, width):
    """One shard's rows — ``width`` strings each. Peer bytes leave this
    module as a ValueError or not at all: never a KeyError or a TypeError."""
    rows = shard.get(name) if isinstance(shard, dict) else None
    if not isinstance(rows, list) or not all(
            isinstance(row, list) and len(row) == width
            and all(isinstance(part, str) for part in row) for row in rows):
        raise ValueError("manifest shape")
    return rows


def _rows(shard, fetch, seen):
    """Entries under one shard, depth-first; separators must agree."""
    if not isinstance(shard, dict):
        raise ValueError("manifest shape")
    if "shards" not in shard:
        rows = [Entry(*row) for row in _list(shard, "entries", 3)]
        if any(
                not is_key(row.sep) or not valid_fid(row.leaf)
                or row.closure and not valid_fid(row.closure)
                for row in rows):
            raise ValueError("manifest entry")
        return rows
    out = []
    for sep, oid in _list(shard, "shards", 2):
        if not is_key(sep) or not valid_fid(oid):
            raise ValueError("manifest shard")
        rows = _rows(_shard(oid, fetch, seen), fetch, seen)
        if not rows or rows[0].sep != sep:
            raise ValueError("manifest separator")
        out += rows
    return out


def decode(raw, fetch):
    """Entries back out of a root shard, resolving child shards via
    ``fetch``, with integrity (oid) and sort-order checks."""
    out = _rows(json.loads(raw), fetch, set())
    if any(a.sep >= b.sep for a, b in zip(out, out[1:])):
        raise ValueError("manifest order")
    return out


def encode_root(
        anchor, globals_, manifest_oid, *,
        action_summary=None, layout_seed=None, trees=None):
    """The mutable root — the only non-content-addressed fact-layer key:

        canon({"anchor": ..., "globals": [[name, value], ...],
               "manifest": <transport manifest oid or "">,
               "trees": {fact, supp, authority},
               "stamp": LAYOUT})

    Suppression and action evidence live in the authenticated logical trees;
    there is deliberately no separately published removal object."""
    layout_seed = layout_seed or h(canon(
        ["composite-layout-seed-v1", anchor]))
    trees = trees or {
        name: {"root": "", "count": 0, "depth": 0}
        for name in TREE_NAMES
    }
    action_summary = action_summary or {
        "count": 0,
        "digest": h(canon(["action-set-v1", []])),
    }
    return canon({
        "actions": action_summary,
        "anchor": anchor,
        "globals": sorted([list(row) for row in globals_]),
        "layout_seed": layout_seed,
        "manifest": manifest_oid or "",
        "stamp": LAYOUT,
        "trees": trees,
    })


def decode_root(raw):
    """``(anchor, globals_, manifest_oid)`` back out of root bytes;
    raises ValueError on any malformation or on ``stamp != LAYOUT`` (the
    rebuild trigger — there is deliberately no other answer)."""
    o = json.loads(raw)
    if not isinstance(o, dict) or o.get("stamp") != LAYOUT:
        raise ValueError("root stamp")
    rows = o.get("globals")
    trees = o.get("trees")
    action_summary = o.get("actions")
    if not (set(o) == {
                "actions", "anchor", "globals", "layout_seed", "manifest",
                "stamp", "trees"}
            and valid_fid(o.get("anchor"))
            and valid_fid(o.get("layout_seed"))
            and isinstance(o.get("manifest"), str)
            and (not o["manifest"] or valid_fid(o["manifest"]))
            and isinstance(rows, list)
            and all(isinstance(row, list) and len(row) == 2
                    and all(isinstance(part, str) for part in row)
                    for row in rows)
            and isinstance(action_summary, dict)
            and set(action_summary) == {"count", "digest"}
            and type(action_summary["count"]) is int
            and action_summary["count"] >= 0
            and valid_fid(action_summary["digest"])
            and _trees_ok(trees)):
        raise ValueError("root shape")
    return (
        o["anchor"],
        frozenset(tuple(row) for row in rows),
        o["manifest"],
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


def decode_composite(raw):
    """Return ``(layout_seed, tree descriptors)`` after the root door."""
    decode_root(raw)
    value = json.loads(raw)
    return value["layout_seed"], {
        name: dict(value["trees"][name]) for name in TREE_NAMES
    }
