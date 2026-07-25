"""PROTOTYPE — the content-defined binary Merkle treap (Leaf(pile) | Node).

This is the structure the design discussion converged on, in its simplest
runnable form, so its cost can be measured against `tinyp2p.layout` (the flat
fence list on `main`).

Shape vs identity, kept apart on purpose:

  * SHAPE is a pure function of the in-range key set. Leaves are the *same*
    content-defined chunks the flat layout cuts — a key ends a chunk iff
    `boundary(fid)` (its own hash mod CUT). The chunks are arranged into a
    binary tree by a treap over the boundary keys, priority = the boundary's
    full fid hash (≈unique, uniform ⇒ balanced in expectation, O(log) depth).
    Because both the chunk edges and the tree shape read only each key's own
    hash, the layout is history-independent and a mid-set insert perturbs only
    the one root-to-leaf path.

  * IDENTITY is the content hash, bottoming out in pile bytes:
        leaf.hash  = h(pile bytes)              # facts(range) + closure
        node.hash  = h("N" | sep | L.hash | R.hash)
    So "download the piles whose bytes changed" is a tree diff on these hashes,
    and a closure-only change (a fork provider appearing) moves the hash without
    moving the shape — the intended re-fetch signal for range-scoped sync.

`build` is a full (from-empty) layout; `update` is the blind incremental one:
descend routing the new keys, rebuild only the leaves they land in (grow, or
split at the boundary), and rebuild a whole subtree only when a new boundary
key out-ranks the separator above it (the treap "rotate up", bounded to that
subtree). Everything else is reused by hash without being read.
"""
import sys

from .close import close, encode_pile
from .crypto import h
from .shape import boundary, fid_of, priority

sys.setrecursionlimit(200000)  # random-treap depth is O(log n); headroom for tails


def _emit_leaf(ks, fact_of, deps_of, objects):
    """One closed pile: the chunk's in-range facts plus their closure, exactly
    as the flat layout's emit_range — so a chunk with the same fids hashes to
    the same object on both."""
    pile = close([fact_of(fid_of(k)) for k in ks], deps_of, fact_of)
    pb = encode_pile(pile)
    hh = h(pb)
    objects[hh] = pb
    return {"leaf": True, "ks": ks, "n": len(ks), "hash": hh}


def build(keys, fact_of, deps_of):
    """Full build. Returns (root, objects) with objects = {hash: pile bytes}
    for every leaf. Pure function of the key set."""
    keys = list(keys)
    objects = {}
    # priority per position, -1 for non-boundary keys (never chosen as separator)
    prio = [
        priority(fid) if boundary(fid) else -1
        for fid in map(fid_of, keys)
    ]

    def rec(a, b):
        # separator = highest-priority boundary strictly inside [a, b) (exclude
        # the last position b-1 so both sides stay non-empty)
        best, bpri = -1, -1
        for i in range(a, b - 1):
            if prio[i] > bpri:
                bpri, best = prio[i], i
        if best < 0:  # no interior boundary ⇒ this chunk is a leaf
            return _emit_leaf(keys[a:b], fact_of, deps_of, objects)
        sep = keys[best]
        L = rec(a, best + 1)      # keys ≤ sep
        R = rec(best + 1, b)      # keys > sep
        hh = h(("N|" + sep + "|" + L["hash"] + "|" + R["hash"]).encode())
        return {"leaf": False, "sep": sep, "n": b - a, "hash": hh, "L": L, "R": R}

    root = rec(0, len(keys)) if keys else {"leaf": True, "ks": [], "n": 0, "hash": h(b"")}
    return root, objects


def _leaf_keys(node):
    if node["leaf"]:
        return list(node["ks"])
    return _leaf_keys(node["L"]) + _leaf_keys(node["R"])


def update(node, delta, fact_of, deps_of, objects):
    """Blind incremental update. `delta` is a sorted list of NEW keys within
    `node`'s range. Untouched subtrees are returned verbatim (never read). The
    result is byte-identical to build(all keys) — verified in the bench."""
    if not delta:
        return node  # blind: whole subtree reused by hash, not read
    if node["leaf"]:
        sub, objs = build(sorted(node["ks"] + delta), fact_of, deps_of)
        objects.update(objs)
        return sub
    sep = node["sep"]
    # rotate-up: a new boundary key out-ranks this separator ⇒ the canonical
    # shape here changes, so rebuild this subtree from its own leaves + delta
    # (bounded to the subtree; still blind to everything outside it).
    maxp = max(
        (priority(fid_of(k)) for k in delta if boundary(fid_of(k))),
        default=-1,
    )
    if maxp > priority(fid_of(sep)):
        sub, objs = build(sorted(_leaf_keys(node) + delta), fact_of, deps_of)
        objects.update(objs)
        return sub
    dl = [k for k in delta if k <= sep]
    dr = [k for k in delta if k > sep]
    L = update(node["L"], dl, fact_of, deps_of, objects)
    R = update(node["R"], dr, fact_of, deps_of, objects)
    hh = h(("N|" + sep + "|" + L["hash"] + "|" + R["hash"]).encode())
    return {"leaf": False, "sep": sep, "n": L["n"] + R["n"], "hash": hh,
            "L": L, "R": R}


def live_hashes(node):
    """The leaf-pile hashes referenced by the current tree (what a store would
    need to hold), for cross-checking against a full rebuild."""
    if node["leaf"]:
        return {node["hash"]} if node["n"] else set()
    return live_hashes(node["L"]) | live_hashes(node["R"])
