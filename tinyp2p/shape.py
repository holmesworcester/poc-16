"""The pure key discipline shared by every tree packing.

Everything the tree engine needs to know about WHERE a key lives — key format,
chunk boundaries, treap priority, cut tiers, range fingerprint — and nothing
about what a fact means. SIMPLIFY.md §1.

Absorbs (delete the originals in the same change):
    layout.CUT / COLD_CUT / GUARD / boundary / _cut_positions / fingerprint
    treap.priority / treap._fid        hoist.priority / hoist._fid
    node.keys' inline "{ts:015d}:{fid}" format      walk's key splitting

The engine (tree.py) is parametric over a Shape. Two planned instantiations:
    FACT          — the canonical set order, key "<ts:015d>:<fid>"
    supp_shape()  — T_supp, key "<suppkey>‖<tag>‖<ts>:<fid>", deletions at
                    tag=0 so a group's deletion sorts at its head
                    (DELETION_CLOSURE.md §3; production bead poc-16-yez.10)

"""
from dataclasses import dataclass
from typing import Callable

from .crypto import h

CUT = 8          # engine leaf density
COLD_CUT = 4096  # legacy flat facade: coarse cold-page density
GUARD = 256      # legacy flat facade: fine warm-zone width


def key(fact):
    """Canonical sort key "<ts:015d>:<fid>" (today inline in node.keys)."""
    return key_parts(fact.ts, fact.fid)


def key_parts(ts, fid):
    """Canonical key from an index row, without loading the fact body."""
    return f"{ts:015d}:{fid}"


def fid_of(k):
    """Inverse projection: the fid inside a key (treap._fid / hoist._fid)."""
    return k.rsplit(":", 1)[1]


def boundary(fid, cut=None):
    """A key ends a chunk iff its own hash mod cut == 0 (layout.boundary).
    Reads only the key's own hash => history independence."""
    return int(fid[:8], 16) % (cut or CUT) == 0


def priority(fid):
    """Treap priority of a boundary key: its full content hash as an int —
    uniform, ~unique => expected-balanced shape (treap.priority)."""
    return int(fid, 16)


def cut_positions(fids):
    """Legacy flat-layout positions, tiered:
    COLD_CUT pages below the last coarse boundary <= len-GUARD, the fine CUT
    window above it (layout._cut_positions, semantics verbatim)."""
    if not COLD_CUT:
        return [
            index + 1
            for index, fid in enumerate(fids)
            if boundary(fid)
        ]
    cold = [
        index + 1
        for index, fid in enumerate(fids)
        if boundary(fid, COLD_CUT)
    ]
    split = max(
        (position for position in cold if position <= len(fids) - GUARD),
        default=0,
    )
    return [position for position in cold if position <= split] + [
        index + 1
        for index, fid in enumerate(fids)
        if index + 1 > split and boundary(fid)
    ]


def stable_cut_positions(fids):
    """Monotone content cuts used by incremental trees.

    Unlike the legacy warm/cold flat layout, adding keys never removes one of
    these boundaries, so a fold can rebuild only the touched leaf and spine.
    """
    return [
        index + 1
        for index, fid in enumerate(fids)
        if boundary(fid)
    ]


def leaf_cut():
    """Current expected leaf width (kept callable for benchmark overrides)."""
    return CUT


def fingerprint(keys):
    """fp over the IN-RANGE keys in key order only — the diff identity.
    The closure lives in the pile but outside the fingerprinted set: fp is
    what the walk prunes on, oid (h(pile bytes)) is what you fetch by.
    Never conflate the two (SIMPLIFY.md §0)."""
    return h("|".join(keys).encode())


@dataclass(frozen=True)
class Shape:
    """The bundle tree.py is parametric over. Every member is a pure function of
    key/fid bytes — no store, no db, no globals."""
    key: Callable
    fid_of: Callable
    boundary: Callable
    priority: Callable
    fingerprint: Callable
    cuts: Callable = cut_positions
    cut: Callable = leaf_cut


FACT = Shape(
    key, fid_of, boundary, priority, fingerprint, stable_cut_positions,
    leaf_cut)


def supp_shape():
    """The T_supp instantiation (poc-16-yez.10): key
    "<suppkey>‖<tag>‖<ts>:<fid>", tag=0 for deletions so a suppression
    group's deletion sorts at its head; a range is one suppression key.
    Built HERE so yez.10 instantiates the engine, not the binary prototype
    that jbg.1 replaces (SIMPLIFY.md §3)."""
    raise NotImplementedError("poc-16-yez.10 — instantiate on the engine")
