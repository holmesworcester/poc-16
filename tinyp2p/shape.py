"""PLAN SKELETON (poc-16-808.1, stage S1) — the key discipline as engine parameters.

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

Every body is unwritten on purpose: signatures + docstrings are the contract;
tests/test_engine.py names the acceptance criteria.
"""
from dataclasses import dataclass

CUT = 8          # fine/warm boundary density (canonical home after S1)
COLD_CUT = 4096  # coarse cold-page density below the guard watermark
GUARD = 256      # keep >= this many recent facts in the fine warm zone


def key(fact):
    """Canonical sort key "<ts:015d>:<fid>" (today inline in node.keys)."""
    raise NotImplementedError("poc-16-808.1")


def fid_of(k):
    """Inverse projection: the fid inside a key (treap._fid / hoist._fid)."""
    raise NotImplementedError("poc-16-808.1")


def boundary(fid, cut=None):
    """A key ends a chunk iff its own hash mod cut == 0 (layout.boundary).
    Reads only the key's own hash => history independence."""
    raise NotImplementedError("poc-16-808.1")


def priority(fid):
    """Treap priority of a boundary key: its full content hash as an int —
    uniform, ~unique => expected-balanced shape (treap.priority)."""
    raise NotImplementedError("poc-16-808.1")


def cut_positions(fids):
    """Boundary positions partitioning the sorted run into leaves, tiered:
    COLD_CUT pages below the last coarse boundary <= len-GUARD, the fine CUT
    window above it (layout._cut_positions, semantics verbatim)."""
    raise NotImplementedError("poc-16-808.1")


def fingerprint(keys):
    """fp over the IN-RANGE keys in key order only — the diff identity.
    The closure lives in the pile but outside the fingerprinted set: fp is
    what the walk prunes on, oid (h(pile bytes)) is what you fetch by.
    Never conflate the two (SIMPLIFY.md §0)."""
    raise NotImplementedError("poc-16-808.1")


@dataclass(frozen=True)
class Shape:
    """The bundle tree.py is parametric over. All five are pure functions of
    key/fid bytes — no store, no db, no globals."""
    key: callable
    fid_of: callable
    boundary: callable
    priority: callable
    fingerprint: callable


FACT = Shape(key, fid_of, boundary, priority, fingerprint)


def supp_shape():
    """The T_supp instantiation (poc-16-yez.10): key
    "<suppkey>‖<tag>‖<ts>:<fid>", tag=0 for deletions so a suppression
    group's deletion sorts at its head; a range is one suppression key.
    Built HERE so yez.10 instantiates the engine, not the binary prototype
    that jbg.1 replaces (SIMPLIFY.md §3)."""
    raise NotImplementedError("poc-16-yez.10 — instantiate on the engine")
