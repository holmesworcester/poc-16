"""PLAN SKELETON (poc-16-808.2, stage S1) — THE one recursion, written once, sans-io.

build / fold / diff / merge are the same simultaneous descent over two tree
views that prunes where identities agree (SIMPLIFY.md §0, the 8-row table).
This module is the extraction that EXECUTES poc-16-jbg.1 (fat nodes, drop the
flat manifest): land it with the BINARY and FLAT packings reproducing today's
treap.py / layout.py bytes under golden gates, then add the fat packing third.
jbg.2 = diff with a range-GET driver; jbg.4 = merge; the production T_supp
(yez.10) = a second Shape instantiation. After this lands, treap.py and
layout.py are deleted and hoist.py keeps only the span/settle math.

Sans-io: the engine does no I/O — drivers hand it callbacks
    fetch(oid) -> bytes            emit(obj_bytes) -> oid
Async-ness, HTTP, S3/R2, retries are driver properties. Test drivers are
dicts with read/write counters asserting the A(B,P)+spine floor
(TREAP_PROTOTYPE.md cost model).

Laws (tests/test_engine.py):
    fold(t, ()) == t
    fold(fold(t, a), b) byte-identical to build(set(t) ∪ a ∪ b), any batching
    diff(T(A), T(B)) == A Δ B, partitioned by leaves
    merge(A, B) == root(A ∪ B), reads O(diff)

The up-accumulator is committed by the CALLER's commit discipline (CAS root
today; append into roots/ + amortized merge under jbg.3) — the engine never
knows which.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class View:
    """One node as the engine sees it. Two identities, never conflated:
    fp  — diff identity, in-range keys only (prune on this);
    oid — storage identity, h(pile bytes) closure included (fetch by this).
    children == () for a leaf; child entries may be unresolved oids until the
    driver fetches them (lazy remote trees via store.RemoteStore)."""
    fp: str
    oid: str
    sep: str
    n: int
    children: tuple


@dataclass(frozen=True)
class Packing:
    """Arrangement parameter — same key set, three physical shapes:
        BINARY   F=2, chunked        today's treap.py bytes
        FLAT     F=∞, inlined spine  today's layout.py manifest bytes
        fat(F)   F≈32–256 nodes      jbg.1 (MST/prolly; the target)
    Golden gates: byte-identity WITHIN a packing across insert orders and
    fold batchings; identical leaf sets ACROSS packings.
    Optional settle hook = hoisting (hoist._spans/_settle absorbed): place
    each fact at LCA(span) instead of every leaf. None = leaves-are-piles."""
    fanout: int  # 0 = inlined flat spine


BINARY = Packing(fanout=2)
FLAT = Packing(fanout=0)


def fat(fanout=64):
    """The jbg.1 packing. Node-size / boundary-promotion rule lives here."""
    raise NotImplementedError("poc-16-jbg.1 / 808.2")


@dataclass(frozen=True)
class Root:
    """What rides the root object once the flat manifest is gone (jbg.1):
    the top View plus anchor + globals. The stateless mint reads anchor and
    globals from HERE (mint.root_globals); nothing may assume a flat fence
    list exists (SIMPLIFY.md §2). Under jbg.3, roots/ holds several of these
    and merge() folds them."""
    view: View
    anchor: str
    globals_: frozenset


def encode_root(root):
    raise NotImplementedError("poc-16-808.2")


def decode_root(b):
    raise NotImplementedError("poc-16-808.2")


def build(keys, shape, packing, fact_of, deps_of, emit):
    """Full build from ∅: a pure function of the key set (§0 table row 1).
    Replaces treap.build AND layout.layout — one build, N packings."""
    raise NotImplementedError("poc-16-808.2")


def fold(view, delta, shape, packing, fact_of, deps_of, fetch, emit):
    """Blind incremental fold (treap.update generalized): descend routing
    delta, rebuild only the leaves it lands in, rotate-up bounded to the
    subtree; untouched subtrees are reused by oid, never read. The ingress
    pile is the durable WAL; a push is a fold executed by someone else."""
    raise NotImplementedError("poc-16-808.2")


def diff(mine, theirs, shape, fetch_mine, fetch_theirs):
    """Simultaneous descent pruning on fp equality; yields, per differing
    leaf range, (lo, hi, my_keys, their_leaf). Drivers make it the sync walk
    (sync.py), the GET-only pruned walk (jbg.2), and the T_supp surfacing
    walk (yez.3). Guarantee: reads >= A(B,P) + spine and O(diff) beyond."""
    raise NotImplementedError("poc-16-808.2")


def merge(a, b, shape, packing, fetch, emit):
    """Two-root merge (jbg.4): root(set(a) ∪ set(b)) as an O(diff) tree-join
    — recurse only where fp differs, reuse whole subtrees by oid."""
    raise NotImplementedError("poc-16-jbg.4 / 808.2")


def verify(root, pad, fact_of, fetch, base_hashes=None, base_phs=None):
    """verify_once as an engine descent (§0 table row 6): the down-
    accumulator is a kernel.Scratchpad — push each node's payload, judge it
    EXACTLY ONCE, recurse, pop on backtrack. Replaces hoist.verify_once;
    judge-ops == |V| on cold catchup (tests/test_engine.py)."""
    raise NotImplementedError("poc-16-808.3")


def leaf_keys(view, fetch):
    raise NotImplementedError("poc-16-808.2")


def live_oids(view):
    """Objects the current tree references — the GC live set (generational
    sweep stays in the store layer, jbg's GC bead reads this)."""
    raise NotImplementedError("poc-16-808.2")
