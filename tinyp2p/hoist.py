"""PROTOTYPE — the multi-level pile: hoist each closure fact to its settle node.

Companion to `treap.py`. Same tree SHAPE (a content-defined binary Merkle
treap, BST over keys, boundary+priority), but a fact's BYTES no longer live in
every leaf whose closure needs it — they live ONCE, at

    settle(f) = LCA(N(f)) = the deepest node whose key-interval covers
    span(f) = [min, max] key-position over {f} ∪ dependents(f).

So a fact shared by k leaves is stored once at their meeting point instead of k
times, and — the theorem (MULTILEVEL_PILE.md A.2) — every root-to-node path is a
dependency-closed set. That is what lets `verify_once` validate as it descends:
a scratchpad = the accumulated ancestor payloads is already closed, so each
fact's deps are present the moment it is reached, and each fact is judged
EXACTLY ONCE, at its settle node, on behalf of every leaf below it.

Build (A.3): shape as in treap.py; spans in ONE reverse-topo pass over the dep
DAG (dependents before deps, O(V+E)); settle each fact by an O(log P) descent;
hash bottom-up over the pile bytes at every level. Placement is a pure function
of (keys, deps): deterministic and history-independent — keys are sorted at the
door, so any insertion order yields the identical tree, exactly as treap.py.

    node.hash = h("HN" | sep | ph | L.hash | R.hash)   (leaf: h("HL" | ph))
    ph        = h(encode_pile(payload)),  payload = facts settling at the node
"""
import sqlite3
import sys

from . import facts as _fam
from .close import encode_pile
from .crypto import h
from .kernel import SCHEMA, Context, proof_rank, resolve_deps
from .layout import CUT, boundary  # same fine boundary density as treap.py

sys.setrecursionlimit(200000)


def _fid(key):
    return key.split(":", 1)[1]


def priority(fid):
    return int(fid, 16)


# ---- Part A: the build ------------------------------------------------------

def _spans(fids, pos, deps_of):
    """span[f] = [min,max] key-position over {f} ∪ dependents(f), in ONE
    reverse-topo pass (a fact after every fact that depends on it). Kahn over
    the DAG whose edges point dependent -> dep: a fact is ready once all its
    dependents are emitted; emitting it releases one prerequisite of each dep."""
    span = {f: [pos[f], pos[f]] for f in fids}
    need = {f: 0 for f in fids}           # need[g] = |dependents(g)| still pending
    for f in fids:
        for g in deps_of(f):
            if g in need:
                need[g] += 1
    ready = [f for f in fids if need[f] == 0]
    seen = 0
    while ready:
        f = ready.pop()
        seen += 1
        lo, hi = span[f]
        for g in deps_of(f):
            if g not in need:
                continue
            s = span[g]
            if lo < s[0]:
                s[0] = lo
            if hi > s[1]:
                s[1] = hi
            need[g] -= 1
            if need[g] == 0:
                ready.append(g)
    assert seen == len(fids), "dependency DAG has a cycle"
    return span


def _shape(keys, prio):
    """The treap over the key positions — same separator rule as treap.py: the
    highest-priority interior boundary. Nodes carry their position interval so
    settle can be an interval-covering descent."""
    def rec(a, b):
        best, bp = -1, -1
        for i in range(a, b - 1):
            if prio[i] > bp:
                bp, best = prio[i], i
        if best < 0:
            return {"leaf": True, "a": a, "b": b, "pay": []}
        return {"leaf": False, "a": a, "b": b, "sep": best, "sepk": keys[best],
                "pay": [], "L": rec(a, best + 1), "R": rec(best + 1, b)}
    return rec(0, len(keys)) if keys else {"leaf": True, "a": 0, "b": 0, "pay": []}


def _settle(root, lo, hi):
    """Deepest node whose interval covers [lo,hi] (positions). left = [a,sep],
    right = [sep+1,b); a span straddling the separator settles here."""
    nd = root
    while not nd["leaf"]:
        s = nd["sep"]
        if hi <= s:
            nd = nd["L"]
        elif lo > s:
            nd = nd["R"]
        else:
            break
    return nd


def _order(pay, deps_of):
    """Deps-first order WITHIN a node's payload (co-settling deps only — every
    other dep sits at an ancestor, delivered by the path). So the payload judges
    front-to-back against the accumulated ancestor context."""
    inset, out, seen = set(pay), [], set()

    def emit(fid):
        if fid in seen:
            return
        seen.add(fid)
        for g in deps_of(fid):
            if g in inset:
                emit(g)
        out.append(fid)
    for fid in sorted(pay):
        emit(fid)
    return out


def _finalize(node, fact_of, deps_of, objects):
    node["pay"] = _order(node["pay"], deps_of)
    pb = encode_pile([fact_of(fid) for fid in node["pay"]])
    ph = h(pb)
    node["ph"], node["n"] = ph, len(node["pay"])
    if node["pay"]:
        objects[ph] = pb
    if node["leaf"]:
        node["hash"] = h(("HL|" + ph).encode())
    else:
        _finalize(node["L"], fact_of, deps_of, objects)
        _finalize(node["R"], fact_of, deps_of, objects)
        node["hash"] = h(("HN|" + node["sepk"] + "|" + ph + "|"
                          + node["L"]["hash"] + "|" + node["R"]["hash"]).encode())


def build(keys, fact_of, deps_of):
    """Multi-level pile over `keys`. Returns (root, objects) with objects =
    {ph: payload bytes} for every non-empty settle node. Pure function of
    (keys, deps): keys are sorted here, so input order is irrelevant."""
    keys = sorted(keys)
    fids = [_fid(k) for k in keys]
    pos = {f: i for i, f in enumerate(fids)}
    prio = [priority(f) if boundary(f) else -1 for f in fids]
    root = _shape(keys, prio)
    span = _spans(fids, pos, deps_of)
    for f in fids:
        lo, hi = span[f]
        _settle(root, lo, hi)["pay"].append(f)
    objects = {}
    _finalize(root, fact_of, deps_of, objects)
    return root, objects


# ---- tree helpers -----------------------------------------------------------

def walk(node):
    """Pre-order node stream."""
    yield node
    if not node["leaf"]:
        yield from walk(node["L"])
        yield from walk(node["R"])


def path_union(root, target):
    """Facts settled on the root->target path (target identified by object).
    Returns the accumulated fid list, in descent order."""
    acc = []

    def rec(nd):
        acc.extend(nd["pay"])
        if nd is target:
            return True
        if not nd["leaf"] and (rec(nd["L"]) or rec(nd["R"])):
            return True
        del acc[len(acc) - len(nd["pay"]):]
        return False
    rec(root)
    return acc


# ---- Part B: verify-once ----------------------------------------------------

def _judge(con, stream, anchor):
    """The kernel VALIDATE loop against a con already holding the ancestor
    context — mirrors kernel.kernel(mode=VALIDATE) without the txn wrapper so
    the caller can push/pop the path. Returns (ok, [accepted fids])."""
    ctx = Context(con, anchor)
    acc = []
    for f in stream:
        if con.execute("SELECT 1 FROM facts WHERE fid=?", (f.fid,)).fetchone():
            continue
        try:
            handler = _fam.handler_for(f.t)
            refs_seen = all(con.execute("SELECT 1 FROM facts WHERE fid=?", (fid,)).fetchone()
                            for _, fid in f.refs())
            deps = resolve_deps(f, con) if handler is not None and refs_seen else None
            good = deps is not None and handler.validate(f, ctx) is True
        except Exception:
            good = False
        if not good:
            return False, acc
        rank = proof_rank(con, deps)
        if rank is None:
            return False, acc
        con.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?)", (f.fid, f.ts, f.t))
        for name, a0, a1 in f.offers():
            con.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)", (name, a0, a1, f.fid))
        con.execute("INSERT OR IGNORE INTO proofs VALUES(?,?)", (f.fid, rank))
        acc.append(f.fid)
    return True, acc


def _insert(con, stream):
    """Materialize an already-verified payload as context, without re-judging."""
    n = 0
    for f in stream:
        if con.execute("SELECT 1 FROM facts WHERE fid=?", (f.fid,)).fetchone():
            continue
        deps = resolve_deps(f, con)
        rank = proof_rank(con, deps) if deps is not None else None
        if rank is None:
            raise ValueError("cached payload is not dependency-closed")
        con.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?)", (f.fid, f.ts, f.t))
        for name, a0, a1 in f.offers():
            con.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)", (name, a0, a1, f.fid))
        con.execute("INSERT OR IGNORE INTO proofs VALUES(?,?)", (f.fid, rank))
        n += 1
    return n


def _pop(con, fids):
    """Undo a node's payload on backtrack — memory stays O(depth·payload)."""
    con.executemany("DELETE FROM facts WHERE fid=?", [(f,) for f in fids])
    con.executemany("DELETE FROM offers WHERE src=?", [(f,) for f in fids])
    con.executemany("DELETE FROM proofs WHERE fid=?", [(f,) for f in fids])


def verify_once(root, anchor, fact_of, base_hashes=None, base_phs=None):
    """Descend top-down carrying a scratchpad = the verified ancestor pathUnion
    (closed, so every fact's deps are already present). Judge each node's
    payload EXACTLY ONCE, recurse, pop on backtrack.

    Incremental: skip any subtree whose node hash is in `base_hashes` (unchanged
    => already judged). On the changed spine, a payload whose ph is in
    `base_phs` is re-materialized as context but NOT re-judged, so judge-ops
    counts only genuinely changed facts. Full catchup (no baseline) judges each
    fact once: judge-ops = |V|."""
    con = sqlite3.connect(":memory:")
    con.executescript(SCHEMA)
    con.execute("BEGIN")
    st = {"judged": set(), "judge_ops": 0, "ctx_ops": 0, "skipped": 0, "ok": True}

    def rec(nd):
        if base_hashes is not None and nd["hash"] in base_hashes:
            st["skipped"] += 1
            return True                       # unchanged subtree: already judged
        stream = [fact_of(fid) for fid in nd["pay"]]
        if base_phs is not None and nd["ph"] in base_phs:
            st["ctx_ops"] += _insert(con, stream)   # unchanged payload on the spine
            acc = nd["pay"]
        else:
            ok, acc = _judge(con, stream, anchor)
            st["judge_ops"] += len(acc)
            st["judged"].update(acc)
            if not ok:
                st["ok"] = False
                _pop(con, acc)
                return False
        good = True
        if not nd["leaf"]:
            good = rec(nd["L"]) and rec(nd["R"])
        _pop(con, acc)
        return good

    st["ok"] = rec(root) and st["ok"]
    con.close()
    return st
