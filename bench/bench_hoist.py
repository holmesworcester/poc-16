"""Measure the quantity multi-level piles remove: dependency-closure redundancy.

Leaf-only piles store, per leaf, the full closure of that leaf's in-range keys.
A fact needed by k leaves is therefore stored k times. Define, over the same
content-defined leaves the flat/treap layout cuts:

    N(f) = # leaves whose closure contains fact f
    rho  = sum_f N(f) / |V|            # leaf-only redundancy (each fact avg N times)

Multi-level piles store each fact exactly ONCE (at settle(f) = LCA of the leaves
that need it), so their full-sync total is |V| and rho -> 1. This script reports
rho, the N(f) distribution, and settle spans (in leaf-index units) on a real
workspace, so the analytic claims in docs/MULTILEVEL_PILE.md sit on measured ground.

Run:  python3 bench/bench_hoist.py            # 50k (matches RESULTS.md flat 3.1x)
      python3 bench/bench_hoist.py 5000 50000
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.shape as shape
from core import treap as T
from core.kernel import resolve_deps

from bench.bench_sync import WORK, build_seed


def _closure_fids(kfids, deps_of):
    """Transitive dependency closure of a leaf's key fids, as a fid set."""
    seen, stack = set(), list(kfids)
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        stack.extend(deps_of(f))
    return seen


def measure(scale):
    d = os.path.join(WORK, f"hoist_{scale}")
    shutil.rmtree(d, ignore_errors=True)
    seed, ws, _ = build_seed(os.path.join(d, "seed"), scale)
    idx = seed.idx(ws)
    keys = seed.keys(ws)
    gl = seed.globals(ws)
    dc = {}

    def fact_of(fid):
        return seed.fact_of(ws, fid)

    def deps_of(fid):
        if fid not in dc:
            dc[fid] = [x for x in (resolve_deps(fact_of(fid), idx) or [])]
        return dc[fid]

    # the content-defined leaves (same cut as the flat layout), in key order
    root, _ = T.build(keys, fact_of, deps_of)
    leaves = []

    def _collect(node):
        if node["leaf"]:
            if node["n"]:
                leaves.append([shape.fid_of(k) for k in node["ks"]])
        else:
            _collect(node["L"])
            _collect(node["R"])
    _collect(root)

    V = len({shape.fid_of(k) for k in keys})     # distinct facts
    P = len(leaves)                                   # leaves
    # N(f) and settle span [min,max] leaf index, via one pass over leaf closures
    cnt, lo, hi = {}, {}, {}
    for i, lf in enumerate(leaves):
        for f in _closure_fids(lf, deps_of):
            cnt[f] = cnt.get(f, 0) + 1
            if f not in lo:
                lo[f], hi[f] = i, i
            else:
                if i < lo[f]:
                    lo[f] = i
                if i > hi[f]:
                    hi[f] = i

    leaf_total = sum(cnt.values())            # sum_f N(f) = leaf-only stored facts
    rho = leaf_total / V
    own_only = sum(1 for f in cnt if cnt[f] == 1)          # settle at own leaf
    to_root = sum(1 for f in cnt if lo[f] == 0 and hi[f] == P - 1)
    maxN = max(cnt.values())
    # settle "height": leaves spanned; log2 ~ tree depth it rises to
    import math
    spans = [hi[f] - lo[f] + 1 for f in cnt]
    avg_span = sum(spans) / len(spans)
    # hoisted full-sync download = |V| (once each); leaf-only = leaf_total
    return {"scale": scale, "V": V, "P": P, "rho": rho,
            "leaf_total": leaf_total, "own_only": own_only, "own_pct": own_only / V,
            "to_root": to_root, "maxN": maxN, "avg_span": avg_span,
            "avg_leaf_facts": leaf_total / P,
            "hoist_saving": 1 - V / leaf_total}


def main():
    args = [int(a) for a in sys.argv[1:] if a.isdigit()]
    scales = args or [50000]
    shape.COLD_CUT = None  # flat fine leaves, so rho matches RESULTS.md sec.3
    os.makedirs(WORK, exist_ok=True)
    print("\n=== closure redundancy the multi-level pile removes  "
          f"(CUT={shape.CUT}, flat) ===\n")
    print("  {:>7} {:>7} {:>6} {:>6} {:>10} {:>9} {:>8} {:>8} {:>9}".format(
        "facts", "leaves", "avg/lf", "rho", "leafTotal", "own-leaf%", "toRoot", "maxN", "hoist-save"))
    for s in scales:
        r = measure(s)
        print("  {:>7} {:>7} {:>6.1f} {:>5.2f}x {:>10} {:>8.1f}% {:>8} {:>8} {:>8.1f}%".format(
            r["V"], r["P"], r["avg_leaf_facts"], r["rho"], r["leaf_total"],
            100 * r["own_pct"], r["to_root"], r["maxN"], 100 * r["hoist_saving"]))
        sys.stdout.flush()
    print()


if __name__ == "__main__":
    main()
