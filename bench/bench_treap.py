"""Prototype cost comparison: the content-defined binary Merkle treap
(tinyp2p.treap) vs the flat fence layout (tinyp2p.layout on main).

On identical real workspaces, in FLAT mode (COLD_CUT=None) so both cut the same
content-defined leaves, we measure:

  * full build time      — the "rebuild the whole tree on mint" cost, each layout.
  * incremental fold      — to absorb a batch of scattered (old-ts) new facts:
                            store objects READ (old leaves consumed) and WRITTEN
                            (new leaves + spine), by structural diff of the leaf
                            and internal hash sets before/after. Plus wall time,
                            and the flat layout's write count for the same batch.
  * correctness           — treap leaves == flat leaves (byte identical), and the
                            blind incremental update == a full rebuild (identical
                            leaf AND spine hash sets).

Run:  python3 bench/bench_treap.py               # 5k/20k/50k
      python3 bench/bench_treap.py 5000 100000   # explicit scales
"""
import gc
import json
import os
import random
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tinyp2p.shape as shape
from tinyp2p import treap as T
from tinyp2p.kernel import resolve_deps
from tinyp2p.layout import layout

from bench.bench_sync import YEARS, WORK, build_seed, bulk_author

perf = time.perf_counter


def _walk(node, leaves, internals):
    if node["leaf"]:
        if node["n"]:
            leaves.add(node["hash"])
    else:
        internals.add(node["hash"])
        _walk(node["L"], leaves, internals)
        _walk(node["R"], leaves, internals)


def hsets(node):
    lv, iv = set(), set()
    _walk(node, lv, iv)
    return lv, iv


def measure(scale, batch_msgs):
    d = os.path.join(WORK, f"treap_{scale}")
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
            dc[fid] = resolve_deps(fact_of(fid), idx) or []
        return dc[fid]

    # ---- full builds (rebuild-on-mint cost) ----
    t0 = perf()
    man, flat_objs = layout(keys, fact_of, deps_of, ws, gl, None)
    flat_build = perf() - t0
    t0 = perf()
    root, tr_objs = T.build(keys, fact_of, deps_of)
    treap_build = perf() - t0
    flat_leaf_hashes = {k[4:] for k in flat_objs}  # strip "obj/" prefix
    leaves_ok = flat_leaf_hashes == set(tr_objs)
    old_lv, old_iv = hsets(root)
    P = len(old_lv)

    # ---- author a scattered (old-ts) batch, then fold it in ----
    lo_ts = idx.execute("SELECT MIN(ts) FROM facts").fetchone()[0]
    window = YEARS * 365 * 24 * 3600 * 1000
    bulk_author(seed, ws, [(seed.sk, seed.pk)], batch_msgs,
                lo_ts, window, random.Random(99), "d")
    new_keys = seed.keys(ws)
    delta = sorted(set(new_keys) - set(keys))

    # flat incremental (memo = reuse unchanged fences), writes = objects re-emitted
    memo = {f["hi"]: f for f in json.loads(man)["fences"]}
    t0 = perf()
    _, flat_objs2 = layout(new_keys, fact_of, deps_of, ws, gl, memo)
    flat_upd = perf() - t0
    flat_wr = len(flat_objs2)

    # treap incremental (blind), reads/writes from the leaf/spine hash diff
    fresh = {}
    t0 = perf()
    root2 = T.update(root, delta, fact_of, deps_of, fresh)
    treap_upd = perf() - t0
    new_lv, new_iv = hsets(root2)
    reads = len(old_lv - new_lv)          # old leaves consumed
    writes = len(new_lv - old_lv)         # new leaf piles emitted
    spine = len(new_iv - old_iv)          # internal nodes on the touched paths

    # correctness: blind update == full rebuild (leaves AND spine)
    root_full, _ = T.build(new_keys, fact_of, deps_of)
    incr_ok = hsets(root2) == hsets(root_full)

    del seed
    gc.collect()
    shutil.rmtree(d, ignore_errors=True)
    return {"facts": len(keys), "P": P, "flat_build": flat_build,
            "treap_build": treap_build, "leaves_ok": leaves_ok,
            "B": len(delta), "reads": reads, "writes": writes, "spine": spine,
            "flat_wr": flat_wr, "treap_upd": treap_upd, "flat_upd": flat_upd,
            "incr_ok": incr_ok}


def main():
    args = [int(a) for a in sys.argv[1:] if a.isdigit()]
    scales = args or [5000, 20000, 50000]
    batch = 250  # 250 msgs -> 500 scattered facts folded in
    shape.COLD_CUT = None  # flat leaves == treap leaves
    os.makedirs(WORK, exist_ok=True)
    print("\n=== TREAP (binary Merkle) vs FLAT layout — "
          f"CUT={shape.CUT}, COLD_CUT=None ===")
    print(f"    100 members / {YEARS}y / fold batch = {batch} scattered msgs "
          f"({batch * 2} facts)\n")
    cols = ("facts", "P", "flatBuild", "treapBuild", "leaves=",
            "B", "rd", "wr", "spine", "flatWr", "treapUpd", "flatUpd", "incr=")
    print("  {:>7} {:>6} {:>9} {:>10} {:>6}  {:>5} {:>4} {:>4} {:>5} {:>6} {:>9} {:>8} {:>5}"
          .format(*cols))
    for scale in scales:
        r = measure(scale, batch)
        print("  {:>7} {:>6} {:>8.2f}s {:>9.2f}s {:>6}  {:>5} {:>4} {:>4} {:>5} "
              "{:>6} {:>8.3f}s {:>7.3f}s {:>5}".format(
                  r["facts"], r["P"], r["flat_build"], r["treap_build"],
                  "y" if r["leaves_ok"] else "N",
                  r["B"], r["reads"], r["writes"], r["spine"], r["flat_wr"],
                  r["treap_upd"], r["flat_upd"], "y" if r["incr_ok"] else "N"))
        sys.stdout.flush()
    print()


if __name__ == "__main__":
    main()
