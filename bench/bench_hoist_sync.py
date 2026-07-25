"""Measure the multi-level pile in action: the range-sync PATH TAX, verify-once
judge counts, and the over-inclusion residual — against the rho figures
MULTILEVEL_PILE.md predicts.

Leaf-only piles ship/judge each leaf's whole closure C(l); a fact needed by k
leaves is paid k times (rho ~ 3x, measured). The multi-level pile stores each
fact ONCE at settle(f) and validates down closed paths (Part A.2), so:

  * full sync ships/judges |V| once            -> redundancy rho -> 1.0
  * range sync (a subtree of s leaves) pays the facts settled INSIDE the
    subtree + the O(log n) ancestor-path payloads (the TAX) -> ADDITIVE, not
    multiplicative
  * verify-once judges each fact once = |V|, vs leaf-only Sum_l |C(l)| = rho|V|

Correctness gates (must all hold):
  * every root-to-node path union is dependency-closed              (A.2)
  * each fact stored exactly once: Sum_v |store(v)| = |V|
  * placement deterministic + history-independent (shuffle -> same hashes)
  * verify-once accepts EXACTLY the leaf-only accepted set
  * a scattered incremental fold == a full rebuild (identical hashes)

Run:  python3 bench/bench_hoist_sync.py            # 5k + 50k
      python3 bench/bench_hoist_sync.py 5000 20000
"""
import math
import os
import random
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tinyp2p.shape as shape
from tinyp2p import hoist
from tinyp2p.close import close, encode_pile
from tinyp2p.kernel import kernel, resolve_deps
from tinyp2p.shape import fid_of

from bench.bench_sync import WORK, YEARS, build_seed, bulk_author

def _closure(kfids, deps_of):
    seen, stack = set(), list(kfids)
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        stack.extend(deps_of(f))
    return seen


def _ctx(scale):
    """Build a seed workspace and the fact/deps accessors over it."""
    d = os.path.join(WORK, f"hsync_{scale}")
    shutil.rmtree(d, ignore_errors=True)
    seed, ws, _ = build_seed(os.path.join(d, "seed"), scale)
    idx = seed.idx(ws)
    fc, dc = {}, {}

    def fact_of(fid):
        if fid not in fc:
            fc[fid] = seed.fact_of(ws, fid)
        return fc[fid]

    def deps_of(fid):
        if fid not in dc:
            dc[fid] = resolve_deps(fact_of(fid), idx) or []
        return dc[fid]

    return d, seed, ws, fact_of, deps_of


# ---- assertions (Part A) ----------------------------------------------------

def assert_closed(root, deps_of):
    """A.2: every root-to-node path union is dependency-closed. Carry the
    accumulated path fid-set down, push/pop the payload."""
    ctx = set()

    def rec(nd):
        for f in nd["pay"]:
            for g in deps_of(f):
                assert g in ctx or g in nd["pay"], "path not closed"
        ctx.update(nd["pay"])
        if not nd["leaf"]:
            rec(nd["L"])
            rec(nd["R"])
        ctx.difference_update(nd["pay"])
    rec(root)


def assert_once(root, fids):
    total, union = 0, set()
    for nd in hoist.walk(root):
        total += len(nd["pay"])
        union.update(nd["pay"])
    assert total == len(fids) == len(union), \
        f"exactly-once broke: stored {total}, union {len(union)}, V {len(fids)}"


# ---- tree annotation --------------------------------------------------------

def annotate(root, objects, leaf_clen, leaf_cbytes):
    """One post-order pass: leaf-index span, leaf-count, subtree aggregates
    (multi-level once vs leaf-only with-dup), payload bytes. Then a top-down
    pass for the ancestor-path tax."""
    def post(nd):
        nd["selfb"] = len(objects[nd["ph"]]) if nd["pay"] else 0
        if nd["leaf"]:
            li = nd.get("li")
            if li is None:                       # empty leaf (no in-range keys)
                nd.update(nl=0, li_lo=None, li_hi=None,
                          mf=len(nd["pay"]), mb=nd["selfb"], lo=0, lb=0)
                return
            nd.update(nl=1, li_lo=li, li_hi=li,
                      mf=len(nd["pay"]), mb=nd["selfb"],
                      lo=leaf_clen[li], lb=leaf_cbytes[li])
            return
        post(nd["L"])
        post(nd["R"])
        a, b = nd["L"], nd["R"]
        los = [x for x in (a["li_lo"], b["li_lo"]) if x is not None]
        his = [x for x in (a["li_hi"], b["li_hi"]) if x is not None]
        nd.update(nl=a["nl"] + b["nl"],
                  li_lo=min(los) if los else None,
                  li_hi=max(his) if his else None,
                  mf=len(nd["pay"]) + a["mf"] + b["mf"],
                  mb=nd["selfb"] + a["mb"] + b["mb"],
                  lo=a["lo"] + b["lo"], lb=a["lb"] + b["lb"])
    # leaf indices, left-to-right
    li = 0
    for nd in hoist.walk(root):
        if nd["leaf"] and (nd["b"] - nd["a"]) > 0:
            nd["li"] = li
            li += 1
    post(root)

    def tax(nd, af, ab):
        nd["taxf"], nd["taxb"] = af, ab
        if not nd["leaf"]:
            tax(nd["L"], af + len(nd["pay"]), ab + nd["selfb"])
            tax(nd["R"], af + len(nd["pay"]), ab + nd["selfb"])
    tax(root, 0, 0)
    return li  # P


# ---- the range-sync path-tax table ------------------------------------------

def range_tax(root, P):
    """Bucket every subtree by leaf-count (power-of-two) and average the
    leaf-only vs multi-level range-sync cost. A range syncer pulling a subtree
    of s leaves pays: multi = facts settled inside + ancestor-path tax;
    leaf-only = Sum over those leaves of |C(l)| (with dup)."""
    buckets = {}
    for nd in hoist.walk(root):
        if nd is root or nd["nl"] == 0:
            continue
        k = 1 << (nd["nl"].bit_length() - 1)     # floor pow2 of leaf-count
        b = buckets.setdefault(k, [])
        mt = nd["mf"] + nd["taxf"]               # multi total facts
        b.append((nd["nl"], nd["lo"], nd["mf"], nd["taxf"], mt,
                  nd["lb"], nd["mb"] + nd["taxb"]))
    rows = []
    for k in sorted(buckets):
        v = buckets[k]
        n = len(v)
        mean = [sum(col) / n for col in zip(*v)]
        rows.append((mean[0], n, mean[1], mean[2], mean[3], mean[4],
                     mean[1] / mean[4] if mean[4] else 0, mean[5], mean[6]))
    return rows


# ---- over-inclusion ---------------------------------------------------------

def over_inclusion(root, cnt):
    """For each fact that hoists above its own leaf (settles at a node covering
    >1 leaf), what fraction of that settle-subtree does NOT need it:
    (leaves_under(settle) - N(f)) / leaves_under(settle)."""
    settle = {}
    for nd in hoist.walk(root):
        for f in nd["pay"]:
            settle[f] = nd
    fracs, wsum, wtot, root_over = [], 0.0, 0, []
    for f, nd in settle.items():
        nl = nd["nl"]
        if nl <= 1:
            continue                              # settles at own leaf: no hoist
        need = cnt.get(f, 1)
        frac = (nl - need) / nl
        fracs.append(frac)
        wsum += frac * nl
        wtot += nl
        if nd is root:
            root_over.append(frac)
    return {
        "hoisted": len(fracs),
        "mean": sum(fracs) / len(fracs) if fracs else 0.0,
        "leaf_weighted": wsum / wtot if wtot else 0.0,
        "root_mean": sum(root_over) / len(root_over) if root_over else 0.0,
        "root_facts": len(root_over),
    }


# ---- driver -----------------------------------------------------------------

def measure(scale):
    d, seed, ws, fact_of, deps_of = _ctx(scale)
    keys = sorted(seed.keys(ws))
    fids = [fid_of(k) for k in keys]
    V = len(fids)

    root, objects = hoist.build(keys, fact_of, deps_of)

    # --- Part A assertions ---
    assert_closed(root, deps_of)
    assert_once(root, fids)
    root_b, _ = hoist.build(keys, fact_of, deps_of)
    shuf = keys[:]
    random.Random(7).shuffle(shuf)
    root_s, _ = hoist.build(shuf, fact_of, deps_of)
    det_ok = root["hash"] == root_b["hash"]
    hist_ok = root["hash"] == root_s["hash"]
    assert det_ok and hist_ok, "placement not deterministic / history-independent"

    # --- leaves, closures, N(f) ---
    leaves = [nd for nd in hoist.walk(root) if nd["leaf"] and (nd["b"] - nd["a"]) > 0]
    leaf_fids = [[fids[i] for i in range(nd["a"], nd["b"])] for nd in leaves]
    leaf_clen, leaf_cbytes = [], []
    cnt, lo_li, hi_li = {}, {}, {}
    for li, lf in enumerate(leaf_fids):
        cl = _closure(lf, deps_of)
        leaf_clen.append(len(cl))
        leaf_cbytes.append(len(encode_pile(close([fact_of(f) for f in lf], deps_of, fact_of))))
        for f in cl:
            cnt[f] = cnt.get(f, 0) + 1
            if f not in lo_li:
                lo_li[f] = hi_li[f] = li
            else:
                lo_li[f] = min(lo_li[f], li)
                hi_li[f] = max(hi_li[f], li)
    leaf_total = sum(leaf_clen)
    rho = leaf_total / V
    P = annotate(root, objects, leaf_clen, leaf_cbytes)

    # --- verify-once vs leaf-only judge-ops (full catchup) ---
    vo = hoist.verify_once(root, ws, fact_of)
    verify_ok = vo["ok"] and vo["judged"] == set(fids) and vo["judge_ops"] == V
    # leaf-only accepted set: each leaf pile validates alone from empty
    leaf_accept = set()
    leaves_ok = True
    for lf in leaf_fids:
        pile = close([fact_of(f) for f in lf], deps_of, fact_of)
        if not kernel(pile, ws).ok:
            leaves_ok = False
        leaf_accept.update(f.fid for f in pile)
    same_set = leaf_accept == vo["judged"] == set(fids)

    # --- over-inclusion ---
    oi = over_inclusion(root, cnt)
    maxN = max(cnt.values())
    to_root = sum(1 for f in cnt if lo_li[f] == 0 and hi_li[f] == P - 1)

    # --- incremental fold == full rebuild (identical hashes) ---
    base_hashes = {nd["hash"] for nd in hoist.walk(root)}
    base_phs = {nd["ph"] for nd in hoist.walk(root)}
    base_obj_phs = {nd["ph"] for nd in hoist.walk(root) if nd["pay"]}
    lo_ts = seed.idx(ws).execute("SELECT MIN(ts) FROM facts").fetchone()[0]
    window = YEARS * 365 * 24 * 3600 * 1000
    bulk_author(seed, ws, [(seed.sk, seed.pk)], 250, lo_ts, window,
                random.Random(99), "d")
    new_keys = sorted(seed.keys(ws))
    new_fids = [fid_of(k) for k in new_keys]
    B = len(new_fids) - V
    root2, objs2 = hoist.build(new_keys, fact_of, deps_of)
    shuf2 = new_keys[:]
    random.Random(3).shuffle(shuf2)
    root2b, _ = hoist.build(shuf2, fact_of, deps_of)
    fold_ok = root2["hash"] == root2b["hash"]           # rebuild == rebuild(shuffled)
    new_obj_phs = {nd["ph"] for nd in hoist.walk(root2) if nd["pay"]}
    writes = len(new_obj_phs - base_obj_phs)            # payload objects rewritten
    reads = len(base_obj_phs - new_obj_phs)
    vo2 = hoist.verify_once(root2, ws, fact_of, base_hashes, base_phs)
    incr_judge = vo2["judge_ops"]                       # changed facts re-judged

    del seed
    shutil.rmtree(d, ignore_errors=True)
    return {
        "scale": scale, "V": V, "P": P, "rho": rho, "leaf_total": leaf_total,
        "avg_leaf": leaf_total / P, "maxN": maxN, "to_root": to_root,
        "obj_bytes": sum(len(b) for b in objects.values()),
        "leaf_bytes": sum(leaf_cbytes),
        "det_ok": det_ok, "hist_ok": hist_ok, "verify_ok": verify_ok,
        "leaves_ok": leaves_ok, "same_set": same_set, "fold_ok": fold_ok,
        "vo_judge": vo["judge_ops"], "oi": oi, "rows": range_tax(root, P),
        "B": B, "writes": writes, "reads": reads, "incr_judge": incr_judge,
        "n_nodes": sum(1 for _ in hoist.walk(root)),
    }


def report(r):
    V, P = r["V"], r["P"]
    print(f"\n================  {V} facts, {P} leaves, {r['n_nodes']} nodes  "
          f"(CUT={shape.CUT}, flat)  ================")
    print(f"  rho (leaf-only) = {r['rho']:.2f}x   avg facts/leaf = {r['avg_leaf']:.1f}   "
          f"maxN = {r['maxN']} ({100*r['maxN']/P:.0f}% of leaves)   "
          f"facts->root = {r['to_root']}")

    print("\n  ASSERTIONS")
    for name, ok in (("path-closed (A.2)", True), ("stored-once (Sum|store|=V)", True),
                     ("deterministic build", r["det_ok"]),
                     ("history-independent (shuffle)", r["hist_ok"]),
                     ("verify-once judged all V once", r["verify_ok"]),
                     ("every leaf validates alone", r["leaves_ok"]),
                     ("verify-once set == leaf-only set", r["same_set"]),
                     ("fold == full rebuild (hashes)", r["fold_ok"])):
        print(f"    [{'OK' if ok else 'FAIL'}]  {name}")

    print("\n  RANGE-SYNC PATH TAX   (facts == judge-ops; LO = leaf-only w/dup, "
          "ML = multi-level once)")
    print("    {:>7} {:>5} | {:>9} | {:>7} {:>6} {:>9} {:>7} | {:>9} {:>9}".format(
        "leaves", "nodes", "LO_facts", "ML_in", "tax", "ML_total", "redund",
        "LO_KB", "ML_KB"))
    for (nl, n, loF, mIn, tax, mT, red, loB, mB) in r["rows"]:
        print("    {:>7.0f} {:>5} | {:>9.0f} | {:>7.0f} {:>6.1f} {:>9.0f} {:>6.2f}x "
              "| {:>9.1f} {:>9.1f}".format(
                  nl, n, loF, mIn, tax, mT, red, loB / 1024, mB / 1024))
    print("    {:>7} {:>5} | {:>9} | {:>7} {:>6} {:>9} {:>6.2f}x | {:>9.1f} {:>9.1f}"
          .format("FULL", 1, r["leaf_total"], V, 0, V, r["rho"],
                  r["leaf_bytes"] / 1024, r["obj_bytes"] / 1024))

    print("\n  VERIFY-ONCE vs LEAF-ONLY  (full catchup, total kernel judge-ops)")
    print(f"    leaf-only  Sum_l |C(l)| = {r['leaf_total']:>9}  ({r['rho']:.2f}x)")
    print(f"    multi-lvl  verify-once  = {r['vo_judge']:>9}  (1.00x)  "
          f"-> {100*(1-V/r['leaf_total']):.1f}% fewer judge-ops")

    oi = r["oi"]
    print("\n  OVER-INCLUSION  (of a hoisted fact's settle-subtree, the fraction of "
          "leaves that do NOT need it)")
    print(f"    hoisted facts (settle above own leaf) = {oi['hoisted']}")
    print(f"    mean over-inclusion            = {100*oi['mean']:.1f}%")
    print(f"    leaf-weighted over-inclusion   = {100*oi['leaf_weighted']:.1f}%  "
          f"(what a range syncer actually over-downloads)")
    print(f"    facts settled at root ({oi['root_facts']})  = {100*oi['root_mean']:.1f}% over")

    print("\n  INCREMENTAL FOLD  (scattered batch of {} facts)".format(r["B"]))
    print(f"    payload objects rewritten (writes) = {r['writes']:>7}  of {r['n_nodes']} nodes"
          f"   (reads {r['reads']})")
    print(f"    verify re-judged (changed facts)   = {r['incr_judge']:>7}  of {V} "
          f"({100*r['incr_judge']/V:.1f}% of full)")
    sys.stdout.flush()


# ---- key-order comparison: does an author/delegation order collapse the tax? --

def owners(fids, fact_of):
    """Two ways to name the member a fact 'belongs to'.

      A = creator   — who signed it (msg/its sig -> author; join/its sig ->
                      joiner; invite/its sig -> the INVITER).
      B = beneficiary — whose membership it serves (an invite + its sig -> the
                      INVITED member, traced invite->join->pk).

    They differ only for invites/invite-sigs: created by the inviter but needed
    by the invited member's messages. In this fixture every member is invited
    directly by genesis (a depth-1 star), so ordering by beneficiary IS a DFS of
    the delegation tree — the two coincide here; a deep invite chain would need
    the real DFS."""
    import collections
    A, B, sig_tgt, inv_member = {}, {}, {}, {}
    for fid in fids:
        f = fact_of(fid)
        if f.t == "signature":
            _, tgt, pk = f.offers()[0]
            sig_tgt[fid], A[fid] = tgt, pk
        elif f.t == "user":
            A[fid] = f.body["pk"]
            inv_member[f.refs()[0][1]] = f.body["pk"]   # invite_fid -> joined member
        else:                                            # invite / msg / genesis
            A[fid] = f.body["pk"]
    for fid in fids:
        f = fact_of(fid)
        if f.t == "user_invite":
            B[fid] = inv_member.get(fid, f.body["pk"])
        elif f.t != "signature":
            B[fid] = f.body["pk"]
    for fid in fids:                                     # a sig belongs to its target
        if fid in sig_tgt:
            B[fid] = B.get(sig_tgt[fid], A[fid])
    return A, B


def keys_for(order, fids, fact_of):
    """Build the sort keys 'prefix:fid' for the requested linearization. `ts`
    reproduces production (primary=timestamp). `author`/`deleg` group a member's
    facts contiguously by creator / beneficiary."""
    if order == "ts":
        return sorted(f"{fact_of(fid).ts:015d}:{fid}" for fid in fids)
    A, Bm = owners(fids, fact_of)
    own = A if order.startswith("author") else Bm
    if order.endswith("+ts"):   # secondary = ts, so a msg sits next to its sig
        return sorted(f"{own[fid]}{fact_of(fid).ts:015d}:{fid}" for fid in fids)
    return sorted(f"{own[fid]}:{fid}" for fid in fids)


def profile(keys, fact_of, deps_of):
    """Light metrics for one key order (no verify/fold): leaf-only rho, the
    range-tax rows, over-inclusion, and what still settles high."""
    import collections
    fids = [fid_of(k) for k in keys]
    V = len(fids)
    root, objects = hoist.build(keys, fact_of, deps_of)
    assert_closed(root, deps_of)
    assert_once(root, fids)
    leaves = [nd for nd in hoist.walk(root) if nd["leaf"] and (nd["b"] - nd["a"]) > 0]
    leaf_fids = [[fids[i] for i in range(nd["a"], nd["b"])] for nd in leaves]
    leaf_clen, leaf_cbytes, cnt = [], [], {}
    for lf in leaf_fids:
        cl = _closure(lf, deps_of)
        leaf_clen.append(len(cl))
        leaf_cbytes.append(len(encode_pile(close([fact_of(f) for f in lf], deps_of, fact_of))))
        for f in cl:
            cnt[f] = cnt.get(f, 0) + 1
    leaf_total = sum(leaf_clen)
    P = annotate(root, objects, leaf_clen, leaf_cbytes)
    rows = range_tax(root, P)
    oi = over_inclusion(root, cnt)
    settle_nl = {}
    for nd in hoist.walk(root):
        for f in nd["pay"]:
            settle_nl[f] = nd["nl"]
    hi = [f for f, z in settle_nl.items() if z >= P / 2]

    def at(sz):
        c = [r for r in rows if r[0] >= sz]
        return c[0] if c else rows[-1]

    return {
        "V": V, "P": P, "rho": leaf_total / V, "leaf_total": leaf_total,
        "ml_save": 1 - V / leaf_total, "rows": rows, "oi": oi,
        "root_core": len(root["pay"]),
        "root_types": dict(collections.Counter(fact_of(f).t for f in root["pay"])),
        "hi_core": len(hi),
        "hi_types": dict(collections.Counter(fact_of(f).t for f in hi)),
        "one": rows[0], "small": at(20), "large": at(max(1, P // 4)),
    }


def compare_orders(scale):
    d, seed, ws, fact_of, deps_of = _ctx(scale)
    fids = [fid_of(k) for k in seed.keys(ws)]
    orders = [("ts (production)", "ts"), ("author (creator)", "author"),
              ("deleg (beneficiary)", "deleg"), ("deleg+ts (DAG)", "deleg+ts")]
    profs = [(name, profile(keys_for(o, fids, fact_of), fact_of, deps_of))
             for name, o in orders]
    V, P = profs[0][1]["V"], profs[0][1]["P"]
    print(f"\n############  KEY-ORDER COMPARISON  —  {V} facts (~{P} leaves), "
          f"100 members, star delegation  ############")

    print("\n  SUMMARY  (redund = leaf-only facts / multi-level facts; >1 ML wins, "
          "<1 ML loses)")
    print("    {:<20} {:>7} {:>8} {:>10} {:>10} {:>10} {:>9} {:>10} {:>10}".format(
        "order", "leaf-rho", "ML-save", "1leaf-red", "~20lf-red", "large-red",
        "over-lw", "root-core", "hi>=P/2"))
    for name, p in profs:
        print("    {:<20} {:>6.2f}x {:>7.1f}% {:>9.2f}x {:>9.2f}x {:>9.2f}x {:>8.1f}% "
              "{:>10} {:>10}".format(
                  name, p["rho"], 100 * p["ml_save"], p["one"][6], p["small"][6],
                  p["large"][6], 100 * p["oi"]["leaf_weighted"],
                  p["root_core"], p["hi_core"]))

    for name, p in profs:
        print(f"\n  --- {name} ---   root-core {p['root_core']} facts {p['root_types']}"
              f"   |   settle>=P/2: {p['hi_core']} facts {p['hi_types']}")
        print("    {:>7} {:>5} | {:>9} | {:>7} {:>7} {:>9} {:>7} | {:>9} {:>9}".format(
            "leaves", "nodes", "LO_facts", "ML_in", "tax", "ML_tot", "redund",
            "LO_KB", "ML_KB"))
        for (nl, n, loF, mIn, tax, mT, red, loB, mB) in p["rows"]:
            print("    {:>7.0f} {:>5} | {:>9.0f} | {:>7.0f} {:>7.1f} {:>9.0f} {:>6.2f}x "
                  "| {:>9.1f} {:>9.1f}".format(
                      nl, n, loF, mIn, tax, mT, red, loB / 1024, mB / 1024))
        print("    {:>7} {:>5} | {:>9} | {:>7} {:>7} {:>9} {:>6.2f}x | {:>9} {:>9}"
              .format("FULL", 1, p["leaf_total"], p["V"], 0, p["V"], p["rho"],
                      "-", "-"))
    del seed
    shutil.rmtree(d, ignore_errors=True)
    sys.stdout.flush()


def main():
    shape.COLD_CUT = None
    os.makedirs(WORK, exist_ok=True)
    args = [int(a) for a in sys.argv[1:] if a.isdigit()]
    if "order" in sys.argv:
        for s in (args or [50000]):
            compare_orders(s)
        print()
        return
    scales = args or [5000, 50000]
    for s in scales:
        report(measure(s))
    print()


if __name__ == "__main__":
    main()
