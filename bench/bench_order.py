"""Does a dependency-aligned key order collapse the multi-level range-sync tax?

Three orders over the SAME facts (only the sort prefix changes; fid, deps,
closure, tree shape-by-hash are all unchanged):
  ts     : key = ts (the shipped order) -> each member's facts scattered over 3y
  author : group each fact by its signer pk, then ts -> joins/msgs/sigs contiguous
  deleg  : DFS preorder of the invite tree; invites grouped by INVITEE -> each
           member's whole downstream delegation subtree contiguous
For each: leaf-only rho, ML full-sync redundancy, and the range-sync tax +
LO/ML redundancy at a 1-leaf / small / large subtree, plus global over-inclusion.
"""
import os, shutil, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tinyp2p.layout as L
from tinyp2p import hoist as H
from tinyp2p.kernel import resolve_deps
from bench.bench_sync import WORK, build_seed


def author_of(f):
    pk = f.body.get("pk")
    if pk:
        return pk
    for name, a0, a1 in f.offers():   # signature: ("author", target, pk)
        if name == "author":
            return a1
    return "zz" + f.fid[:8]


def invitee_of(f):
    for name, a0, a1 in f.offers():   # invite: ("invitee", invitee_pk, "")
        if name == "invitee":
            return a0
    return None


def closure(kfids, deps_of):
    seen, stack = set(), list(kfids)
    while stack:
        x = stack.pop()
        if x in seen:
            continue
        seen.add(x)
        stack.extend(deps_of(x))
    return seen


def leaves_of(root):
    out = []
    def rec(nd):
        if nd["leaf"]:
            out.append(nd)
        else:
            rec(nd["L"]); rec(nd["R"])
    rec(root)
    return out


def subtree_counts(root):
    """Per node: leaves under it, facts settled in its subtree, and facts
    settled strictly above it (the range-sync tax for pulling its leaves)."""
    info = {}
    def rec(nd, anc_pay):
        if nd["leaf"]:
            lv, inpay = 1, nd["n"]
        else:
            lv = 0; inpay = nd["n"]
            for c in (nd["L"], nd["R"]):
                rec(c, anc_pay + nd["n"])
                lv += info[id(c)][0]; inpay += info[id(c)][1]
        info[id(nd)] = (lv, inpay, anc_pay)
    rec(root, 0)
    return info


def measure(scale, order, fids, fact_of, deps_of, rank):
    keys = [f"{rank[f]:09d}:{f}" for f in fids]
    root, _ = H.build(keys, fact_of, deps_of)
    sfids = sorted(fids, key=lambda f: rank[f])
    leaves = leaves_of(root)
    V = len(fids)

    # leaf-only closures over THIS order's leaf grouping -> rho and N(f)
    cnt = {}
    leafC = []
    for lf in leaves:
        c = closure(sfids[lf["a"]:lf["b"]], deps_of)
        leafC.append(c)
        for x in c:
            cnt[x] = cnt.get(x, 0) + 1
    P = len(leaves)
    leaf_total = sum(cnt.values())
    rho = leaf_total / V

    # ML settle subtree size per fact -> over-inclusion
    info = subtree_counts(root)
    lu = {}                                   # leaves under each node
    def annotate(nd):
        lu[id(nd)] = info[id(nd)][0]
        if not nd["leaf"]:
            annotate(nd["L"]); annotate(nd["R"])
    annotate(root)
    over_num = over_den = 0
    for nd in H.walk(root):
        for x in nd["pay"]:
            need = cnt.get(x, 1)
            ride = lu[id(nd)]
            over_den += ride
            over_num += ride - need
    over_pct = 100 * over_num / over_den

    # range-sync tax at ~1 / small / large / full subtree sizes
    leaf_index = {id(lf): i for i, lf in enumerate(leaves)}
    rows = []
    targets = [1, max(2, P // 512), max(4, P // 64), P // 2, P]
    picked = set()
    for tgt in targets:
        best = min((nd for nd in H.walk(root)),
                   key=lambda nd: abs(info[id(nd)][0] - tgt))
        if id(best) in picked:
            continue
        picked.add(id(best))
        lvs, inpay, ancpay = info[id(best)]
        # leaf indices spanned by this subtree
        sub_leaves = [lf for lf in leaves
                      if best["a"] <= lf["a"] < best["b"]]
        lo_facts = sum(len(leafC[leaf_index[id(lf)]]) for lf in sub_leaves)
        ml_total = inpay + ancpay
        rows.append((lvs, lo_facts, inpay, ancpay, ml_total,
                     (lo_facts / ml_total) if ml_total else 0))
    return {"order": order, "V": V, "P": P, "rho": rho, "over": over_pct, "rows": rows}


def build_orders(fids, fact_of):
    facts = {f: fact_of(f) for f in fids}
    # delegation tree from invites
    parent, invitees = {}, {}
    for f, fo in facts.items():
        if fo.t == "invite":
            inv = invitee_of(fo)
            invitees[f] = inv
            parent[inv] = author_of(fo)          # invitee_pk -> inviter_pk
    members = {author_of(fo) for fo in facts.values()}
    founders = [m for m in members if m not in parent]
    kids = {}
    for c, p in parent.items():
        kids.setdefault(p, []).append(c)
    dfs, seen = [], set()
    stack = list(founders)
    while stack:
        m = stack.pop()
        if m in seen:
            continue
        seen.add(m); dfs.append(m)
        stack.extend(sorted(kids.get(m, []), reverse=True))
    for m in members:
        if m not in seen:
            dfs.append(m)
    didx = {m: i for i, m in enumerate(dfs)}

    def member_author(f):
        return author_of(facts[f])

    def member_deleg(f):
        fo = facts[f]
        return invitee_of(fo) if fo.t == "invite" else author_of(fo)

    ts = {f: facts[f].ts for f in fids}
    rank_ts = {f: i for i, f in enumerate(sorted(fids, key=lambda f: (ts[f], f)))}
    rank_au = {f: i for i, f in enumerate(
        sorted(fids, key=lambda f: (member_author(f), ts[f], f)))}
    rank_dl = {f: i for i, f in enumerate(
        sorted(fids, key=lambda f: (didx.get(member_deleg(f), 1 << 30), ts[f], f)))}
    return {"ts": rank_ts, "author": rank_au, "deleg": rank_dl}


def main():
    scale = int(sys.argv[1]) if len(sys.argv) > 1 else 50000
    L.COLD_CUT = None
    d = os.path.join(WORK, f"order_{scale}")
    shutil.rmtree(d, ignore_errors=True)
    seed, ws, _ = build_seed(os.path.join(d, "seed"), scale)
    idx = seed.idx(ws)
    dc = {}
    def fact_of(fid):
        return seed.fact_of(ws, fid)
    def deps_of(fid):
        if fid not in dc:
            dc[fid] = resolve_deps(fact_of(fid), idx) or []
        return dc[fid]
    fids = [k.split(":", 1)[1] for k in seed.keys(ws)]
    ranks = build_orders(fids, fact_of)

    print(f"\n=== key-order effect on the multi-level range-sync tax  (V={len(fids)}) ===\n")
    for order in ("ts", "author", "deleg"):
        r = measure(scale, order, fids, fact_of, deps_of, ranks[order])
        print(f"[{order:6}] P={r['P']:5}  leaf-only rho={r['rho']:.2f}x  "
              f"ML full-sync=1.00x  over-inclusion={r['over']:.1f}%")
        print("         {:>7} {:>9} {:>7} {:>6} {:>9} {:>8}".format(
            "leaves", "LO_facts", "ML_in", "tax", "ML_total", "LO/ML"))
        for lvs, lo, inpay, anc, tot, rd in r["rows"]:
            print("         {:>7} {:>9} {:>7} {:>6} {:>9} {:>7.2f}x".format(
                lvs, lo, inpay, anc, tot, rd))
        print()
    shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
