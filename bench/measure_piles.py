"""Measure pile/closure economics for docs/COSTS.md.

Builds real corpora through the ordinary ingress (Node + kernel), lays out
the production fat tree, and reports, per configuration:
  - fact bytes by family
  - "piles are full closure": per-leaf closed pile bytes and the ratio rho
  - member-only pile bytes and out-of-leaf dep home-leaf spread
  - warm-delta tail locality (leaves touched by 40 new messages)
Deterministic (fixed seed and timestamps). Node dirs and JSON output land in
a temp dir (or --out DIR). Usage: python3 bench/measure_piles.py [all|<tag>]
"""
import json
import os
import random
import sys
import tempfile
import time
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from core import tree
from core.close import close, encode_pile
from core.crypto import h
from core.fact import canon
from core.kernel import resolve_deps
from core.node import Node
from core.shape import FACT, fid_of
from facts.auth.workspace import create
from util import add_member, author_msg

WORDS = ("the quick brown fox jumps over lazy dog and then some more words "
         "for realistic message body lengths ok let us keep going a bit "
         "longer with plausible chat text here").split()

RUNS = {
    "flat-m8-n600": (8, "flat", 600),
    "flat-m8-n2400": (8, "flat", 2400),
    "flat-m32-n2400": (32, "flat", 2400),
    "chain-m32-n2400": (32, "chain", 2400),
}


def msg_text(rng):
    n = max(3, int(rng.lognormvariate(2.5, 0.8)))  # median ~12 words
    return " ".join(rng.choice(WORDS) for _ in range(n))


def build_corpus(path, members, shape, messages, seed=7):
    rng = random.Random(seed)
    node = Node(path)
    ts = 1000
    ws = create(node, "founder", ts=ts)
    founder = node.identity(ws)
    idents = [founder]
    for i in range(members):
        ts += 10
        inviter = founder if shape == "flat" else idents[-1]
        sk, pk, _ = add_member(node, ws, f"member-{i}", ts=ts, inviter=inviter)
        idents.append((sk, pk))
    weights = [1.0 / (i + 1) for i in range(len(idents))]  # zipf-ish authors
    chans, cweights = ["general", "random", "dev", "ops"], [8, 4, 2, 1]
    for _ in range(messages):
        ts += rng.randint(1, 40)
        sk, pk = rng.choices(idents, weights)[0]
        author_msg(node, ws, sk, pk, msg_text(rng), ts=ts,
                   chan=rng.choices(chans, cweights)[0])
    return node, ws, ts


def layout(node, ws):
    """Production tree.build with a dict emit; returns (view, objects, ...)."""
    objs = {}

    def emit(raw):
        oid = h(raw)
        objs[oid] = raw
        return oid

    idx = node.idx(ws)
    fact_of = lambda fid: node.fact_of(ws, fid)
    deps_of = lambda fid: resolve_deps(fact_of(fid), idx) or []
    view = tree.build(node.keys(ws), FACT, tree.FAT, fact_of, deps_of, emit)
    return view, objs, fact_of, deps_of


def leaves_of(view):
    out = []

    def rec(nd):
        if nd.level == 0:
            out.append(nd)
        else:
            for c in nd.children:
                rec(c)

    rec(view)
    return out


def measure(node, ws):
    view, objs, fact_of, deps_of = layout(node, ws)
    leaves = leaves_of(view)
    idx = node.idx(ws)

    fam_bytes, fam_count, body_len = defaultdict(int), defaultdict(int), {}
    for (fid,) in idx.execute("SELECT fid FROM facts"):
        f = fact_of(fid)
        raw = len(canon(f.to_json()))
        body_len[fid] = raw
        fam_bytes[f.t] += raw
        fam_count[f.t] += 1
    corpus_bytes = sum(body_len.values())

    leaf_of_key = {
        k: li for li, lf in enumerate(leaves) for k in lf.keys}

    per_leaf = []
    for lf in leaves:
        member_fids = [fid_of(k) for k in lf.keys]
        member_facts = [fact_of(fid) for fid in member_fids]
        closed = close(member_facts, deps_of, fact_of)
        mset = set(member_fids)
        closure_only = [f for f in closed if f.fid not in mset]
        homes, keyless = set(), 0
        for f in closure_only:
            k = FACT.key(f)
            if k is None or k not in leaf_of_key:
                keyless += 1
            else:
                homes.add(leaf_of_key[k])
        per_leaf.append({
            "members": len(member_fids),
            "member_pile": len(encode_pile(member_facts)),
            "closed_pile": len(encode_pile(closed)),
            "closure_facts": len(closure_only),
            "dep_home_leaves": len(homes),
            "keyless": keyless,
        })

    med = lambda xs: sorted(xs)[len(xs) // 2]
    closed_total = sum(p["closed_pile"] for p in per_leaf)
    member_total = sum(p["member_pile"] for p in per_leaf)
    return {
        "facts": len(body_len),
        "corpus_bytes": corpus_bytes,
        "families": {
            t: {"n": fam_count[t], "bytes": fam_bytes[t],
                "avg": fam_bytes[t] // max(1, fam_count[t])}
            for t in sorted(fam_count)
        },
        "leaves": len(leaves),
        "store_objects_main": len(objs),
        "store_bytes_main": sum(len(b) for b in objs.values()),
        "a_closed_pile_total": closed_total,
        "e_member_pile_total": member_total,
        "rho_vs_corpus": round(closed_total / corpus_bytes, 3),
        "rho_vs_members": round(closed_total / member_total, 3),
        "leaf_closed_bytes": {
            "median": med([p["closed_pile"] for p in per_leaf]),
            "max": max(p["closed_pile"] for p in per_leaf)},
        "leaf_member_bytes": {
            "median": med([p["member_pile"] for p in per_leaf]),
            "max": max(p["member_pile"] for p in per_leaf)},
        "closure_facts_per_leaf_median":
            med([p["closure_facts"] for p in per_leaf]),
        "dep_home_leaves_per_leaf": {
            "median": med([p["dep_home_leaves"] for p in per_leaf]),
            "max": max(p["dep_home_leaves"] for p in per_leaf)},
        "keyless_per_leaf_max": max(p["keyless"] for p in per_leaf),
        "view": view,
    }


def tail_locality(node, ws, ts, before_view, extra=40, seed=11):
    rng = random.Random(seed)
    sk, pk = node.identity(ws)
    for _ in range(extra):
        ts += rng.randint(1, 40)
        author_msg(node, ws, sk, pk, msg_text(rng), ts=ts, chan="general")
    after_view, _, _, _ = layout(node, ws)
    before = {lf.oid for lf in leaves_of(before_view)}
    after = [lf.oid for lf in leaves_of(after_view)]
    return {"extra_msgs": extra, "leaves_after": len(after),
            "changed_or_new_leaves": sum(1 for o in after if o not in before)}


def run(tag, out_dir):
    members, shape, messages = RUNS[tag]
    t0 = time.time()
    node, ws, ts = build_corpus(
        os.path.join(out_dir, f"node-{tag}"), members, shape, messages)
    built = time.time()
    m = measure(node, ws)
    view = m.pop("view")
    m["tail"] = tail_locality(node, ws, ts, view)
    m["build_s"] = round(built - t0, 1)
    m["measure_s"] = round(time.time() - built, 1)
    m["config"] = {"members": members, "shape": shape, "messages": messages}
    with open(os.path.join(out_dir, f"{tag}.json"), "w") as f:
        json.dump(m, f, indent=1)
    print(f"== {tag}: facts={m['facts']} corpus={m['corpus_bytes']/1e3:.0f}KB "
          f"leaves={m['leaves']} rho={m['rho_vs_corpus']}/{m['rho_vs_members']} "
          f"leafA_med={m['leaf_closed_bytes']['median']} "
          f"leafE_med={m['leaf_member_bytes']['median']} "
          f"depleaves_med={m['dep_home_leaves_per_leaf']['median']} "
          f"tail={m['tail']['changed_or_new_leaves']}/{m['tail']['leaves_after']} "
          f"({m['build_s']}s+{m['measure_s']}s)")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv \
        else tempfile.mkdtemp(prefix="poc16-bench-")
    print(f"output: {out}")
    for tag in (RUNS if which == "all" else [which]):
        run(tag, out)
