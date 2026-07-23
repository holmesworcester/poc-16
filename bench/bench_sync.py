"""Sync throughput benchmarks for tinyp2p.

Two questions, both answered against the *real* engine paths:

  catchup   A fresh node ingests a whole workspace from empty. This is the
            "download + ingestion" number: decode every published unit
            (annex ++ page), judge each through the kernel (parallel, own
            scratchpads — exactly what turn() does), merge by id, then one
            layout commit. facts/s here is directly comparable to the
            2000-5000 facts/s poc-7..13 have gotten.

  bidi      Two peers with shared membership and disjoint message sets do
            one one-sided walk (pull differing ranges as closed units, push
            the symmetric difference as one closed pile). Both converge; we
            measure the diff.

The seed is bulk-built (facts inserted straight into the index, one layout
at the end) so setup is O(n log n), not O(n^2) — building 500k facts by
replaying 250k turns would be hopeless. The measured paths are the honest
ones.

Run:   python3 bench/bench_sync.py                 # 5k/10k/50k/100k facts
       python3 bench/bench_sync.py 500000          # add the 500k run
       python3 bench/bench_sync.py 5000 10000      # explicit scales
"""
import gc
import json
import os
import random
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinyp2p import cmds, fact as F
from tinyp2p.close import close, decode_pile, encode_pile
from tinyp2p.fact import from_json
from tinyp2p.kernel import kernel, resolve_deps
from tinyp2p.layout import fingerprint
from tinyp2p.node import Node, now_ms

from tests.util import add_member, all_fids

WORK = os.environ.get("BENCH_DIR",
    "/mnt/storage/holmes-tmp/claude-1000/-home-holmes/"
    "2e3d3589-1ecc-43e9-bdec-47eb67d97e56/scratchpad/bench")
YEARS = 3
MEMBERS = 100
WORKERS = 8
BATCH = 256

perf = time.perf_counter


# ---- bulk seed building ------------------------------------------------------

def _insert(idx, fact):
    idx.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?,?)",
                (fact.fid, fact.ts, fact.t, json.dumps(fact.to_json())))
    for name, a0, a1 in fact.offers():
        idx.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
                    (name, a0, a1, fact.fid))


def build_members(node, ws, n_members, base_ts):
    """Genesis + (n_members-1) joins, each a real ingest so the membership
    closure is exactly what a live workspace holds."""
    members = [(node.sk, node.pk)]
    for i in range(n_members - 1):
        bsk, bpk, _ = add_member(node, ws, f"u{i}", base_ts + 1 + i)
        members.append((bsk, bpk))
    return members


def bulk_author(node, ws, members, n_msgs, first_ts, window, rng, tag=""):
    """Author n_msgs (msg + sig = 2 facts each) straight into the index,
    random member, ts uniform over `window`. No commit — caller lays out."""
    idx = node.idx(ws)
    idx.execute("BEGIN")
    for i in range(n_msgs):
        sk, pk = rng.choice(members)
        ts = first_ts + rng.randrange(window)
        f = F.msg(pk, "general", f"{tag}m{i}", ts)
        _insert(idx, F.sig_for(sk, pk, f, ts))
        _insert(idx, f)
    idx.commit()


def build_seed(node_dir, total_facts, n_members=MEMBERS, years=YEARS, seed=16):
    rng = random.Random(seed)
    n = Node(node_dir)
    t0 = perf()
    ws = cmds.create(n, "alice")
    base_ts = now_ms()
    window = years * 365 * 24 * 3600 * 1000
    members = build_members(n, ws, n_members, base_ts)
    base = n.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    n_msgs = max(0, (total_facts - base) // 2)
    t_auth = perf()
    bulk_author(n, ws, members, n_msgs, base_ts + n_members + 1, window, rng)
    t_layout = perf()
    n.commit(ws)  # one full layout over the whole set
    t_end = perf()
    total = n.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    return n, ws, {"members": n_members, "msgs": n_msgs, "facts": total,
                   "author_s": t_layout - t_auth, "layout_s": t_end - t_layout,
                   "setup_s": t_auth - t0}


# ---- unit streaming ----------------------------------------------------------

def manifest_objs(store):
    man = json.loads(store.get("root"))
    ohs = set()
    for fen in man["fences"] + [man["tail"]]:
        for oh in (fen.get("annex"), fen.get("page")):
            if oh:
                ohs.add(oh)
    return man, ohs


def seed_units(store, man):
    """Every published unit as the closed pile a walk would deliver:
    annex ++ page, in that (dep-first) order."""
    for fen in man["fences"] + [man["tail"]]:
        facts = []
        for oh in (fen.get("annex"), fen.get("page")):
            if oh:
                facts += decode_pile(store.get("obj/" + oh))[0]
        if facts:
            yield facts


def ingest(node, ws, units, workers=WORKERS, batch=BATCH):
    """decode is the caller's (serial, like turn); kernel is parallel; merge
    + materialize serial. Returns streamed-record count. No commit — caller
    lays out once at the end."""
    streamed = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        buf = []

        def flush(bb):
            for ok, vs, _ in ex.map(lambda u: kernel(u, ws), bb):
                assert ok, "a published unit failed the kernel"
                out, _ = node.merge(ws, vs)
                node.materialize(ws, out)

        for u in units:
            streamed += len(u)
            buf.append(u)
            if len(buf) >= batch:
                flush(buf)
                buf = []
        if buf:
            flush(buf)
    return streamed


# ---- the catchup benchmark ---------------------------------------------------

def catchup(seed, ws, fresh_dir):
    fresh = Node(fresh_dir)
    src = seed.store(ws)
    man, ohs = manifest_objs(src)
    dl_bytes = len(src.get("root")) + sum(len(src.get("obj/" + oh)) for oh in ohs)

    t0 = perf()
    streamed = ingest(fresh, ws, seed_units(src, man))
    fresh.commit(ws)
    t1 = perf()

    total = fresh.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    match = fresh.store(ws).get("root") == src.get("root")
    return {"ingest_s": t1 - t0, "facts": total, "streamed": streamed,
            "dl_bytes": dl_bytes, "objs": len(ohs), "match": match,
            "pages": len(man["fences"])}


# ---- the bidi benchmark ------------------------------------------------------

def copy_facts(dst, ws, src, fids):
    di, si = dst.idx(ws), src.idx(ws)
    di.execute("BEGIN")
    for fid in fids:
        row = si.execute("SELECT fid,ts,t,j FROM facts WHERE fid=?", (fid,)).fetchone()
        di.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?,?)", row)
        for name, a0, a1 in from_json(json.loads(row[3])).offers():
            di.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)", (name, a0, a1, fid))
    di.commit()


def reconcile(A, B, ws):
    """One one-sided dial, exactly as walk(): A prunes by fingerprint, pulls
    B's differing ranges as closed units, pushes the symmetric difference as
    one closed pile that B ingests. Both sides converge."""
    bstore = B.store(ws)
    man = json.loads(bstore.get("root"))
    ranges, lo = [], ""
    for fen in man["fences"]:
        ranges.append((lo, fen["hi"], fen))
        lo = fen["hi"]
    ranges.append((lo, "~", man["tail"]))

    lkeys = A.keys(ws)
    lfids = {k.split(":", 1)[1] for k in lkeys}

    t0 = perf()
    pulled, push_fids, pull_bytes = [], [], 0
    for lo, hi, fen in ranges:
        mine = [k for k in lkeys if lo < k <= hi]
        if fen["fp"] == fingerprint(mine):
            continue  # equal fingerprint, equal range — prune
        pageb = bstore.get("obj/" + fen["page"]) if fen.get("page") else None
        page = decode_pile(pageb)[0] if pageb else []
        rfids = {f.fid for f in page}
        if any(fid not in lfids for fid in rfids):
            annexb = bstore.get("obj/" + fen["annex"]) if fen.get("annex") else None
            annex = decode_pile(annexb)[0] if annexb else []
            pull_bytes += (len(pageb) if pageb else 0) + (len(annexb) if annexb else 0)
            pulled.append(annex + page)
        push_fids += [k.split(":", 1)[1] for k in mine
                      if k.split(":", 1)[1] not in rfids]

    ingest(A, ws, pulled)  # A absorbs B's half
    if pulled:
        A.commit(ws)

    push_bytes = 0
    if push_fids:
        idx = A.idx(ws)
        news = [A.fact_of(ws, fid) for fid in push_fids]
        facts = close(news, lambda fid: resolve_deps(A.fact_of(ws, fid), idx) or [],
                      lambda fid: A.fact_of(ws, fid))
        pile = encode_pile(facts)
        push_bytes = len(pile)
        ingest(B, ws, [decode_pile(pile)[0]])  # B absorbs A's half
        B.commit(ws)
    t1 = perf()

    match = A.store(ws).get("root") == B.store(ws).get("root")
    total = A.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    return {"recon_s": t1 - t0, "pulled_units": len(pulled),
            "pull_facts": sum(len(u) for u in pulled), "push_facts": len(push_fids),
            "pull_mb": pull_bytes / 1e6, "push_mb": push_bytes / 1e6,
            "facts": total, "match": match}


def bidi(total_facts, base_dir, n_members=MEMBERS, years=YEARS):
    A = Node(os.path.join(base_dir, "A"))
    ws = cmds.create(A, "alice")
    base_ts = now_ms()
    window = years * 365 * 24 * 3600 * 1000
    members = build_members(A, ws, n_members, base_ts)
    membership = all_fids(A, ws)

    B = Node(os.path.join(base_dir, "B"))
    copy_facts(B, ws, A, membership)

    per_side = max(1, (total_facts - len(membership)) // 4)  # msgs per side
    first = base_ts + n_members + 1
    bulk_author(A, ws, members, per_side, first, window, random.Random(1), "A")
    bulk_author(B, ws, members, per_side, first, window, random.Random(2), "B")
    A.commit(ws)
    B.commit(ws)
    a_facts = A.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    b_facts = B.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    st = reconcile(A, B, ws)
    st.update({"a_before": a_facts, "b_before": b_facts})
    return st


# ---- driver ------------------------------------------------------------------

def mb(b):
    return b / 1e6


def run_catchup(scales):
    print("\n=== CATCHUP: fresh node ingests a whole workspace from empty ===")
    print(f"    {MEMBERS} members, messages over {YEARS} years, {WORKERS} kernel "
          f"workers, CUT=8\n")
    hdr = ("target", "facts", "msgs", "pages", "seed_build",
           "dl_MB", "streamed", "redund", "ingest_s", "facts/s", "rec/s", "ok")
    print("  {:>7} {:>8} {:>7} {:>7} {:>10} {:>7} {:>9} {:>6} {:>9} {:>8} {:>8} {:>3}"
          .format(*hdr))
    for scale in scales:
        d = os.path.join(WORK, f"catchup_{scale}")
        shutil.rmtree(d, ignore_errors=True)
        seed, ws, bs = build_seed(os.path.join(d, "seed"), scale)
        r = catchup(seed, ws, os.path.join(d, "fresh"))
        build_s = bs["setup_s"] + bs["author_s"] + bs["layout_s"]
        print("  {:>7} {:>8} {:>7} {:>7} {:>9.1f} {:>7.1f} {:>9} {:>5.1f}x "
              "{:>9.2f} {:>8.0f} {:>8.0f} {:>3}".format(
                  scale, r["facts"], bs["msgs"], r["pages"], build_s,
                  mb(r["dl_bytes"]), r["streamed"], r["streamed"] / r["facts"],
                  r["ingest_s"], r["facts"] / r["ingest_s"],
                  r["streamed"] / r["ingest_s"],
                  "y" if r["match"] else "N"))
        sys.stdout.flush()
        del seed
        gc.collect()
        shutil.rmtree(d, ignore_errors=True)


def run_bidi(scales):
    print("\n=== BIDI: two peers, shared membership, disjoint messages, "
          "one one-sided walk ===\n")
    hdr = ("converged", "A_before", "B_before", "pull_facts", "push_facts",
           "pull_MB", "push_MB", "recon_s", "facts/s", "ok")
    print("  {:>9} {:>9} {:>9} {:>10} {:>10} {:>8} {:>8} {:>8} {:>8} {:>3}"
          .format(*hdr))
    for scale in scales:
        d = os.path.join(WORK, f"bidi_{scale}")
        shutil.rmtree(d, ignore_errors=True)
        r = bidi(scale, d)
        print("  {:>9} {:>9} {:>9} {:>10} {:>10} {:>8.1f} {:>8.1f} {:>8.2f} "
              "{:>8.0f} {:>3}".format(
                  r["facts"], r["a_before"], r["b_before"], r["pull_facts"],
                  r["push_facts"], r["pull_mb"], r["push_mb"], r["recon_s"],
                  r["facts"] / r["recon_s"], "y" if r["match"] else "N"))
        sys.stdout.flush()
        gc.collect()
        shutil.rmtree(d, ignore_errors=True)


def main():
    args = [int(a) for a in sys.argv[1:] if a.isdigit()]
    scales = args or [5000, 10000, 50000, 100000]
    os.makedirs(WORK, exist_ok=True)
    run_catchup(scales)
    run_bidi([s for s in scales if s <= 200000] or scales)
    print()


if __name__ == "__main__":
    main()
