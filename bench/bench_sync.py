"""Sync throughput benchmarks for core.

Two questions, both answered against the *real* engine paths:

  catchup   A fresh node ingests a whole workspace from empty. This is the
            "download + ingestion" number: fetch every validated fact,
            assemble fresh bounded closures, and judge them through the shared
            RepositoryApplier. facts/s is measured at that real boundary.

  bidi      Two peers with shared membership and disjoint message sets do
            one validated-fact join in both directions. Both converge; we
            measure the exact fresh closures transferred.

The seed and measured catchup both use the production PileSender →
RepositoryApplier transition. There is no benchmark-only SQL admission or
snapshot publication seam.

Run:   python3 bench/bench_sync.py                 # 5k/10k/50k/100k facts
       python3 bench/bench_sync.py 500000          # add the 500k run
       python3 bench/bench_sync.py 5000 10000      # explicit scales
"""
import gc
import os
import random
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import facts

from core import snapshot
from full_peer import sync as sync_module
from core.close import close
from facts.auth.signature import signature
from facts.content.message import message
from core.kernel import kernel, resolve_deps
from core.limits import MAX_CLOSURE_FACTS
from full_peer.node import FullPeer, now_ms
from core.repository_reader import RepositoryReader

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

def admit_batch(node, workspace, news, deps_new):
    """Author one bounded batch through the production sender and applier."""
    return node.ingest_new(workspace, tuple(news), deps_new)


def build_members(node, ws, n_members, base_ts):
    """Genesis + (n_members-1) joins, each a real ingest so the membership
    closure is exactly what a live workspace holds."""
    members = [(node.sk, node.pk)]
    for i in range(n_members - 1):
        bsk, bpk, _ = add_member(node, ws, f"u{i}", base_ts + 1 + i)
        members.append((bsk, bpk))
    return members


def bulk_author(
        node, ws, members, n_msgs, first_ts, window, rng, tag="",
        owners=None):
    """Author ``n_msgs`` messages in production-sized exact piles."""
    authored, deps = [], {}
    context = node.sql(ws)

    def flush():
        if authored:
            admit_batch(node, ws, authored, deps)
            authored.clear()
            deps.clear()

    for i in range(n_msgs):
        sk, pk = rng.choice(members)
        owner = pk if owners is None else owners[pk]
        ts = first_ts + rng.randrange(window)
        fact = message(
            ws, pk, "general", f"{tag}m{i}", ts, owner)
        signed = signature(sk, pk, fact, ts)
        member = context.resolve_offer("member", pk, owner)
        if member is None:
            raise ValueError("bulk author is not a member")
        authored.extend((signed, fact))
        deps[signed.fid] = ()
        deps[fact.fid] = (signed.fid, member)
        # Leave room for the shared membership/signature closure while making
        # benchmark seeds pay only production-sized Applier commits.
        if len(authored) >= MAX_CLOSURE_FACTS // 2:
            flush()
    flush()


def build_seed(node_dir, total_facts, n_members=MEMBERS, years=YEARS, seed=16):
    rng = random.Random(seed)
    n = FullPeer(node_dir)
    t0 = perf()
    ws = facts.auth.workspace.create(n, "alice")
    base_ts = now_ms()
    window = years * 365 * 24 * 3600 * 1000
    members = build_members(n, ws, n_members, base_ts)
    base = n.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    n_msgs = max(0, (total_facts - base) // 2)
    t_auth = perf()
    bulk_author(n, ws, members, n_msgs, base_ts + n_members + 1, window, rng)
    t_layout = t_end = perf()
    total = n.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    return n, ws, {"members": n_members, "msgs": n_msgs, "facts": total,
                   "author_s": t_layout - t_auth, "layout_s": t_end - t_layout,
                   "setup_s": t_auth - t0}


# ---- unit streaming ----------------------------------------------------------

def snapshot_objs(store):
    """``(root bytes, unique cold object reads)`` for validated facts."""
    root = store.get("root")
    oids = []

    def fetch(oid):
        oids.append(oid)
        return store.get("obj/" + oid)

    # This helper intentionally receives only a store. Construct the public
    # reader and touch each authenticated canonical fact residence.
    workspace = snapshot.decode_root(root).anchor
    view = RepositoryReader(workspace, root, fetch).validated()
    for fid in view.fact_ids():
        view.fact(fid)
    return root, tuple(dict.fromkeys(oids))


def seed_units(store, root, workspace):
    """The production sync units: fresh validated-fact closures."""
    view = RepositoryReader(
        workspace, root,
        lambda oid: store.get("obj/" + oid)).validated()
    if view.root.anchor != workspace:
        raise ValueError("benchmark snapshot workspace")
    for fid in view.fact_ids():
        yield view.closure((fid,))


def ingest(node, ws, units, workers=WORKERS, batch=BATCH):
    """Receive bounded batches through the exact production Applier."""
    _ = workers  # retained for benchmark-call compatibility
    streamed = 0
    buf = []

    def flush(bb):
        ordered = {}
        for unit in bb:
            for fact in unit:
                ordered.setdefault(fact.fid, fact)
        raw = node.sender(ws).pack(tuple(ordered.values()))
        node.receive_pile(ws, "benchmark", raw)

    for unit in units:
        streamed += len(unit)
        buf.append(unit)
        if len(buf) >= batch:
            flush(buf)
            buf = []
    if buf:
        flush(buf)
    return streamed


# ---- the catchup benchmark ---------------------------------------------------

def catchup(seed, ws, fresh_dir):
    fresh = FullPeer(fresh_dir)
    fresh.add_workspace(ws, "benchmark-catchup", peers=[])
    src = seed.store(ws)
    root, ohs = snapshot_objs(src)
    dl_bytes = len(src.get("root")) + sum(len(src.get("obj/" + oh)) for oh in ohs)

    t0 = perf()
    streamed = ingest(fresh, ws, seed_units(src, root, ws))
    t1 = perf()

    total = fresh.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    match = fresh.store(ws).get("root") == src.get("root")
    return {"ingest_s": t1 - t0, "facts": total, "streamed": streamed,
            "dl_bytes": dl_bytes, "objs": len(ohs), "match": match,
            "pages": sum(1 for _ in seed_units(src, root, ws))}


# ---- the bidi benchmark ------------------------------------------------------

def copy_facts(dst, ws, src, fids):
    selected = [src.fact_of(ws, fid) for fid in fids]
    facts = close(
        selected,
        lambda fid: resolve_deps(
            src.fact_of(ws, fid), src.sql(ws)) or (),
        lambda fid: src.fact_of(ws, fid),
    )
    if ws not in dst.workspaces():
        dst.add_workspace(ws, "benchmark-copy", peers=[])
    dst.receive_pile(ws, "benchmark", dst.sender(ws).pack(facts))


def reconcile(A, B, ws):
    """One validated-fact join in both directions, as the sync core does."""
    astore, bstore = A.store(ws), B.store(ws)
    remote_objects = {}

    def fetch_remote(oid):
        if oid not in remote_objects:
            remote_objects[oid] = bstore.get("obj/" + oid)
        return remote_objects[oid]

    t0 = perf()
    mine = A.reader(ws).validated()
    theirs = RepositoryReader(
        ws, bstore.get("root"), fetch_remote).validated()
    delta = sync_module._delta(mine, theirs)
    pull_fids, push_fids = set(delta.pull), set(delta.push)
    pulled = [theirs.closure((fid,)) for fid in delta.pull]
    pushed = [mine.closure((fid,)) for fid in delta.push]
    pull_bytes = sum(
        len(raw) for raw in remote_objects.values() if raw is not None)
    push_streamed = sum(len(unit) for unit in pushed)
    push_bytes = sum(
        len(A.sender(ws).pack(unit)) for unit in pushed)
    if pushed:
        ingest(B, ws, pushed)

    # Preserve sync's push-before-pull order so both deltas were computed
    # against the same two pinned roots.
    ingest(A, ws, pulled)
    t1 = perf()

    match = A.store(ws).get("root") == B.store(ws).get("root")
    total = A.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    return {"recon_s": t1 - t0, "pulled_units": len(pulled),
            "pull_useful": len(pull_fids),
            "pull_streamed": sum(len(u) for u in pulled),
            "push_useful": len(push_fids), "push_streamed": push_streamed,
            "pull_mb": pull_bytes / 1e6, "push_mb": push_bytes / 1e6,
            "facts": total, "match": match}


def bidi(total_facts, base_dir, n_members=MEMBERS, years=YEARS, *,
         shape=None, seed=16):
    A = FullPeer(os.path.join(base_dir, "A"))
    ws = facts.auth.workspace.create(A, "alice")
    base_ts = now_ms()
    window = years * 365 * 24 * 3600 * 1000
    depth = None
    if shape is None:
        members = build_members(A, ws, n_members, base_ts)
    else:
        from bench.seed_chain import grow_tree
        root_ts = A.fact_of(ws, ws).ts
        members, _, depths, _ = grow_tree(
            A, ws, n_members, root_ts + 1, random.Random(seed), shape=shape)
        depth = {
            "min": min(depths.values()),
            "max": max(depths.values()),
        }
    membership = all_fids(A, ws)

    B = FullPeer(os.path.join(base_dir, "B"))
    copy_facts(B, ws, A, membership)

    per_side = max(1, (total_facts - len(membership)) // 4)  # msgs per side
    first = max(
        A.fact_of(ws, fid).ts
        for (fid,) in A.idx(ws).execute("SELECT fid FROM facts")
    ) + 1
    bulk_author(A, ws, members, per_side, first, window, random.Random(1), "A")
    bulk_author(B, ws, members, per_side, first, window, random.Random(2), "B")
    a_facts = A.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    b_facts = B.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    st = reconcile(A, B, ws)
    st.update({"a_before": a_facts, "b_before": b_facts,
               "shape": shape or "star", "depth": depth})
    return st


# ---- driver ------------------------------------------------------------------

def mb(b):
    return b / 1e6


def run_catchup(scales):
    print("\n=== CATCHUP: fresh node ingests a whole workspace from empty ===")
    print(f"    {MEMBERS} members, messages over {YEARS} years, {WORKERS} kernel "
          "workers, one four-map validated snapshot\n")
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
    hdr = (
        "converged", "A_before", "B_before",
        "pull_use", "pull_sent", "pull_rho",
        "push_use", "push_sent", "push_rho",
        "pull_MB", "push_MB", "recon_s", "useful/s", "ok",
    )
    print(
        "  {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>9} {:>9} {:>8} "
        "{:>8} {:>8} {:>8} {:>9} {:>3}".format(*hdr))
    for scale in scales:
        d = os.path.join(WORK, f"bidi_{scale}")
        shutil.rmtree(d, ignore_errors=True)
        r = bidi(scale, d)
        useful = r["pull_useful"] + r["push_useful"]
        print(
            "  {:>9} {:>9} {:>9} {:>9} {:>9} {:>7.2f}x {:>9} {:>9} "
            "{:>7.2f}x {:>8.1f} {:>8.1f} {:>8.2f} {:>9.0f} {:>3}".format(
                r["facts"], r["a_before"], r["b_before"],
                r["pull_useful"], r["pull_streamed"],
                r["pull_streamed"] / r["pull_useful"],
                r["push_useful"], r["push_streamed"],
                r["push_streamed"] / r["push_useful"],
                r["pull_mb"], r["push_mb"], r["recon_s"],
                useful / r["recon_s"], "y" if r["match"] else "N"))
        sys.stdout.flush()
        gc.collect()
        shutil.rmtree(d, ignore_errors=True)


def check_leaves(seed, ws):
    """Every validated residence can be assembled into a fresh closure."""
    view = seed.reader(ws).validated()
    fids = view.fact_ids()
    for fid in fids:
        assert kernel(view.closure((fid,)), ws).ok, \
            "a validated fact failed fresh closure assembly"
    return len(fids)


def chained_guard(scale, base_dir, shapes=("star", "wide", "random", "chain"),
                  n_members=MEMBERS):
    """Exercise catchup, bidi reconciliation, and every leaf on chained seeds."""
    from bench.seed_chain import build_seed as build_chained_seed

    results = {}
    for shape in shapes:
        directory = os.path.join(base_dir, shape)
        shutil.rmtree(directory, ignore_errors=True)
        seed, ws, stats = build_chained_seed(
            os.path.join(directory, "seed"), scale,
            n_members=n_members, shape=shape)
        leaves = check_leaves(seed, ws)
        caught = catchup(seed, ws, os.path.join(directory, "fresh"))
        reconciled = bidi(
            scale, os.path.join(directory, "bidi"),
            n_members=n_members, shape=shape)
        assert caught["match"], f"{shape} catchup did not match"
        assert reconciled["match"], f"{shape} bidi did not converge"
        results[shape] = {
            "depth": stats["depth"],
            "leaves": leaves,
            "catchup": caught,
            "bidi": reconciled,
        }
    return results


def measure_write_cost(node_dir, scale, posts=200):
    """Build a promoted seed, then size the obj bytes each post rewrites.
    STEADY posts land at the hot end (ts after every seed fact) — the normal
    append. STRAGGLER posts land deep in sealed history (old ts) — the
    re-cut-a-whole-cold-page case. Seeds spread ts into the future, so ts must
    be chosen explicitly or a 'post' is an accidental straggler."""
    import statistics as S
    shutil.rmtree(node_dir, ignore_errors=True)
    seed, ws, _ = build_seed(node_dir, scale)
    timestamps = [
        seed.fact_of(ws, fid).ts
        for (fid,) in seed.idx(ws).execute("SELECT fid FROM facts")
    ]
    lo, hi = min(timestamps), max(timestamps)
    st = seed.store(ws)
    acc = {"b": 0}
    orig = st.put
    st.put = lambda k, b: (acc.__setitem__("b", acc["b"] + (len(b) if k.startswith("obj/") else 0)), orig(k, b))[1]

    def one(text, ts):
        acc["b"] = 0
        facts.content.message.post(seed, ws, "general", text, ts=ts)
        return acc["b"]

    steady = [one(f"h{i}", hi + 1 + i) for i in range(posts)]      # hot-end append
    strag = [one(f"s{i}", lo + 10 + i) for i in range(5)]          # into sealed cold
    st.put = orig
    del seed
    gc.collect()
    ss = sorted(steady)
    return {"mean_kb": S.mean(steady) / 1024, "p50_kb": ss[len(ss) // 2] / 1024,
            "p90_kb": ss[int(len(ss) * .9)] / 1024, "max_kb": max(steady) / 1024,
            "straggler_kb": S.mean(strag) / 1024, "posts": posts}


def main():
    args = [int(a) for a in sys.argv[1:] if a.isdigit()]
    os.makedirs(WORK, exist_ok=True)
    if "chain" in sys.argv:
        scale = args[0] if args else 5000
        results = chained_guard(
            scale, os.path.join(WORK, f"chained_guard_{scale}"))
        print("\n=== CHAINED SEED GREEN GUARD ===")
        for shape, result in results.items():
            depth = result["depth"]
            print(
                f"  {shape:6} depth={depth['min']}/{depth['median']:g}/"
                f"{depth['max']} leaves={result['leaves']} "
                f"catchup={'y' if result['catchup']['match'] else 'N'} "
                f"bidi={'y' if result['bidi']['match'] else 'N'}")
        return
    scales = args or [5000, 10000, 50000, 100000]
    run_catchup(scales)
    run_bidi([s for s in scales if s <= 200000] or scales)
    print()


if __name__ == "__main__":
    main()
