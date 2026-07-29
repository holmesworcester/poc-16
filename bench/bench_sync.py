"""Sync throughput benchmarks for core.

Two questions, both answered against the *real* engine paths:

  catchup   A fresh node ingests a whole workspace from empty. This is the
            "download + ingestion" number: fetch the manifest's leaf piles
            and closure siblings, judge each unit through the kernel, merge
            by id, then one commit. facts/s here is directly comparable to
            the 2000-5000 facts/s poc-7..13 have gotten.

  bidi      Two peers with shared membership and disjoint message sets do
            one one-sided walk (pull differing ranges as closed units, push
            the symmetric difference as one closed pile). Both converge; we
            measure the diff.

The seed is bulk-built (facts inserted straight into the index, one manifest
build at the end) so setup is O(n log n), not O(n^2) — building 500k facts by
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

from core import catalog, cmds, manifest
from core import node as node_module
from core import sync as sync_module
from core.close import close, decode_pile, encode_pile
from core.fact import decode
from facts.auth.signature import signature
from facts.content.message import message
from core.kernel import extend_proofs, kernel, resolve_deps
from core.node import Node, now_ms
from core.publication import Publisher
from core.shape import fid_of

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
    catalog.Catalog(idx, "").stage(fact)


def _commit_index(node, workspace):
    """Benchmark-only direct-write boundary; runtime code never uses it."""
    idx = node.idx(workspace)
    idx.execute(
        "INSERT OR REPLACE INTO meta VALUES('publish-base', ?)",
        (node.store(workspace).etag("root"),))
    idx.execute("DELETE FROM meta WHERE k='root'")
    idx.execute(
        "INSERT OR REPLACE INTO meta VALUES('tree-rebuild','1')")
    idx.commit()


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
    random member, ts uniform over `window`. Rank the new signature providers
    before returning because incremental benchmark callers resolve the batch's
    closures without an intervening ``Node.commit()``."""
    idx = node.idx(ws)
    idx.execute("BEGIN")
    try:
        signatures, authored = [], []
        for i in range(n_msgs):
            sk, pk = rng.choice(members)
            ts = first_ts + rng.randrange(window)
            f = message(pk, "general", f"{tag}m{i}", ts)
            signed = signature(sk, pk, f, ts)
            _insert(idx, signed)
            _insert(idx, f)
            signatures.append(signed.fid)
            authored.extend((signed.fid, f.fid))
        unresolved = extend_proofs(
            idx, authored, lambda fid: node.candidate_of(ws, fid), ws)
        if set(signatures).intersection(unresolved):
            raise ValueError("bulk-authored signatures could not be ranked")
        _commit_index(node, ws)
    except Exception:
        idx.rollback()
        raise


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
    n.commit(ws)  # one full manifest build over the whole set
    t_end = perf()
    total = n.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    return n, ws, {"members": n_members, "msgs": n_msgs, "facts": total,
                   "author_s": t_layout - t_auth, "layout_s": t_end - t_layout,
                   "setup_s": t_auth - t0}


# ---- unit streaming ----------------------------------------------------------

def manifest_objs(store):
    """``(manifest oid, live oids)`` — every object a cold reader fetches:
    RangeTree pages, leaf piles, and closure siblings."""
    oids = []
    fetch = lambda oid: (oids.append(oid) or store.get("obj/" + oid))
    man = manifest.decode_root(store.get("root")).manifest
    entries = manifest.decode(fetch(man), fetch)
    oids += [e.leaf for e in entries]
    oids += [e.closure for e in entries if e.closure]
    return man, oids


def seed_units(store, man, workspace):
    """The production full-sync unit: one closed stream, each fact once."""
    stream = node_module.resident(
        man, lambda oid: store.get("obj/" + oid), workspace)
    if stream:
        yield stream


def ingest(node, ws, units, workers=WORKERS, batch=BATCH):
    """decode is the caller's (serial, like turn); kernel is parallel; merge
    + catalog settlement serial. Returns streamed-record count. No commit — caller
    lays out once at the end."""
    node._sync_index(ws)
    base = Publisher(node, ws).base()
    streamed = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        buf = []

        def flush(bb):
            for judgment in ex.map(lambda u: kernel(u, ws), bb):
                assert judgment.ok, "a published unit failed the kernel"
                node.merge(
                    ws, (valid.fact for valid in judgment.valids), base=base)

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
    streamed = ingest(fresh, ws, seed_units(src, man, ws))
    fresh.commit(ws)
    t1 = perf()

    total = fresh.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    match = fresh.store(ws).get("root") == src.get("root")
    return {"ingest_s": t1 - t0, "facts": total, "streamed": streamed,
            "dl_bytes": dl_bytes, "objs": len(ohs), "match": match,
            "pages": sum(1 for _ in seed_units(src, man, ws))}


# ---- the bidi benchmark ------------------------------------------------------

def copy_facts(dst, ws, src, fids):
    di, si = dst.idx(ws), src.idx(ws)
    di.execute("BEGIN")
    for fid in fids:
        raw = si.execute(
            "SELECT blob FROM facts WHERE fid=?", (fid,)).fetchone()[0]
        _insert(di, decode(raw))
    _commit_index(dst, ws)


def reconcile(A, B, ws):
    """One one-sided dial, exactly as sync(): A diffs B's manifest by oid,
    assembles the differing leaves into one closed union, and pushes the
    local-only keys as one closed pile that B ingests. Both converge."""
    astore, bstore = A.store(ws), B.store(ws)
    remote_objects = {}

    def fetch_remote(oid):
        if oid not in remote_objects:
            remote_objects[oid] = bstore.get("obj/" + oid)
        return remote_objects[oid]

    fetch_remote.many = lambda oids: tuple(fetch_remote(oid) for oid in oids)

    t0 = perf()
    fetch_local = lambda oid: astore.get("obj/" + oid)
    my_man = manifest.decode_root(astore.get("root")).manifest
    their_man = manifest.decode_root(bstore.get("root")).manifest
    mine = manifest.decode(fetch_local(my_man), fetch_local)
    theirs, changed = manifest.compare(mine, their_man, fetch_remote)
    differing = set(changed)
    my_keys = A.keys(ws)
    members_of = lambda e: manifest.range_members(e, fetch_remote)
    pulled_piles, push_keys = sync_module.frontier(
        my_keys, theirs, differing, members_of)
    held = set(my_keys)
    pull_fids = {
        fact.fid for _, members in pulled_piles for fact in members
        if fact.key not in held}

    pulled = []
    if pulled_piles:
        pulled.append(tuple(sync_module.assemble(
            A, ws, pulled_piles, theirs, fetch_remote)))
    pull_bytes = sum(
        len(raw) for raw in remote_objects.values() if raw is not None)
    push_bytes = push_streamed = 0
    push_fids = {fid_of(key) for key in push_keys}
    if push_fids:
        idx = A.idx(ws)
        news = [A.fact_of(ws, fid) for fid in sorted(push_fids)]
        facts = close(news, lambda fid: resolve_deps(A.fact_of(ws, fid), idx) or [],
                      lambda fid: A.fact_of(ws, fid))
        push_streamed = len(facts)
        pile = encode_pile(facts)
        push_bytes = len(pile)
        ingest(B, ws, [decode_pile(pile)[0]])  # B absorbs A's half
        # ingest() is the bulk benchmark seam and does not return Node.turn's
        # exact new-fid delta; force the canonical full maintenance path.
        B.commit(ws, reuse=False)

    # sync() pushes each local difference before draining its pulled ingress.
    # Preserve that order so canonical pruning cannot remove a fact before its
    # precomputed symmetric-difference pile reaches the peer.
    ingest(A, ws, pulled)  # A absorbs B's half
    if pulled:
        A.commit(ws, reuse=False)
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
    A = Node(os.path.join(base_dir, "A"))
    ws = cmds.create(A, "alice")
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
        # ``grow_tree`` is a benchmark-only direct catalog writer. Settle it
        # before taking the shared membership snapshot; otherwise all but the
        # anchor are still staged and a one-round reconciliation can expose
        # previously invisible content only after its frontier was computed.
        A.commit(ws)
    membership = all_fids(A, ws)

    B = Node(os.path.join(base_dir, "B"))
    copy_facts(B, ws, A, membership)

    per_side = max(1, (total_facts - len(membership)) // 4)  # msgs per side
    first = max(
        A.candidate_of(ws, fid).ts
        for (fid,) in A.idx(ws).execute("SELECT fid FROM facts")
    ) + 1
    bulk_author(A, ws, members, per_side, first, window, random.Random(1), "A")
    bulk_author(B, ws, members, per_side, first, window, random.Random(2), "B")
    A.commit(ws)
    B.commit(ws)
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
    import core.shape as shape
    print("\n=== CATCHUP: fresh node ingests a whole workspace from empty ===")
    print(f"    {MEMBERS} members, messages over {YEARS} years, {WORKERS} kernel "
          f"workers, one-store manifest with monotone CUT={shape.CUT}\n")
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
    """Every published leaf plus its closure sibling still judges alone."""
    st = seed.store(ws)
    fetch = lambda oid: st.get("obj/" + oid)
    man = manifest.decode_root(st.get("root")).manifest
    entries = manifest.decode(fetch(man), fetch)
    piles = {e.leaf: decode_pile(fetch(e.leaf))[0] for e in entries}
    n = 0
    for entry in entries:
        items = {f.fid: f for f in piles[entry.leaf]}
        if entry.closure:
            for key in json.loads(fetch(entry.closure))["keys"]:
                home = manifest.locate(entries, key)
                items.update({
                    f.fid: f for f in piles[home.leaf] if f.key == key})
        deps = node_module._edges(items)
        stream = close(items.values(), deps.__getitem__, items.__getitem__)
        assert kernel(stream, ws).ok, \
            "a leaf plus its closure sibling failed the kernel"
        n += 1
    return n


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
        seed.candidate_of(ws, fid).ts
        for (fid,) in seed.idx(ws).execute("SELECT fid FROM facts")
    ]
    lo, hi = min(timestamps), max(timestamps)
    st = seed.store(ws)
    acc = {"b": 0}
    orig = st.put
    st.put = lambda k, b: (acc.__setitem__("b", acc["b"] + (len(b) if k.startswith("obj/") else 0)), orig(k, b))[1]

    def one(text, ts):
        acc["b"] = 0
        cmds.post(seed, ws, "general", text, ts=ts)
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
