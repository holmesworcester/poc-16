"""Measure one-store pile/closure economics for docs/COSTS.md.

Rewritten for the one-store layout (oyd.7; the previous harness drove the
deleted fact-tree engine). Builds the four historical corpus shapes through
the REAL ingress — Node + cmds.create/add_member, per-message closed piles
drained by turn() — then measures everything FROM THE STORE ITSELF:

  - leaf-pile size distribution at CUT=64 (members, bytes: med/p95/max)
  - closure siblings (count, keys, bytes, dep home-leaf spread)
  - manifest shard bytes and depth
  - reachable store bytes vs corpus bytes (the rho analog for config E)
    plus on-disk obj/ totals (settle garbage: no GC)
  - cold-clone GET count (root + shards + leaves)
  - a deletion mix: 2% single-target removals through the PRODUCTION
    family (facts/content/delete.py via cmds.remove) + one channel kill
    via the synthetic KillFamily fixture (production has no kill family
    yet) — index bytes, entry count, head width, warm-slice locality,
    per-removal commit cost (objects/bytes written), and a full
    retraction-correctness check against message_rows
  - warm-delta tail locality (leaves touched by 40 new messages)
  - flat-m8-n600 additionally exercises the prune cascade: a
    shadowed-deleter quarantine (removal pruned, victim resident) with the
    grow-only entry floor and suppression asserted through the window and
    after restore

SEEDED deterministic: identities come from a seeded stream, timestamps and
authorship draws from fixed rngs. Output: one JSON per tag in --out DIR
(default: a fresh temp dir) plus printed summary lines.
Usage: python3 bench/measure_piles.py [all|<tag>] [--out DIR] [--seed N]
(§3.1's tables are seed 7; its cross-seed caveat is seed 8.)
"""
import json
import os
import random
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import facts as facts_pkg

from core import cmds, manifest, removals
from core.close import decode_pile, encode_pile
from core.crypto import h, keypair, load_sk
from core.fact import canon
from core.node import Node
from core.shape import key as shape_key
from facts._commands import closer
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.content.message import message
from tests import util
from tests.util import (
    DeletionFamily,
    add_member,
    channel_kill,
    inject_device_claim,
    member_src,
)

WORDS = ("the quick brown fox jumps over lazy dog and then some more words "
         "for realistic message body lengths ok let us keep going a bit "
         "longer with plausible chat text here").split()

RUNS = {
    "flat-m8-n600": (8, "flat", 600),
    "flat-m8-n2400": (8, "flat", 2400),
    "flat-m32-n2400": (32, "flat", 2400),
    "chain-m32-n2400": (32, "chain", 2400),
}
BATCH = 64  # messages staged per turn(); ingress stays per-message piles
CHANS, CWEIGHTS = ["general", "random", "dev", "ops"], [8, 4, 2, 1]
KILL_CHAN = "dev"


class KillFamily(DeletionFamily):
    """The synthetic kill fixture (tests/test_removals.py): production has
    no kill family yet, and head-width/kill-retraction need one entry."""
    TAG = "channel_kill"

    @staticmethod
    def validate(fact, context):
        try:
            channel = fact.atoms[0][2]
        except (IndexError, TypeError):
            return False
        return not fact.refs() and fact == channel_kill(channel, fact.ts)


facts_pkg.ROUTES[KillFamily.TAG] = KillFamily


def seeded_keys(seed):
    rng = random.Random(seed)

    def det_keypair():
        sk = load_sk(f"{rng.getrandbits(256):064x}")
        return sk, sk.verify_key.encode().hex()

    return det_keypair


def msg_text(rng):
    n = max(3, int(rng.lognormvariate(2.5, 0.8)))  # median ~12 words
    return " ".join(rng.choice(WORDS) for _ in range(n))


def stage_msg(node, ws, sk, pk, text, ts, chan):
    """One closed per-message pile into ingress, without draining."""
    f = message(pk, chan, text, ts)
    s = signature(sk, pk, f, ts)
    deps = {f.fid: [s.fid, member_src(node, ws, pk)], s.fid: []}
    raw = encode_pile(closer(node, ws, {f.fid: f, s.fid: s}, deps))
    node.store(ws).put(f"pile/{node.member_for(ws)}/{h(raw)}", raw)
    return f.fid


def build_corpus(path, members, shape, messages, seed=7):
    """The real ingress: members one turn each, messages in drained batches.
    Identities come from a seeded stream (add_member draws keypairs), so a
    corpus is byte-identical run to run."""
    rng = random.Random(seed)
    node = Node(path, initial_secret=load_sk(f"{seed:064x}"))
    ts = 1000
    ws = cmds.create(node, "founder", ts=ts)
    idents = [node.identity(ws)]
    real, util.keypair = util.keypair, seeded_keys(
        (seed * 1000 + members) * 2 + (shape == "chain"))
    try:
        for i in range(members):
            ts += 10
            inviter = idents[0] if shape == "flat" else idents[-1]
            sk, pk, _ = add_member(
                node, ws, f"member-{i}", ts=ts, inviter=inviter)
            idents.append((sk, pk))
    finally:
        util.keypair = real
    weights = [1.0 / (i + 1) for i in range(len(idents))]  # zipf-ish authors
    posted, staged = [], 0
    for _ in range(messages):
        ts += rng.randint(1, 40)
        sk, pk = rng.choices(idents, weights)[0]
        chan = rng.choices(CHANS, CWEIGHTS)[0]
        posted.append(
            (stage_msg(node, ws, sk, pk, msg_text(rng), ts, chan), chan))
        staged += 1
        if staged % BATCH == 0:
            node.turn(ws)
    node.turn(ws)
    return node, ws, posted, ts


# ---- reading the store like any reader --------------------------------------


def store_view(node, ws):
    """Everything reachable from the root, plus shard depth."""
    st = node.store(ws)
    root_raw = st.get("root")
    _, _, man, slot = manifest.decode_root(root_raw)
    fetch = lambda oid: st.get("obj/" + oid)
    shards = {}

    def walk(oid, depth):
        raw = fetch(oid)
        shards[oid] = raw
        obj = json.loads(raw)
        if "shards" in obj:
            return max(walk(child, depth + 1) for _, child in obj["shards"])
        return depth

    depth = walk(man, 1) if man else 0
    entries = manifest.decode(root_raw and fetch(man), fetch) if man else []
    return {
        "root_raw": root_raw,
        "slot": slot,
        "entries": entries,
        "shards": shards,
        "depth": depth,
        "leaves": {e.leaf: fetch(e.leaf) for e in entries},
        "siblings": {e.closure: fetch(e.closure)
                     for e in entries if e.closure},
        "index_raw": fetch(slot["oid"]) if slot["oid"] else None,
        "fetch": fetch,
    }


def disk_objects(node, ws):
    st = node.store(ws)
    keys = st.list("obj/")
    return len(keys), sum(
        os.path.getsize(os.path.join(st.root, k)) for k in keys)


def pctl(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def measure_layout(node, ws, view):
    idx = node.idx(ws)
    corpus_bytes, fams = 0, {}
    for (fid,) in idx.execute("SELECT fid FROM facts"):
        f = node.fact_of(ws, fid)
        raw = len(canon(f.to_json()))
        corpus_bytes += raw
        n, b = fams.get(f.t, (0, 0))
        fams[f.t] = (n + 1, b + raw)
    entries = view["entries"]
    leaf_bytes = [len(raw) for raw in view["leaves"].values()]
    leaf_members = [len(decode_pile(raw)[0]) for raw in view["leaves"].values()]
    sib_bytes = [len(raw) for raw in view["siblings"].values()]
    sib_keys = [len(json.loads(raw)["keys"])
                for raw in view["siblings"].values()]
    spread = []
    for e in entries:
        if not e.closure:
            spread.append(0)
            continue
        keys = json.loads(view["siblings"][e.closure])["keys"]
        spread.append(len({
            manifest.locate(entries, k).leaf for k in keys
            if manifest.locate(entries, k)}))
    shard_bytes = sum(len(raw) for raw in view["shards"].values())
    reachable = len(view["root_raw"]) + shard_bytes + sum(leaf_bytes) \
        + sum(sib_bytes) + (len(view["index_raw"] or b""))
    count, disk = disk_objects(node, ws)
    med = statistics.median
    return {
        "facts": idx.execute("SELECT COUNT(*) FROM facts").fetchone()[0],
        "corpus_bytes": corpus_bytes,
        "families": {t: {"n": n, "bytes": b, "avg": b // n}
                     for t, (n, b) in sorted(fams.items())},
        "leaves": len(entries),
        "leaf_members": {"median": med(leaf_members), "max": max(leaf_members)},
        "leaf_bytes": {"median": int(med(leaf_bytes)),
                       "p95": pctl(leaf_bytes, 0.95), "max": max(leaf_bytes),
                       "total": sum(leaf_bytes)},
        "siblings": {"count": len(sib_bytes),
                     "keys_median": int(med(sib_keys)) if sib_keys else 0,
                     "keys_max": max(sib_keys) if sib_keys else 0,
                     "bytes_median": int(med(sib_bytes)) if sib_bytes else 0,
                     "bytes_total": sum(sib_bytes)},
        "dep_home_leaves_per_leaf": {
            "median": int(med(spread)), "max": max(spread)},
        "manifest": {"shards": len(view["shards"]), "bytes": shard_bytes,
                     "depth": view["depth"]},
        "cold_gets": 1 + len(view["shards"]) + len(entries),
        "reachable_bytes": reachable,
        "rho_vs_corpus": round(reachable / corpus_bytes, 3),
        "disk_objects": count,
        "disk_bytes": disk,
    }


# ---- the deletion mix -------------------------------------------------------


def measure_deletions(node, ws, posted, ts, rng):
    """2% production point removals + one synthetic channel kill, one commit
    each, costed by obj/ delta; then retraction correctness at scale."""
    n_points = max(1, len(posted) // 50)
    victims = rng.sample([fid for fid, _ in posted], n_points)
    costs = []
    for fid in victims:
        ts += 10
        before_n, before_b = disk_objects(node, ws)
        cmds.remove(node, ws, fid, ts=ts)
        after_n, after_b = disk_objects(node, ws)
        costs.append((after_n - before_n, after_b - before_b))
    ts += 10
    kill = channel_kill(KILL_CHAN, ts)
    before_n, before_b = disk_objects(node, ws)
    node.ingest_new(ws, [kill], {kill.fid: []})
    after_n, after_b = disk_objects(node, ws)
    kill_cost = (after_n - before_n, after_b - before_b)

    view = store_view(node, ws)
    entries, refs = removals.decode(view["index_raw"])
    head = [e for e in entries if (e.lo, e.hi) == removals.HEAD]
    recent = sorted(
        shape_key(node.fact_of(ws, fid)) for fid, _ in posted[-40:])
    warm_slice = removals.overlapping(entries, recent[0], recent[-1])

    # retraction correctness at scale, straight from the read model
    rows = {src: chan for src, chan in node.app.execute(
        "SELECT src, chan FROM message_rows WHERE ws=?", (ws,))}
    dead = set(victims) | {
        fid for fid, chan in posted if chan == KILL_CHAN}
    alive = {fid for fid, _ in posted} - dead
    assert not dead & set(rows), "a removed message survived in message_rows"
    assert alive <= set(rows), "a surviving message was over-retracted"
    assert not any(chan == KILL_CHAN for chan in rows.values())

    objs = sorted(c[0] for c in costs)
    byts = sorted(c[1] for c in costs)
    return {
        "points": n_points,
        "kills": 1,
        "index_bytes": len(view["index_raw"]),
        "index_entries": len(entries),
        "index_refs": len(refs),
        "head_width": len(head),
        "warm_slice_entries": len(warm_slice),
        "per_point_commit": {
            "objects_median": int(statistics.median(objs)),
            "objects_max": objs[-1],
            "bytes_median": int(statistics.median(byts)),
            "bytes_max": byts[-1]},
        "kill_commit": {"objects": kill_cost[0], "bytes": kill_cost[1]},
        "index_bytes_per_removal": round(
            len(view["index_raw"]) / (n_points + 1), 1),
        "retraction_check": {
            "retracted": len(dead), "surviving": len(alive)},
    }, ts


def tail_locality(node, ws, ts, rng, extra=40):
    before = {e.leaf for e in store_view(node, ws)["entries"]}
    sk, pk = node.identity(ws)
    for _ in range(extra):
        ts += rng.randint(1, 40)
        stage_msg(node, ws, sk, pk, msg_text(rng), ts, "general")
    node.turn(ws)
    after = [e.leaf for e in store_view(node, ws)["entries"]]
    return {"extra_msgs": extra, "leaves_after": len(after),
            "changed_or_new_leaves": sum(1 for o in after if o not in before)}


# ---- the prune cascade ------------------------------------------------------


def prune_cascade(node, ws, posted, ts):
    """The shadowed-deleter quarantine (tests/test_removals.py::
    test_quarantined_removal_holds_locally_but_diverges_peers), measured:
    the removal is pruned while its victim stays resident; the entry must
    ride the published slot and suppression must hold, then restore."""
    real, util.keypair = util.keypair, seeded_keys(0xCA5CADE)
    try:
        founder_sk, founder_pk = node.identity(ws)
        q_sk, q, _ = add_member(node, ws, "q", ts=ts + 10)
        short_sk, short, _ = add_member(
            node, ws, "cascade-short", inviter=(q_sk, q), ts=ts + 20)
        deep_sk, deep, _ = add_member(node, ws, "c-d1", ts=ts + 30)
        for i, name in enumerate(("c-d2", "c-d3", "cascade-deep")):
            deep_sk, deep, _ = add_member(
                node, ws, name, inviter=(deep_sk, deep), ts=ts + 40 + 10 * i)
        for sk, pk, label in ((short_sk, short, "c-short-dev"),
                              (deep_sk, deep, "c-deep-dev")):
            node.keychain.add_identity(sk)
            node.bind_identity(ws, pk)
            cmds.bind_device(node, ws, label)
        target_sk, target = util.keypair()
        node.keychain.add_identity(target_sk)
        inject_device_claim(
            node, ws, deep_sk, deep, deep, target, "c-from-deep", ts + 100)
        node.bind_identity(ws, target)
        deleter_sk, deleter = util.keypair()
        node.keychain.add_identity(deleter_sk)
        claim = inject_device_claim(
            node, ws, target_sk, target, deep, deleter, "c-deleter", ts + 101)
        victim = next(  # an ordinary SURVIVING message; stays resident
            fid for fid, _ in posted if node.app.execute(
                "SELECT 1 FROM message_rows WHERE ws=? AND src=?",
                (ws, fid)).fetchone())
        node.bind_identity(ws, deleter)
        removal_fid = cmds.remove(node, ws, victim, ts=ts + 200)
        entries_before = len(node.removal_entries(ws))

        inject_device_claim(  # the shadow: prune cascades to the removal
            node, ws, short_sk, short, short, target, "c-from-short", ts + 300)
        quarantined = node.fact_of(ws, removal_fid) is None \
            and node.store(ws).has("quarantine/" + removal_fid)
        victim_resident = node.fact_of(ws, victim) is not None
        entries_window = len(node.removal_entries(ws))
        suppressed_window = node.app.execute(
            "SELECT 1 FROM message_rows WHERE ws=? AND src=?",
            (ws, victim)).fetchone() is None

        invite_sk, invite_pk = util.keypair()  # restore: direct rejoin
        invitation = user_invite(founder_pk, invite_pk, ts + 400)
        invitation_sig = signature(founder_sk, founder_pk, invitation, ts + 400)
        rejoined = user(invitation, invite_sk, deep, "c-deep-direct", ts + 401)
        rejoined_sig = signature(deep_sk, deep, rejoined, ts + 401)
        node.ingest_new(
            ws, [invitation_sig, invitation, rejoined_sig, rejoined], {
                invitation_sig.fid: [],
                invitation.fid: [
                    invitation_sig.fid, member_src(node, ws, founder_pk)],
                rejoined_sig.fid: [],
                rejoined.fid: [invitation.fid, rejoined_sig.fid],
            })
        restored = node.fact_of(ws, removal_fid) is not None
        suppressed_after = node.app.execute(
            "SELECT 1 FROM message_rows WHERE ws=? AND src=?",
            (ws, victim)).fetchone() is None
        out = {
            "removal_quarantined": quarantined,
            "victim_stayed_resident": victim_resident,
            "entry_floor_held": entries_window == entries_before,
            "suppression_held_in_window": suppressed_window,
            "restored": restored,
            "suppression_held_after_restore": suppressed_after,
        }
        assert all(out.values()), out
        return out
    finally:
        util.keypair = real


# ---- driver -----------------------------------------------------------------


def run(tag, out_dir, seed=7):
    members, shape, messages = RUNS[tag]
    t0 = time.time()
    node, ws, posted, ts = build_corpus(
        os.path.join(out_dir, f"node-{tag}"), members, shape, messages, seed)
    built = time.time()
    layout = measure_layout(node, ws, store_view(node, ws))
    deletion_rng = random.Random(11)
    deletions, ts = measure_deletions(node, ws, posted, ts, deletion_rng)
    layout["tail"] = tail_locality(node, ws, ts + 1000, random.Random(13))
    if tag == "flat-m8-n600":
        deletions["prune_cascade"] = prune_cascade(
            node, ws, posted, ts + 10_000)
    out = {
        "config": {"members": members, "shape": shape, "messages": messages,
                   "cut": 64, "seed": seed},
        **layout,
        "deletions": deletions,
        "build_s": round(built - t0, 1),
        "measure_s": round(time.time() - built, 1),
    }
    with open(os.path.join(out_dir, f"{tag}.json"), "w") as f:
        json.dump(out, f, indent=1)
    d = deletions
    print(f"== {tag}: facts={out['facts']} "
          f"corpus={out['corpus_bytes'] / 1e3:.0f}KB "
          f"leaves={out['leaves']} rho={out['rho_vs_corpus']} "
          f"leaf_med={out['leaf_bytes']['median']} "
          f"p95={out['leaf_bytes']['p95']} "
          f"sib_med={out['siblings']['bytes_median']} "
          f"depth={out['manifest']['depth']} "
          f"gets={out['cold_gets']} "
          f"idx={d['index_bytes']}B/{d['index_entries']}e "
          f"pt_commit={d['per_point_commit']['objects_median']}obj "
          f"tail={out['tail']['changed_or_new_leaves']}"
          f"/{out['tail']['leaves_after']} "
          f"({out['build_s']}s+{out['measure_s']}s)")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1][0] != "-" \
        else "all"
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv \
        else tempfile.mkdtemp(prefix="poc16-bench-")
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) \
        if "--seed" in sys.argv else 7
    print(f"output: {out} (seed {seed})")
    for tag in (RUNS if which == "all" else [which]):
        run(tag, out, seed)
