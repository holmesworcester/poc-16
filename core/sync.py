"""Reconciliation over the one-store layout (docs/CUTOVER.md §2).

One dial: the removal-index leg first (docs/REMOVALS.md §5), then a
manifest oid-diff splitting the key space, a push of the local-only keys,
then two-wave closure assembly of the pulled ranges — the push lands
before the pulled pile is drained, so canonical pruning during the turn
cannot retract a fact ahead of its delivery. Every arriving fact is judged
by the same ingress admission push and mint use; the kernel never learns
where a pile came from.
"""
import json
import sqlite3

from . import manifest, removals, shape
from .close import close, decode_pile, encode_pile
from .crypto import h
from .kernel import extend_proofs, resolve_deps
from .pump import pump
from .store import RemoteStore
from .walk import Peer, _fetch_blobs, _push


def _object(oid, fetch):
    """One immutable remote object, hash-verified at the door."""
    raw = fetch(oid) if oid else None
    if raw is None or h(raw) != oid:
        raise ValueError("remote object integrity")
    return raw


def _resolver(node, ws, extra):
    """Own store first (docs/CUTOVER.md §2.2): a scratch kernel db — the
    derived index plus ``extra`` arrivals, ranked so ``resolve_deps``
    answers over both. Returns ``(mem, fact_of, load)``; ``load`` folds
    later arrivals in and reports the fids it could not rank."""
    mem = sqlite3.connect(":memory:")
    with node.lock:
        node.idx(ws).backup(mem)

    def fact_of(fid):
        return extra.get(fid) or node.fact_of(ws, fid)

    def load(facts):
        facts = tuple(facts)
        extra.update({f.fid: f for f in facts})
        mem.executemany(
            "INSERT OR IGNORE INTO facts VALUES(?,?,?,?)",
            ((f.fid, f.ts, f.t, json.dumps(f.to_json())) for f in facts))
        mem.executemany(
            "INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
            ((*offer, f.fid) for f in facts for offer in f.offers()))
        return extend_proofs(mem, [f.fid for f in facts], fact_of)

    return mem, fact_of, load


def _holds(node, ws, extra, key):
    """Whether ``key``'s fact is already in hand (index or arrivals)."""
    fact = extra.get(shape.fid_of(key)) or node.fact_of(ws, shape.fid_of(key))
    return fact is not None and shape.key(fact) == key


def _extract(node, ws, extra, entries, keys, fetch):
    """One batched wave over home leaves: fetch_plan groups ``keys``, each
    pile is fetched once, and exactly the needed facts come out by key."""
    plan = manifest.fetch_plan(entries, keys)
    raws = fetch.many(list(plan))
    out = []
    for (leaf, wanted), raw in zip(plan.items(), raws):
        members, _ = decode_pile(_object(leaf, lambda oid: raw))
        held = {shape.key(f): f for f in members}
        out += [held[k] for k in wanted if k in held]
    return out


def sync(node, ws, url):
    """One dial converges both sides; return ``(pulled piles, pushed facts)``."""
    peer = Peer(node, ws, url)
    remote = RemoteStore(peer)
    cache = peer.cache
    got = peer.root(cache.get("etag"))
    if got is None:
        if node.store(ws).etag("root") == cache.get("local"):
            _fetch_blobs(node, ws, peer)
            return 0, 0
        remote_root, retag = cache.get("root"), cache.get("etag")
    else:
        remote_root, retag = got

    remote_objects = {}

    def fetch_remote(oid):
        if oid not in remote_objects:
            remote_objects[oid] = remote.get("obj/" + oid)
        return remote_objects[oid]

    def fetch_many(oids):
        missing = [oid for oid in oids if oid not in remote_objects]
        if missing:
            remote_objects.update(zip(
                missing,
                remote.get_many(["obj/" + oid for oid in missing]),
            ))
        return tuple(remote_objects.get(oid) for oid in oids)

    fetch_remote.many = fetch_many

    st = node.store(ws)
    their_man = ""
    if remote_root:
        anchor, _, their_man, _ = manifest.decode_root(remote_root)
        if anchor != ws:
            raise ValueError("root anchor")

    pull_removals(node, ws, remote_root, fetch_remote)

    local_root, mine = st.get("root"), ()
    if local_root:
        anchor, _, man, _ = manifest.decode_root(local_root)
        if anchor != ws:
            raise ValueError("root anchor")
        if man:
            fetch_local = lambda oid: st.get("obj/" + oid)
            mine = manifest.decode(
                _object(man, fetch_local), fetch_local)
    with node.lock:
        my_keys = node.keys(ws)

    pulled_piles, push_keys = [], set(my_keys)
    if their_man:
        theirs = manifest.decode(
            _object(their_man, fetch_remote), fetch_remote)
        differing = set(manifest.diff(mine, their_man, fetch_remote))
        raws = dict(zip(
            (e.leaf for e in theirs if e in differing),
            fetch_remote.many(
                [e.leaf for e in theirs if e in differing])))
        members_of = lambda e: decode_pile(
            _object(e.leaf, lambda oid: raws[oid]))[0]
        pulled_piles, push_keys = frontier(
            my_keys, theirs, differing, members_of)

    # Push before draining the pulled ingress: the turn's canonical pruning
    # must never retract a fact ahead of its precomputed difference pile
    # reaching the peer (bench_sync.reconcile keeps the same order).
    push_fids = sorted({shape.fid_of(k) for k in push_keys})
    if push_fids:
        sent = set(push(node, ws, peer, push_fids))
        if not set(push_fids) <= sent:
            raise ValueError("local range is missing committed facts")
        retag = None
    pulled = 0
    if pulled_piles:
        stream = assemble(node, ws, pulled_piles, theirs, fetch_remote)
        raw = encode_pile(stream)
        pull(node, ws, h(raw), raw)
        pulled = 1
        node.turn(ws)
    _fetch_blobs(node, ws, peer)
    cache.update({
        "etag": retag, "root": remote_root,
        "local": node.store(ws).etag("root"),
    })
    return pulled, len(push_fids)


def frontier(my_keys, theirs, differing, members_of):
    """Split the key space at the differing leaves: ``(pulled piles, push
    keys)`` — theirs-minus-mine feeds pull, mine-minus-theirs feeds push.

    Every remote leaf is either in ``differing`` (fetch and compare member
    keys) or byte-identical to one of ours (oid pruned by the diff) — in
    which case its members are exactly our chunk starting at its separator,
    so the whole remote key set is known without touching cold ranges."""
    chunks, start = {}, 0
    for stop in shape.stable_cut_positions(
            [shape.fid_of(k) for k in my_keys]) + [len(my_keys)]:
        if stop > start:
            chunks[my_keys[start]] = my_keys[start:stop]
            start = stop
    held, their_keys, pulled = set(my_keys), set(), []
    for entry in theirs:
        if entry not in differing:
            their_keys.update(chunks.get(entry.sep, ()))
            continue
        members = members_of(entry)
        keys = {shape.key(fact) for fact in members}
        their_keys |= keys
        if keys - held:
            pulled.append((entry, members))
    return pulled, held - their_keys


def pull(node, ws, oid, raw):
    """Put one verified path union into local ingress."""
    if raw is None or h(raw) != oid:
        raise ValueError("remote object integrity")
    node.store(ws).put(f"pile/{node.member_for(ws)}/{oid}", raw)


def push(node, ws, peer, fids):
    """Close this dial's local-only union and deliver it once."""
    return _push(node, ws, peer, fids)


def pull_removals(node, ws, remote_root, fetch):
    """The removal-index leg, run BEFORE the fact leg (REMOVALS.md §5).

    Compare the remote root's removals fp (manifest.decode_root) with ours;
    when they differ, fetch the index pile, decode entries, and admit each
    entry individually (removals.admit + judging its removal's closure via
    the ordinary assembly below — one judge, I3). node.apply_removals then
    appends retroactive '-' rows for already-materialized victims and the
    pump applies them. Replaces the SUPP index leg and close_deletions.
    Returns the admitted entries — the per-entry admission observable
    (I3); the fact leg reads the same table through node.removal_entries,
    THE one accessor."""
    ours = {"oid": "", "fp": ""}
    local_root = node.store(ws).get("root")
    if local_root:
        ours = manifest.decode_root(local_root)[3]
    if not remote_root:
        return ()
    _, _, man, theirs = manifest.decode_root(remote_root)
    if not theirs["oid"] or theirs["fp"] == ours["fp"]:
        with node.lock:
            return node.removal_entries(ws)
    entries, refs = removals.decode(_object(theirs["oid"], fetch))
    if removals.fingerprint(entries) != theirs["fp"]:
        raise ValueError("removal index fingerprint")

    extra = {}
    mem, fact_of, load = _resolver(node, ws, extra)
    try:
        need = [k for k in refs if not _holds(node, ws, extra, k)]
        if need:
            spine = manifest.decode(_object(man, fetch), fetch)
            load(_extract(node, ws, extra, spine, need, fetch))
        by_fid = {shape.fid_of(k): k for k in refs}
        judged = False
        for entry in entries:
            fact = extra.get(entry.fid)
            if node.fact_of(ws, entry.fid) is not None \
                    or entry.fid not in by_fid or fact is None:
                continue
            try:  # one poisoned closure rejects alone (I3), never the index
                unit = close([fact], _deps(mem, fact_of), fact_of)
            except ValueError:
                continue
            raw = encode_pile(unit)
            pull(node, ws, h(raw), raw)
            judged = True
        if judged:
            node.turn(ws)
    finally:
        mem.close()
    admitted = tuple(
        entry for entry in entries
        if (fact := node.fact_of(ws, entry.fid)) is not None
        and removals.admit(entry, fact))
    with node.lock:
        node.apply_removals(ws, admitted)
        node.idx(ws).commit()
        pump(node, ws)
    return admitted


def _sibling_keys(raw):
    """One closure sibling's key set (manifest.build's ``{"keys": [...]}``).
    Peer bytes leave as a ValueError or not at all — never a KeyError or a
    TypeError; ``":" in k`` guards ``shape.fid_of`` downstream."""
    obj = json.loads(raw)
    keys = obj.get("keys") if isinstance(obj, dict) else None
    if not isinstance(keys, list) or not all(
            isinstance(k, str) and ":" in k for k in keys):
        raise ValueError("closure sibling shape")
    return set(keys)


def _deps(mem, fact_of):
    """Dep edges over the scratch db; a gap is a routing bug, never a loop."""
    def deps_of(fid):
        fact = fact_of(fid)
        deps = resolve_deps(fact, mem) if fact else None
        if deps is None or any(fact_of(dep) is None for dep in deps):
            raise ValueError("closure assembly")
        return deps
    return deps_of


def assemble(node, ws, pulled_piles, entries, fetch):
    """Two-wave closed-set assembly (docs/CUTOVER.md §2.2).

    Wave 1 already happened: ``pulled_piles`` are the differing home-leaf
    piles from manifest.diff. For their member facts, resolve every dep from
    our own store first (kernel.resolve_deps against the index); the
    remainder is the union of the leaves' closure-sibling keys, filtered to
    keys we don't hold. Wave 2: manifest.fetch_plan groups those keys by
    home leaf; one batched GET wave (fetch.many / store.PAGE_BATCH); extract
    exactly the needed facts from each fetched pile by key. Sibling keys are
    transitive, so there is no wave 3 — assert, don't loop. Returns one
    deps-first stream (close.close) ready for encode_pile -> pull() ->
    node.turn(): the ordinary ingress admission, same as push and mint."""
    extra = {}
    mem, fact_of, load = _resolver(node, ws, extra)
    try:
        gaps = set(load(
            fact for _, members in pulled_piles for fact in members))
        for fid in extra:
            deps = resolve_deps(fact_of(fid), mem)
            if deps is None or any(fact_of(dep) is None for dep in deps):
                gaps.add(fid)
        if gaps:  # cold-partial only: the warm path never touches siblings
            siblings = [e.closure for e, _ in pulled_piles if e.closure]
            keys = set()
            for oid, raw in zip(siblings, fetch.many(siblings)):
                keys |= _sibling_keys(_object(oid, lambda _: raw))
            need = sorted(
                k for k in keys if not _holds(node, ws, extra, k))
            load(_extract(node, ws, extra, entries, need, fetch))
        return close(tuple(extra.values()), _deps(mem, fact_of), fact_of)
    finally:
        mem.close()
