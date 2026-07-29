"""Reconciliation over the one-store layout.

One dial: the authenticated action leg first, then a manifest oid-diff
splitting the key space, a capability-gated push of the local-only keys,
then two-wave closure assembly of the pulled ranges — the push lands
before the pulled pile is drained, so canonical pruning during the turn
cannot retract a fact ahead of its delivery. Every arriving fact is judged
by the same ingress admission push and mint use; the kernel never learns
where a pile came from.
"""
import sqlite3

from . import catalog, indexes, manifest, shape, suppression_state
from .close import close, decode_pile, encode_pile
from .crypto import h
from .kernel import drain, proof_rank, rebuild_proofs, resolve_deps
from .limits import MAX_OBJECT_BYTES, decode_json
from .object_store import verified_object
from .store import RemoteStore
from .walk import Peer, _fetch_blobs, _push
from .worker import WorkerView


def _root_digest(store):
    raw = store.get("root")
    return h(raw) if raw is not None else None


def _object(oid, fetch):
    """One immutable remote object, hash-verified at the door."""
    try:
        return verified_object(oid, fetch)
    except ValueError as error:
        raise ValueError("remote object integrity") from error


def _resolver(node, ws, extra):
    """Own store first: a scratch kernel db — the
    derived index plus ``extra`` arrivals, ranked so ``resolve_deps``
    answers over both. Returns ``(mem, fact_of, load)``; ``load`` folds
    later arrivals in and reports the fids it could not rank."""
    mem = sqlite3.connect(":memory:")
    with node.lock:
        node.idx(ws).backup(mem)
    scratch = catalog.Catalog(mem, ws)

    def fact_of(fid):
        return extra.get(fid) or node.fact_of(ws, fid)

    def load(facts):
        facts = tuple(facts)
        extra.update({f.fid: f for f in facts})
        for fact in facts:
            scratch.stage(fact)
        # A newly arrived lower-rank provider can change the canonical winner
        # for facts already present in the scratch copy.  Incrementally ranking
        # only ``facts`` leaves those old rows stale and wedges the next closure
        # assembly after a shadow/restore window.  The scratch database is
        # bounded to this sync proof, so rebuild its ranks from the exact
        # current fact set before resolving any edge.
        rebuild_proofs(mem, fact_of, ws)
        unresolved = set()
        for fact in facts:
            deps = resolve_deps(fact, mem)
            if deps is None or proof_rank(mem, deps) is None:
                unresolved.add(fact.fid)
        return frozenset(unresolved)

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
    accepts_push = getattr(peer, "accepts_push", True)
    if got is None:
        local_etag = _root_digest(node.store(ws))
        if local_etag == cache.get("local") and not (
                cache.get("pending_push") and accepts_push):
            if cache.get("blobs") != local_etag:
                _, complete = _fetch_blobs(node, ws, peer)
                if complete:
                    cache["blobs"] = local_etag
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
    local_before = st.get("root")
    their_man = ""
    if remote_root:
        remote_snapshot = manifest.decode_root(remote_root)
        their_man = remote_snapshot.manifest
        if remote_snapshot.anchor != ws:
            raise ValueError("root anchor")

    same_actions = remote_root and local_before \
        and remote_snapshot.action_etag \
        == manifest.decode_root(local_before).action_etag
    if same_actions:
        with node.lock:
            remote_actions = {
                sid: (fid, evidence)
                for sid, fid, evidence in node.idx(ws).execute(
                    "SELECT sid, fid, evidence FROM actions")
            }
    else:
        remote_actions = action_rows(remote_root, fetch_remote) \
            if remote_root else {}
    pull_actions(node, ws, remote_root, fetch_remote, remote_actions)
    action_difference = push_actions(
        node, ws, peer, remote_actions, deliver=accepts_push)
    pushed_actions = action_difference if accepts_push else 0

    local_root, mine = st.get("root"), ()
    local_man = ""
    if local_root:
        local_snapshot = manifest.decode_root(local_root)
        local_man = local_snapshot.manifest
        if local_snapshot.anchor != ws:
            raise ValueError("root anchor")
        if local_man and local_man != their_man:
            fetch_local = lambda oid: st.get("obj/" + oid)
            mine = manifest.decode(
                _object(local_man, fetch_local), fetch_local)

    pulled_piles, push_keys = [], set()
    if local_man != their_man:
        with node.lock:
            my_keys = node.keys(ws)
        push_keys = set(my_keys)
    else:
        my_keys = ()
    if their_man and local_man != their_man:
        theirs, changed = manifest.compare(
            mine, their_man, fetch_remote)
        differing = set(changed)
        raws = dict(zip(
            (e.leaf for e in theirs if e in differing),
            fetch_remote.many(
                [e.leaf for e in theirs if e in differing])))
        members_of = lambda e: manifest.range_members(
            e, lambda oid: raws[oid])
        pulled_piles, push_keys = frontier(
            my_keys, theirs, differing, members_of)

    # Push before draining the pulled ingress: the turn's canonical pruning
    # must never retract a fact ahead of its precomputed difference pile
    # reaching the peer (bench_sync.reconcile keeps the same order).
    push_fids = sorted({shape.fid_of(k) for k in push_keys})
    pushed_facts = 0
    if push_fids and accepts_push:
        sent = set(push(node, ws, peer, push_fids))
        if not set(push_fids) <= sent:
            raise ValueError("local range is missing committed facts")
        pushed_facts = len(push_fids)
        retag = None
    pulled = 0
    if pulled_piles:
        stream = assemble(node, ws, pulled_piles, theirs, fetch_remote)
        raw = encode_pile(stream)
        pull(node, ws, h(raw), raw)
        pulled = 1
        node.turn(ws)
    _, blobs_complete = _fetch_blobs(node, ws, peer)
    local_etag = _root_digest(node.store(ws))
    cache.update({
        "etag": retag, "root": remote_root,
        "local": local_etag,
    })
    if not accepts_push and (push_fids or action_difference):
        # This edge is a reader, not a delivery receipt.  Preserve the dirty
        # marker so a later full-profile remint can deliver unchanged intent.
        cache["pending_push"] = True
    else:
        cache.pop("pending_push", None)
    if blobs_complete:
        cache["blobs"] = local_etag
    else:
        cache.pop("blobs", None)
    return pulled, pushed_facts + pushed_actions


def frontier(my_keys, theirs, differing, members_of):
    """Split the key space at the differing leaves: ``(pulled piles, push
    keys)`` — theirs-minus-mine feeds pull, mine-minus-theirs feeds push.

    Every remote row is either in ``differing`` (fetch and compare member
    keys) or exactly one of ours (RangeTree page pruned by the compare) — in
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
    node.store(ws).put_if_absent(
        f"pile/{node.member_for(ws)}/{oid}", raw)


def push(node, ws, peer, fids):
    """Close this dial's local-only union and deliver it once."""
    return _push(node, ws, peer, fids)


def action_rows(root_bytes, fetch):
    """Certified active sid -> (witness fid, evidence oid) off-request map."""
    if not root_bytes:
        return {}
    view = WorkerView.from_root(root_bytes, fetch)
    fact_tree = view._reader(indexes.FACT)
    out = {}
    for sid, slot in view._reader(indexes.SUPP).items():
        if not isinstance(slot, dict) or slot.get("state") != "active":
            continue
        try:
            fid = slot.get("action")
            if fact_tree.get(indexes.action_key(sid)) != slot:
                continue
            record = view.fact_record(fid)
            if not record["evidence"]:
                continue
            out[sid] = (fid, record["evidence"])
        except (TypeError, ValueError):
            continue
    return out


def pull_actions(node, ws, remote_root, fetch, rows=None):
    """Land independently validated action witnesses before ordinary ranges."""
    rows = action_rows(remote_root, fetch) if rows is None else rows
    accepted = []
    with node.lock:
        local = {
            sid: (fid, evidence)
            for sid, fid, evidence in node.idx(ws).execute(
                "SELECT sid, fid, evidence FROM actions")
        }
    for sid, (fid, evidence_oid) in sorted(rows.items()):
        if local.get(sid) == (fid, evidence_oid):
            continue
        try:
            fact, raw = suppression_state.validate_evidence(
                ws, sid, fid, evidence_oid, fetch)
        except (TypeError, ValueError):
            continue
        accepted.append((sid, fact, evidence_oid, raw))
    if not accepted:
        return ()

    # Action evidence uses the same pile door and workspace turn as every
    # other arrival. Sync does not gain a private archive/commit bypass.
    for _, _, _, raw in accepted:
        pull(node, ws, h(raw), raw)
    node.turn(ws)
    return tuple(fact.fid for _, fact, _, _ in accepted)


def push_actions(node, ws, peer, remote_rows, *, deliver=True):
    """Find local witnesses missing from the peer and optionally deliver them."""
    with node.lock:
        rows = node.idx(ws).execute(
            "SELECT sid, fid, evidence FROM actions ORDER BY sid").fetchall()
        evidence_oids = {
            evidence
            for sid, fid, evidence in rows
            if remote_rows.get(sid) != (fid, evidence)
        }
        payloads = [
            node.store(ws).get("obj/" + evidence)
            for evidence in sorted(evidence_oids)
        ]
    for raw in payloads:
        if raw is None:
            raise ValueError("local action evidence")
        if deliver:
            peer.put_pile(raw)
    return len(payloads)


def _sibling_keys(raw):
    """One closure sibling's key set (manifest.build's ``{"keys": [...]}``).
    Peer bytes leave as a ValueError or not at all — never a KeyError or a
    TypeError; ``":" in k`` guards ``shape.fid_of`` downstream."""
    obj = decode_json(raw, MAX_OBJECT_BYTES, "closure sibling")
    keys = obj.get("keys") if isinstance(obj, dict) else None
    if not isinstance(keys, list) or not all(shape.is_key(k) for k in keys) \
            or keys != sorted(set(keys)):
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
    """Two-wave closed-set assembly.

    Wave 1 already happened: ``pulled_piles`` are the differing home-leaf
    piles from the RangeTree compare. For their member facts, resolve every
    dep from our own store first (kernel.resolve_deps against the index); the
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
