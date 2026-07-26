"""Thin reconciliation driver over :mod:`core.tree`."""
from . import tree
from .close import encode_pile
from .crypto import h
from .shape import FACT, SUPP, SUPP_INDEX
from .store import RemoteStore
from .suppression import close_deletions
from .walk import Peer, _fetch_blobs, _push


def _empty(shape):
    return tree.View(
        shape.fingerprint([]), h(b""), "", 0, (), kind="flat")


def _union(units):
    """Deduplicate closed topological streams without disturbing their order."""
    out, seen = [], set()
    for fact in (fact for unit in units for fact in unit):
        if fact.fid not in seen:
            seen.add(fact.fid)
            out.append(fact)
    return tuple(out)


def closure_sync(view, ranges, supp, fetch):
    """Close primary ranges under deps first, then suppression matches."""
    primary = tree.range_facts(view, ranges, fetch, FACT)
    return close_deletions(primary, supp, fetch).unit


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
    local_root = node.store(ws).get("root")
    local = tree.decode_root(local_root) if local_root else None
    other = tree.decode_root(remote_root) if remote_root else None
    if any(root.anchor != ws for root in (local, other) if root):
        raise ValueError("root anchor")
    if any(
            name != SUPP_INDEX
            for root in (local, other) if root
            for name, _ in root.indexes):
        raise ValueError("root indexes")
    local_supp = local.index(SUPP_INDEX) if local else None
    remote_supp = other.index(SUPP_INDEX) if other else None
    local_supp = local_supp or _empty(SUPP)
    remote_supp = remote_supp or _empty(SUPP)
    indexes = (
        (SUPP, local_supp, remote_supp),
        (
            FACT,
            local.view if local else _empty(FACT),
            other.view if other else _empty(FACT),
        ),
    )

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
    fetch_local = lambda oid: node.store(ws).get("obj/" + oid)
    pull_units, pushed_fids = [], set()
    for projection, mine, theirs in indexes:
        pull_ranges, missing_fids = [], set()
        for lo, hi, my_keys, their_leaf in tree.diff(
                mine, theirs, projection, fetch_local, fetch_remote):
            their_keys = set(tree.range_keys(
                their_leaf, lo, hi, projection, fetch_remote))
            mine_keys = set(my_keys)
            missing = {
                projection.fid_of(key)
                for key in their_keys - mine_keys
            }
            if missing:
                pull_ranges.append((lo, hi))
                missing_fids.update(missing)
            local_only = {
                projection.fid_of(key)
                for key in mine_keys - their_keys
            }
            pushed_fids.update(local_only)
        if pull_ranges:
            if projection is FACT:
                stream = closure_sync(
                    theirs, pull_ranges, remote_supp, fetch_remote)
            else:
                stream = tree.range_facts(
                    theirs, pull_ranges, fetch_remote, projection)
            if not missing_fids.issubset(
                    fact.fid for fact in stream):
                raise ValueError("remote range is missing committed facts")
            pull_units.append(stream)

    if pushed_fids:
        sent = set(push(node, ws, peer, sorted(pushed_fids)))
        if not pushed_fids <= sent:
            raise ValueError("local range is missing committed facts")
        retag = None

    pulled = 0
    if pull_units:
        stream = _union(pull_units)
        raw = encode_pile(stream)
        pull(node, ws, h(raw), raw)
        pulled = 1
        node.turn(ws)
    _fetch_blobs(node, ws, peer)
    cache.update({
        "etag": retag, "root": remote_root,
        "local": node.store(ws).etag("root"),
    })
    return pulled, len(pushed_fids)


def pull(node, ws, oid, raw):
    """Put one verified path union into local ingress."""
    if raw is None or h(raw) != oid:
        raise ValueError("remote object integrity")
    node.store(ws).put(f"pile/{node.member_for(ws)}/{oid}", raw)


def push(node, ws, peer, fids):
    """Close this dial's local-only union and deliver it once."""
    return _push(node, ws, peer, fids)


# ---- cutover skeletons (oyd.3, docs/CUTOVER.md §2) --------------------------
# Bodies land with the sync rewrite; everything above this line except
# _union, pull, and push is deleted by that rewrite.


def pull_removals(node, ws, remote_root, fetch):
    """The removal-index leg, run BEFORE the fact leg (REMOVALS.md §5).

    Compare the remote root's removals fp (manifest.decode_root) with ours;
    when they differ, fetch the index pile, decode entries, and admit each
    entry individually (removals.admit + judging its removal's closure via
    the ordinary assembly below — one judge, I3). Replaces the SUPP index
    leg and close_deletions. Returns the admitted entries so the fact leg
    carries the removal set while reading."""
    raise NotImplementedError


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
    raise NotImplementedError
