"""Thin reconciliation driver over :mod:`core.tree`."""
from . import tree
from .close import encode_pile
from .crypto import h
from .shape import FACT
from .store import RemoteStore
from .walk import Peer, _fetch_blobs, _push


def _empty():
    return tree.View(
        FACT.fingerprint([]), h(b""), "", 0, (), kind="flat")


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
    mine = local.view if local else _empty()
    theirs = other.view if other else _empty()

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
    pull_ranges, missing_fids, pushed_fids = [], set(), set()
    for lo, hi, my_keys, their_leaf in tree.diff(
            mine, theirs, FACT, fetch_local, fetch_remote):
        their_keys = set(tree.range_keys(
            their_leaf, lo, hi, FACT, fetch_remote))
        mine_keys = set(my_keys)
        missing = {FACT.fid_of(key) for key in their_keys - mine_keys}
        if missing:
            pull_ranges.append((lo, hi))
            missing_fids.update(missing)
        outgoing = [
            FACT.fid_of(key) for key in mine_keys - their_keys
            if FACT.fid_of(key) not in pushed_fids
        ]
        if outgoing:
            push(node, ws, peer, outgoing)
            pushed_fids.update(outgoing)
            retag = None

    pulled = 0
    if pull_ranges:
        stream = tree.range_facts(
            theirs, pull_ranges, fetch_remote, FACT)
        if not missing_fids.issubset(
                fact.fid for fact in stream):
            raise ValueError("remote range is missing committed facts")
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
    """Close one range's local-only facts and deliver it."""
    _push(node, ws, peer, fids)
