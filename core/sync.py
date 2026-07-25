"""Thin reconciliation driver over :mod:`core.tree`."""
from . import tree
from .close import decode_pile
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

    fetch_local = lambda oid: node.store(ws).get("obj/" + oid)
    pulled_oids, pushed_fids = set(), set()
    for lo, hi, my_keys, their_leaf in tree.diff(
            mine, theirs, FACT, fetch_local, fetch_remote):
        their_keys = set(tree.range_keys(
            their_leaf, lo, hi, FACT, fetch_remote))
        mine_keys = set(my_keys)
        missing = {FACT.fid_of(key) for key in their_keys - mine_keys}
        if missing:
            candidates = (
                [(their_leaf.oid, fetch_remote(their_leaf.oid))]
                if their_leaf.oid else remote_objects.items()
            )
            for oid, raw in candidates:
                if oid in pulled_oids or raw is None:
                    continue
                try:
                    stream, _ = decode_pile(raw)
                except Exception:
                    continue
                if missing.intersection(fact.fid for fact in stream):
                    pull(node, ws, oid, raw)
                    pulled_oids.add(oid)
        outgoing = [
            FACT.fid_of(key) for key in mine_keys - their_keys
            if FACT.fid_of(key) not in pushed_fids
        ]
        if outgoing:
            push(node, ws, peer, outgoing)
            pushed_fids.update(outgoing)
            retag = None

    if pulled_oids:
        node.turn(ws)
        _fetch_blobs(node, ws, peer)
    cache.update({
        "etag": retag, "root": remote_root,
        "local": node.store(ws).etag("root"),
    })
    return len(pulled_oids), len(pushed_fids)


def pull(node, ws, oid, raw):
    """Put a remote leaf pile verbatim into local ingress."""
    if raw is None or h(raw) != oid:
        raise ValueError("remote object integrity")
    node.store(ws).put(f"pile/{node.member_for(ws)}/{oid}", raw)


def push(node, ws, peer, fids):
    """Close one range's local-only facts and deliver it."""
    _push(node, ws, peer, fids)
