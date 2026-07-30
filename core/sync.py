"""Peer reconciliation as one join over admitted candidates.

The replicated value is:

``candidate fid -> (exact fact bytes, minimum verified proof root)``

FactOrder, eligibility, resolved edges, suppression, and authority are pure
projections of that join.  Sync therefore has no separate action channel,
range-leaf protocol, closure sibling, or projection authority.  Every selected
historical proof re-enters through the ordinary closed-pile ingress door.
Detached file bytes remain a separate best-effort completion pass.
"""
from dataclasses import dataclass

import facts

from .crypto import h
from .limits import MAX_OBJECT_BYTES, MAX_ROOT_BYTES
from .repository_reader import RepositoryReader
from .store import RemoteStore
from .walk import Peer, _fetch_blobs


@dataclass(frozen=True)
class CandidateDelta:
    pull: tuple
    push: tuple


_UNREAD = object()


def _root_digest(store):
    raw = store.get_bounded("root", MAX_ROOT_BYTES)
    return h(raw) if raw is not None else None


def _candidate_record(view, fid):
    if view is None:
        return None
    try:
        return view.fact_record(fid)
    except ValueError as error:
        if str(error) == "missing FactRecord":
            return None
        raise


def _delta(local, remote):
    """Compute the min-proof semilattice delta for two pinned roots."""
    remote_fids = remote.candidate_ids() if remote is not None else ()
    local_fids = local.candidate_ids() if local is not None else ()
    pull, push = [], []
    for fid in remote_fids:
        theirs = remote.fact_record(fid)
        ours = _candidate_record(local, fid)
        if ours is None or theirs["admission"] < ours["admission"]:
            pull.append(fid)
    for fid in local_fids:
        ours = local.fact_record(fid)
        theirs = _candidate_record(remote, fid)
        if theirs is None or ours["admission"] < theirs["admission"]:
            push.append(fid)
    return CandidateDelta(tuple(pull), tuple(push))


def _push_candidates(view, fids, peer, sender):
    """Deliver verified deltas as bounded ordinary piles.

    Bad witnesses remain independent: every valid closure is still delivered.
    Detached objects precede every pile that can name them, and the receiver
    invokes its one RepositoryApplier settlement path per bounded batch.
    """
    closures, failures = [], []
    for fid in fids:
        try:
            closures.append(view.verify(fid).facts)
        except (TypeError, ValueError) as error:
            failures.append(error)
    sender.deliver(peer, closures)
    return failures


def pull(node, workspace, oid, raw):
    """Stage one verified proof closure through ordinary pile ingress."""
    if raw is None or h(raw) != oid:
        raise ValueError("remote object integrity")
    node.stage_received_pile(
        workspace, node.member_for(workspace), raw)


def reconcile_candidates(
        node, workspace, peer, remote_root, fetch_remote, *,
        deliver=True, local_root=_UNREAD):
    """Join candidate/proof state, landing independent valid proofs first.

    A poisoned selected proof cannot become a cached false convergence.  Valid
    independent candidates are staged and settled, then the first unresolved
    difference is raised so the remote root remains eligible for retry or
    operator diagnosis.
    """
    store = node.store(workspace)
    if local_root is _UNREAD:
        local_root = store.get_bounded("root", MAX_ROOT_BYTES)
    remote = RepositoryReader(
        workspace, remote_root, fetch_remote,
    ).candidates() if remote_root else None
    local = RepositoryReader(
        workspace,
        local_root,
        lambda oid: store.get_bounded(
            "obj/" + oid, MAX_OBJECT_BYTES),
    ).candidates() if local_root else None
    delta = _delta(local, remote)
    failures = []

    if deliver and local is not None:
        try:
            failures.extend(_push_candidates(
                local, delta.push, peer, node.sender(workspace)))
        except (TypeError, ValueError) as error:
            failures.append(error)

    landed = 0
    if remote is not None:
        closures = []
        for fid in delta.pull:
            try:
                closures.append(remote.verify(fid).facts)
                landed += 1
            except (TypeError, ValueError) as error:
                failures.append(error)
        for raw in node.sender(workspace).pack_batches(closures):
            pull(node, workspace, h(raw), raw)
    if landed:
        node.turn(workspace)
    if failures:
        raise ValueError(
            "unresolved candidate difference") from failures[0]
    return (
        int(bool(landed)),
        len(delta.push) if deliver else 0,
        bool(delta.push),
    )


def sync(node, workspace, url):
    """Converge one peer dial; return ``(pulled turn, pushed candidates)``."""
    peer = Peer(node, workspace, url)
    remote_store = RemoteStore(peer)
    cache = peer.cache
    got = peer.root(
        cache.get("etag"), response_limit=MAX_ROOT_BYTES)
    accepts_push = peer.accepts_push
    if got is None:
        local_etag = _root_digest(node.store(workspace))
        if local_etag == cache.get("local") and not (
                cache.get("pending_push") and accepts_push):
            if cache.get("blobs") != local_etag:
                _, complete = _fetch_blobs(node, workspace, peer)
                if complete:
                    cache["blobs"] = local_etag
            return 0, 0
        remote_root, remote_etag = cache.get("root"), cache.get("etag")
    else:
        remote_root, remote_etag = got

    objects = {}

    def fetch_remote(oid):
        if oid not in objects:
            objects[oid] = remote_store.get_bounded(
                "obj/" + oid, MAX_OBJECT_BYTES)
        return objects[oid]

    local_root = node.store(workspace).get_bounded(
        "root", MAX_ROOT_BYTES)
    pulled, pushed, pending_push = reconcile_candidates(
        node,
        workspace,
        peer,
        remote_root,
        fetch_remote,
        deliver=accepts_push,
        local_root=local_root,
    )
    if pushed:
        # The peer consumed an ordinary pile and may now expose a new root.
        remote_etag = None

    _, blobs_complete = _fetch_blobs(node, workspace, peer)
    cache.update({"etag": remote_etag, "root": remote_root})
    if pulled:
        # The turn produced a new local snapshot after the compared root.  A
        # confirmation dial must compare that exact result.
        cache.pop("local", None)
    else:
        cache["local"] = h(local_root) if local_root is not None else None
    if pending_push and not accepts_push:
        cache["pending_push"] = True
    else:
        cache.pop("pending_push", None)
    current_etag = _root_digest(node.store(workspace))
    compared_etag = h(local_root) if local_root is not None else None
    if blobs_complete and not pulled and current_etag == compared_etag:
        cache["blobs"] = compared_etag
    else:
        cache.pop("blobs", None)
    return pulled, pushed


__all__ = ["CandidateDelta", "pull", "reconcile_candidates", "sync"]
