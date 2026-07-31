"""Peer reconciliation as one join over validated fact identities.

The replicated value is:

``fid -> canonical fact bytes``

FactOrder, suppression, and authority are mechanical projections of that
monotone set.  A sender assembles a fresh closure for each missing fact; no
stored validation path crosses the wire. Every closure re-enters through the
ordinary exact-pile door. Detached file bytes remain a separate best-effort
completion pass.
"""
from dataclasses import dataclass

import facts

from core.crypto import h
from core.limits import MAX_REPOSITORY_OBJECT_BYTES, MAX_ROOT_BYTES
from core.repository_reader import RepositoryReader
from core.store import RemoteStore
from .walk import Peer, _fetch_blobs


@dataclass(frozen=True)
class FactDelta:
    pull: tuple
    push: tuple


_UNREAD = object()


def _root_digest(store):
    raw = store.get_bounded("root", MAX_ROOT_BYTES)
    return h(raw) if raw is not None else None


def _delta(local, remote):
    """Compute the grow-only validated-fid delta for two pinned roots."""
    remote_fids = set(remote.fact_ids()) if remote is not None else set()
    local_fids = set(local.fact_ids()) if local is not None else set()
    for fid in remote_fids & local_fids:
        if remote.fact_oid(fid) != local.fact_oid(fid):
            raise ValueError("validated fact identity conflict")
    return FactDelta(
        tuple(sorted(remote_fids - local_fids)),
        tuple(sorted(local_fids - remote_fids)),
    )


def _push_facts(view, fids, peer, sender):
    """Deliver freshly closed validated-fact deltas as ordinary piles.

    Bad closures remain independent: every valid closure is still delivered.
    Detached objects precede every pile that can name them, and the receiver
    invokes its one RepositoryApplier path per bounded batch.
    """
    closures, failures = [], []
    for fid in fids:
        try:
            closures.append(view.closure((fid,)))
        except (TypeError, ValueError) as error:
            failures.append(error)
    sender.deliver(peer, closures)
    return failures


def pull(node, workspace, oid, raw):
    """Stage one freshly verified closure through ordinary pile ingress."""
    if raw is None or h(raw) != oid:
        raise ValueError("remote object integrity")
    node.stage_received_pile(
        workspace, node.member_for(workspace), raw)


def reconcile_facts(
        node, workspace, peer, remote_root, fetch_remote, *,
        deliver=True, local_root=_UNREAD):
    """Join validated facts, landing independent valid closures first.

    A poisoned closure cannot become a cached false convergence.  Valid
    independent facts are staged and applied, then the first unresolved
    difference is raised so the remote root remains available for retry or
    operator diagnosis.
    """
    store = node.store(workspace)
    if local_root is _UNREAD:
        local_root = store.get_bounded("root", MAX_ROOT_BYTES)
    remote = RepositoryReader(
        workspace, remote_root, fetch_remote,
    ).validated() if remote_root else None
    local = RepositoryReader(
        workspace,
        local_root,
        lambda oid: store.get_bounded(
            "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES),
    ).validated() if local_root else None
    delta = _delta(local, remote)
    failures = []

    if deliver and local is not None:
        try:
            failures.extend(_push_facts(
                local, delta.push, peer, node.sender(workspace)))
        except (TypeError, ValueError) as error:
            failures.append(error)

    landed = 0
    if remote is not None:
        closures = []
        for fid in delta.pull:
            try:
                closures.append(remote.closure((fid,)))
                landed += 1
            except (TypeError, ValueError) as error:
                failures.append(error)
        for raw in node.sender(workspace).pack_batches(closures):
            pull(node, workspace, h(raw), raw)
    if landed:
        node.turn(workspace)
    if failures:
        raise ValueError(
            "unresolved validated-fact difference") from failures[0]
    return (
        int(bool(landed)),
        len(delta.push) if deliver else 0,
        bool(delta.push),
    )


def sync(node, workspace, url):
    """Converge one peer dial; return ``(pulled turn, pushed facts)``."""
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
                "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES)
        return objects[oid]

    local_root = node.store(workspace).get_bounded(
        "root", MAX_ROOT_BYTES)
    pulled, pushed, pending_push = reconcile_facts(
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


__all__ = ["FactDelta", "pull", "reconcile_facts", "sync"]
