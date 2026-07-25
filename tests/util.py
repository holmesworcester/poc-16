"""Test helpers: author facts directly (bypassing HTTP) to build fixtures."""
import random

from tinyp2p.close import close, encode_pile
from tinyp2p.crypto import h, keypair
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.facts.content.message import message
from tinyp2p.kernel import resolve_deps
from tinyp2p.node import Node, now_ms


def add_member(
        n, ws, name, ts=None, inviter=None, member_identity=None):
    """Add a user through an existing member and return ``(sk, pk, user)``.

    ``inviter`` is that member's ``(sk, pk)`` identity and defaults to the
    workspace founder. ``member_identity`` can pin the joining key in
    adversarial fixtures. ``ts`` is the invite timestamp; the user follows
    one tick later so every delegation edge is strictly forward in time.
    """
    inviter_sk, inviter_pk = inviter or n.identity(ws)
    with n.lock:
        from tinyp2p.kernel import offer_src
        member_source = offer_src(n.idx(ws), "member", inviter_pk)
        if member_source is None:
            raise ValueError("inviter is not a workspace member")
        member_ts = n.fact_of(ws, member_source).ts
    invite_ts = max(now_ms(), member_ts + 1) if ts is None else ts
    if invite_ts <= member_ts:
        raise ValueError("invite timestamp must follow the inviter's membership")
    user_ts = invite_ts + 1
    isk, ipk = keypair()
    inv = user_invite(inviter_pk, ipk, invite_ts)
    si = signature(inviter_sk, inviter_pk, inv, invite_ts)
    bsk, bpk = member_identity or keypair()
    joined = user(inv, isk, bpk, name, user_ts)
    joined_sig = signature(bsk, bpk, joined, user_ts)
    deps = {inv.fid: [si.fid, member_source], si.fid: [],
            joined.fid: [inv.fid, joined_sig.fid], joined_sig.fid: []}
    n.ingest_new(ws, [si, inv, joined_sig, joined], deps)
    return bsk, bpk, joined


def author_msg(n, ws, sk, pk, text, ts=None, chan="general"):
    """A message from an arbitrary member key, via the ordinary ingress."""
    ts = ts or now_ms()
    f = message(pk, chan, text, ts)
    s = signature(sk, pk, f, ts)
    deps = {f.fid: [s.fid, member_src(n, ws, pk)], s.fid: []}
    n.ingest_new(ws, [s, f], deps)
    return f


def member_src(n, ws, pk):
    from tinyp2p.kernel import offer_src
    with n.lock:
        return offer_src(n.idx(ws), "member", pk)


def closed_subset(n, ws, fids):
    """close() an arbitrary subset out of a node's index — a valid pile."""
    with n.lock:
        idx = n.idx(ws)
        facts = close([n.fact_of(ws, fid) for fid in fids],
                      lambda fid: resolve_deps(n.fact_of(ws, fid), idx) or [],
                      lambda fid: n.fact_of(ws, fid))
    return encode_pile(facts)


def deliver(dst, ws, pile_bytes, member="feed7feed7feed7f"):
    dst.store(ws).put(f"pile/{member}/{h(pile_bytes)}", pile_bytes)


def all_fids(n, ws):
    return [fid for (fid,) in n.idx(ws).execute("SELECT fid FROM facts ORDER BY ts, fid")]
