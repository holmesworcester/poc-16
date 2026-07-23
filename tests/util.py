"""Test helpers: author facts directly (bypassing HTTP) to build fixtures."""
import random

from tinyp2p.close import close, encode_pile
from tinyp2p.crypto import h, keypair
from tinyp2p.facts.auth.invite import invite
from tinyp2p.facts.auth.join import join
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.content.message import message
from tinyp2p.kernel import resolve_deps
from tinyp2p.node import Node, now_ms


def add_member(n, ws, name, ts=None):
    """Invite + join without the HTTP blob dance: returns (sk, pk, join_fact)."""
    ts = ts or now_ms()
    isk, ipk = keypair()
    inv = invite(n.pk, ipk, ts)
    si = signature(n.sk, n.pk, inv, ts)
    bsk, bpk = keypair()
    j = join(inv, isk, bpk, name, ts)
    sj = signature(bsk, bpk, j, ts)
    with n.lock:
        from tinyp2p.kernel import offer_src
        asrc = offer_src(n.idx(ws), "admin", n.pk)
    deps = {inv.fid: [si.fid, asrc], si.fid: [],
            j.fid: [inv.fid, sj.fid], sj.fid: []}
    n.ingest_new(ws, [si, inv, sj, j], deps)
    return bsk, bpk, j


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
