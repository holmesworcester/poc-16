"""Pure mint: decode → family grant hook + kernel evaluate.

The caller has already closed one ephemeral request over its authority proof.
The request family owns tag, verb, expiry, and removal policy; the daemon only
supplies root metadata, a canonical authority view, and sealing.

Stable validity never reads suppression:

    valid(f) = pred(f, closure(f))   immutable, globals-blind, per-fact
    S(D)     = targets of valid suppression facts     monotone semilattice
    E(D)     = V(D) ∖ S(D)           a difference of monotone sets
                                     => order-independent, no linearization

Suppression masks only after judgment. A peer also passes its root-stamped idx
so evaluate can reject omitted incompatible authority winners. A stateless
runtime must derive the equivalent view from the root/tree (poc-16-jbg.10);
root metadata alone covers only conflict-free requests.
"""
import facts as families
from . import tree
from .close import decode_pile
from .kernel import evaluate


def mint(pile_bytes, anchor, globals_, now, canonical_db=None):
    """decode → kernel.evaluate(facts, anchor, globals ∪ {("now", now)}) →
    grant_of. Returns (pk, verb) to seal, or None to refuse. The challenge is
    ephemeral (never persisted); replay is harmless because the grant is
    sealed to the requester's pk. ``canonical_db`` binds already-known needs
    to the committed authority winners."""
    try:
        facts, _ = decode_pile(pile_bytes)
        grant = grant_of(facts)
        allowed = evaluate(
            facts, anchor, frozenset(globals_) | {("now", now)},
            canonical_db=canonical_db)
    except Exception:
        return None
    return grant if grant is not None and allowed else None


def grant_of(facts):
    """The one request fact's (pk, verb) via the family hook — the daemon
    stops parsing fact bodies."""
    ephemeral = [
        (fact, handler)
        for fact in facts
        if (handler := families.handler_for(fact.t)) is not None
        and not handler.DURABLE
    ]
    if len(ephemeral) != 1:
        return None
    fact, handler = ephemeral[0]
    try:
        return handler.grant(fact)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def screen(facts, supp):
    """Gate mask, the gxz candidate seam: screen the WHOLE submitted closure
    against S at mint/ingress — not just the requester — so an active member
    cannot relay an evicted signer's facts through their own grant. The
    DECISION belongs to poc-16-yez.9; this stub only fixes the seam so every
    option keeps valid() globals-blind."""
    raise NotImplementedError("poc-16-yez.9 decides; wire here")


def root_globals(root_bytes):
    """Read root-riding metadata, not the canonical authority projection.

    Mint never needs app.db. Peers pass idx.db separately; stateless runtimes
    must derive an equivalent view from the tree before production use.
    """
    root = tree.decode_root(root_bytes)
    return root.anchor, root.globals_
