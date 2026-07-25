"""PLAN SKELETON (poc-16-808.4, stage S3) — mint = evaluate ∘ close({request}).

SIMPLIFY.md §4. daemon.Handler.mint thins to: decode → mint() → seal; its
hand-rolled checks (tag filter, arity, expiry) move into the request family's
evaluate hook, next to the rest of the policy. Rule: a mint pile contains
exactly ONE DURABLE=False fact.

The two-predicate frame, stated once (feeds yez.9's matrix and the gxz seam):

    valid(f) = pred(f, closure(f))   immutable, globals-blind, per-fact
    S(D)     = targets of valid suppression facts     monotone semilattice
    E(D)     = V(D) ∖ S(D)           a difference of monotone sets
                                     => order-independent, no linearization

Verdicts never read S — suppression masks AFTER judgment, at exactly three
places: the gate (here), the closure edge (yez.11 resolve_supp), the pump
(pump.py). Never the kernel, never the tree.

Family hooks to add in facts/auth/request.py:
    grant(f)         -> (pk, verb)   the sealed grant's subject
    evaluate(f, g)   -> bool         absorbs tag/arity/exp; g has ("now", ms)
"""
from . import facts as families
from . import tree
from .close import decode_pile
from .kernel import evaluate


def mint(pile_bytes, anchor, globals_, now, canonical_db=None):
    """decode → kernel.evaluate(facts, anchor, globals ∪ {("now", now)}) →
    grant_of. Returns (pk, verb) to seal, or None to refuse. The challenge is
    ephemeral (never persisted); replay is harmless because the grant is
    sealed to the requester's pk."""
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
    """(anchor, globals) read off the root object — they ride the root node
    once jbg.1 drops the manifest (tree.Root). The stateless Worker/λ mint is
    GET root → mint() → presign: kernel + tree + gate is its entire world; it
    NEVER builds app.db (SIMPLIFY.md §4)."""
    root = tree.decode_root(root_bytes)
    return root.anchor, root.globals_
