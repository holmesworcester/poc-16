"""Pure mint: decode → family grant hook + kernel evaluate.

The caller has already closed one ephemeral request over its authority proof.
The request family owns tag, verb, expiry, and removal policy; the daemon only
supplies root metadata, a canonical authority view, and sealing.

Stable validity never reads suppression:

    valid(f) = pred(f, closure(f))   immutable, globals-blind, per-fact
    S(D)     = targets of valid suppression facts     monotone semilattice
    E(D)     = V(D) ∖ S(D)           a difference of monotone sets
                                     => order-independent, no linearization

Suppression masks only after judgment. A peer passes its root-stamped idx so
evaluate can reject omitted incompatible authority winners. A stateless
runtime builds the same read-only projection from validated tree leaves and
may reuse it while its root ETag matches.
"""
import sqlite3
from dataclasses import dataclass

import facts as families
from . import tree
from .close import decode_pile
from .crypto import h
from .kernel import SCHEMA, evaluate, unresolved_facts, validate
from .shape import FACT


@dataclass
class Authority:
    """A reusable canonical offer/proof projection for exactly one root."""

    etag: str
    root: tree.Root
    db: sqlite3.Connection

    @classmethod
    def from_root(cls, root_bytes, fetch):
        root = tree.decode_root(root_bytes)
        active, closure = {}, set()
        for lo, hi, leaf in tree.leaf_ranges(root.view, fetch):
            unit = tree.leaf_facts(leaf, lo, hi, FACT, fetch)
            if not validate(unit, root.anchor):
                raise ValueError("invalid authority leaf")
            closure.update(fact.fid for fact in unit)
            active.update(
                (fact.fid, fact)
                for fact in unit
                if lo < FACT.key(fact) <= hi
            )
        if len(active) != root.view.n or not closure.issubset(active):
            raise ValueError("authority projection does not match root")

        db = sqlite3.connect(":memory:", check_same_thread=False)
        try:
            db.executescript(SCHEMA)
            db.executemany(
                "INSERT INTO facts VALUES(?,?,?)",
                ((fact.fid, fact.ts, fact.t) for fact in active.values()),
            )
            db.executemany(
                "INSERT INTO offers VALUES(?,?,?,?)",
                ((*offer, fact.fid)
                 for fact in active.values() for offer in fact.offers()),
            )
            unresolved = unresolved_facts(db, active.get)
            if unresolved:
                raise ValueError("authority root has no finite proof set")
            db.commit()
            db.execute("PRAGMA query_only=ON")
            return cls(h(root_bytes), root, db)
        except Exception:
            db.close()
            raise

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def mint(pile_bytes, anchor, globals_, now, *, canonical_db):
    """decode → kernel.evaluate(facts, anchor, globals ∪ {("now", now)}) →
    grant_of. Returns (pk, verb) to seal, or None to refuse. The challenge is
    ephemeral (never persisted); replay is harmless because the grant is
    sealed to the requester's pk. ``canonical_db`` binds already-known needs
    to the committed authority winners."""
    if canonical_db is None:
        return None
    try:
        facts, _ = decode_pile(pile_bytes)
        grant = grant_of(facts)
        allowed = evaluate(
            facts, anchor, frozenset(globals_) | {("now", now)},
            canonical_db=canonical_db)
    except Exception:
        return None
    return grant if grant is not None and allowed else None


def stateless(pile_bytes, root_bytes, fetch, now, projection=None):
    """Mint from store state alone, optionally reusing a matching projection."""
    authority, owned = projection, False
    try:
        if authority is None or authority.etag != h(root_bytes):
            authority = Authority.from_root(root_bytes, fetch)
            owned = True
        root = authority.root
        return mint(
            pile_bytes, root.anchor, root.globals_, now,
            canonical_db=authority.db)
    except Exception:
        return None
    finally:
        if owned and authority is not None:
            authority.close()


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
    """Read root-riding metadata; stateless production uses ``stateless``."""
    root = tree.decode_root(root_bytes)
    return root.anchor, root.globals_
