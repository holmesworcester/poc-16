"""The family-neutral streaming judge.

``validate(stream, anchor) -> bool`` is the small trustless-consumer path.
``drain(stream, anchor)`` additionally returns kernel-minted ``Valid`` values
and monotone global rows for the engine.  ``evaluate(stream, anchor, globals)``
applies optional ephemeral family gates and returns only a boolean.  All three
share the same one-pass seen-set judge; input is already canonical-topological,
so the kernel never sorts or waits.

Families under :mod:`tinyp2p.facts` own exact shapes, declared needs, immutable
boolean validation, mode policy, global deltas, and materialization.  The core
only resolves relationships and dispatches.
"""
import sqlite3
from dataclasses import dataclass
from typing import NamedTuple

from . import facts
from .fact import Fact

SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(fid TEXT PRIMARY KEY, ts INT, t TEXT);
CREATE TABLE IF NOT EXISTS offers(name TEXT, a0 TEXT, a1 TEXT, src TEXT,
                                  PRIMARY KEY(name, a0, a1, src));
CREATE TABLE IF NOT EXISTS proofs(fid TEXT PRIMARY KEY, rank INT NOT NULL);
-- src-leading covering index: offers_from() matches on (src, name), which the
-- PK index (src last) can't serve, so without this it full-scans the offers
-- table per lookup -> O(joins * offers) rebuild/validate. We have a db; seek.
CREATE INDEX IF NOT EXISTS offers_by_src ON offers(src, name, a0, a1);
"""

DRAIN = "drain"
VALIDATE = "validate"
EVALUATE = "evaluate"
MODES = {DRAIN, VALIDATE, EVALUATE}


class Valid(NamedTuple):
    fact: Fact
    deps: tuple  # refs + canonical providers for family-declared needs


class Global(NamedTuple):
    name: str
    value: str


class Judgment(NamedTuple):
    ok: bool
    valids: tuple
    globals: frozenset


@dataclass(frozen=True)
class Context:
    """Immutable in-pile context visible to every family validator.

    Mutable globals are intentionally absent.  Only a family's optional
    evaluate hook receives them, which makes persistent validity incapable of
    depending on time-varying state.
    """

    db: object
    anchor: str

    def offers_from(self, source, name):
        return self.db.execute(
            "SELECT a0, a1 FROM offers WHERE src=? AND name=? ORDER BY a0, a1",
            (source, name)).fetchall()

    def has_offer_value(self, name, value):
        """Whether any accepted in-pile offer has ``value`` in its a1 slot."""
        return self.db.execute(
            "SELECT 1 FROM offers WHERE name=? AND a1=? LIMIT 1",
            (name, value)).fetchone() is not None


def offer_src(db, name, a0, a1=None, requires=()):
    """Canonical finite-proof provider for an offer address, or ``None``.

    Providers are ordered by their shortest authority proof and then source
    id.  Proof rank is well-founded: every dependency has a lower rank than
    its dependent, so a later lower-fid offer cannot rewire the final graph
    into a cycle.

    ``requires`` is a family-declared tuple of co-offers that must come from
    the selected source.  Selection happens *before* those checks.  This lets
    a family declare one globally canonical claim (for example, ownership of
    a key) while also checking the claim's associated value without allowing
    a losing claimant to become authoritative.
    """
    query = (
        "SELECT o.src FROM offers o "
        "JOIN proofs p ON p.fid=o.src "
        "WHERE o.name=? AND o.a0=?"
    )
    args = [name, a0]
    if a1 is not None:
        query, args = query + " AND o.a1=?", args + [a1]
    row = db.execute(
        query + " ORDER BY p.rank, o.src LIMIT 1", args).fetchone()
    if row is None:
        return None
    source = row[0]
    for required_name, required_a0, required_a1 in requires:
        if db.execute(
                "SELECT 1 FROM offers "
                "WHERE src=? AND name=? AND a0=? AND a1=?",
                (source, required_name, required_a0,
                 required_a1 or "")).fetchone() is None:
            return None
    return source


def _need_parts(need):
    """Normalize the public three-field need and its optional co-offers."""
    if len(need) == 3:
        return (*need, ())
    if len(need) == 4:
        name, a0, a1, requires = need
        return name, a0, a1, tuple(requires)
    raise ValueError("a need must have three fields plus optional co-offers")


def resolve_deps(f: Fact, db):
    """Resolve refs and family needs to deterministic provider ids.

    ``None`` means an unmet need or unknown family.  The same resolver is used
    during judgment and by the closure/layout paths, so closure edges are a pure
    function of the accepted set.
    """
    handler = facts.handler_for(f.t)
    if handler is None:
        return None
    deps = [fid for _, fid in f.refs()]
    try:
        for need in handler.needs(f):
            name, a0, a1, requires = _need_parts(need)
            source = offer_src(db, name, a0, a1, requires)
            if source is None:
                return None
            deps.append(source)
    except Exception:
        return None
    return deps


def proof_rank(db, deps):
    """Return one plus the maximum dependency rank (or zero at a root)."""
    if not deps:
        return 0
    rows = db.execute(
        f"SELECT fid, rank FROM proofs WHERE fid IN "
        f"({','.join('?' for _ in deps)})",
        tuple(deps),
    ).fetchall()
    ranks = {fid: rank for fid, rank in rows}
    if any(fid not in ranks for fid in deps):
        return None
    return 1 + max(ranks[fid] for fid in deps)


def extend_proofs(db, fids, fact_of):
    """Add shortest authority proofs with work proportional to ``fids``.

    Existing proofs and offers are consulted by indexed point/range lookups;
    they are never materialized wholesale on the append path.  A fact becomes
    a candidate exactly when all of its references have ranks and each family
    need has a ranked canonical provider.  Providers that become ready
    together are installed as one rank wave, so equal-rank conflicts
    participate in the canonical ``(rank, fid)`` choice before dependents run.
    """
    ranked = {}

    def has_proof(fid):
        if fid not in ranked:
            ranked[fid] = db.execute(
                "SELECT 1 FROM proofs WHERE fid=?", (fid,)).fetchone() \
                is not None
        return ranked[fid]

    unresolved, pending = {}, list(fids)
    while pending:
        fid = pending.pop()
        if fid in unresolved or has_proof(fid):
            continue
        fact = fact_of(fid)
        if fact is None:
            continue
        unresolved[fid] = fact
        pending.extend(ref for _, ref in fact.refs())

    ref_waiters, offer_waiters = {}, {}
    missing, candidates = {}, set()

    def wait_for_offer(fid, condition):
        _, name, a0, a1, _ = condition
        offer_waiters.setdefault((name, a0, a1), set()).add(
            (fid, condition))

    for fid, fact in unresolved.items():
        conditions = {
            ("ref", ref)
            for _, ref in fact.refs()
            if not has_proof(ref)
        }
        try:
            handler = facts.handler_for(fact.t)
            if handler is None:
                continue
            for need in handler.needs(fact):
                name, a0, a1, requires = _need_parts(need)
                if offer_src(db, name, a0, a1, requires) is None:
                    conditions.add(
                        ("offer", name, a0, a1, requires))
        except Exception:
            continue
        missing[fid] = conditions
        if not conditions:
            candidates.add(fid)
        for condition in conditions:
            if condition[0] == "ref":
                ref_waiters.setdefault(condition[1], set()).add(fid)
            else:
                wait_for_offer(fid, condition)

    while candidates:
        ready = []
        for fid in sorted(candidates):
            deps = resolve_deps(unresolved[fid], db)
            rank = proof_rank(db, deps) if deps is not None else None
            if rank is not None:
                ready.append((fid, rank))
        if not ready:
            break
        db.executemany("INSERT OR REPLACE INTO proofs VALUES(?,?)", ready)
        candidates = set()
        for fid, _ in ready:
            ranked[fid] = True
            for dependent in ref_waiters.pop(fid, ()):
                if dependent not in unresolved or dependent not in missing:
                    continue
                missing[dependent].discard(("ref", fid))
                if not missing[dependent]:
                    candidates.add(dependent)
            for name, a0, a1 in unresolved[fid].offers():
                for address in ((name, a0, a1), (name, a0, None)):
                    waiting = tuple(offer_waiters.get(address, ()))
                    for dependent, condition in waiting:
                        if dependent not in unresolved \
                                or dependent not in missing:
                            offer_waiters[address].discard(
                                (dependent, condition))
                            continue
                        _, needed_name, needed_a0, needed_a1, requires = \
                            condition
                        if offer_src(
                                db, needed_name, needed_a0, needed_a1,
                                requires) is None:
                            continue
                        missing[dependent].discard(condition)
                        offer_waiters[address].discard(
                            (dependent, condition))
                        if not missing[dependent]:
                            candidates.add(dependent)
            unresolved.pop(fid)
            missing.pop(fid, None)
    return frozenset(unresolved)


def rebuild_proofs(db, fact_of):
    """Recompute shortest authority proofs for every offer source.

    Facts are admitted in rank waves.  A fact in wave ``r`` can depend only on
    providers from earlier waves, which gives every accepted set one
    history-independent dependency DAG even when offers shadow one another.
    Facts that neither provide an offer nor anchor a reference cannot
    authorize anything and need no persistent rank; the streaming kernel
    still ranks them while judging.

    Returns the source ids that have no finite proof.
    """
    db.execute("DELETE FROM proofs")
    return extend_proofs(
        db,
        [fid for (fid,) in db.execute("SELECT DISTINCT src FROM offers")],
        fact_of,
    )


def _globals(rows):
    """Normalize the family-neutral public ``(name, value)`` row shape."""
    return frozenset(Global(*row) for row in (rows or ()))


def kernel(stream, anchor, *, mode=VALIDATE, globals_=(), db=None):
    """Run the shared judge and return its complete internal result.

    Most callers should use :func:`validate`, :func:`drain`, or
    :func:`evaluate`, whose return values make their side-effect contract
    explicit.
    """
    if mode not in MODES:
        raise ValueError(f"unknown kernel mode {mode!r}")
    supplied = _globals(globals_)
    con = db or sqlite3.connect(":memory:")
    con.executescript(SCHEMA)
    con.execute("BEGIN")
    valids, emitted = [], set()
    ctx = Context(con, anchor)
    for f in stream:
        if con.execute("SELECT 1 FROM facts WHERE fid=?", (f.fid,)).fetchone():
            continue
        try:
            handler = facts.handler_for(f.t)
            refs_seen = all(con.execute(
                "SELECT 1 FROM facts WHERE fid=?", (fid,)).fetchone()
                for _, fid in f.refs())
            deps = resolve_deps(f, con) if handler is not None and refs_seen else None
            good = deps is not None and handler.validate(f, ctx) is True
            if good and mode == EVALUATE and hasattr(handler, "evaluate"):
                good = handler.evaluate(f, supplied, ctx) is True
        except Exception:
            good = False  # hostile family bytes are litter, never poison
        if not good:
            con.rollback()
            if db is None:
                con.close()
            return Judgment(False, (), frozenset())
        rank = proof_rank(con, deps)
        if rank is None:
            con.rollback()
            if db is None:
                con.close()
            return Judgment(False, (), frozenset())
        con.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?)", (f.fid, f.ts, f.t))
        for name, a0, a1 in f.offers():
            con.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
                        (name, a0, a1, f.fid))
        con.execute("INSERT OR IGNORE INTO proofs VALUES(?,?)", (f.fid, rank))
        if mode == DRAIN:
            emitted.update(Global(*row) for row in handler.global_rows(f))
        valids.append(Valid(f, tuple(deps)))
    con.commit()
    if db is None:
        con.close()
    return Judgment(True, tuple(valids), frozenset(emitted))


def validate(stream, anchor, *, db=None):
    """Validate one already-topological closed unit; return exactly ``bool``."""
    return kernel(stream, anchor, mode=VALIDATE, db=db).ok


def drain(stream, anchor, *, db=None):
    """Validate persistent ingress and expose Valid values plus global deltas."""
    return kernel(stream, anchor, mode=DRAIN, db=db)


def evaluate(stream, anchor, globals_, *, db=None):
    """Validate an ephemeral payload against committed globals; return bool."""
    return kernel(stream, anchor, mode=EVALUATE, globals_=globals_, db=db).ok
