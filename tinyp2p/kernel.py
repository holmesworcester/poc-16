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


def offer_src(db, name, a0, a1=None):
    """Canonical provider (minimum source id) for an offer address, or None."""
    query, args = "SELECT src FROM offers WHERE name=? AND a0=?", [name, a0]
    if a1 is not None:
        query, args = query + " AND a1=?", args + [a1]
    row = db.execute(query + " ORDER BY src LIMIT 1", args).fetchone()
    return row and row[0]


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
        for name, a0, a1 in handler.needs(f):
            source = offer_src(db, name, a0, a1)
            if source is None:
                return None
            deps.append(source)
    except Exception:
        return None
    return deps


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
                good = handler.evaluate(f, supplied) is True
        except Exception:
            good = False  # hostile family bytes are litter, never poison
        if not good:
            con.rollback()
            if db is None:
                con.close()
            return Judgment(False, (), frozenset())
        con.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?)", (f.fid, f.ts, f.t))
        for name, a0, a1 in f.offers():
            con.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
                        (name, a0, a1, f.fid))
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
