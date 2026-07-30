"""The family-neutral streaming judge.

``validate`` is the boolean trustless-consumer door; ``drain`` exposes the
same judgment as kernel-minted ``Valid`` values to a client runtime. Families
own exact shapes, named needs, and immutable validity. Ephemeral authorization
is a separate family-owned Worker grant over authenticated point reads.
"""
from typing import NamedTuple

import facts
from .fact_index import EDGE_INDEX, STATE_INDEX
from .fact import Fact, bound_to
from .limits import MAX_CLOSURE_FACTS, MAX_RESOLVED_EDGES
from .shape import valid_fid

class Valid(NamedTuple):
    fact: Fact
    deps: tuple  # refs + canonical providers for family-declared needs
    edges: tuple = ()  # same dependencies with stable family-declared roles


class ResolvedEdge(NamedTuple):
    role: str
    fid: str
    kind: str


class Judgment(NamedTuple):
    ok: bool
    valids: tuple
    failure: Exception | None = None


def valid_resolved_edges(deps, edges):
    """Whether a receipt has one canonical, exact dependency-edge tuple."""
    if not isinstance(deps, (list, tuple)) \
            or not isinstance(edges, (list, tuple)):
        return False
    if any(not isinstance(edge, ResolvedEdge) for edge in edges):
        return False
    roles = [edge.role for edge in edges]
    if not all(isinstance(role, str) and role for role in roles):
        return False
    return roles == sorted(roles) \
        and len(roles) == len(set(roles)) \
        and all(valid_fid(edge.fid) for edge in edges) \
        and all(edge.kind in ("need", "ref") for edge in edges) \
        and tuple(deps) == tuple(edge.fid for edge in edges)


class MemoryContext:
    """Bounded database-free relationship state for CF authorization."""

    def __init__(self, anchor):
        self.anchor = anchor
        self.facts = {}
        self.proofs = {}
        self.edges = {}
        self.closures = {}

    def has_fact(self, fid):
        return fid in self.facts

    def fact_meta(self, fid):
        fact = self.facts.get(fid)
        return (fact.ts, fact.t) if fact is not None else None

    def offers_from(self, source, name):
        fact = self.facts.get(source)
        return sorted(
            (a0, a1) for offer, a0, a1 in (fact.offers() if fact else ())
            if offer == name
        )

    def edge_source(self, source, role):
        return self.edges.get((source, role))

    def provider(self, name, a0, a1=None, requires=()):
        return self.resolve_offer(name, a0, a1, requires)

    def resolve_offer(self, name, a0, a1=None, requires=()):
        candidates = []
        for fid, fact in self.facts.items():
            if fid not in self.proofs or not any(
                    offer == name and value0 == a0
                    and (a1 is None or value1 == a1)
                    for offer, value0, value1 in fact.offers()):
                continue
            candidates.append((self.proofs[fid], fid))
        if not candidates:
            return None
        source = min(candidates)[1]
        offered = set(self.facts[source].offers())
        return source if all(
            (required_name, required_a0, required_a1 or "") in offered
            for required_name, required_a0, required_a1 in requires
        ) else None

    def rank(self, deps):
        if not deps:
            return 0
        if any(fid not in self.proofs for fid in deps):
            return None
        return 1 + max(self.proofs[fid] for fid in deps)

    def closure(self, deps):
        if any(fid not in self.closures for fid in deps):
            return None
        return frozenset().union(
            *(self.closures[fid] for fid in deps))

    def admit(self, fact, rank, edges):
        self.facts[fact.fid], self.proofs[fact.fid] = fact, rank
        closure = self.closure(tuple(edge.fid for edge in edges))
        self.closures[fact.fid] = frozenset((fact.fid,)) | closure
        self.edges.update(
            ((fact.fid, edge.role), edge.fid) for edge in edges)


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
    if hasattr(db, "resolve_offer"):
        return db.resolve_offer(name, a0, a1, requires)
    query = (
        "SELECT o.src FROM fact_index o "
        "JOIN fact_index p ON p.src=o.src "
        "AND p.kind=? AND p.k0='eligible' "
        "WHERE o.kind=? AND o.k0=?"
    )
    args = [STATE_INDEX, name, a0]
    if a1 is not None:
        query, args = query + " AND o.k1=?", args + [a1]
    row = db.execute(
        query + " ORDER BY CAST(p.k1 AS INTEGER), o.src LIMIT 1",
        args,
    ).fetchone()
    if row is None:
        return None
    source = row[0]
    for required_name, required_a0, required_a1 in requires:
        if db.execute(
                "SELECT 1 FROM fact_index "
                "WHERE src=? AND kind=? AND k0=? AND k1=?",
                (source, required_name, required_a0,
                 required_a1 or "")).fetchone() is None:
            return None
    return source


def resolve_edges(f: Fact, db, strict=False):
    """Resolve self-named refs and needs to deterministic dependency edges."""
    handler = facts.family_for(f.t)
    if handler is None:
        return None
    edges = [
        ResolvedEdge(role, fid, "ref")
        for role, fid in f.refs()
    ]
    try:
        for need in handler.needs(f):
            source = offer_src(
                db, need.name, need.a0, need.a1, need.requires)
            if source is None:
                return None
            edges.append(ResolvedEdge(need.role, source, "need"))
    except Exception:
        if strict:
            raise
        return None
    edges.sort(key=lambda edge: edge.role)
    if not valid_resolved_edges(
            tuple(edge.fid for edge in edges), edges):
        return None
    return tuple(edges)


def resolve_deps(f: Fact, db):
    """Resolve refs and family needs to deterministic provider ids.

    ``None`` means an unmet need or unknown family.  The same resolver is used
    during judgment and by proof-based sync, so closure
    edges are a pure function of the accepted set.
    """
    edges = resolve_edges(f, db)
    return None if edges is None else [edge.fid for edge in edges]


def proof_rank(db, deps):
    """Return one plus the maximum dependency rank (or zero at a root)."""
    if hasattr(db, "rank"):
        return db.rank(deps)
    if not deps:
        return 0
    rows = db.execute(
        f"SELECT src, CAST(k1 AS INTEGER) FROM fact_index "
        f"WHERE kind=? AND k0='eligible' AND src IN "
        f"({','.join('?' for _ in deps)})",
        (STATE_INDEX, *deps),
    ).fetchall()
    ranks = {fid: rank for fid, rank in rows}
    if any(fid not in ranks for fid in deps):
        return None
    return 1 + max(ranks[fid] for fid in deps)


def proof_closure_size(db, deps, *, stop_after=None):
    """Count the unique current proof ancestors of ``deps``.

    The database-free context already retains exact closure sets.  SQLite
    stores only direct edges, so derive the same set with a recursive UNION.
    ``stop_after`` bounds work for callers that need only a protocol-limit
    verdict; the returned value is then capped at ``stop_after + 1``.
    """
    deps = tuple(dict.fromkeys(deps))
    if not deps:
        return 0
    if hasattr(db, "closure"):
        closure = db.closure(deps)
        if closure is None:
            return None
        size = len(closure)
        return size if stop_after is None else min(size, stop_after + 1)
    seeds = ", ".join("(?)" for _ in deps)
    limit = "" if stop_after is None else " LIMIT ?"
    args = deps if stop_after is None else deps + (stop_after + 1,)
    rows = db.execute(
        "WITH RECURSIVE closure(fid) AS ("
        f"VALUES {seeds} "
        "UNION "
        "SELECT e.k1 FROM fact_index e JOIN closure c ON e.src=c.fid "
        "WHERE e.kind=?"
        ") SELECT fid FROM closure" + limit,
        (*deps, EDGE_INDEX) if stop_after is None
        else (*deps, EDGE_INDEX, stop_after + 1),
    ).fetchall()
    return len(rows)


def accepts(fact, edges, ctx, strict=False):
    """Run one family's shape and policy checks against resolved edges."""
    try:
        handler = facts.family_for(fact.t)
        return bound_to(fact, ctx.anchor) \
            and handler is not None \
            and (fact.ws is not None or facts.is_genesis(fact.t)) \
            and handler.validate(fact, ctx) is True \
            and facts.validate_fact_policy(
                handler.POLICY, fact, edges, ctx)
    except Exception:
        if strict:
            raise
        return False


def _judge(stream, ctx):
    """The one streaming judge over one bounded, topological closure."""
    valids = []
    for fact in stream:
        # Prove the ambient anchor from authenticated fact bytes before
        # family lookup, needs resolution, policy, or staging can run.
        if not bound_to(fact, ctx.anchor):
            return Judgment(False, tuple(valids))
        if ctx.has_fact(fact.fid):
            continue
        try:
            handler = facts.family_for(fact.t)
            refs_seen = all(ctx.has_fact(fid) for _, fid in fact.refs())
            edges = resolve_edges(
                fact, ctx, strict=True
            ) if handler is not None and refs_seen else None
            if edges is not None and len(edges) > MAX_RESOLVED_EDGES:
                return Judgment(False, tuple(valids))
            deps = None if edges is None else [edge.fid for edge in edges]
            good = edges is not None and accepts(
                fact, edges, ctx, strict=True)
        except Exception as error:
            # Stateless readers still fail closed. The client ingress runtime
            # also needs the typed distinction: an unexpected family/program
            # failure retains its pile instead of manufacturing a permanent
            # rejection verdict.
            return Judgment(False, tuple(valids), error)
        rank = proof_rank(ctx, deps) if good else None
        closure = ctx.closure(deps) if rank is not None else None
        if rank is None or closure is None \
                or len(closure) + 1 > MAX_CLOSURE_FACTS:
            return Judgment(False, tuple(valids))
        ctx.admit(fact, rank, edges)
        valids.append(Valid(fact, tuple(deps), tuple(edges)))
    return Judgment(True, tuple(valids))


def kernel(stream, anchor):
    """Judge one bounded closure without a database or host state."""
    result = _judge(stream, MemoryContext(anchor))
    return result if result.ok else Judgment(False, (), result.failure)


def validate(stream, anchor):
    """Validate one already-topological closed unit; return exactly ``bool``."""
    return kernel(stream, anchor).ok


def drain(stream, anchor):
    """Validate ingress and expose kernel-minted named dependency edges."""
    return kernel(stream, anchor)
