"""The family-neutral streaming judge.

``validate`` is the boolean trustless-consumer door; ``drain`` exposes the
same judgment as kernel-minted ``Valid`` values to a client runtime. Families
own exact shapes, named needs, and immutable validity. Ephemeral authorization
is a separate family-owned Worker grant over authenticated point reads.
"""
from typing import NamedTuple

import facts
from .fact import Fact, bound_to, decode

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


class Context(NamedTuple):
    """Immutable in-pile context visible to every family validator.

    Mutable host state is intentionally absent. Time and current suppression
    belong to the database-free Worker authorization boundary.
    """

    db: object
    anchor: str

    def fact_meta(self, fid):
        row = self.db.execute(
            "SELECT blob FROM facts WHERE fid=?", (fid,)).fetchone()
        if row is None:
            return None
        fact = decode(row[0])
        return fact.ts, fact.t

    def offers_from(self, source, name):
        return self.db.execute(
            "SELECT k0, k1 FROM fact_index "
            "WHERE src=? AND kind=? ORDER BY k0, k1",
            (source, name)).fetchall()

    def edge_source(self, source, role):
        row = self.db.execute(
            "SELECT dst FROM edges WHERE src=? AND role=?",
            (source, role)).fetchone()
        return row[0] if row else None

    def provider(self, name, a0, a1=None, requires=()):
        return offer_src(self.db, name, a0, a1, requires)


class MemoryContext:
    """Bounded database-free relationship state for CF authorization."""

    def __init__(self, anchor):
        self.anchor = anchor
        self.facts = {}
        self.proofs = {}
        self.edges = {}

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

    def admit(self, fact, rank, edges):
        self.facts[fact.fid], self.proofs[fact.fid] = fact, rank
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
        "JOIN proofs p ON p.fid=o.src "
        "WHERE o.kind=? AND o.k0=?"
    )
    args = [name, a0]
    if a1 is not None:
        query, args = query + " AND o.k1=?", args + [a1]
    row = db.execute(
        query + " ORDER BY p.rank, o.src LIMIT 1", args).fetchone()
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
    roles = [edge.role for edge in edges]
    if not all(isinstance(role, str) and role for role in roles) \
            or len(roles) != len(set(roles)):
        return None
    return tuple(edges)


def resolve_deps(f: Fact, db):
    """Resolve refs and family needs to deterministic provider ids.

    ``None`` means an unmet need or unknown family.  The same resolver is used
    during judgment and by the closure paths (manifest build, sync), so closure
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
        f"SELECT fid, rank FROM proofs WHERE fid IN "
        f"({','.join('?' for _ in deps)})",
        tuple(deps),
    ).fetchall()
    ranks = {fid: rank for fid, rank in rows}
    if any(fid not in ranks for fid in deps):
        return None
    return 1 + max(ranks[fid] for fid in deps)


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


def extend_proofs(db, fids, fact_of, anchor=None, accept=None):
    """Add shortest authority proofs with work proportional to ``fids``.

    Existing proofs and offers are consulted by indexed point/range lookups;
    they are never materialized wholesale on the append path.  A fact becomes
    a candidate exactly when all of its references have ranks and each family
    need has a ranked canonical provider.  Providers that become ready
    together are installed as one rank wave, so equal-rank conflicts
    participate in the canonical ``(rank, fid)`` choice before dependents run.
    """
    ranked = {}
    context = Context(db, anchor) if anchor is not None else None
    accept = accept or (
        (lambda fact, edges: accepts(fact, edges, context))
        if context is not None else
        (lambda _fact, _edges: True)
    )

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
        if anchor is not None and not bound_to(fact, anchor):
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
            handler = facts.family_for(fact.t)
            if handler is None:
                continue
            for need in handler.needs(fact):
                if offer_src(
                        db, need.name, need.a0, need.a1,
                        need.requires) is None:
                    conditions.add(
                        ("offer", need.name, need.a0, need.a1,
                         need.requires))
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
            fact = unresolved[fid]
            edges = resolve_edges(fact, db)
            deps = None if edges is None else [edge.fid for edge in edges]
            rank = proof_rank(db, deps) if deps is not None else None
            if rank is not None and accept(fact, edges):
                ready.append((fid, rank, edges))
        if not ready:
            break
        db.executemany(
            "INSERT OR REPLACE INTO proofs VALUES(?,?)",
            ((fid, rank) for fid, rank, _ in ready),
        )
        db.executemany(
            "INSERT OR REPLACE INTO edges VALUES(?,?,?,?)",
            (
                (fid, edge.role, edge.fid, edge.kind)
                for fid, _, edges in ready
                for edge in edges
            ),
        )
        candidates = set()
        for fid, _, _ in ready:
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


def rebuild_proofs(db, fact_of, anchor=None, accept=None, fids=None):
    """Derive eligibility and shortest ranks for the whole admitted catalog."""
    db.execute("DELETE FROM proofs")
    db.execute("DELETE FROM edges")
    selected = fids if fids is not None else (
        fid for (fid,) in db.execute("SELECT fid FROM facts")
    )
    return extend_proofs(
        db, selected, fact_of, anchor, accept,
    )


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
        if rank is None:
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
