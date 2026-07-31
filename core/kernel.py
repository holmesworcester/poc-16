"""The family-neutral streaming judge.

``validate`` is the boolean trustless-consumer door; ``drain`` exposes the
same judgment as kernel-minted ``Valid`` values to a client runtime. Families
own exact shapes, named needs, and immutable validity. Ephemeral authorization
is a separate family-owned Worker grant over authenticated point reads.
"""
from typing import NamedTuple

import facts
from facts._policy import FactContext
from .fact import Fact, bound_to, encode
from .limits import MAX_CLOSURE_FACTS, MAX_RESOLVED_EDGES
from .shape import valid_fid

class Valid(NamedTuple):
    fact: Fact
    edges: tuple  # ephemeral named dependencies for this closed pile


class ResolvedEdge(NamedTuple):
    role: str
    fid: str


class Judgment(NamedTuple):
    ok: bool
    valids: tuple
    failure: Exception | None = None


class MemoryContext:
    """Bounded database-free relationship state for CF authorization."""

    def __init__(self, anchor):
        self.anchor = anchor
        self.facts = {}
        self.depths = {}
        self.closures = {}

    def has_fact(self, fid):
        return fid in self.facts

    def fact_of(self, fid):
        return self.facts.get(fid)

    def offers_from(self, source, name):
        fact = self.facts.get(source)
        return sorted(
            (a0, a1) for offer, a0, a1 in (fact.offers() if fact else ())
            if offer == name
        )

    def resolve_offer(self, name, a0, a1=None, source=None):
        if source is not None:
            fact = self.facts.get(source)
            if fact is None or source not in self.depths:
                return None
            return source if any(
                offer == name and value0 == a0
                and (a1 is None or value1 == a1)
                for offer, value0, value1 in fact.offers()
            ) else None
        candidates = []
        for fid, fact in self.facts.items():
            if fid not in self.depths or not any(
                    offer == name and value0 == a0
                    and (a1 is None or value1 == a1)
                    for offer, value0, value1 in fact.offers()):
                continue
            candidates.append(fid)
        if not candidates:
            return None
        return min(candidates)

    def depth(self, deps):
        if not deps:
            return 0
        if any(fid not in self.depths for fid in deps):
            return None
        return 1 + max(self.depths[fid] for fid in deps)

    def closure(self, deps):
        if any(fid not in self.closures for fid in deps):
            return None
        return frozenset().union(
            *(self.closures[fid] for fid in deps))

    def admit(self, fact, depth, edges):
        self.facts[fact.fid], self.depths[fact.fid] = fact, depth
        closure = self.closure(tuple(edge.fid for edge in edges))
        self.closures[fact.fid] = frozenset((fact.fid,)) | closure


def resolve_edges(f: Fact, ctx: FactContext, strict=False):
    """Resolve self-named refs and needs to deterministic dependency edges."""
    handler = facts.family_for(f.t)
    if handler is None:
        return None
    edges = [
        ResolvedEdge(role, fid)
        for role, fid in f.refs()
    ]
    try:
        for need in handler.needs(f):
            source = facts.explicit_provider(f, need.role)
            source = ctx.resolve_offer(
                need.name, need.a0, need.a1, source=source)
            if source is None:
                return None
            edges.append(ResolvedEdge(need.role, source))
    except Exception:
        if strict:
            raise
        return None
    edges.sort(key=lambda edge: edge.role)
    roles = [edge.role for edge in edges]
    if not all(isinstance(role, str) and role for role in roles) \
            or roles != sorted(roles) or len(roles) != len(set(roles)) \
            or not all(valid_fid(edge.fid) for edge in edges):
        return None
    return tuple(edges)


def resolve_deps(f: Fact, ctx: FactContext):
    """Resolve refs and family needs to deterministic provider ids.

    ``None`` means an unmet need or unknown family. The same resolver is used
    for local closed-pile construction and database-free judgment.
    """
    edges = resolve_edges(f, ctx)
    return None if edges is None else [edge.fid for edge in edges]


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
            encode(fact)
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
        depth = ctx.depth(deps) if good else None
        closure = ctx.closure(deps) if depth is not None else None
        if depth is None or closure is None \
                or len(closure) + 1 > MAX_CLOSURE_FACTS:
            return Judgment(False, tuple(valids))
        ctx.admit(fact, depth, edges)
        valids.append(Valid(fact, tuple(edges)))
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
