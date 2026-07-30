"""Pure canonical eligibility and action projection over admitted candidates.

This is the database-free reference answer used when authenticating a cold
candidate archive.  It deliberately calls the same family registry, edge
resolver, validator, proof-rank rule, authorization-scope expansion, and
action ordering as the SQLite accelerator; no serialized state label is an
input to the answer.
"""
from dataclasses import dataclass

import facts

from .kernel import (
    MemoryContext,
    accepts,
    proof_rank,
    resolve_edges,
)
from .limits import MAX_CLOSURE_FACTS, MAX_RESOLVED_EDGES


@dataclass(frozen=True)
class Projection:
    """Canonical standing ``fid -> (rank, edges)`` and ``sid -> action fid``."""

    standing: dict
    actions: dict


def _derive_standing(anchor, candidates, actions):
    context = MemoryContext(anchor)
    pending = dict(candidates)
    resolved = {}

    def edges_of(fid):
        return {
            role: target
            for (source, role), target in context.edges.items()
            if source == fid
        }

    while pending:
        ready = []
        for fid in sorted(pending):
            fact = pending[fid]
            if any(not context.has_fact(parent) for _, parent in fact.refs()):
                continue
            edges = resolve_edges(fact, context)
            deps = None if edges is None else tuple(
                edge.fid for edge in edges)
            rank = proof_rank(context, deps) if deps is not None else None
            closure = context.closure(deps) if rank is not None else None
            if rank is None or closure is None \
                    or len(closure) + 1 > MAX_CLOSURE_FACTS \
                    or len(edges) > MAX_RESOLVED_EDGES \
                    or not accepts(fact, edges, context):
                continue
            try:
                guards = facts.authorization_scopes(
                    fact, edges, edges_of, candidates.get)
                blocked = any(
                    candidates[action].key < fact.key
                    for sid in guards
                    if (action := actions.get(sid)) is not None
                )
            except (KeyError, TypeError, ValueError):
                continue
            if not blocked:
                ready.append((fid, fact, rank, edges))
        if not ready:
            break
        for fid, fact, rank, edges in ready:
            context.admit(fact, rank, edges)
            resolved[fid] = (rank, tuple(edges))
            pending.pop(fid)
    return context, resolved


def _derive_actions(context, candidates):
    active, selected = set(), {}

    def edges_of(fid):
        return {
            role: target
            for (source, role), target in context.edges.items()
            if source == fid
        }

    eligible = sorted(
        context.facts.values(), key=lambda fact: (fact.key, fact.fid))
    for fact in eligible:
        targets = set(facts.action_sids(fact))
        if not targets:
            continue
        # Recreate named edges, including their kinds, from the same resolver;
        # the context is already the complete standing graph for this round.
        resolved = resolve_edges(fact, context)
        if resolved is None:
            raise ValueError("action projection edges")
        guards = facts.authorization_scopes(
            fact, resolved, edges_of, candidates.get)
        if active.intersection(guards):
            continue
        for sid in sorted(targets - active):
            selected[sid] = fact.fid
        active.update(targets)
    return selected


def project(anchor, candidates):
    """Derive the unique eligibility/action fixed point without a database."""
    if not isinstance(candidates, dict):
        raise TypeError("candidate projection input")
    actions, seen = {}, set()
    while True:
        state = tuple(sorted(actions.items()))
        if state in seen:
            raise ValueError("action settlement cycle")
        seen.add(state)
        context, standing = _derive_standing(
            anchor, candidates, actions)
        current = _derive_actions(context, candidates)
        if current == actions:
            return Projection(standing, current)
        actions = current
