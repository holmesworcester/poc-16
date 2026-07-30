"""Pure canonical standing and action projection over admitted candidates.

This is the database-free reference answer used when authenticating a cold
candidate archive.  It deliberately calls the same family registry, edge
resolver, validator, proof-rank rule, and action ordering as the SQLite
accelerator; no serialized state label is an input to the answer.
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


def _derive_standing(anchor, candidates):
    context = MemoryContext(anchor)
    pending = dict(candidates)
    resolved = {}

    while pending:
        ready = []
        for fid in sorted(pending):
            fact = pending[fid]
            if any(not context.has_fact(parent) for _, parent in fact.refs()):
                continue
            edges = resolve_edges(fact, context, strict=True)
            deps = None if edges is None else tuple(
                edge.fid for edge in edges)
            rank = proof_rank(context, deps) if deps is not None else None
            closure = context.closure(deps) if rank is not None else None
            if rank is None or closure is None \
                    or len(closure) + 1 > MAX_CLOSURE_FACTS \
                    or len(edges) > MAX_RESOLVED_EDGES \
                    or not accepts(fact, edges, context, strict=True):
                continue
            ready.append((fid, fact, rank, edges))
        if not ready:
            break
        for fid, fact, rank, edges in ready:
            context.admit(fact, rank, edges)
            resolved[fid] = (rank, tuple(edges))
            pending.pop(fid)
    return context, resolved


def _derive_actions(context):
    active, selected = set(), {}

    eligible = sorted(
        context.facts.values(), key=lambda fact: (fact.key, fact.fid))
    for fact in eligible:
        targets = set(facts.action_sids(fact))
        if not targets:
            continue
        for sid in sorted(targets - active):
            selected[sid] = fact.fid
        active.update(targets)
    return selected


def project(anchor, candidates):
    """Derive canonical standing and actions without a database.

    Named needs and family validation proved authority when each candidate was
    admitted.  A later suppression action cannot rewrite that historical
    judgment.  Current authority liveness is an authenticated Reader concern.
    """
    if not isinstance(candidates, dict):
        raise TypeError("candidate projection input")
    context, standing = _derive_standing(anchor, candidates)
    return Projection(standing, _derive_actions(context))
