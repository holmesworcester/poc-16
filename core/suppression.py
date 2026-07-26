"""Clear-envelope suppression keys, independent of bodies and policy."""
import json
from typing import NamedTuple

ATOM = "supp"
DOMAIN = "chan"
TARGET = "target"
DELETE = "delete"


class SuppressionClosure(NamedTuple):
    """Exact semantic facts and their closed transport/judgment unit."""
    facts: tuple
    unit: tuple


def atom(channel, *, deletion=False):
    """Canonical channel suppression marker for a target or deletion."""
    return [ATOM, DOMAIN, channel, DELETE if deletion else TARGET]


def _markers(fact):
    """Every well-formed suppression marker — no 0-or-2+ collapse (the
    one-group-per-fact assumption fossilized in code; REMOVALS.md §2)."""
    return [
        entry for entry in fact.atoms
        if isinstance(entry, list) and len(entry) == 4 and entry[0] == ATOM
        and entry[1] == DOMAIN and isinstance(entry[2], str)
        and entry[3] in (TARGET, DELETE)
    ]


def _group(marker):
    return json.dumps(marker[1:3], separators=(",", ":"))


def suppkeys(fact):
    """The SET of groups the fact's TARGET-tag markers declare (§2).

    Membership, never a scalar: one fact can sit in many groups at once
    (channel, author, thread), each reachable by its own kill."""
    return frozenset(
        _group(marker) for marker in _markers(fact)
        if marker[3] == TARGET)


def deathkey(fact):
    """The one group the DELETE-tag marker names, or None.

    Exactly one death marker is I3's admission rule; 0 or 2+ yield None,
    so such a fact is no deletion and admits no removal entry."""
    deaths = [m for m in _markers(fact) if m[3] == DELETE]
    return _group(deaths[0]) if len(deaths) == 1 else None


def is_deletion(fact):
    """Whether the clear envelope carries exactly one death marker."""
    return deathkey(fact) is not None


def key_bounds(group, *, deletions=False):
    """Open-left tree bounds for one suppression group or its head."""
    prefix = f"{group}|0|" if deletions else f"{group}|"
    return prefix, prefix + "~"


def supp_walk(view, group, fetch):
    """Return exact group facts separately from their closed path unit."""
    from . import tree
    from .shape import SUPP

    unit = tree.range_facts(
        view, key_bounds(group), fetch, SUPP)
    facts = tuple(
        fact for fact in unit
        if group in suppkeys(fact) or deathkey(fact) == group)
    return SuppressionClosure(facts, unit if facts else ())


def close_deletions(closure, view, fetch):
    """Return exact deletion closure and its closed transport context."""
    facts, fact_fids = [], set()
    unit, unit_fids = [], set()

    def extend(out, seen, stream):
        for fact in stream:
            if fact.fid not in seen:
                seen.add(fact.fid)
                out.append(fact)

    closure = tuple(closure)
    extend(facts, fact_fids, closure)
    extend(unit, unit_fids, closure)
    groups = sorted(filter(None, {deathkey(fact) for fact in facts}))
    for group in groups:
        walked = supp_walk(view, group, fetch)
        extend(facts, fact_fids, walked.facts)
        extend(unit, unit_fids, walked.unit)
    return SuppressionClosure(tuple(facts), tuple(unit))


def victims(fact, fact_of):
    """The explicit non-deletion target of today's single-target deletion."""
    if not is_deletion(fact):
        return ()
    targets = tuple(
        fid for name, fid in fact.refs() if name == TARGET)
    if len(targets) != 1:
        return ()
    target = fact_of(targets[0])
    return targets if target is not None and not is_deletion(target) else ()
