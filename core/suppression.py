"""Clear-envelope suppression keys, independent of bodies and policy."""
import json

ATOM = "supp"
DOMAIN = "chan"
TARGET = "target"
DELETE = "delete"


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
