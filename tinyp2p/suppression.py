"""Clear-envelope suppression keys, independent of bodies and policy."""
import json

ATOM = "supp"
DOMAIN = "chan"
TARGET = "target"
DELETE = "delete"


def atom(channel, *, deletion=False):
    """Canonical channel suppression marker for a target or deletion."""
    return [ATOM, DOMAIN, channel, DELETE if deletion else TARGET]


def _marker(fact):
    markers = [
        entry for entry in fact.atoms
        if isinstance(entry, list) and len(entry) == 4 and entry[0] == ATOM
        and entry[1] == DOMAIN and isinstance(entry[2], str)
        and entry[3] in (TARGET, DELETE)
    ]
    return markers[0] if len(markers) == 1 else None


def is_deletion(fact):
    """Whether the clear envelope carries one canonical deletion marker."""
    marker = _marker(fact)
    return marker is not None and marker[3] == DELETE


def suppkey(fact):
    """Canonical T_supp key component, or None for a non-participant."""
    marker = _marker(fact)
    return None if marker is None else json.dumps(
        marker[1:3], separators=(",", ":"))


def deathkey(fact):
    """A deletion's suppression key, or None for targets/non-participants."""
    return suppkey(fact) if is_deletion(fact) else None
