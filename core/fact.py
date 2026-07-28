"""Canonical facts: the family-neutral value and wire codec.

Atoms carry the clear envelope's refs, offers, and inert suppression keys
("refs say where, offers say what"). Concrete shapes and all meaning live
under :mod:`facts`; this module only gives those families one
canonical value to construct.
"""
import json
from dataclasses import dataclass, field

from .crypto import h
from .shape import key, valid_timestamp


def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Fact:
    t: str
    ts: int
    atoms: list
    body: dict
    bh: str = field(init=False)
    fid: str = field(init=False)

    def __post_init__(self):
        if not valid_timestamp(self.ts):
            raise ValueError("fact timestamp")
        object.__setattr__(self, "bh", h(canon(self.body)))
        object.__setattr__(self, "fid", h(canon(self.env)))

    @property
    def env(self):
        return {"a": self.atoms, "bh": self.bh, "t": self.t, "ts": self.ts}

    @property
    def key(self) -> str:
        return key(self)

    def refs(self):
        return [(a[1], a[2]) for a in self.atoms if a[0] == "ref"]

    def offers(self):
        return [(a[1], a[2], a[3] if len(a) > 3 else "") for a in self.atoms if a[0] == "offer"]

    def to_json(self):
        return {"e": self.env, "b": self.body}


def _atoms_ok(atoms) -> bool:
    """Atom shape, checked at the door so refs()/offers() cannot crash the
    kernel — a malformed atom is litter, never poison."""
    if not isinstance(atoms, list):
        return False
    for a in atoms:
        if not (isinstance(a, list) and a):
            return False
        if a[0] == "ref":
            if len(a) != 3:
                return False
        elif a[0] == "offer":
            if len(a) not in (3, 4):
                return False
        elif a[0] == "supp":
            if len(a) != 4 or not all(isinstance(value, str) for value in a[1:]):
                return False
        else:
            return False
    return True


def from_json(o) -> Fact:
    e = o.get("e") if isinstance(o, dict) else None
    if not (isinstance(e, dict) and isinstance(e.get("t"), str)
            and valid_timestamp(e.get("ts")) and isinstance(o.get("b"), dict)
            and _atoms_ok(e.get("a"))):
        raise ValueError("fact shape")
    f = Fact(e["t"], e["ts"], e["a"], o["b"])
    if f.fid != h(canon(e)) or f.bh != e.get("bh"):
        raise ValueError("fact integrity")
    return f
