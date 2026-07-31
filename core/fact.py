"""Canonical facts: the family-neutral value and wire codec.

Atoms carry the clear envelope's refs, offers, and inert suppression keys
("refs say where, offers say what"). Concrete shapes and all meaning live
under :mod:`facts`; this module only gives those families one
canonical value to construct.
"""
import json
from dataclasses import dataclass, field

from .crypto import h
from .limits import (
    InvalidEncoding,
    MAX_ATOM_NAME_BYTES,
    MAX_ATOM_VALUE_BYTES,
    MAX_FACT_BYTES,
    PayloadTooLarge,
    decode_json,
    valid_bounded_text,
)
from .shape import key, valid_fid, valid_timestamp


def canon(o) -> bytes:
    return json.dumps(
        o,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


@dataclass(frozen=True)
class Need:
    """A named dependency on the canonical provider of an offer address."""

    role: str
    name: str
    a0: str
    a1: str | None = None


@dataclass(frozen=True)
class Fact:
    t: str
    ts: int
    atoms: list
    body: dict
    ws: str | None
    bh: str = field(init=False)
    fid: str = field(init=False)

    def __post_init__(self):
        if not valid_timestamp(self.ts):
            raise ValueError("fact timestamp")
        if self.ws is not None and not valid_fid(self.ws):
            raise ValueError("fact workspace")
        object.__setattr__(self, "bh", h(canon(self.body)))
        object.__setattr__(self, "fid", h(canon(self.env)))

    @property
    def env(self):
        envelope = {
            "a": self.atoms,
            "bh": self.bh,
            "t": self.t,
            "ts": self.ts,
        }
        if self.ws is not None:
            envelope["ws"] = self.ws
        return envelope

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
            if len(a) != 3 \
                    or not valid_bounded_text(
                        a[1], MAX_ATOM_NAME_BYTES) \
                    or not valid_fid(a[2]):
                return False
        elif a[0] == "offer":
            if len(a) not in (3, 4) \
                    or not valid_bounded_text(
                        a[1], MAX_ATOM_NAME_BYTES) \
                    or not valid_bounded_text(
                        a[2], MAX_ATOM_VALUE_BYTES) \
                    or len(a) == 4 and not valid_bounded_text(
                        a[3], MAX_ATOM_VALUE_BYTES):
                return False
        elif a[0] == "supp":
            from .suppression import valid_selector_marker
            if not valid_selector_marker(a):
                return False
        elif a[0] == "action":
            from .suppression import valid_action_marker
            if not valid_action_marker(a):
                return False
        else:
            return False
    return True


def from_json(o) -> Fact:
    try:
        e = o.get("e") if isinstance(o, dict) and set(o) == {"e", "b"} \
            else None
        fields = set(e) if isinstance(e, dict) else set()
        if not (fields in (
                    {"a", "bh", "t", "ts"},
                    {"a", "bh", "t", "ts", "ws"},
                )
                and isinstance(e.get("t"), str)
                and valid_timestamp(e.get("ts"))
                and isinstance(o.get("b"), dict)
                and _atoms_ok(e.get("a"))
                and ("ws" not in e or valid_fid(e.get("ws")))):
            raise InvalidEncoding("fact shape")
        f = Fact(e["t"], e["ts"], e["a"], o["b"], e.get("ws"))
        if f.fid != h(canon(e)) or f.bh != e.get("bh"):
            raise InvalidEncoding("fact integrity")
        return f
    except (RecursionError, UnicodeError) as error:
        raise InvalidEncoding("fact encoding") from error


def encode(fact: Fact) -> bytes:
    """The one canonical byte representation stored and carried for a fact."""
    if not isinstance(fact, Fact):
        raise ValueError("not a fact")
    raw = canon(fact.to_json())
    if len(raw) > MAX_FACT_BYTES:
        raise PayloadTooLarge("fact too large")
    return raw


def workspace_of(fact: Fact) -> str:
    """The one workspace named by a fact envelope.

    The sole ws-less value is the genesis whose own fid defines the anchor.
    Kernel/family judgment decides whether that ws-less value is the declared
    genesis family; every other path can compare this value before dispatch.
    """
    return fact.fid if fact.ws is None else fact.ws


def bound_to(fact: Fact, workspace: str) -> bool:
    """Whether exact fact bytes name ``workspace`` without ambient inference."""
    return valid_fid(workspace) and (
        fact.ws == workspace
        or fact.ws is None and fact.fid == workspace
    )


def decode(raw: bytes) -> Fact:
    """Strictly decode one canonical fact blob and re-check its content id."""
    if not isinstance(raw, bytes):
        raise ValueError("fact bytes")
    value = decode_json(raw, MAX_FACT_BYTES, "fact")
    try:
        fact = from_json(value)
        if encode(fact) != raw:
            raise ValueError("non-canonical fact encoding")
        return fact
    except RecursionError as error:
        raise InvalidEncoding("fact encoding") from error
