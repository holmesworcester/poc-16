"""Facts: type tag + ts + canonical atom set; fid hashes the canonical envelope.

Atoms carry the clear envelope's refs and offers ("refs say where, offers say
what"). Needs are family-declared functions of the fact (kernel.NEEDS) because
a fact cannot name its own fid in its atoms. The authors below are the sole
construction chokepoint — callers pass parameters, never build atoms.
"""
import json
from dataclasses import dataclass, field

from .crypto import h, sign


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
        object.__setattr__(self, "bh", h(canon(self.body)))
        object.__setattr__(self, "fid", h(canon(self.env)))

    @property
    def env(self):
        return {"a": self.atoms, "bh": self.bh, "t": self.t, "ts": self.ts}

    @property
    def key(self) -> str:
        return f"{self.ts:015d}:{self.fid}"

    def refs(self):
        return [(a[1], a[2]) for a in self.atoms if a[0] == "ref"]

    def offers(self):
        return [(a[1], a[2], a[3] if len(a) > 3 else "") for a in self.atoms if a[0] == "offer"]

    def to_json(self):
        return {"e": self.env, "b": self.body}


def from_json(o) -> Fact:
    e = o["e"]
    f = Fact(e["t"], e["ts"], e["a"], o["b"])
    if f.fid != h(canon(e)) or f.bh != e["bh"]:
        raise ValueError("fact integrity")
    return f


def presig(t, ts, atoms) -> str:
    return h(canon([t, ts, atoms]))


# ---- authors: one constructor per family ------------------------------------

def genesis(sk, pk, name, ts) -> Fact:
    atoms = [["offer", "member", pk], ["offer", "admin", pk]]
    return Fact("genesis", ts, atoms, {"name": name, "pk": pk, "sig": sign(sk, presig("genesis", ts, atoms))})


def sig_for(sk, pk, target: Fact, ts) -> Fact:
    return Fact("sig", ts, [["offer", "author", target.fid, pk]], {"sig": sign(sk, target.fid)})


def invite(pk, invite_pk, ts) -> Fact:
    return Fact("invite", ts, [["offer", "invitee", invite_pk]], {"pk": pk})


def join(invite_fact: Fact, invite_sk, pk, name, ts) -> Fact:
    atoms = [["ref", invite_fact.ts, invite_fact.fid], ["offer", "member", pk]]
    return Fact("join", ts, atoms, {"name": name, "pk": pk, "countersig": sign(invite_sk, pk)})


def msg(pk, chan, text, ts) -> Fact:
    return Fact("msg", ts, [], {"pk": pk, "chan": chan, "text": text})


def file_fact(pk, chan, name, size, blob, ts) -> Fact:
    return Fact("file", ts, [], {"pk": pk, "chan": chan, "name": name, "size": size, "blob": blob})


def evict(pk, target_pk, ts) -> Fact:
    return Fact("evict", ts, [["offer", "removed", target_pk]], {"pk": pk})


def req(pk, verb, exp, ts) -> Fact:
    return Fact("req", ts, [], {"pk": pk, "verb": verb, "exp": exp})
