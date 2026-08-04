"""Facts as leaves.

fid = h(canonical bytes). Refs are located (writer, seq) pointers into
dense logs: a ref at or below the target's stored head always resolves
with one ranged GET, a ref above it is a pending interval — classified,
never probed. Control families carry detached signature facts so their
closures stay carriable; messages are authenticated by residence alone
and get extractable proofs (proof.carry) when they must travel.
"""
from dataclasses import dataclass

CONTROL = frozenset({"member", "device", "channel", "invite", "removal", "sig"})


@dataclass(frozen=True)
class Ref:
    writer: bytes
    seq: int


@dataclass(frozen=True)
class Fact:
    family: str
    ts: int  # uninterpreted locality key, writer-chosen
    refs: tuple[Ref, ...]
    body: bytes


def canonical(fact: Fact) -> bytes:
    """Deterministic unsigned encoding, identical at every store."""
    raise NotImplementedError


def fid(fact: Fact) -> bytes:
    """h(canonical(fact))."""
    raise NotImplementedError


def is_control(fact: Fact) -> bool:
    return fact.family in CONTROL
