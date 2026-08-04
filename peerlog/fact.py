"""Canonical facts used as leaves of per-writer logs."""
import base64
import hashlib
import json
from dataclasses import dataclass

from core.fact import canon
from core.limits import MAX_FACT_BYTES, PayloadTooLarge, decode_json
from core.shape import valid_timestamp

CONTROL = frozenset({"member", "device", "channel", "invite", "removal", "sig"})
FACT_FORMAT = "poc16-peer-fact-v1"
SLICE_FORMAT = "poc16-peer-slice-v1"
MAX_REFS = 256
MAX_FAMILY_BYTES = 128


def _writer(value):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("fact writer")
    return value


@dataclass(frozen=True)
class Ref:
    writer: bytes
    seq: int

    def __post_init__(self):
        _writer(self.writer)
        if type(self.seq) is not int or self.seq < 0:
            raise ValueError("fact ref sequence")


@dataclass(frozen=True)
class Fact:
    family: str
    ts: int
    refs: tuple[Ref, ...]
    body: bytes

    def __post_init__(self):
        if not isinstance(self.family, str) or not self.family \
                or len(self.family.encode("utf-8")) > MAX_FAMILY_BYTES:
            raise ValueError("fact family")
        if not valid_timestamp(self.ts):
            raise ValueError("fact timestamp")
        if not isinstance(self.refs, tuple) or len(self.refs) > MAX_REFS \
                or any(not isinstance(ref, Ref) for ref in self.refs):
            raise ValueError("fact refs")
        if not isinstance(self.body, bytes):
            raise ValueError("fact body")


def _document(fact):
    return {
        "body": base64.b64encode(fact.body).decode("ascii"),
        "family": fact.family,
        "format": FACT_FORMAT,
        "refs": [[ref.writer.hex(), ref.seq] for ref in fact.refs],
        "ts": fact.ts,
    }


def canonical(fact: Fact) -> bytes:
    """Deterministic unsigned encoding, identical at every store."""
    if not isinstance(fact, Fact):
        raise ValueError("fact")
    raw = canon(_document(fact))
    if len(raw) > MAX_FACT_BYTES:
        raise PayloadTooLarge("fact too large")
    return raw


def decode(raw: bytes) -> Fact:
    value = decode_json(raw, MAX_FACT_BYTES, "peer fact")
    if not isinstance(value, dict) or set(value) != {
            "body", "family", "format", "refs", "ts"} \
            or value.get("format") != FACT_FORMAT \
            or not isinstance(value.get("refs"), list):
        raise ValueError("peer fact")
    try:
        refs = tuple(Ref(bytes.fromhex(writer), seq)
                     for writer, seq in value["refs"])
        body = base64.b64decode(value["body"], validate=True)
        fact = Fact(value["family"], value["ts"], refs, body)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("peer fact") from error
    if canonical(fact) != raw:
        raise ValueError("non-canonical peer fact")
    return fact


def encode_slice(facts: tuple[Fact, ...]) -> bytes:
    if not isinstance(facts, tuple):
        raise ValueError("fact slice")
    return canon([
        SLICE_FORMAT,
        [base64.b64encode(canonical(fact)).decode("ascii") for fact in facts],
    ])


def decode_slice(raw: bytes, expected=None) -> tuple[Fact, ...]:
    if not isinstance(raw, bytes) or len(raw) > 4 * 95 * 1024 * 1024 // 3 + 4096:
        raise ValueError("fact slice")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_finite)
        if not isinstance(value, list) or len(value) != 2 \
                or value[0] != SLICE_FORMAT or not isinstance(value[1], list):
            raise ValueError
        facts = tuple(decode(base64.b64decode(item, validate=True))
                      for item in value[1])
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("fact slice") from error
    if expected is not None and len(facts) != expected:
        raise ValueError("fact slice length")
    if encode_slice(facts) != raw:
        raise ValueError("non-canonical fact slice")
    return facts


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _finite(_value):
    raise ValueError("non-finite JSON number")


def fid(fact: Fact) -> bytes:
    """h(canonical(fact)), as the lowercase address bytes used by the treap."""
    return hashlib.sha256(canonical(fact)).hexdigest().encode("ascii")


def is_control(fact: Fact) -> bool:
    return fact.family in CONTROL
