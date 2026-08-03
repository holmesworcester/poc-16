"""Closure ordering and the sole device-signed pile wire codec.

Requests, authority checks, writer leaves, and peer sync use the same signed
ordered fact-list codec. Published fact bodies have one canonical residence;
FactOrder stores only key-to-object references and deliberately does not
introduce a second body or pile codec.
close() emits the closure walk's own completion order: news in key order,
deps first, emit on completion, dedup by fid — deps-first by construction,
deterministic, and the walk that gathers the closure IS the serializer.
"""
from dataclasses import dataclass
from itertools import islice

from .crypto import h, sign, verify
from .fact import Fact, bound_to, canon, encode, from_json
from .ingress import InvalidPile, KernelRejected
from .limits import (
    MIN_HOSTED_MEMORY_BYTES,
    InvalidEncoding,
    MAX_PILE_BYTES,
    MAX_PILE_FACTS,
    MAX_PILE_JSON_VALUES,
    PayloadTooLarge,
    applier_peak_bound,
    decode_json,
)
from .shape import valid_fid


SIGNED_PILE_FORMAT = "poc16-signed-pile-v1"
SIGNED_PILE_SIGNATURE_DOMAIN = "poc16-signed-pile-signature-v1"
SIGNATURE_HEX_CHARS = 128


def check_pile_bounds(raw):
    """Reject byte/count amplification before reserving untrusted work.

    The small lexical scanner finds a root ``facts`` key under any JSON
    whitespace/key order and counts arbitrary top-level array values without
    decoding their bodies. Malformed input that cannot amplify that array
    continues to the exact decoder, where the RepositoryApplier returns the
    typed result for that one retained source.
    """
    if not isinstance(raw, bytes):
        raise InvalidEncoding("pile bytes")
    if len(raw) > MAX_PILE_BYTES:
        raise PayloadTooLarge("pile too large")
    values = _scan_json_values(raw)
    facts = _scan_root_facts(raw)
    if applier_peak_bound(len(raw), values, facts) \
            > MIN_HOSTED_MEMORY_BYTES:
        raise PayloadTooLarge("pile exceeds hosted memory budget")


_JSON_SPACE = b" \t\r\n"
_OPEN = {ord("{"): ord("}"), ord("["): ord("]")}
_JSON_DELIMITERS = _JSON_SPACE + b'{}[],:\"'


def _scan_json_values(raw):
    """Bound decoder objects lexically before the JSON graph is allocated."""
    at = count = 0
    while at < len(raw):
        byte = raw[at]
        if byte == ord('"'):
            count += 1
            end = _string_end(raw, at)
            if end is None:
                return count
            at = end
        elif byte in _OPEN:
            count += 1
            at += 1
        elif byte in _JSON_DELIMITERS:
            at += 1
        else:
            count += 1
            at += 1
            while at < len(raw) and raw[at] not in _JSON_DELIMITERS:
                at += 1
        if count > MAX_PILE_JSON_VALUES:
            raise PayloadTooLarge("pile has too many JSON values")
    return count


def _nonspace(raw, at):
    while at < len(raw) and raw[at] in _JSON_SPACE:
        at += 1
    return at


def _string_end(raw, at):
    at += 1
    while at < len(raw):
        if raw[at] == ord("\\"):
            at += 2
        elif raw[at] == ord('"'):
            return at + 1
        else:
            at += 1
    return None


def _facts_key(raw, start, end):
    token = raw[start:end]
    if token == b'"facts"':
        return True
    if len(token) > 64:
        return False
    try:
        return decode_json(token, 64, "pile key") == "facts"
    except ValueError:
        return False


def _count_array(raw, at):
    stack, count, expecting = [ord("]")], 0, True
    at += 1
    while at < len(raw) and stack:
        byte = raw[at]
        if byte in _JSON_SPACE:
            at += 1
            continue
        if len(stack) == 1 and expecting and byte != ord("]"):
            count += 1
            if count > MAX_PILE_FACTS:
                raise PayloadTooLarge("pile has too many facts")
            expecting = False
        if byte == ord('"'):
            end = _string_end(raw, at)
            if end is None:
                raise InvalidEncoding("pile facts array")
            at = end
        elif byte in _OPEN:
            stack.append(_OPEN[byte])
            at += 1
        elif byte == stack[-1]:
            stack.pop()
            at += 1
            if not stack:
                return at, count
        elif byte in (ord("}"), ord("]")):
            raise InvalidEncoding("pile facts array")
        elif byte == ord(",") and len(stack) == 1:
            expecting = True
            at += 1
        else:
            at += 1
    if stack:
        raise InvalidEncoding("pile facts array")


def _scan_root_facts(raw):
    at = _nonspace(raw, 0)
    if at >= len(raw) or raw[at] != ord("{"):
        return 0
    stack, maximum = [ord("}")], 0
    at += 1
    while at < len(raw) and stack:
        byte = raw[at]
        if byte == ord('"'):
            end = _string_end(raw, at)
            if end is None:
                return maximum
            after = _nonspace(raw, end)
            if len(stack) == 1 and after < len(raw) \
                    and raw[after] == ord(":") \
                    and _facts_key(raw, at, end):
                value = _nonspace(raw, after + 1)
                if value < len(raw) and raw[value] == ord("["):
                    at, count = _count_array(raw, value)
                    maximum = max(maximum, count)
                    continue
            at = end
        elif byte in _OPEN:
            stack.append(_OPEN[byte])
            at += 1
        elif byte == stack[-1]:
            stack.pop()
            at += 1
        elif byte in (ord("}"), ord("]")):
            return maximum
        else:
            at += 1
    return maximum


def close(news, deps_of, fact_of):
    """Serialize ``news`` plus its full closure, deps-first and stack-safe."""
    out, seen = [], set()
    for f in sorted(news, key=lambda f: f.key):
        stack = [(f.fid, False)]
        while stack:
            fid, expanded = stack.pop()
            if expanded:
                out.append(fact_of(fid))
                continue
            if fid in seen:
                continue
            seen.add(fid)
            stack.append((fid, True))
            stack.extend(
                (dependency, False)
                for dependency in reversed(tuple(deps_of(fid)))
            )
    return out


def _signature(value):
    return isinstance(value, str) \
        and len(value) == SIGNATURE_HEX_CHARS \
        and all(character in "0123456789abcdef" for character in value)


def _signed_document(workspace, writer, facts):
    if not valid_fid(workspace) or not valid_fid(writer) \
            or not isinstance(facts, tuple) \
            or len(facts) > MAX_PILE_FACTS \
            or not all(isinstance(fact, Fact) for fact in facts) \
            or not all(bound_to(fact, workspace) for fact in facts):
        raise ValueError("signed pile")
    for fact in facts:
        encode(fact)
    return {
        "facts": [fact.to_json() for fact in facts],
        "format": SIGNED_PILE_FORMAT,
        "workspace": workspace,
        "writer": writer,
    }


def signed_pile_message(workspace, writer, facts):
    """Return the domain-separated digest signed by the writer device."""
    return h(canon([
        SIGNED_PILE_SIGNATURE_DOMAIN,
        _signed_document(workspace, writer, facts),
    ]))


@dataclass(frozen=True, slots=True)
class SignedPile:
    """One portable, independently closed publication unit.

    ``writer`` is the publishing device's root Ed25519 public key. Individual
    facts retain their own authorship signatures; this outer signature says
    only that the device published this exact ordered closure.
    """

    workspace: str
    writer: str
    facts: tuple[Fact, ...]
    signature: str

    def __post_init__(self):
        _signed_document(self.workspace, self.writer, self.facts)
        if not _signature(self.signature) or not verify(
                self.writer,
                signed_pile_message(
                    self.workspace, self.writer, self.facts),
                self.signature):
            raise ValueError("signed pile signature")


def make_signed_pile(secret, workspace, writer, facts):
    """Sign one exact bounded closure with its publishing device key."""
    facts = tuple(islice(facts, MAX_PILE_FACTS + 1))
    if len(facts) > MAX_PILE_FACTS:
        raise PayloadTooLarge("pile has too many facts")
    message = signed_pile_message(workspace, writer, facts)
    return SignedPile(workspace, writer, facts, sign(secret, message))


def signed_pile_document(pile):
    if not isinstance(pile, SignedPile):
        raise TypeError("signed pile")
    return {
        **_signed_document(pile.workspace, pile.writer, pile.facts),
        "signature": pile.signature,
    }


def encode_signed_pile(pile):
    """Encode the one signed-pile format used by push and pull."""
    try:
        raw = canon(signed_pile_document(pile))
        check_pile_bounds(raw)
        return raw
    except PayloadTooLarge:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidPile("signed pile encoding") from error


def decode_signed_pile(raw, workspace=None, writer=None):
    """Decode and verify one canonical signed closed-pile value."""
    try:
        check_pile_bounds(raw)
        value = decode_json(raw, MAX_PILE_BYTES, "signed pile")
        if not isinstance(value, dict) or set(value) != {
                "facts", "format", "signature", "workspace", "writer"} \
                or value.get("format") != SIGNED_PILE_FORMAT \
                or not isinstance(value.get("facts"), list) \
                or len(value["facts"]) > MAX_PILE_FACTS:
            raise InvalidEncoding("signed pile shape")
        pile = SignedPile(
            value["workspace"],
            value["writer"],
            tuple(from_json(item) for item in value["facts"]),
            value["signature"],
        )
        if workspace is not None and pile.workspace != workspace \
                or writer is not None and pile.writer != writer \
                or encode_signed_pile(pile) != raw:
            raise InvalidEncoding("signed pile binding")
        return pile
    except PayloadTooLarge as error:
        raise InvalidPile(str(error)) from error
    except (InvalidEncoding, KeyError, RecursionError, TypeError,
            UnicodeError, ValueError) as error:
        raise InvalidPile(str(error) or "signed pile encoding") from error


def signed_pile_oid(value):
    raw = encode_signed_pile(value) if isinstance(value, SignedPile) else value
    decode_signed_pile(raw)
    return h(raw)


@dataclass(frozen=True, slots=True)
class EvaluatedPile:
    """A signed pile plus the kernel judgment over those exact bytes."""

    pile: SignedPile
    judgment: object


class ClosedPileEvaluator:
    """The shared signed-pile semantic door for push and pull."""

    def __init__(self, workspace, *, max_bytes=MAX_PILE_BYTES):
        if not valid_fid(workspace) \
                or type(max_bytes) is not int \
                or not 0 < max_bytes <= MAX_PILE_BYTES:
            raise ValueError("pile evaluator options")
        self.workspace = workspace
        self.max_bytes = max_bytes

    def evaluate(self, raw, *, writer=None):
        from .kernel import drain

        if not isinstance(raw, bytes) or len(raw) > self.max_bytes:
            raise InvalidPile("pile too large")
        pile = decode_signed_pile(
            raw, workspace=self.workspace, writer=writer)
        judgment = drain(pile.facts, self.workspace)
        if not judgment.ok:
            if judgment.failure is not None:
                raise judgment.failure
            raise KernelRejected("closed pile rejected")
        return EvaluatedPile(pile, judgment)


__all__ = (
    "ClosedPileEvaluator",
    "EvaluatedPile",
    "SIGNED_PILE_FORMAT",
    "SIGNED_PILE_SIGNATURE_DOMAIN",
    "SignedPile",
    "check_pile_bounds",
    "close",
    "decode_signed_pile",
    "encode_signed_pile",
    "make_signed_pile",
    "signed_pile_document",
    "signed_pile_message",
    "signed_pile_oid",
)
