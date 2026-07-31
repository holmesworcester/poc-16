"""close(): the canonical-topo serializer, and the wire ingress unit codec.

Ingress, request, invite, and sync-push piles use the same ordered fact-list
codec. Detached immutable objects have their own object-ingress capability;
they are never smuggled through a pile. Published fact bodies instead have one
canonical content-addressed residence; FactOrder stores only key-to-object
references and deliberately does not introduce a second body or pile codec.
close() emits the closure walk's own completion order: news in key order,
deps first, emit on completion, dedup by fid — deps-first by construction,
deterministic, and the walk that gathers the closure IS the serializer.
"""
from itertools import islice

from .fact import bound_to, canon, encode, from_json, workspace_of
from .ingress import InvalidPile
from .limits import (
    InvalidEncoding,
    MAX_PILE_BYTES,
    MAX_PILE_FACTS,
    PayloadTooLarge,
    decode_json,
)
from .shape import valid_fid


def check_pile_bounds(raw):
    """Reject byte/count amplification before reserving untrusted work.

    The small scanner recognizes only the canonical ``facts`` prefix and
    counts top-level fact objects without decoding their bodies. Malformed
    input that cannot be counted continues to the exact decoder, where the
    RepositoryApplier can retain typed rejection evidence.
    """
    if not isinstance(raw, bytes):
        raise InvalidEncoding("pile bytes")
    if len(raw) > MAX_PILE_BYTES:
        raise PayloadTooLarge("pile too large")
    prefix = b'{"facts":['
    if not raw.startswith(prefix):
        return
    at = len(prefix)
    if at < len(raw) and raw[at] == ord("]"):
        return
    count = 0
    while at < len(raw) and raw[at] == ord("{"):
        depth, quoted, escaped = 0, False, False
        while at < len(raw):
            byte = raw[at]
            at += 1
            if quoted:
                if escaped:
                    escaped = False
                elif byte == ord("\\"):
                    escaped = True
                elif byte == ord('"'):
                    quoted = False
            elif byte == ord('"'):
                quoted = True
            elif byte in (ord("{"), ord("[")):
                depth += 1
            elif byte in (ord("}"), ord("]")):
                depth -= 1
                if depth == 0:
                    break
        else:
            return
        count += 1
        if count > MAX_PILE_FACTS:
            raise PayloadTooLarge("pile has too many facts")
        if at >= len(raw) or raw[at] == ord("]"):
            return
        if raw[at] != ord(","):
            return
        at += 1


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


def encode_pile(facts, *, workspace=None) -> bytes:
    """Encode one workspace-bound closed unit.

    ``workspace`` is inferred from non-empty fact bytes when omitted. Empty
    diagnostic/corruption fixtures must name it explicitly.
    """
    facts = tuple(islice(facts, MAX_PILE_FACTS + 1))
    if len(facts) > MAX_PILE_FACTS:
        raise PayloadTooLarge("pile has too many facts")
    if workspace is None:
        if not facts:
            raise ValueError("pile workspace")
        workspace = workspace_of(facts[0])
    if not valid_fid(workspace):
        raise ValueError("pile workspace")
    if not all(bound_to(fact, workspace) for fact in facts):
        raise ValueError("mixed workspace pile")
    for fact in facts:
        encode(fact)
    raw = canon({
        "ws": workspace,
        "facts": [f.to_json() for f in facts],
    })
    if len(raw) > MAX_PILE_BYTES:
        raise PayloadTooLarge("pile too large")
    return raw


def decode_pile(b: bytes, workspace):
    """Hash-verify everything at the door — cheapest checks first.

    Total over arbitrary JSON: foreign bytes leave here as ``InvalidPile`` or
    ``PayloadTooLarge``. Unexpected exception types remain program failures
    and must never become destructive quarantine verdicts.
    """
    try:
        check_pile_bounds(b)
        if not valid_fid(workspace):
            raise InvalidEncoding("pile workspace")
        o = decode_json(b, MAX_PILE_BYTES, "pile")
        if not isinstance(o, dict) \
                or set(o) != {"ws", "facts"} \
                or not valid_fid(o.get("ws")) \
                or not isinstance(o.get("facts"), list):
            raise InvalidEncoding("pile shape")
        if len(o["facts"]) > MAX_PILE_FACTS:
            raise PayloadTooLarge("pile has too many facts")
        pile_workspace = o["ws"]
        facts = [
            from_json(fo) for fo in o["facts"]
        ]  # raises on integrity mismatch
        if pile_workspace != workspace:
            raise InvalidEncoding("pile workspace")
        if not all(bound_to(fact, pile_workspace) for fact in facts):
            raise InvalidEncoding("mixed workspace pile")
        if encode_pile(facts, workspace=pile_workspace) != b:
            raise InvalidEncoding("pile is not canonical")
        return facts
    except PayloadTooLarge as error:
        raise InvalidPile(str(error)) from error
    except InvalidEncoding as error:
        raise InvalidPile(str(error) or "pile encoding") from error
