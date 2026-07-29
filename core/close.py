"""close(): the canonical-topo serializer, and the ingress unit codec.

Ingress, request, and invite piles use the same ordered fact-list codec
(+ attached blobs) — and so does a settled home leaf: one pile codec serves
the wire and residence alike, so a fact's bytes live once and a resident leaf
decodes with the reader the ingress already has.
close() emits the closure walk's own completion order: news in key order,
deps first, emit on completion, dedup by fid — deps-first by construction,
deterministic, and the walk that gathers the closure IS the serializer.
"""
import base64
import binascii

from .crypto import h
from .fact import canon, from_json
from .limits import MAX_PILE_BYTES, PayloadTooLarge, decode_json


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


def encode_pile(facts, blobs=None) -> bytes:
    o = {"facts": [f.to_json() for f in facts]}
    if blobs:
        o["blobs"] = {k: base64.b64encode(v).decode() for k, v in blobs.items()}
    raw = canon(o)
    if len(raw) > MAX_PILE_BYTES:
        raise PayloadTooLarge("pile too large")
    return raw


def decode_pile(b: bytes):
    """Hash-verify everything at the door — cheapest checks first.

    Total over arbitrary JSON: foreign bytes leave here as a ValueError or
    not at all, so a caller can say ``except ValueError`` and mean it.
    """
    try:
        o = decode_json(b, MAX_PILE_BYTES, "pile")
        if not isinstance(o, dict) or not isinstance(o.get("facts"), list) \
                or not isinstance(o.get("blobs", {}), dict):
            raise ValueError("pile shape")
        facts = [
            from_json(fo) for fo in o["facts"]
        ]  # raises on integrity mismatch
        blobs = {}
        for k, v in o.get("blobs", {}).items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError("blob shape")
            raw = base64.b64decode(v, validate=True)
            if h(raw) != k:
                raise ValueError("blob integrity")
            blobs[k] = raw
        return facts, blobs
    except (binascii.Error, RecursionError, UnicodeError) as error:
        raise ValueError("pile encoding") from error
