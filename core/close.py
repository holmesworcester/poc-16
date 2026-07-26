"""close(): the canonical-topo serializer, and the ingress unit codec.

Ingress, request, and invite piles use the same ordered fact-list codec
(+ attached blobs) — and so does a settled home leaf: one pile codec serves
the wire and residence alike (docs/CUTOVER.md §3), so a fact's bytes live
once and a resident leaf decodes with the reader the ingress already has.
close() emits the closure walk's own completion order: news in key order,
deps first, emit on completion, dedup by fid — deps-first by construction,
deterministic, and the walk that gathers the closure IS the serializer.
"""
import base64
import json

from .crypto import h
from .fact import canon, from_json


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
    return canon(o)


def decode_pile(b: bytes):
    """Hash-verify everything at the door — cheapest checks first.

    Total over arbitrary JSON: foreign bytes leave here as a ValueError or
    not at all, so a caller can say ``except ValueError`` and mean it.
    """
    o = json.loads(b)
    if not isinstance(o, dict) or not isinstance(o.get("facts"), list) \
            or not isinstance(o.get("blobs", {}), dict):
        raise ValueError("pile shape")
    facts = [from_json(fo) for fo in o["facts"]]  # raises on integrity mismatch
    blobs = {}
    for k, v in o.get("blobs", {}).items():
        raw = base64.b64decode(v)
        if h(raw) != k:
            raise ValueError("blob integrity")
        blobs[k] = raw
    return facts, blobs
