"""close(): the canonical-topo serializer, and the one unit codec.

Every fetchable unit — ingress pile, leaf pile, tail, request payload,
invite blob — is the same codec: an ordered fact list (+ attached blobs)
that satisfies the kernel's seen-set rule when streamed front to back.
close() emits the closure walk's own completion order: news in key order,
deps first, emit on completion, dedup by fid — deps-first by construction,
deterministic, and the walk that gathers the closure IS the serializer.
"""
import base64
import json

from .crypto import h
from .fact import canon, from_json


def close(news, deps_of, fact_of):
    """Serialize `news` plus its full recursive closure, deps-first."""
    out, seen = [], set()

    def emit(fid):
        if fid in seen:
            return
        seen.add(fid)
        for d in deps_of(fid):
            emit(d)
        out.append(fact_of(fid))

    for f in sorted(news, key=lambda f: f.key):
        emit(f.fid)
    return out


def encode_pile(facts, blobs=None) -> bytes:
    o = {"facts": [f.to_json() for f in facts]}
    if blobs:
        o["blobs"] = {k: base64.b64encode(v).decode() for k, v in blobs.items()}
    return canon(o)


def decode_pile(b: bytes):
    """Hash-verify everything at the door — cheapest checks first."""
    o = json.loads(b)
    facts = [from_json(fo) for fo in o["facts"]]  # raises on integrity mismatch
    blobs = {}
    for k, v in o.get("blobs", {}).items():
        raw = base64.b64decode(v)
        if h(raw) != k:
            raise ValueError("blob integrity")
        blobs[k] = raw
    return facts, blobs
