"""Canonical self-confined removal paths for the two-phase access gate."""

import base64
from dataclasses import dataclass
from itertools import islice

from .fact import canon
from .limits import (
    MAX_REMOVAL_PATH_BYTES,
    MAX_REMOVAL_PATH_SCOPES,
    MAX_REMOVAL_PROOF_BYTES,
    MAX_SUPPRESSION_ID_BYTES,
    PayloadTooLarge,
    decode_json,
    valid_bounded_text,
)
from .shape import valid_fid
from .suppression_tree import SuppressionPin


FORMAT = "poc16-removal-path-v1"


class ProofRefreshRequired(ValueError):
    """The recipient no longer pins the root named by this path."""


class RemovalDenied(ValueError):
    """One exact caller scope is ACTIVE at the pinned root."""


@dataclass(frozen=True, slots=True)
class RemovalPath:
    workspace: str
    root: str
    proofs: tuple[tuple[str, bytes], ...]

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.root) \
                or not isinstance(self.proofs, tuple) \
                or len(self.proofs) > MAX_REMOVAL_PATH_SCOPES:
            raise ValueError("removal path")
        sids = []
        for row in self.proofs:
            if not isinstance(row, tuple) or len(row) != 2:
                raise ValueError("removal path row")
            sid, proof = row
            if not valid_bounded_text(sid, MAX_SUPPRESSION_ID_BYTES) \
                    or not isinstance(proof, bytes) \
                    or not 0 < len(proof) <= MAX_REMOVAL_PROOF_BYTES:
                raise ValueError("removal path row")
            sids.append(sid)
        if sids != sorted(set(sids)):
            raise ValueError("removal path order")


def _document(path):
    if not isinstance(path, RemovalPath):
        raise TypeError("removal path")
    return {
        "format": FORMAT,
        "paths": [
            [sid, base64.b64encode(proof).decode("ascii")]
            for sid, proof in path.proofs
        ],
        "root": path.root,
        "workspace": path.workspace,
    }


def encode(path):
    raw = canon(_document(path))
    if len(raw) > MAX_REMOVAL_PATH_BYTES:
        raise PayloadTooLarge("removal path too large")
    return raw


def decode(raw):
    value = decode_json(raw, MAX_REMOVAL_PATH_BYTES, "removal path")
    if not isinstance(value, dict) or set(value) != {
            "format", "paths", "root", "workspace"} \
            or value.get("format") != FORMAT \
            or not isinstance(value.get("paths"), list):
        raise ValueError("removal path")
    try:
        path = RemovalPath(
            value["workspace"],
            value["root"],
            tuple(
                (row[0], base64.b64decode(row[1], validate=True))
                for row in value["paths"]
                if isinstance(row, list) and len(row) == 2
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("removal path") from error
    if len(path.proofs) != len(value["paths"]) \
            or _document(path) != value or canon(value) != raw:
        raise ValueError("removal path")
    return path


def _scopes(values):
    try:
        bounded = tuple(islice(iter(values), MAX_REMOVAL_PATH_SCOPES + 1))
    except TypeError as error:
        raise ValueError("removal path scopes") from error
    if len(bounded) > MAX_REMOVAL_PATH_SCOPES:
        raise PayloadTooLarge("too many removal path scopes")
    if not all(valid_bounded_text(sid, MAX_SUPPRESSION_ID_BYTES)
               for sid in bounded):
        raise ValueError("removal path scope")
    return tuple(sorted(set(bounded)))


async def build(pin, scopes):
    """Read only the exact caller-derived points from one private pin."""
    if not isinstance(pin, SuppressionPin):
        raise TypeError("removal path pin")
    proofs = []
    for sid in _scopes(scopes):
        proof = await pin.proof(sid)
        if proof is None:
            raise ValueError("missing removal state")
        proofs.append((sid, proof))
    return RemovalPath(pin.workspace, pin.root_oid, tuple(proofs))


def verify_clear(pin, supplied, scopes):
    """Verify an exact path set and require every caller scope to be CLEAR."""
    if not isinstance(pin, SuppressionPin):
        raise TypeError("removal path pin")
    path = decode(supplied) if isinstance(supplied, bytes) else supplied
    if not isinstance(path, RemovalPath) or path.workspace != pin.workspace:
        raise ValueError("removal path binding")
    if path.root != pin.root_oid:
        raise ProofRefreshRequired("proof_refresh_required")
    expected = _scopes(scopes)
    if tuple(sid for sid, _proof in path.proofs) != expected:
        raise ValueError("removal path scope set")
    for sid, proof in path.proofs:
        if pin.verify(sid, proof).get("state") != "clear":
            raise RemovalDenied("removal denied")
    return True


__all__ = (
    "ProofRefreshRequired",
    "RemovalDenied",
    "RemovalPath",
    "build",
    "decode",
    "encode",
    "verify_clear",
)
