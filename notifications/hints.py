"""Canonical bounded notification work handed to a managed carrier."""
from dataclasses import dataclass

from core.crypto import h
from core.fact import canon
from core.limits import MAX_PILE_FACTS, decode_json
from core.shape import valid_fid

from .carrier import MAX_CARRIER_BYTES
from .delivery import PublicationHint


FORMAT = "notification-hint-v2"
MAX_HINT_BYTES = MAX_CARRIER_BYTES


@dataclass(frozen=True, slots=True)
class NotificationHint:
    workspace: str
    owner: str
    generation: str
    root_oid: str
    facts: tuple[str, ...]

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.owner) \
                or not valid_fid(self.generation) \
                or not valid_fid(self.root_oid) \
                or not isinstance(self.facts, tuple) \
                or len(self.facts) > MAX_PILE_FACTS \
                or tuple(sorted(set(self.facts))) != self.facts \
                or not all(valid_fid(fid) for fid in self.facts):
            raise ValueError("notification hint")


def _body(hint):
    if not isinstance(hint, NotificationHint):
        raise TypeError("notification hint")
    return {
        "facts": list(hint.facts),
        "format": FORMAT,
        "generation": hint.generation,
        "owner": hint.owner,
        "root_oid": hint.root_oid,
        "workspace": hint.workspace,
    }


def encode_hint(hint):
    raw = canon(_body(hint))
    if len(raw) > MAX_HINT_BYTES:
        raise ValueError("notification hint too large")
    return raw


def decode_hint(raw):
    value = decode_json(raw, MAX_HINT_BYTES, "notification hint")
    if not isinstance(value, dict) or set(value) != {
            "facts", "format", "generation", "owner", "root_oid",
            "workspace"} \
            or value.get("format") != FORMAT \
            or not isinstance(value.get("facts"), list):
        raise ValueError("notification hint shape")
    hint = NotificationHint(
        value.get("workspace"), value.get("owner"),
        value.get("generation"), value.get("root_oid"),
        tuple(value["facts"]))
    if encode_hint(hint) != raw:
        raise ValueError("notification hint identity")
    return hint


def materialize_hint(hint, root):
    """Bind carrier work to hash-verified root bytes from cursor storage."""
    if not isinstance(hint, NotificationHint) \
            or not isinstance(root, bytes) or h(root) != hint.root_oid:
        raise ValueError("notification hint root")
    return PublicationHint(hint.workspace, root, hint.facts)


__all__ = (
    "MAX_HINT_BYTES",
    "NotificationHint",
    "decode_hint",
    "encode_hint",
    "materialize_hint",
)
