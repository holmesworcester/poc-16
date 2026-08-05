"""Canonical bounded notification work handed to a managed carrier."""
from dataclasses import dataclass

from core.crypto import h
from core.fact import canon
from core.limits import decode_json
from core.shape import valid_fid

from .carrier import MAX_CARRIER_BYTES
from .delivery import PublicationHint


FORMAT = "notification-writer-hint-v1"
MAX_HINT_BYTES = MAX_CARRIER_BYTES
# One durable pending item carries one event.  Delivery derives users,
# preferences, and endpoints from current authority, so reference count and
# fact byte count alone cannot bound the aggregate downstream work of a batch.
# Keeping this at one makes every worker budget apply independently to one
# event and prevents a large multi-pile writer suffix from creating a pending
# item that can never complete.
MAX_HINT_EVENTS = 1


@dataclass(frozen=True, slots=True, order=True)
class EventRef:
    fid: str
    oid: str

    def __post_init__(self):
        if not valid_fid(self.fid) or not valid_fid(self.oid):
            raise ValueError("notification event reference")


@dataclass(frozen=True, slots=True)
class NotificationHint:
    workspace: str
    owner: str
    generation: str
    device: str
    base_head: str | None
    head: str
    events: tuple[EventRef, ...]

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.owner, self.generation,
                self.device, self.head)) \
                or self.base_head is not None \
                and not valid_fid(self.base_head) \
                or not isinstance(self.events, tuple) \
                or not 1 <= len(self.events) <= MAX_HINT_EVENTS \
                or tuple(sorted(set(self.events))) != self.events:
            raise ValueError("notification hint")

    @property
    def facts(self):
        return tuple(event.fid for event in self.events)


def _body(hint):
    if not isinstance(hint, NotificationHint):
        raise TypeError("notification hint")
    return {
        "base_head": hint.base_head,
        "device": hint.device,
        "events": [[event.fid, event.oid] for event in hint.events],
        "format": FORMAT,
        "generation": hint.generation,
        "head": hint.head,
        "owner": hint.owner,
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
            "base_head", "device", "events", "format", "generation",
            "head", "owner", "workspace"} \
            or value.get("format") != FORMAT \
            or not isinstance(value.get("events"), list):
        raise ValueError("notification hint shape")
    try:
        events = tuple(EventRef(*row) for row in value["events"])
        hint = NotificationHint(
            value.get("workspace"), value.get("owner"),
            value.get("generation"), value.get("device"),
            value.get("base_head"), value.get("head"), events)
    except (TypeError, ValueError) as error:
        raise ValueError("notification hint shape") from error
    if encode_hint(hint) != raw:
        raise ValueError("notification hint identity")
    return hint


def materialize_hint(hint, raw_events):
    """Bind scanner-validated event references to hash-verified fact bytes."""
    if not isinstance(hint, NotificationHint):
        raise ValueError("notification hint")
    raw_events = tuple(raw_events)
    if len(raw_events) != len(hint.events) or any(
            not isinstance(raw, bytes) or h(raw) != event.oid
            for event, raw in zip(hint.events, raw_events)):
        raise ValueError("notification hint events")
    return PublicationHint(hint.workspace, raw_events)


__all__ = (
    "EventRef",
    "MAX_HINT_BYTES",
    "MAX_HINT_EVENTS",
    "NotificationHint",
    "decode_hint",
    "encode_hint",
    "materialize_hint",
)
