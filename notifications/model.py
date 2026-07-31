"""Small checked values shared by triggering families and the matcher."""
from dataclasses import dataclass

from core.limits import MAX_ATOM_VALUE_BYTES, valid_bounded_text
from core.shape import valid_fid


ROUTE_TYPE_OFFER = "notification.route.type"
ROUTE_CHANNEL_OFFER = "notification.route.channel"
MAX_TRIGGER_ROUTES = 16
MAX_TRIGGER_MENTIONS = 32


@dataclass(frozen=True, slots=True, order=True)
class RouteProbe:
    """One exact generic FactTree offer prefix to probe."""

    kind: str
    value: str

    def __post_init__(self):
        if self.kind not in {ROUTE_TYPE_OFFER, ROUTE_CHANNEL_OFFER} \
                or not valid_bounded_text(
                    self.value, MAX_ATOM_VALUE_BYTES):
            raise ValueError("notification route probe")


@dataclass(frozen=True, slots=True)
class NotificationTrigger:
    """Bounded family-owned routing metadata for one immutable event."""

    channel: str
    mentions: tuple[str, ...]
    routes: tuple[RouteProbe, ...]

    def __post_init__(self):
        if not valid_bounded_text(self.channel, MAX_ATOM_VALUE_BYTES):
            raise ValueError("notification trigger channel")
        if not isinstance(self.mentions, tuple) \
                or len(self.mentions) > MAX_TRIGGER_MENTIONS \
                or tuple(sorted(set(self.mentions))) != self.mentions \
                or not all(valid_fid(value) for value in self.mentions):
            raise ValueError("notification trigger mentions")
        if not isinstance(self.routes, tuple) \
                or not self.routes \
                or len(self.routes) > MAX_TRIGGER_ROUTES \
                or tuple(sorted(set(self.routes))) != self.routes \
                or not all(isinstance(route, RouteProbe)
                           for route in self.routes):
            raise ValueError("notification trigger routes")


__all__ = (
    "MAX_TRIGGER_MENTIONS",
    "MAX_TRIGGER_ROUTES",
    "NotificationTrigger",
    "ROUTE_CHANNEL_OFFER",
    "ROUTE_TYPE_OFFER",
    "RouteProbe",
)
