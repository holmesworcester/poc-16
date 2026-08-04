"""Bounded notification derivation from scanner-validated event bytes.

The durable cursor certifies which writer-head diff produced each event.  A
separately rebuilt current repository owns every mutable delivery decision:
event suppression, recipient preferences, member/device liveness, and endpoint
liveness. Delivery is never a repository commit effect.
"""
from dataclasses import dataclass
from typing import Awaitable, Protocol

import facts

from core.crypto import h
from core.fact import canon, decode, encode
from core.limits import (
    MAX_ATOM_VALUE_BYTES,
    MAX_PILE_FACTS,
    valid_bounded_text,
)
from core.shape import FACT_TS_MAX, valid_fid
from facts._notification import NotificationTrigger
from facts.auth import push_endpoint
from facts.content import notification_preference as preference
from .forest import CurrentView


MAX_MATCH_ROWS = 16_384
MAX_DELIVERIES = 4_096
# Notification data contains only workspace/event/channel/kind identifiers.
# Keep its raw canonical form far below FCM's 4,096-byte encoded data budget;
# Base64 expansion, delivery_id, and JSON keys must fit too.
MAX_PAYLOAD_BYTES = 1_024
MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000
MAX_TTL_SECONDS = 28 * 24 * 60 * 60
MAX_FIREBASE_ROUTES = 32


class InvalidPublicationHint(ValueError):
    """Scanner-certified bytes do not encode the claimed event work."""


@dataclass(frozen=True, slots=True)
class PublicationHint:
    """Scanner-validated historical event facts for one writer-head page."""

    workspace: str
    events: tuple[bytes, ...]

    def __post_init__(self):
        if not valid_fid(self.workspace) \
                or not isinstance(self.events, tuple) \
                or not 1 <= len(self.events) <= MAX_PILE_FACTS:
            raise ValueError("notification publication hint")
        try:
            decoded = tuple(decode(raw) for raw in self.events)
        except Exception as error:
            raise ValueError("notification publication hint") from error
        if any(encode(fact) != raw for fact, raw in zip(
                decoded, self.events)) \
                or tuple(sorted(set(fact.fid for fact in decoded))) != tuple(
                    fact.fid for fact in decoded):
            raise ValueError("notification publication hint")

    @property
    def facts(self):
        return tuple(decode(raw).fid for raw in self.events)


@dataclass(frozen=True, slots=True)
class NotificationIntent:
    workspace: str
    event: str
    event_ts: int
    endpoint: str
    user: str
    push_node: str
    platform: str
    application: str
    environment: str
    sealed_target: str
    payload: bytes
    kind: str
    delivery_id: str


seal_target = push_endpoint.seal_target


@dataclass(frozen=True, slots=True)
class PushRequest:
    application: str
    environment: str
    platform: str
    target: str
    payload: bytes
    delivery_id: str
    expires_at_ms: int
    ttl_seconds: int
    kind: str

    def __post_init__(self):
        if not valid_bounded_text(
                self.application, MAX_ATOM_VALUE_BYTES) \
                or not valid_bounded_text(
                    self.environment, MAX_ATOM_VALUE_BYTES) \
                or self.platform not in push_endpoint.PLATFORMS:
            raise ValueError("push request application")
        push_endpoint.checked_target(self.target)
        if not isinstance(self.payload, bytes) \
                or not 0 < len(self.payload) <= MAX_PAYLOAD_BYTES \
                or not valid_fid(self.delivery_id) \
                or not 0 < self.expires_at_ms <= FACT_TS_MAX \
                or type(self.ttl_seconds) is not int \
                or not 0 <= self.ttl_seconds <= MAX_TTL_SECONDS \
                or self.kind not in {"mention", "message"}:
            raise ValueError("push request")


@dataclass(frozen=True, slots=True)
class PushAccepted:
    message_id: str

    def __post_init__(self):
        if not isinstance(self.message_id, str) or not self.message_id \
                or len(self.message_id.encode("utf-8")) > 4_096:
            raise ValueError("push message id")


class PushError(OSError):
    pass


class PushRetryable(PushError):
    pass


class PushPermanent(PushError):
    pass


class PushInvalidEndpoint(PushPermanent):
    pass


class PushUnregistered(PushInvalidEndpoint):
    pass


class CurrentRepositoryBehind(PushRetryable):
    """The current validated writer forest has not observed the event yet."""


class PushProvider(Protocol):
    def send(self, request: PushRequest) \
            -> PushAccepted | Awaitable[PushAccepted]: ...


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    delivery_id: str
    status: str
    message_id: str = ""


class _Budget:
    def __init__(self):
        self.rows = 0

    def add(self, count):
        self.rows += count
        if self.rows > MAX_MATCH_ROWS:
            raise ValueError("notification match row budget")


def delivery_domain_id(push_node, routes):
    """Name one stable Firebase delivery authority, not its wake carrier."""
    if not valid_fid(push_node) or not isinstance(routes, tuple) \
            or not 1 <= len(routes) <= MAX_FIREBASE_ROUTES:
        raise ValueError("notification delivery domain")
    normalized = []
    for route in routes:
        if not isinstance(route, tuple) or len(route) != 3 \
                or not all(valid_bounded_text(
                    value, MAX_ATOM_VALUE_BYTES) for value in route):
            raise ValueError("notification delivery route")
        normalized.append(route)
    if len(set(normalized)) != len(normalized):
        raise ValueError("duplicate notification delivery route")
    normalized.sort()
    return h(canon([
        "notification-delivery-domain-v1",
        push_node,
        [list(route) for route in normalized],
    ]))


def _postings(view, kind, k0, k1, budget):
    after = None
    while True:
        page = view.postings(kind, k0, k1, after=after)
        budget.add(len(page.rows))
        for row in page.rows:
            yield row, view.fact_of(row.fid)
        if page.cursor is None:
            return
        if page.cursor == after:
            raise ValueError("notification posting cursor")
        after = page.cursor


def _cell(view, user, scope, target, budget):
    identifier = preference.cell_id(scope, target)
    selected = []
    for row, fact in _postings(
            view, preference.PREFERENCE_OFFER, user, identifier, budget):
        body = fact.body
        if fact.t != preference.TAG \
                or body.get("user") != user \
                or preference.cell_id(
                    body.get("scope"), body.get("target")) != identifier \
                or (preference.PREFERENCE_OFFER, user, identifier) \
                not in fact.offers():
            raise ValueError("notification preference posting")
        if view.fact_active(row.fid):
            selected.append(fact)
    return selected


def _effective(view, user, channel, budget):
    return preference.resolved_mode(
        _cell(view, user, preference.CHANNEL, channel, budget),
        _cell(view, user, preference.GLOBAL, "", budget),
    )


def _users(view, trigger, budget):
    users = set()
    for kind, value in (
            (preference.ROUTE_TYPE_OFFER, trigger.kind),
            (preference.ROUTE_CHANNEL_OFFER, trigger.channel)):
        for row, fact in _postings(view, kind, value, None, budget):
            user = row.k1
            if not valid_fid(user) or fact.t != preference.TAG \
                    or (kind, value, user) not in fact.offers() \
                    or fact.body.get("user") != user:
                raise ValueError("notification route posting")
            if view.fact_active(row.fid):
                users.add(user)
    return sorted(users)


def _endpoints(view, user, push_node, budget):
    cells = {}
    for row, fact in _postings(
            view, push_endpoint.ENDPOINT_OFFER, user, None, budget):
        body = fact.body
        if fact.t != push_endpoint.TAG \
                or body.get("owner") != user \
                or (push_endpoint.ENDPOINT_OFFER, user,
                    body.get("installation", "")) not in fact.offers():
            raise ValueError("notification endpoint posting")
        if view.fact_active(row.fid):
            cells.setdefault(body["installation"], []).append(fact)

    # Concurrent registration can leave two otherwise valid facts in the
    # same logical installation cell.  Neither target is authoritative until
    # ordinary suppression resolves that conflict.  Group before filtering
    # by push node so two workers cannot each select one side of the conflict.
    selected = [
        values[0]
        for _installation, values in sorted(cells.items())
        if len(values) == 1 and (
            push_node is None or values[0].body["push_node"] == push_node)
    ]
    return sorted(selected, key=lambda fact: fact.fid)


def trigger_for(fact):
    """Return the family-owned trigger, if this fact can notify."""
    family = facts.family_for(fact.t)
    hook = None if family is None else getattr(
        family, "notification_trigger", None)
    if hook is None:
        return None
    value = hook(fact)
    if not isinstance(value, NotificationTrigger):
        raise ValueError("notification family trigger")
    return value


def _check_derivation(hint, current_view, push_node):
    if not isinstance(hint, PublicationHint) \
            or not isinstance(current_view, CurrentView) \
            or current_view.workspace != hint.workspace \
            or push_node is not None and not valid_fid(push_node):
        raise ValueError("notification derivation")


def _derive_from(hint, current_view, push_node):
    budget, intents = _Budget(), {}
    for raw in hint.events:
        try:
            fact = decode(raw)
            fid = fact.fid
            trigger = trigger_for(fact)
        except Exception as error:
            raise InvalidPublicationHint(
                "invalid notification event fact") from error
        if trigger is None:
            continue
        if not current_view.fact_known(fid):
            raise CurrentRepositoryBehind(
                "current notification repository has not observed event")
        current_fact = current_view.fact_of(fid)
        if current_fact != fact:
            raise ValueError("notification event residence conflict")
        if not current_view.fact_active(fid):
            continue
        for user in _users(current_view, trigger, budget):
            mode = _effective(
                current_view, user, trigger.channel, budget)
            mentioned = user in trigger.mentions
            if mode == preference.NONE \
                    or mode == preference.MENTIONS and not mentioned:
                continue
            kind = "mention" if mentioned else "message"
            payload = canon({
                "channel": trigger.channel,
                "event": fid,
                "kind": kind,
                "workspace": hint.workspace,
            })
            for endpoint in _endpoints(
                    current_view, user, push_node, budget):
                body = endpoint.body
                delivery_id = h(canon([
                    "notification-delivery-v2",
                    hint.workspace,
                    fid,
                    user,
                    body["installation"],
                    h(payload),
                ]))
                intent = NotificationIntent(
                    hint.workspace,
                    fid,
                    fact.ts,
                    endpoint.fid,
                    user,
                    body["push_node"],
                    body["platform"],
                    body["application"],
                    body["environment"],
                    body["sealed_target"],
                    payload,
                    kind,
                    delivery_id,
                )
                key = fid, endpoint.fid
                if key in intents and intents[key] != intent:
                    raise ValueError("notification intent conflict")
                intents[key] = intent
                if len(intents) > MAX_DELIVERIES:
                    raise ValueError("notification delivery budget")
    return tuple(intents[key] for key in sorted(intents))


def derive(hint, current_view, *, push_node=None):
    """Join scanner-certified events with current validated forest state."""
    _check_derivation(hint, current_view, push_node)
    return _derive_from(hint, current_view, push_node)


def request_for(intent, push_node_secret, now_ms):
    """Open one current endpoint and assign TTL from this send attempt."""
    if not isinstance(intent, NotificationIntent) \
            or type(now_ms) is not int or not 0 <= now_ms <= FACT_TS_MAX:
        raise ValueError("notification request")
    try:
        target = push_endpoint.open_target(
            push_node_secret, intent.sealed_target)
    except (TypeError, ValueError) as error:
        raise PushInvalidEndpoint(
            "invalid sealed FCM installation") from error
    expires = min(FACT_TS_MAX, now_ms + MAX_TTL_MS)
    return PushRequest(
        intent.application,
        intent.environment,
        intent.platform,
        target,
        intent.payload,
        intent.delivery_id,
        expires,
        min(MAX_TTL_SECONDS, (expires - now_ms + 999) // 1000),
        intent.kind,
    )


__all__ = (
    "CurrentRepositoryBehind",
    "DeliveryResult",
    "InvalidPublicationHint",
    "MAX_FIREBASE_ROUTES",
    "MAX_PAYLOAD_BYTES",
    "NotificationIntent",
    "PublicationHint",
    "PushAccepted",
    "PushInvalidEndpoint",
    "PushPermanent",
    "PushRequest",
    "PushRetryable",
    "PushUnregistered",
    "derive",
    "delivery_domain_id",
    "request_for",
    "seal_target",
    "trigger_for",
)
