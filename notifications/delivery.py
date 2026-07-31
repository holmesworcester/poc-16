"""Prototype stateless push derivation from an explicit repository hint.

No production root-commit path, carrier, or provider deployment invokes this
library yet. A future emitter must name only newly published event facts and
must not treat an Applier's whole admitted closure as that event set.
"""
from dataclasses import dataclass
from typing import Protocol

import facts

from core.crypto import h
from core.fact import canon
from core.limits import (
    MAX_ATOM_VALUE_BYTES,
    MAX_PILE_FACTS,
    MAX_ROOT_BYTES,
    valid_bounded_text,
)
from core.repository_reader import RepositoryReader
from core.shape import FACT_TS_MAX, valid_fid
from facts._notification import NotificationTrigger
from facts.auth import push_endpoint
from facts.content import notification_preference as preference


MAX_MATCH_ROWS = 16_384
MAX_DELIVERIES = 4_096
MAX_PAYLOAD_BYTES = 4_096
MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000
MAX_TTL_SECONDS = 28 * 24 * 60 * 60
@dataclass(frozen=True, slots=True)
class PublicationHint:
    """Advisory work created only after this exact root was published."""

    workspace: str
    root: bytes
    facts: tuple[str, ...]

    def __post_init__(self):
        if not valid_fid(self.workspace) \
                or not isinstance(self.root, bytes) \
                or not 0 < len(self.root) <= MAX_ROOT_BYTES \
                or not isinstance(self.facts, tuple) \
                or len(self.facts) > MAX_PILE_FACTS \
                or tuple(sorted(set(self.facts))) != self.facts \
                or not all(valid_fid(fid) for fid in self.facts):
            raise ValueError("notification publication hint")


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


class PushUnregistered(PushPermanent):
    pass


class PushProvider(Protocol):
    def send(self, request: PushRequest) -> PushAccepted: ...


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


def _postings(view, kind, k0, k1, budget):
    after = None
    while True:
        page = view.postings(kind, k0, k1, after=after)
        budget.add(len(page.rows))
        for row in page.rows:
            yield row, view.fact(row.fid)
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
    selected = []
    for row, fact in _postings(
            view, push_endpoint.ENDPOINT_OFFER, user, None, budget):
        body = fact.body
        if fact.t != push_endpoint.TAG \
                or body.get("owner") != user \
                or (push_endpoint.ENDPOINT_OFFER, user,
                    body.get("installation", "")) not in fact.offers():
            raise ValueError("notification endpoint posting")
        if view.fact_active(row.fid) \
                and (push_node is None or body["push_node"] == push_node):
            selected.append(fact)
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


def derive(hint, fetch, *, push_node=None):
    """Join triggers, preferences, and endpoints in the hint's exact root."""
    if not isinstance(hint, PublicationHint) or not callable(fetch) \
            or push_node is not None and not valid_fid(push_node):
        raise ValueError("notification derivation")
    view = RepositoryReader(hint.workspace, hint.root, fetch).worker()
    budget, intents = _Budget(), {}
    for fid in hint.facts:
        fact = view.fact(fid)
        trigger = trigger_for(fact)
        if trigger is None or not view.fact_active(fid):
            continue
        for user in _users(view, trigger, budget):
            mode = _effective(view, user, trigger.channel, budget)
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
                    view, user, push_node, budget):
                body = endpoint.body
                delivery_id = h(canon([
                    "notification-delivery-v1",
                    hint.workspace,
                    fid,
                    endpoint.fid,
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


def deliver(hint, fetch, push_node_secret, provider, now_ms):
    """Perform stateless at-least-once delivery for one push-node key."""
    try:
        public = push_node_secret.verify_key.encode().hex()
    except Exception as error:
        raise TypeError("push node secret key") from error
    if not valid_fid(public) or not callable(getattr(provider, "send", None)) \
            or type(now_ms) is not int or not 0 <= now_ms <= FACT_TS_MAX:
        raise ValueError("notification delivery")
    outcomes = []
    for intent in derive(hint, fetch, push_node=public):
        expires = min(FACT_TS_MAX, intent.event_ts + MAX_TTL_MS)
        if now_ms >= expires:
            outcomes.append(DeliveryResult(intent.delivery_id, "expired"))
            continue
        request = PushRequest(
            intent.application,
            intent.environment,
            intent.platform,
            push_endpoint.open_target(
                push_node_secret, intent.sealed_target),
            intent.payload,
            intent.delivery_id,
            expires,
            min(MAX_TTL_SECONDS, (expires - now_ms + 999) // 1000),
            intent.kind,
        )
        accepted = provider.send(request)
        if not isinstance(accepted, PushAccepted):
            raise PushRetryable("push provider returned no acceptance")
        outcomes.append(DeliveryResult(
            intent.delivery_id, "accepted", accepted.message_id))
    return tuple(outcomes)


__all__ = (
    "DeliveryResult",
    "NotificationIntent",
    "PublicationHint",
    "PushAccepted",
    "PushPermanent",
    "PushRequest",
    "PushRetryable",
    "PushUnregistered",
    "deliver",
    "derive",
    "seal_target",
    "trigger_for",
)
