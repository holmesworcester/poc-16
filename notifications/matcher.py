"""Authenticated indexed join from immutable events to live endpoints."""
from dataclasses import dataclass

import facts

from core.fact import canon
from core.limits import MAX_PILE_FACTS
from core.shape import valid_fid
from core.worker import WorkerView
from facts.auth import push_endpoint
from facts.content import notification_preference as preference
from .model import NotificationTrigger


MAX_MATCH_ROWS = 16_384
MAX_NOTIFICATION_INTENTS = 4_096


@dataclass(frozen=True, slots=True)
class NotificationIntent:
    """One resolved endpoint delivery; no later policy lookup is required."""

    workspace: str
    event: str
    endpoint: str
    user: str
    push_node: str
    platform: str
    application: str
    environment: str
    sealed_target: bytes
    payload: bytes
    preferences: tuple[str, ...]

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.event, self.endpoint, self.user,
                self.push_node)):
            raise ValueError("notification intent identity")
        if self.platform not in push_endpoint.PLATFORMS:
            raise ValueError("notification intent platform")
        push_endpoint._application(self.application)
        push_endpoint._environment(self.environment)
        push_endpoint.encode_sealed_target(self.sealed_target)
        if not isinstance(self.payload, bytes) or not self.payload:
            raise ValueError("notification intent payload")
        if not isinstance(self.preferences, tuple) \
                or tuple(sorted(set(self.preferences))) != self.preferences \
                or not all(valid_fid(fid) for fid in self.preferences):
            raise ValueError("notification intent preferences")


@dataclass(frozen=True, slots=True)
class NotificationPlan:
    """Deterministic result for the exact root and trigger residence set."""

    triggers: tuple[str, ...]
    intents: tuple[NotificationIntent, ...]


class _Budget:
    def __init__(self):
        self.rows = 0

    def add(self, count):
        self.rows += count
        if self.rows > MAX_MATCH_ROWS:
            raise ValueError("notification match row budget")


def _posting_facts(view, kind, k0, k1, budget):
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
    for row, fact in _posting_facts(
            view,
            preference.PREFERENCE_OFFER,
            user,
            identifier,
            budget):
        body = fact.body
        if fact.t != preference.TAG \
                or body.get("user") != user \
                or preference.cell_id(
                    body.get("scope"), body.get("target")) != identifier \
                or (
                    preference.PREFERENCE_OFFER,
                    user,
                    identifier,
                ) not in fact.offers() \
                or not view.fact_active(row.fid):
            raise ValueError("notification preference posting")
        selected.append(fact)
    heads = preference.preference_heads(selected)
    return preference.meet_mode(heads), tuple(
        fact.fid for fact in heads)


def _effective(view, user, channel, budget):
    channel_mode, channel_heads = _cell(
        view, user, preference.CHANNEL, channel, budget)
    if channel_mode != preference.INHERIT:
        return channel_mode, channel_heads
    global_mode, global_heads = _cell(
        view, user, preference.GLOBAL, "", budget)
    return (
        preference.NONE if global_mode == preference.INHERIT else global_mode,
        tuple(sorted(set(channel_heads) | set(global_heads))),
    )


def _candidate_users(view, trigger, budget):
    users = set()
    for route in trigger.routes:
        for row, fact in _posting_facts(
                view, route.kind, route.value, None, budget):
            user = row.k1
            if not valid_fid(user) \
                    or fact.t != preference.TAG \
                    or (route.kind, route.value, user) not in fact.offers() \
                    or fact.body.get("user") != user \
                    or fact.body.get("mode") not in {
                        preference.MENTIONS, preference.ALL}:
                raise ValueError("notification route posting")
            users.add(user)
    return tuple(sorted(users))


def _endpoints(view, user, budget):
    selected = {}
    for row, fact in _posting_facts(
            view, push_endpoint.ENDPOINT_OFFER, user, None, budget):
        body = fact.body
        offered = (
            push_endpoint.ENDPOINT_OFFER,
            user,
            body.get("installation", ""),
        )
        if fact.t != push_endpoint.TAG \
                or body.get("owner") != user \
                or offered not in fact.offers():
            raise ValueError("notification endpoint posting")
        if view.fact_active(row.fid):
            selected[fact.fid] = fact
    return tuple(selected[fid] for fid in sorted(selected))


def _trigger(fact):
    family = facts.family_for(fact.t)
    hook = None if family is None else getattr(
        family, "notification_trigger", None)
    if hook is None:
        return None
    value = hook(fact)
    if not isinstance(value, NotificationTrigger):
        raise ValueError("notification family trigger")
    return value


def _payload(workspace, event, channel, mentioned):
    return canon({
        "channel": channel,
        "event": event,
        "kind": "mention" if mentioned else "message",
        "workspace": workspace,
    })


def match_notifications(root_bytes, fetch, trigger_fids):
    """Perform the route/posting join against one exact authenticated root."""
    trigger_fids = tuple(sorted(set(trigger_fids)))
    if len(trigger_fids) > MAX_PILE_FACTS \
            or not all(valid_fid(fid) for fid in trigger_fids):
        raise ValueError("notification trigger set")
    view = WorkerView.from_root(root_bytes, fetch)
    budget = _Budget()
    considered, intents = [], {}
    for fid in trigger_fids:
        fact = view.fact(fid)
        trigger = _trigger(fact)
        if trigger is None:
            continue
        considered.append(fid)
        if not view.fact_active(fid):
            continue
        for user in _candidate_users(view, trigger, budget):
            mode, heads = _effective(view, user, trigger.channel, budget)
            mentioned = user in trigger.mentions
            if mode == preference.NONE \
                    or mode == preference.MENTIONS and not mentioned:
                continue
            payload = _payload(
                view.anchor, fid, trigger.channel, mentioned)
            for endpoint in _endpoints(view, user, budget):
                body = endpoint.body
                intent = NotificationIntent(
                    workspace=view.anchor,
                    event=fid,
                    endpoint=endpoint.fid,
                    user=user,
                    push_node=body["push_node"],
                    platform=body["platform"],
                    application=body["application"],
                    environment=body["environment"],
                    sealed_target=push_endpoint.decode_sealed_target(
                        body["sealed_target"]),
                    payload=payload,
                    preferences=tuple(sorted(heads)),
                )
                key = intent.event, intent.endpoint
                incumbent = intents.setdefault(key, intent)
                if incumbent != intent:
                    raise ValueError("notification intent conflict")
                if len(intents) > MAX_NOTIFICATION_INTENTS:
                    raise ValueError("notification intent budget")
    return NotificationPlan(
        tuple(considered),
        tuple(intents[key] for key in sorted(intents)),
    )


__all__ = (
    "MAX_MATCH_ROWS",
    "MAX_NOTIFICATION_INTENTS",
    "NotificationIntent",
    "NotificationPlan",
    "match_notifications",
)
