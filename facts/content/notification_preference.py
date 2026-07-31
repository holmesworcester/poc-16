"""facts/content/notification_preference.py — user-scoped push settings."""
from core.crypto import h
from core.fact import Fact, Need, canon
from core.limits import (
    MAX_ATOM_VALUE_BYTES,
    MAX_RESOLVED_EDGES,
    valid_bounded_text,
)
from core.shape import valid_fid
from .._commands import member_source, offer_source
from .._policy import FamilyPolicy
from ..auth import signature


TAG = "notification_preference"
PREFERENCE_OFFER = "notification.preference"
ROUTE_TYPE_OFFER = "notification.route.type"
ROUTE_CHANNEL_OFFER = "notification.route.channel"
GLOBAL = "global"
CHANNEL = "channel"
NONE = "none"
MENTIONS = "mentions"
ALL = "all"
INHERIT = "inherit"
GLOBAL_MODES = frozenset((NONE, MENTIONS, ALL))
CHANNEL_MODES = frozenset((*GLOBAL_MODES, INHERIT))
MAX_SUPERSEDES = MAX_RESOLVED_EDGES - 3
_SUPERSEDES_PREFIX = "supersedes."
_BODY_FIELDS = {"clock", "mode", "pk", "scope", "target", "user"}
_RESTRICTIVENESS = {NONE: 0, MENTIONS: 1, ALL: 2, INHERIT: 3}

POLICY = FamilyPolicy()


def _scope_target(scope, target):
    if scope == GLOBAL and target == "":
        return scope, target
    if scope == CHANNEL \
            and valid_bounded_text(target, MAX_ATOM_VALUE_BYTES):
        return scope, target
    raise ValueError("notification preference scope")


def _mode(scope, mode):
    allowed = GLOBAL_MODES if scope == GLOBAL else CHANNEL_MODES
    if mode not in allowed:
        raise ValueError("notification preference mode")
    return mode


def cell_id(scope, target):
    scope, target = _scope_target(scope, target)
    return h(canon(["notification-preference-cell-v1", scope, target]))


def superseded_fids(fact):
    refs = fact.refs()
    expected = [
        (f"{_SUPERSEDES_PREFIX}{index:02d}", fid)
        for index, (_role, fid) in enumerate(refs)
    ]
    if refs != expected or len(refs) > MAX_SUPERSEDES:
        raise ValueError("notification preference supersedes")
    return tuple(fid for _role, fid in refs)


def preference_heads(values):
    """Return explicit DAG heads without treating clocks as winner order."""
    facts_by_fid = {fact.fid: fact for fact in values}
    superseded = {
        fid
        for fact in facts_by_fid.values()
        for fid in superseded_fids(fact)
        if fid in facts_by_fid
    }
    return tuple(
        facts_by_fid[fid]
        for fid in sorted(set(facts_by_fid) - superseded)
    )


def meet_mode(heads):
    """Resolve concurrent values conservatively; a mute always wins."""
    modes = [fact.body["mode"] for fact in heads]
    return min(modes, key=_RESTRICTIVENESS.__getitem__) \
        if modes else INHERIT


def _offers(user, scope, target, mode):
    offers = [["offer", PREFERENCE_OFFER, user, cell_id(scope, target)]]
    if mode in {MENTIONS, ALL}:
        if scope == GLOBAL:
            offers.append(["offer", ROUTE_TYPE_OFFER, "msg", user])
        else:
            offers.append(["offer", ROUTE_CHANNEL_OFFER, target, user])
    return offers


# SHAPE
def notification_preference(
        workspace, pk, user, scope, target, mode, clock, supersedes, ts):
    if not valid_fid(pk) or not valid_fid(user):
        raise ValueError("notification preference principal")
    scope, target = _scope_target(scope, target)
    mode = _mode(scope, mode)
    if type(clock) is not int or clock < 0:
        raise ValueError("notification preference clock")
    supersedes = tuple(sorted(set(supersedes)))
    if len(supersedes) > MAX_SUPERSEDES \
            or not all(valid_fid(fid) for fid in supersedes):
        raise ValueError("notification preference supersedes")
    refs = [
        ["ref", f"{_SUPERSEDES_PREFIX}{index:02d}", fid]
        for index, fid in enumerate(supersedes)
    ]
    return Fact(
        TAG,
        ts,
        refs + _offers(user, scope, target, mode),
        {
            "clock": clock,
            "mode": mode,
            "pk": pk,
            "scope": scope,
            "target": target,
            "user": user,
        },
        workspace,
    )


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    user = f.body.get("user", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk, user),
        Need("device", "device_key", pk, user),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != _BODY_FIELDS:
            return False
        supersedes = superseded_fids(f)
        parents = [ctx.fact_of(fid) for fid in supersedes]
        if any(parent is None or parent.t != TAG for parent in parents):
            return False
        expected_cell = cell_id(body["scope"], body["target"])
        if any(
                parent.ws != f.ws
                or parent.body.get("user") != body["user"]
                or cell_id(
                    parent.body.get("scope"),
                    parent.body.get("target")) != expected_cell
                for parent in parents):
            return False
        expected_clock = 0 if not parents else 1 + max(
            parent.body.get("clock", -1) for parent in parents)
        return body["clock"] == expected_clock \
            and f == notification_preference(
                f.ws,
                body["pk"],
                body["user"],
                body["scope"],
                body["target"],
                body["mode"],
                body["clock"],
                supersedes,
                f.ts,
            )
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


def _cell_facts(node, workspace, user, scope, target):
    identifier = cell_id(scope, target)
    return tuple(
        fact for fact in node.select(
            workspace,
            PREFERENCE_OFFER,
            user,
            identifier,
            include_suppressed=True,
        )
        if fact.t == TAG
        and fact.body.get("user") == user
        and cell_id(
            fact.body.get("scope"), fact.body.get("target")) == identifier
    )


def _set(node, workspace, scope, target, mode, ts=None):
    secret, public = node.identity(workspace)
    with node.lock:
        member, user = member_source(node, workspace, public)
        if member is None:
            raise ValueError("local identity is not a workspace member")
        device = offer_source(
            node, workspace, "device_key", public, user)
        if device is None:
            raise ValueError("local identity is not an enrolled device")
        heads = preference_heads(
            _cell_facts(node, workspace, user, scope, target))
        if len(heads) > MAX_SUPERSEDES:
            raise ValueError("too many concurrent preference heads")
        clock = 0 if not heads else 1 + max(
            fact.body["clock"] for fact in heads)
        timestamp = node.now_ms() if ts is None else ts
        item = notification_preference(
            workspace,
            public,
            user,
            scope,
            target,
            mode,
            clock,
            tuple(fact.fid for fact in heads),
            timestamp,
        )
        signed = signature.signature(secret, public, item, timestamp)
        node.ingest_new(
            workspace,
            [signed, item],
            {
                signed.fid: (),
                item.fid: (
                    signed.fid,
                    member,
                    device,
                    *(fact.fid for fact in heads),
                ),
            },
        )
        return item.fid


# COMMANDS
def set_global(node, workspace, mode, ts=None):
    return _set(node, workspace, GLOBAL, "", mode, ts)


def set_channel(node, workspace, channel, mode, ts=None):
    return _set(node, workspace, CHANNEL, channel, mode, ts)


# QUERIES
def preferences(node, workspace, user=None):
    with node.lock:
        rows = [
            fact for fact in node.by_type(
                workspace, TAG, include_suppressed=True)
            if user is None or fact.body["user"] == user
        ]
    cells = {}
    for fact in rows:
        body = fact.body
        key = body["user"], body["scope"], body["target"]
        cells.setdefault(key, []).append(fact)
    return [
        {
            "clock": max(fact.body["clock"] for fact in heads),
            "head_fids": [fact.fid for fact in heads],
            "mode": meet_mode(heads),
            "scope": scope,
            "target": target,
            "user": owner,
        }
        for (owner, scope, target), values in sorted(cells.items())
        for heads in (preference_heads(values),)
    ]


CLI = {
    "content.notification.list": preferences,
    "content.notification.set_channel": set_channel,
    "content.notification.set_global": set_global,
}


__all__ = (
    "ALL",
    "CHANNEL",
    "GLOBAL",
    "INHERIT",
    "MENTIONS",
    "NONE",
    "PREFERENCE_OFFER",
    "TAG",
    "cell_id",
    "meet_mode",
    "notification_preference",
    "preference_heads",
    "superseded_fids",
)
