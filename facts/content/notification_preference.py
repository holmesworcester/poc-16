"""facts/content/notification_preference.py — shared user push settings."""
from core.crypto import h
from core.fact import Fact, canon
from core.limits import MAX_ATOM_VALUE_BYTES, valid_bounded_text
from core.shape import valid_fid
from .. import _policy
from .._commands import member_source, offer_source
from .._identity import actor_needs
from .._policy import DELETE_SELF, FamilyPolicy, Self, author_selectors
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
MAX_ACTIVE_VALUES = 32
_BODY_FIELDS = {"mode", "pk", "scope", "target", "user"}
_RESTRICTIVENESS = {NONE: 0, MENTIONS: 1, ALL: 2, INHERIT: 3}

POLICY = FamilyPolicy(
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_field="user",
)


# SHAPE
def _scope_target(scope, target):
    if scope == GLOBAL and target == "":
        return scope, target
    if scope == CHANNEL and valid_bounded_text(
            target, MAX_ATOM_VALUE_BYTES):
        return scope, target
    raise ValueError("notification preference scope")


def _mode(scope, value):
    if value not in (
            GLOBAL_MODES if scope == GLOBAL else CHANNEL_MODES):
        raise ValueError("notification preference mode")
    return value


def cell_id(scope, target):
    scope, target = _scope_target(scope, target)
    return h(canon(["notification-preference-cell-v1", scope, target]))


def effective_mode(values, default=INHERIT):
    """Meet concurrent active values; an independently authored mute wins."""
    modes = [fact.body["mode"] for fact in values]
    return min(modes, key=_RESTRICTIVENESS.__getitem__) \
        if modes else default


def resolved_mode(channel_values, global_values):
    """Resolve inheritance before meeting concurrent channel values."""
    global_mode = effective_mode(global_values, NONE)
    modes = [
        global_mode if fact.body["mode"] == INHERIT else fact.body["mode"]
        for fact in channel_values
    ]
    return min(modes, key=_RESTRICTIVENESS.__getitem__) \
        if modes else global_mode


def _offers(user, scope, target, mode):
    offers = [["offer", PREFERENCE_OFFER, user, cell_id(scope, target)]]
    if mode in {MENTIONS, ALL}:
        offers.append([
            "offer",
            ROUTE_TYPE_OFFER if scope == GLOBAL else ROUTE_CHANNEL_OFFER,
            "msg" if scope == GLOBAL else target,
            user,
        ])
    return offers


def notification_preference(
        workspace, pk, user, scope, target, mode, ts):
    if not valid_fid(pk) or not valid_fid(user):
        raise ValueError("notification preference principal")
    scope, target = _scope_target(scope, target)
    mode = _mode(scope, mode)
    return Fact(
        TAG,
        ts,
        author_selectors(POLICY, {}) + _offers(
            user, scope, target, mode),
        {
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
    return actor_needs(f, pk, user, require_device=True)


# VALIDATE
def validate(f, _ctx):
    try:
        body = f.body
        return set(body) == _BODY_FIELDS and f == notification_preference(
            f.ws,
            body["pk"],
            body["user"],
            body["scope"],
            body["target"],
            body["mode"],
            f.ts,
        )
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def _cell_facts(node, workspace, user, scope, target):
    identifier = cell_id(scope, target)
    return tuple(
        fact for fact in node.select(
            workspace, PREFERENCE_OFFER, user, identifier)
        if fact.t == TAG
        and fact.body.get("user") == user
        and cell_id(
            fact.body.get("scope"), fact.body.get("target")) == identifier
    )


def _set(node, workspace, scope, target, mode, ts=None):
    from . import delete as deletion

    secret, public = node.identity(workspace)
    with node.lock:
        member, user = member_source(node, workspace, public)
        if member is None:
            raise ValueError("local identity is not a workspace member")
        device = offer_source(
            node, workspace, "device_key", public, user)
        if device is None:
            raise ValueError("local identity is not an enrolled device")
        current = _cell_facts(node, workspace, user, scope, target)
        if len(current) > MAX_ACTIVE_VALUES:
            raise ValueError("too many concurrent notification preferences")
        timestamp = node.now_ms() if ts is None else ts
        item = notification_preference(
            workspace, public, user, scope, target, mode, timestamp)
        stale = tuple(old for old in current if old.fid != item.fid)
        if current and not stale:
            return item.fid
        signed = signature.signature(secret, public, item, timestamp)
        news = [signed, item]
        deps = {
            signed.fid: (),
            item.fid: (signed.fid, member, device),
        }
        for old in stale:
            removal = deletion.delete(
                workspace, public, old.key, _policy.OWNER, timestamp, user)
            removal_signature = signature.signature(
                secret, public, removal, timestamp)
            news.extend((removal_signature, removal))
            deps[removal_signature.fid] = ()
            deps[removal.fid] = (
                removal_signature.fid, old.fid, member)
        node.ingest_new(workspace, news, deps)
        return item.fid


def set_global(node, workspace, mode, ts=None):
    return _set(node, workspace, GLOBAL, "", mode, ts)


def set_channel(node, workspace, channel, mode, ts=None):
    return _set(node, workspace, CHANNEL, channel, mode, ts)


# QUERIES
def preferences(node, workspace, user=None):
    with node.lock:
        rows = [
            fact for fact in node.by_type(workspace, TAG)
            if user is None or fact.body["user"] == user
        ]
    cells = {}
    for fact in rows:
        body = fact.body
        cells.setdefault(
            (body["user"], body["scope"], body["target"]), []).append(fact)
    return [
        {
            "fids": sorted(fact.fid for fact in values),
            "mode": effective_mode(values),
            "scope": scope,
            "target": target,
            "user": owner,
        }
        for (owner, scope, target), values in sorted(cells.items())
    ]


CLI = {
    "content.notification.list": preferences,
    "content.notification.set_channel": set_channel,
    "content.notification.set_global": set_global,
}
