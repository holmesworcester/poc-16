"""facts/auth/removal.py — an admin-member terminal-removal proposal."""
from core.fact import Fact, Need
from .._commands import member_key, member_source, offer_source, publish
from .._identity import actor_needs
from .._policy import FamilyPolicy, SidOffer
from . import signature

TAG = "evict"
POLICY = FamilyPolicy(
    control_fact=True,
    action_offers=(SidOffer("removed", "member"),),
)


# SHAPE
def removal(workspace, pk, target_pk, ts, actor=None):
    actor = pk if actor is None else actor
    return Fact(
        TAG, ts, [["offer", "removed", target_pk]],
        {"actor": actor, "pk": pk}, workspace)


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    actor = f.body.get("actor", "")
    offers = f.offers()
    target = offers[0][1] if len(offers) == 1 \
        and offers[0][0] == "removed" \
        and offers[0][2] == "" else ""
    return actor_needs(f, pk, actor) + (
        Need("admin", "admin", actor),
        Need("target_member", "member", target, target),
    )


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"actor", "pk"} or len(f.offers()) != 1:
            return False
        name, target, empty = f.offers()[0]
        return name == "removed" and empty == "" \
            and f == removal(
                f.ws, f.body["pk"], target, f.ts, f.body["actor"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def evict(node, workspace, target):
    target_pk = member_key(node, workspace, target)
    target_member, target_owner = member_source(
        node, workspace, target_pk)
    ts = node.now_ms()
    secret, public = node.identity(workspace)
    actor_member, actor = member_source(node, workspace, public)
    admin_source = offer_source(node, workspace, "admin", actor) \
        if actor is not None else None
    if actor_member is None or admin_source is None:
        raise ValueError(
            "publishing identity is not a workspace admin")
    if target_member is None:
        raise ValueError("target is not a workspace member")
    item = removal(workspace, public, target_owner, ts, actor)
    signed = signature.signature(secret, public, item, ts)
    return publish(node, workspace, item, signed)


# QUERIES — member status is exposed by auth.user.members.
CLI = {"auth.removal.evict": evict}
