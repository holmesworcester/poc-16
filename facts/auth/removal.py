"""facts/auth/removal.py — an admin-signed terminal-removal proposal."""
from core.fact import Fact, Need
from .._commands import member_key, offer_source
from .._policy import FamilyPolicy, SidOffer
from . import signature

TAG = "evict"
POLICY = FamilyPolicy(action_offers=(SidOffer("removed", "member"),))


# SHAPE
def removal(workspace, pk, target_pk, ts):
    return Fact(
        TAG, ts, [["offer", "removed", target_pk]], {"pk": pk}, workspace)


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    offers = f.offers()
    target = offers[0][1] if len(offers) == 1 \
        and offers[0][0] == "removed" \
        and offers[0][2] == "" else ""
    return (
        Need("author", "author", f.fid, pk),
        Need("admin", "admin", pk),
        Need("target_member", "member", target),
    )


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"pk"} or len(f.offers()) != 1:
            return False
        name, target, empty = f.offers()[0]
        return name == "removed" and empty == "" \
            and f == removal(f.ws, f.body["pk"], target, f.ts)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def evict(node, workspace, target):
    from full_peer.node import now_ms

    target_pk = member_key(node, workspace, target)
    ts = now_ms()
    secret, public = node.identity(workspace)
    admin = offer_source(node, workspace, "admin", public)
    target_member = offer_source(node, workspace, "member", target_pk)
    if admin is None:
        raise ValueError(
            "publishing identity is not a workspace admin")
    if target_member is None:
        raise ValueError("target is not a workspace member")
    item = removal(workspace, public, target_pk, ts)
    signed = signature.signature(secret, public, item, ts)
    node.ingest_new(
        workspace,
        [signed, item],
        {
            signed.fid: (),
            item.fid: (signed.fid, admin, target_member),
        },
    )
    return item.fid


# QUERIES — member status is exposed by auth.user.members.
CLI = {"auth.removal.evict": evict}
