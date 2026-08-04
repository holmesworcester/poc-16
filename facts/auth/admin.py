"""facts/auth/admin.py — a delegable member-principal elevation.

An existing admin may elevate an enrolled member, beginning with the founder
admin embedded in the workspace root.  Authority belongs to the member, not
one device: an owned device proves its member link and then consumes the same
``admin(owner)`` offer.
"""
from core.fact import Fact, Need
from .._commands import member_key, member_source, offer_source, publish
from .._identity import actor_needs
from .._policy import FamilyPolicy
from . import signature

TAG = "admin"
POLICY = FamilyPolicy(
    control_fact=True,
    # The grantor_admin Need is checked when the grant is admitted. The resulting
    # admin authority remains live only while the grantee remains a member.
    authority_liveness_guards=("grantee_member",),
)


# SHAPE
def admin(workspace, pk, target, ts, actor=None):
    actor = pk if actor is None else actor
    if actor == target:
        raise ValueError("an admin grant must target another member")
    return Fact(
        TAG, ts, [["offer", "admin", target]],
        {"actor": actor, "pk": pk, "target": target}, workspace)


# NEEDS
def needs(f):
    body = f.body
    signer = body.get("pk", "")
    actor = body.get("actor", "")
    target = body.get("target", "")
    return actor_needs(f, signer, actor) + (
        Need("grantor_admin", "admin", actor),
        Need("grantee_member", "member", target, target),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"actor", "pk", "target"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == admin(
                f.ws, body["pk"], body["target"], f.ts, body["actor"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS — build a fact, admit it, stop.
def grant(node, workspace, target):
    target_pk = member_key(node, workspace, target)
    secret, public = node.identity(workspace)
    signer_member, actor = member_source(node, workspace, public)
    target_member, target_owner = member_source(
        node, workspace, target_pk)
    signer_admin = offer_source(node, workspace, "admin", actor) \
        if actor is not None else None
    if signer_admin is None:
        raise ValueError("local identity is not an admin")
    if target_member is None:
        raise ValueError("target is not a workspace member")

    ts = node.now_ms()
    item = admin(workspace, public, target_owner, ts, actor)
    signed = signature.signature(secret, public, item, ts)
    return publish(node, workspace, item, signed)


# QUERIES
def admins(node, workspace):
    from .user import members

    rows = [
        row for row in members(node, workspace)
        if row["role"] == "admin"
    ]
    return [
        {"pk": row["pk"], "name": row["name"], "evicted": row["evicted"]}
        for row in rows
    ]
