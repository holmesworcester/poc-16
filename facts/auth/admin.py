"""facts/auth/admin.py — a delegable member elevation for eviction.

An existing admin may elevate an enrolled member, beginning with the founder
admin embedded in the workspace root. This follows the poc-13 admin edge while
making its authority recursively usable in poc-16's offers-and-needs kernel.
"""
from core.fact import Fact, Need
from .._commands import member_key, member_source, offer_source
from .._policy import FamilyPolicy
from . import signature

TAG = "admin"
POLICY = FamilyPolicy(
    authority_resident=True,
    # The grantor_admin Need is checked when the grant is admitted. The resulting
    # admin authority remains live only while the grantee remains a member.
    authority_liveness_guards=("grantee_member",),
)


# SHAPE
def admin(workspace, pk, target_pk, ts, target_owner=None):
    if pk == target_pk:
        raise ValueError("an admin grant must target another member")
    target_owner = target_pk if target_owner is None else target_owner
    return Fact(
        TAG, ts, [["offer", "admin", target_pk]],
        {"pk": pk, "target": target_pk, "owner": target_owner}, workspace)


# NEEDS
def needs(f):
    body = f.body
    signer = body.get("pk", "")
    target = body.get("target", "")
    owner = body.get("owner", "")
    return (
        Need("author", "author", f.fid, signer),
        Need("grantor_admin", "admin", signer),
        Need("grantee_member", "member", target, owner),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "target", "owner"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == admin(
                f.ws, body["pk"], body["target"], f.ts, body["owner"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS — build a fact, admit it, stop.
def grant(node, workspace, target):
    target_pk = member_key(node, workspace, target)
    secret, public = node.identity(workspace)
    signer_admin = offer_source(node, workspace, "admin", public)
    target_member, target_owner = member_source(
        node, workspace, target_pk)
    if signer_admin is None:
        raise ValueError("local identity is not an admin")
    if target_member is None:
        raise ValueError("target is not a workspace member")

    ts = node.now_ms()
    item = admin(
        workspace, public, target_pk, ts, target_owner)
    signed = signature.signature(secret, public, item, ts)
    deps = {
        item.fid: [signed.fid, signer_admin, target_member],
        signed.fid: [],
    }
    node.ingest_new(workspace, [signed, item], deps)
    return item.fid


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
