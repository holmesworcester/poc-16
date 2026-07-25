"""facts/auth/admin.py — a delegable member elevation for eviction.

An existing admin may elevate an enrolled member, beginning with the founder
admin embedded in the workspace root. This follows the poc-13 admin edge while
making its authority recursively usable in poc-16's offers-and-needs kernel.
"""
from ...fact import Fact
from .._commands import offer_source
from . import signature

TAG = "admin"


# SHAPE
def admin(pk, target_pk, ts):
    if pk == target_pk:
        raise ValueError("an admin grant must target another member")
    return Fact(
        TAG, ts, [["offer", "admin", target_pk]],
        {"pk": pk, "target": target_pk})


# NEEDS
def needs(f):
    body = f.body
    signer = body.get("pk", "")
    target = body.get("target", "")
    return (
        ("author", f.fid, signer),
        ("admin", signer, None),
        ("member", target, None),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "target"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == admin(body["pk"], body["target"], f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return ()


# MATERIALIZE
def materialize(db, workspace, valid):
    target = valid.fact.body["target"]
    db.execute(
        "UPDATE members SET role='admin' WHERE ws=? AND pk=?",
        (workspace, target))


# COMMANDS — build a fact, admit it, stop.
def grant(node, workspace, target):
    from ...node import now_ms

    with node.lock:
        row = node.app.execute(
            "SELECT pk FROM members WHERE ws=? AND (pk=? OR name=?)",
            (workspace, target, target)).fetchone()
    if row is None:
        raise ValueError(f"no member {target!r}")
    target_pk = row[0]
    secret, public = node.identity(workspace)
    signer_admin = offer_source(node, workspace, "admin", public)
    target_member = offer_source(node, workspace, "member", target_pk)
    if signer_admin is None:
        raise ValueError("local identity is not an admin")
    if target_member is None:
        raise ValueError("target is not a workspace member")

    ts = now_ms()
    item = admin(public, target_pk, ts)
    signed = signature.signature(secret, public, item, ts)
    deps = {
        item.fid: [signed.fid, signer_admin, target_member],
        signed.fid: [],
    }
    node.ingest_new(workspace, [signed, item], deps)
    return item.fid


# QUERIES
def admins(node, workspace):
    with node.lock:
        rows = node.app.execute(
            "SELECT pk, name, evicted FROM members "
            "WHERE ws=? AND role='admin' ORDER BY name, pk",
            (workspace,)).fetchall()
    return [
        {"pk": public, "name": name, "evicted": bool(evicted)}
        for public, name, evicted in rows
    ]
