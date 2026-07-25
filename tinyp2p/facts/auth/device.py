"""facts/auth/device.py — a member's self-bound primary device.

An enrolled member may bind its own signing key into a flat device set. This
is the poc-13 device authority edge with poc-10 transport atoms omitted; all
devices are equal peers and the fact carries no endpoint policy.
"""
from ...fact import Fact
from .._commands import offer_source_by_value, publish
from . import signature

TAG = "device"


# SHAPE
def device(pk, label, ts):
    return Fact(
        TAG, ts, [["offer", "device", pk, pk]],
        {"pk": pk, "label": label})


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("member", pk, None))


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "label"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == device(body["pk"], body["label"], f.ts)
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
    fact = valid.fact
    body = fact.body
    db.execute(
        "INSERT INTO devices VALUES(?,?,?,?,?) "
        "ON CONFLICT(ws, pk) DO UPDATE SET "
        "user=excluded.user, label=excluded.label, source=excluded.source "
        "WHERE excluded.source < devices.source",
        (workspace, body["pk"], body["pk"], body["label"], fact.fid))


# COMMANDS — build a fact, admit it, stop.
def bind(node, workspace, label):
    from ...node import now_ms

    secret, public = node.identity(workspace)
    if offer_source_by_value(
            node, workspace, "device", public) is not None:
        raise ValueError("local identity is already in a device set")
    ts = now_ms()
    item = device(public, label, ts)
    return publish(
        node, workspace, item,
        signature.signature(secret, public, item, ts))


# QUERIES
def devices(node, workspace, user=None):
    query = "SELECT user, pk, label FROM devices WHERE ws=?" \
        + (" AND user=?" if user else "") + " ORDER BY user, pk"
    args = (workspace, user) if user else (workspace,)
    with node.lock:
        rows = node.app.execute(query, args).fetchall()
    return [
        {"user": user_pk, "pk": device_pk, "label": label}
        for user_pk, device_pk, label in rows
    ]
