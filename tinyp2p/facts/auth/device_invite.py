"""facts/auth/device_invite.py — a one-step direct-key device grant.

A device-set peer names a known sibling key and immediately declares it both a
device and workspace member. There is no bearer secret or follow-up join; the
poc-13 two-family flow collapses to the direct-key form settled for poc-16.
"""
from ...fact import Fact
from .._commands import offer_source
from . import signature

TAG = "device_invite"


# SHAPE
def device_invite(pk, user, device_pk, label, ts):
    return Fact(
        TAG, ts,
        [["offer", "member", device_pk],
         ["offer", "device", user, device_pk]],
        {"pk": pk, "user": user, "device": device_pk, "label": label})


# NEEDS
def needs(f):
    body = f.body
    signer = body.get("pk", "")
    user = body.get("user", "")
    return (
        ("author", f.fid, signer),
        ("member", signer, None),
        ("device", user, signer),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "user", "device", "label"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == device_invite(
                body["pk"], body["user"], body["device"],
                body["label"], f.ts)
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
        "INSERT OR IGNORE INTO members VALUES(?,?,?,?,0)",
        (workspace, body["device"], body["label"], "device"))
    db.execute(
        "INSERT OR IGNORE INTO devices VALUES(?,?,?,?,?)",
        (workspace, body["user"], body["device"], body["label"], fact.fid))


# COMMANDS — build a fact, admit it, stop.
def grant(node, workspace, user, device_pk, label):
    from ...node import now_ms

    secret, public = node.identity(workspace)
    ts = now_ms()
    item = device_invite(public, user, device_pk, label, ts)
    signed = signature.signature(secret, public, item, ts)
    member = offer_source(node, workspace, "member", public)
    device_source = offer_source(node, workspace, "device", user, public)
    existing = offer_source(node, workspace, "device", user, device_pk)
    if member is None or device_source is None:
        raise ValueError("local identity is not a device-set member")
    if existing is not None:
        raise ValueError("device key is already in this device set")
    deps = {
        item.fid: [signed.fid, member, device_source],
        signed.fid: [],
    }
    node.ingest_new(workspace, [signed, item], deps)
    return item.fid


# QUERIES — device roster observations belong to auth.device.devices.
