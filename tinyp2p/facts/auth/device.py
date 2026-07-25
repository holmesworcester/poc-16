"""facts/auth/device.py — a member's self-bound primary device.

An enrolled member may bind its own signing key into a flat device set. This
is the poc-13 device authority edge with poc-10 transport atoms omitted; all
devices are equal peers and the fact carries no endpoint policy.
"""
from ...fact import Fact
from .._commands import offer_source, publish
from . import signature

TAG = "device"


# SHAPE
def device(pk, label, ts):
    return Fact(
        TAG, ts,
        [["offer", "device_key", pk],
         ["offer", "device", pk, pk]],
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


def reconcile(db, workspace, index, fact_of, valids):
    """Project the same canonical device-key winners used by the kernel.

    A duplicate offer in any family forces a proof rebuild and can change an
    existing device claim's rank, even when this batch has no new device fact.
    """
    offered = [
        offer
        for valid in valids
        for offer in valid.fact.offers()
    ]
    if not any(name == "device_key" for name, _, _ in offered) \
            and not any(index.execute(
                "SELECT COUNT(*) FROM offers "
                "WHERE name=? AND a0=? AND a1=?",
                offer).fetchone()[0] > 1 for offer in offered):
        return
    rows = index.execute(
        "SELECT o.a0, o.src FROM offers o "
        "JOIN proofs p ON p.fid=o.src "
        "WHERE o.name='device_key' "
        "ORDER BY o.a0, p.rank, o.src"
    ).fetchall()
    winners = {}
    for device_pk, source in rows:
        winners.setdefault(device_pk, source)

    db.execute("DELETE FROM devices WHERE ws=?", (workspace,))
    for device_pk, source in winners.items():
        body = fact_of(source).body
        user = body.get("user", body["pk"])
        db.execute(
            "INSERT INTO devices VALUES(?,?,?,?,?)",
            (workspace, user, device_pk, body["label"], source))
        db.execute(
            "UPDATE members SET name=? "
            "WHERE ws=? AND pk=? AND role='device'",
            (body["label"], workspace, device_pk))


# COMMANDS — build a fact, admit it, stop.
def bind(node, workspace, label):
    from ...node import now_ms

    secret, public = node.identity(workspace)
    if offer_source(
            node, workspace, "device_key", public) is not None:
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
