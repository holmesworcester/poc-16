"""facts/auth/removal.py — admin-signed, monotone connection removal."""
from ...fact import Fact
from .._commands import publish
from . import signature

TAG = "evict"


# SHAPE
def removal(pk, target_pk, ts):
    return Fact(TAG, ts, [["offer", "removed", target_pk]], {"pk": pk})


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("admin", pk, None))


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"pk"} or len(f.offers()) != 1:
            return False
        name, target, empty = f.offers()[0]
        return name == "removed" and empty == "" \
            and f == removal(f.body["pk"], target, f.ts)
    except Exception:
        return False


# MODE — only drain publishes this monotone row; evaluate merely consumes it.
DURABLE = True


def global_rows(f):
    return (("removal", f.offers()[0][1]),)


def blob_refs(f):
    return ()


# MATERIALIZE
def materialize(db, workspace, valid):
    target = valid.fact.offers()[0][1]
    db.execute("UPDATE members SET evicted=1 WHERE ws=? AND pk=?",
               (workspace, target))


# COMMANDS
def evict(node, workspace, target):
    from ...node import now_ms

    with node.lock:
        row = node.app.execute(
            "SELECT pk FROM members WHERE ws=? AND (pk=? OR name=?)",
            (workspace, target, target)).fetchone()
    if not row:
        raise ValueError(f"no member {target!r}")
    ts = now_ms()
    secret, public = node.identity(workspace)
    item = removal(public, row[0], ts)
    return publish(node, workspace, item,
                   signature.signature(secret, public, item, ts), role="admin")


# QUERIES — member status is exposed by auth.user.members.
