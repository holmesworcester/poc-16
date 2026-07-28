"""facts/auth/removal.py — admin-signed, monotone connection removal."""
from core.fact import Fact
from .._commands import member_key, publish
from . import signature

TAG = "evict"
TABLES = ("removal_rows",)


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


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return ()


# MATERIALIZE
def materialize(db, workspace, valid):
    fact = valid.fact
    db.execute(
        "INSERT INTO removal_rows VALUES(?,?,?)",
        (workspace, fact.fid, fact.offers()[0][1]))


# COMMANDS
def evict(node, workspace, target):
    from core.node import now_ms

    target_pk = member_key(node, workspace, target)
    ts = now_ms()
    secret, public = node.identity(workspace)
    item = removal(public, target_pk, ts)
    return publish(node, workspace, item,
                   signature.signature(secret, public, item, ts), role="admin")


# QUERIES — member status is exposed by auth.user.members.
