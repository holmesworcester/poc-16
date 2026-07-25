"""facts/auth/legacy_genesis.py — read compatibility for persisted genesis roots.

This handler keeps the pre-chained-auth wire tag judgeable during upgrade and
rebuild. New commands author only the ``workspace`` family.
"""
from ...crypto import h, sign, verify
from ...fact import Fact, canon

TAG = "genesis"


# SHAPE
def genesis(sk, pk, name, ts):
    atoms = [["offer", "member", pk], ["offer", "admin", pk]]
    presig = h(canon([TAG, ts, atoms]))
    return Fact(
        TAG, ts, atoms,
        {"name": name, "pk": pk, "sig": sign(sk, presig)})


# NEEDS
def needs(f):
    return ()


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {"name", "pk", "sig"}:
            return False
        pk, name, signature = body["pk"], body["name"], body["sig"]
        atoms = [["offer", "member", pk], ["offer", "admin", pk]]
        shaped = Fact(
            TAG, f.ts, atoms,
            {"name": name, "pk": pk, "sig": signature})
        presig = h(canon([TAG, f.ts, atoms]))
        return f == shaped and f.fid == ctx.anchor \
            and verify(pk, presig, signature)
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
    body = valid.fact.body
    db.execute(
        "INSERT OR IGNORE INTO members VALUES(?,?,?,?,0)",
        (workspace, body["pk"], body["name"], "admin"))


# COMMANDS — compatibility handler only; new roots use auth.workspace.


# QUERIES — none.
