"""facts/auth/legacy_signature.py — read compatibility for persisted sig facts.

The old and new signature families have identical meaning; only their wire tag
differs. New commands author only ``signature``.
"""
from core.crypto import sign, verify
from core.fact import Fact

TAG = "sig"
TABLES = ()


# SHAPE
def legacy_signature(sk, pk, target, ts):
    return Fact(
        TAG, ts, [["offer", "author", target.fid, pk]],
        {"sig": sign(sk, target.fid)})


# NEEDS
def needs(f):
    return ()


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"sig"} or len(f.offers()) != 1:
            return False
        name, target, pk = f.offers()[0]
        shaped = Fact(
            TAG, f.ts, [["offer", "author", target, pk]],
            {"sig": f.body["sig"]})
        return name == "author" and f == shaped \
            and verify(pk, target, f.body["sig"])
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
    return None


# COMMANDS — compatibility handler only; new signatures use auth.signature.


# QUERIES — none.
