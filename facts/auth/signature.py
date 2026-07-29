"""facts/auth/signature.py — detached Ed25519 authorship evidence."""
from core.crypto import sign, verify
from core.fact import Fact
from .._policy import FamilyPolicy

TAG = "signature"
POLICY = FamilyPolicy()


# SHAPE
def signature(sk, pk, target, ts):
    return Fact(TAG, ts, [["offer", "author", target.fid, pk]],
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
        shaped = Fact(TAG, f.ts, [["offer", "author", target, pk]],
                      {"sig": f.body["sig"]})
        return name == "author" and f == shaped \
            and verify(pk, target, f.body["sig"])
    except Exception:
        return False


# MODE
DURABLE = True


# MATERIALIZE — no client read-model rows.


# COMMANDS — ``signature`` is the command helper used by signed families.


# QUERIES — none.
