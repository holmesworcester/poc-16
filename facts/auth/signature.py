"""facts/auth/signature.py — detached Ed25519 authorship evidence."""
from core.crypto import sign, verify
from core.fact import Fact, workspace_of
from .._policy import FamilyPolicy

TAG = "signature"
POLICY = FamilyPolicy(authority_resident=True)


# SHAPE
def signature(sk, pk, target, ts):
    return Fact(TAG, ts, [["offer", "author", target.fid, pk]],
                {"sig": sign(sk, target.fid)}, workspace_of(target))


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
                      {"sig": f.body["sig"]}, f.ws)
        return name == "author" and f == shaped \
            and verify(pk, target, f.body["sig"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def project_authority(f, fact_of):
    """Keep authorship evidence only when its exact target is authority."""
    try:
        name, target, _public = f.offers()[0]
        target_fact = fact_of(target)
        if name != "author" or target_fact is None:
            return False
        from facts import family_for

        family = family_for(target_fact.t)
        return family is not None and family.DURABLE \
            and family.POLICY.authority_resident
    except (IndexError, TypeError, ValueError):
        return False


def authority_context(f):
    """Carry the signed target so projection can classify this evidence."""
    try:
        name, target, _public = f.offers()[0]
        return (target,) if name == "author" else ()
    except (IndexError, TypeError, ValueError):
        return ()


# MODE
DURABLE = True


# MATERIALIZE — no client read-model rows.


# COMMANDS — ``signature`` is the command helper used by signed families.


# QUERIES — none.
