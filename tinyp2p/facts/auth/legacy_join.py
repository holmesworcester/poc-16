"""facts/auth/legacy_join.py — read compatibility for persisted join facts.

This preserves the old bearer-redemption wire shape during upgrade and rebuild.
New commands author only the ``user`` family.
"""
from ...crypto import sign, verify
from ...fact import Fact

TAG = "join"
TABLES = ("member_rows",)


# SHAPE
def join(invite_fact, invite_sk, pk, name, ts):
    atoms = [
        ["ref", invite_fact.ts, invite_fact.fid],
        ["offer", "member", pk],
    ]
    return Fact(
        TAG, ts, atoms,
        {"name": name, "pk": pk, "countersig": sign(invite_sk, pk)})


# NEEDS
def needs(f):
    return (("author", f.fid, f.body.get("pk", "")),)


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"name", "pk", "countersig"} \
                or len(f.refs()) != 1:
            return False
        if f.offers() != [("member", f.body["pk"], "")]:
            return False
        ref_ts, ref_fid = f.refs()[0]
        invited = ctx.offers_from(ref_fid, "invitee")
        if len(invited) != 1:
            return False
        invite_pk = invited[0][0]
        shaped = Fact(
            TAG, f.ts,
            [["ref", ref_ts, ref_fid],
             ["offer", "member", f.body["pk"]]],
            dict(f.body))
        return f == shaped \
            and verify(invite_pk, f.body["pk"], f.body["countersig"])
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
    fact, body = valid.fact, valid.fact.body
    db.execute(
        "INSERT INTO member_rows VALUES(?,?,?,?,?)",
        (workspace, fact.fid, body["pk"], body["name"], "member"))


# COMMANDS — compatibility handler only; new members use auth.user.


# QUERIES — member observations are shared with auth.user.
