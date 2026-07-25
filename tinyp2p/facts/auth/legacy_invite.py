"""facts/auth/legacy_invite.py — read compatibility for persisted invite facts.

Legacy bearer invitations retain their original admin-only authority rule.
New ``user_invite`` facts use the member-can-invite rule.
"""
from ...fact import Fact

TAG = "invite"


# SHAPE
def invite(pk, invite_pk, ts):
    return Fact(TAG, ts, [["offer", "invitee", invite_pk]], {"pk": pk})


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("admin", pk, None))


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"pk"} or len(f.offers()) != 1:
            return False
        name, invite_pk, empty = f.offers()[0]
        return name == "invitee" and empty == "" \
            and f == invite(f.body["pk"], invite_pk, f.ts)
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


# COMMANDS — compatibility handler only; new invitations use auth.user_invite.


# QUERIES — none.
