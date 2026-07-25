"""facts/auth/user_invite.py — a member-signed bearer invitation.

Any existing workspace member, including the founder member established by
the workspace fact, may invite a user. This is the poc-13 authority rule on
the poc-10/poc-16 offers-and-needs kernel.
"""
import base64
import os

from ...crypto import box_encrypt, kdf, keypair
from ...fact import Fact, canon
from .._commands import closer, offer_source
from . import signature

TAG = "user_invite"
TABLES = ()


# SHAPE
def user_invite(pk, invite_pk, ts):
    return Fact(TAG, ts, [["offer", "invitee", invite_pk]], {"pk": pk})


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("member", pk, None))


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"pk"} or len(f.offers()) != 1:
            return False
        name, invite_pk, empty = f.offers()[0]
        return name == "invitee" and empty == "" \
            and f == user_invite(f.body["pk"], invite_pk, f.ts)
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


# COMMANDS
def make(node, workspace):
    """Publish a closed invite blob without adding the invitation to the set."""
    from ...node import now_ms

    seed = os.urandom(32)
    invite_sk, invite_pk = keypair()
    ts = now_ms()
    secret, public = node.identity(workspace)
    item = user_invite(public, invite_pk, ts)
    sig = signature.signature(secret, public, item, ts)
    member = offer_source(node, workspace, "member", public)
    if member is None:
        raise ValueError("local identity is not a workspace member")
    with node.lock:
        facts = closer(node, workspace, {sig.fid: sig, item.fid: item},
                       {item.fid: [sig.fid, member], sig.fid: []})
    blob = canon({"pile": [fact.to_json() for fact in facts],
                  "isk": invite_sk.encode().hex(), "ws": workspace})
    node.store(workspace).put("invite/" + kdf(seed, "id").hex(),
                              box_encrypt(kdf(seed, "key"), blob))
    return base64.urlsafe_b64encode(
        canon({"u": node.url, "ws": workspace, "s": seed.hex()})).decode()


# QUERIES — none; invite ids deliberately cannot be listed.
