"""facts/auth/user_invite.py — a member-signed bearer invitation.

Any existing workspace member, including the founder member established by
the workspace fact, may invite a user. This is the poc-13 authority rule on
the poc-10/poc-16 offers-and-needs kernel.
"""
import base64
import os

from core.crypto import box_encrypt, kdf, keypair
from core.fact import Fact, Need, canon
from .._commands import offer_source
from .._policy import FamilyPolicy
from . import signature

TAG = "user_invite"
POLICY = FamilyPolicy()


# SHAPE
def user_invite(workspace, pk, invite_pk, ts):
    return Fact(
        TAG, ts, [["offer", "invitee", invite_pk]], {"pk": pk}, workspace)


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk),
    )


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"pk"} or len(f.offers()) != 1:
            return False
        name, invite_pk, empty = f.offers()[0]
        return name == "invitee" and empty == "" \
            and f == user_invite(f.ws, f.body["pk"], invite_pk, f.ts)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# MATERIALIZE — no client read-model rows.


# COMMANDS
def make(node, workspace):
    """Publish a closed invite blob without adding the invitation to the set."""
    from core.node import now_ms

    seed = os.urandom(32)
    invite_sk, invite_pk = keypair()
    ts = now_ms()
    secret, public = node.identity(workspace)
    item = user_invite(workspace, public, invite_pk, ts)
    sig = signature.signature(secret, public, item, ts)
    member = offer_source(node, workspace, "member", public)
    if member is None:
        raise ValueError("local identity is not a workspace member")
    pile = node.sender(workspace).pile(
        [sig, item],
        {item.fid: [sig.fid, member], sig.fid: []},
    )
    blob = canon({"pile": base64.b64encode(pile).decode(),
                  "isk": invite_sk.encode().hex(), "ws": workspace})
    node.store(workspace).put("invite/" + kdf(seed, "id").hex(),
                              box_encrypt(kdf(seed, "key"), blob))
    return base64.urlsafe_b64encode(
        canon({"u": node.url, "ws": workspace, "s": seed.hex()})).decode()


# QUERIES — none; invite ids deliberately cannot be listed.
CLI = {"auth.user_invite.create": make}
