"""facts/auth/user_invite.py — a member-signed bearer invitation.

Any existing workspace member, including the founder member established by
the workspace fact, may invite a user. This is the poc-13 authority rule on
the poc-10/poc-16 offers-and-needs kernel.
"""
import base64
import os

from core.crypto import box_encrypt, kdf, keypair
from core.fact import Fact, Need, canon
from core.limits import (
    MAX_INVITE_ARTIFACT_BYTES,
    MAX_INVITE_BYTES,
    MAX_INVITE_LINK_BYTES,
    PayloadTooLarge,
)
from .._commands import offer_source
from .._policy import FamilyPolicy
from . import signature

TAG = "user_invite"
POLICY = FamilyPolicy(control_fact=True)


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
    """Return a bearer artifact carrying the complete signed invite closure."""
    peer = node.advertised_peer()
    seed = os.urandom(32)
    invite_sk, invite_pk = keypair()
    ts = node.now_ms()
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
    encrypted = box_encrypt(kdf(seed, "key"), blob)
    if len(encrypted) > MAX_INVITE_BYTES:
        raise PayloadTooLarge("invite too large")
    artifact = canon({
        "b": base64.b64encode(encrypted).decode(),
        "p": peer,
        "s": seed.hex(),
        "ws": workspace,
    })
    if len(artifact) > MAX_INVITE_ARTIFACT_BYTES:
        raise PayloadTooLarge("invite artifact too large")
    link = base64.urlsafe_b64encode(artifact).decode()
    if len(link) > MAX_INVITE_LINK_BYTES:
        raise PayloadTooLarge("invite link too large")
    return link


# QUERIES — none; the store never receives a recipient-addressed artifact.
CLI = {"auth.user_invite.create": make}
