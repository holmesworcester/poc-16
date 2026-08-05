"""facts/auth/user_invite.py — a member-signed bearer invitation.

Any existing workspace member, including the founder member established by
the workspace fact, may invite a user. This is the poc-13 authority rule on
the poc-10/poc-16 offers-and-needs kernel.
"""
import base64
import os
import zlib

from core.crypto import box_encrypt, kdf, keypair
from core.fact import Fact, Need, canon
from core.limits import (
    MAX_INVITE_ARTIFACT_BYTES,
    MAX_INVITE_BYTES,
    MAX_INVITE_LINK_BYTES,
    PayloadTooLarge,
    decode_json,
)
from .._commands import offer_source
from .._policy import FamilyPolicy
from . import signature

TAG = "user_invite"
POLICY = FamilyPolicy(control_fact=True)
ARTIFACT_MAGIC = b"P16I2\0"
BLOB_MAGIC = b"P16B2\0"
ARTIFACT_FIXED_BYTES = len(ARTIFACT_MAGIC) + 32 + 2
BLOB_FIXED_BYTES = len(BLOB_MAGIC) + 32 + 32


def _encode_artifact(seed, peer, encrypted):
    if not isinstance(seed, bytes) or len(seed) != 32 \
            or not isinstance(encrypted, bytes):
        raise ValueError("invite artifact")
    peer_raw = canon(peer)
    if len(peer_raw) > 0xffff:
        raise PayloadTooLarge("invite peer too large")
    artifact = b"".join((
        ARTIFACT_MAGIC,
        seed,
        len(peer_raw).to_bytes(2, "big"),
        peer_raw,
        encrypted,
    ))
    if len(artifact) > MAX_INVITE_ARTIFACT_BYTES:
        raise PayloadTooLarge("invite artifact too large")
    link = base64.urlsafe_b64encode(artifact).decode()
    if len(link) > MAX_INVITE_LINK_BYTES:
        raise PayloadTooLarge("invite link too large")
    return link


def decode_artifact(link):
    """Decode one canonical QR/link frame without opening its ciphertext."""
    if not isinstance(link, str):
        raise ValueError("invite link")
    try:
        encoded = link.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("invite link") from error
    if len(encoded) > MAX_INVITE_LINK_BYTES:
        raise PayloadTooLarge("invite link too large")
    try:
        artifact = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("invite link") from error
    if len(artifact) > MAX_INVITE_ARTIFACT_BYTES:
        raise PayloadTooLarge("invite artifact too large")
    if base64.urlsafe_b64encode(artifact) != encoded \
            or len(artifact) < ARTIFACT_FIXED_BYTES + 1 \
            or not artifact.startswith(ARTIFACT_MAGIC):
        raise ValueError("invite link")
    offset = len(ARTIFACT_MAGIC)
    seed = artifact[offset:offset + 32]
    offset += 32
    peer_size = int.from_bytes(artifact[offset:offset + 2], "big")
    offset += 2
    peer_stop = offset + peer_size
    if peer_stop >= len(artifact):
        raise ValueError("invite link")
    peer_raw = artifact[offset:peer_stop]
    peer = decode_json(peer_raw, peer_size, "invite peer")
    if canon(peer) != peer_raw:
        raise ValueError("invite link")
    return seed, peer, artifact[peer_stop:]


def encode_blob(workspace, invite_sk, pile):
    """Compress the exact closure before authenticated encryption."""
    try:
        workspace_raw = bytes.fromhex(workspace)
    except (TypeError, ValueError) as error:
        raise ValueError("invite workspace") from error
    if len(workspace_raw) != 32 or not isinstance(pile, bytes):
        raise ValueError("invite blob")
    return zlib.compress(b"".join((
        BLOB_MAGIC, workspace_raw, invite_sk.encode(), pile,
    )), level=9)


def decode_blob(compressed):
    """Open one bounded canonical compressed invite payload."""
    if not isinstance(compressed, bytes):
        raise ValueError("invite blob")
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(compressed, MAX_INVITE_BYTES + 1)
    except zlib.error as error:
        raise ValueError("invite compression") from error
    if len(raw) > MAX_INVITE_BYTES:
        raise PayloadTooLarge("invite plaintext too large")
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail \
            or len(raw) < BLOB_FIXED_BYTES + 1 \
            or not raw.startswith(BLOB_MAGIC):
        raise ValueError("invite compression")
    offset = len(BLOB_MAGIC)
    workspace = raw[offset:offset + 32].hex()
    offset += 32
    invite_secret = raw[offset:offset + 32].hex()
    offset += 32
    return workspace, invite_secret, raw[offset:]


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
    blob = encode_blob(workspace, invite_sk, pile)
    encrypted = box_encrypt(kdf(seed, "key"), blob)
    if len(encrypted) > MAX_INVITE_BYTES:
        raise PayloadTooLarge("invite too large")
    return _encode_artifact(seed, peer, encrypted)


# QUERIES — none; the store never receives a recipient-addressed artifact.
CLI = {"auth.user_invite.create": make}
