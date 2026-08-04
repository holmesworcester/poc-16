"""facts/auth/device_invite.py — an owner-signed direct-key device grant.

The durable member key names and signs each device it owns. The new device can
then sign live requests itself; sibling devices never acquire ambient power to
assert another device's ownership on the member's behalf.
"""
from core.fact import Fact, Need
from .._policy import FamilyPolicy, Self, SidOffer, author_selectors
from .._commands import offer_source
from . import signature
from ._display import display

TAG = "device_invite"
POLICY = FamilyPolicy(
    authority_resident=True,
    suppression=(Self(),),
    authority_liveness_guards=("member", "device"),
    principal_offers=(
        SidOffer("member", "member"),
        SidOffer("device_key", "device"),
    ),
)


# SHAPE
def device_invite(workspace, user, device_pk, label, ts):
    if user == device_pk:
        raise ValueError("a device grant must target another key")
    label = display(label)
    return Fact(
        TAG, ts,
        author_selectors(POLICY, {}) + [
         ["offer", "member", device_pk, user],
         ["offer", "device_key", device_pk, user],
         ["offer", "device", user, device_pk]],
        {"user": user, "device": device_pk, "label": label},
        workspace)


# NEEDS
def needs(f):
    body = f.body
    user = body.get("user", "")
    return (
        Need("author", "author", f.fid, user),
        Need("member", "member", user, user),
        Need("device", "device_key", user, user),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"user", "device", "label"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == device_invite(
                f.ws, body["user"], body["device"], body["label"], f.ts)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS — build a fact, admit it, stop.
def grant(node, workspace, user, device_pk, label):
    """Idempotently add one device with the owning member's signature."""
    with node.lock:
        secret, public = node.identity(workspace)
        if public != user:
            raise ValueError("only the owning member may grant a device")
        member = offer_source(
            node, workspace, "member", user, user)
        device_source = offer_source(
            node, workspace, "device_key", user, user)
        if member is None or device_source is None:
            raise ValueError("owning member is not an enrolled device")
        # Timestamps order facts but do not establish causality. Reuse the
        # immutable workspace anchor's timestamp so this logical grant has
        # stable bytes even if the current mechanical provider later changes;
        # refs/needs and close() carry the actual relation.
        ts = node.fact_of(workspace, workspace).ts
        item = device_invite(workspace, user, device_pk, label, ts)
        if node.fact_of(workspace, item.fid) is not None:
            return item.fid

        target_member = offer_source(
            node, workspace, "member", device_pk)
        existing = offer_source(
            node, workspace, "device_key", device_pk)
        if target_member is not None or existing is not None:
            raise ValueError("device key is already enrolled")
        signed = signature.signature(secret, public, item, ts)
        deps = {
            item.fid: [signed.fid, member, device_source],
            signed.fid: [],
        }
        node.ingest_new(workspace, [signed, item], deps, owner=user)
        return item.fid


# QUERIES — device roster observations belong to auth.device.devices.
