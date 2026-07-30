"""facts/auth/device_invite.py — a one-step direct-key device grant.

A device-set peer names a known sibling key and immediately declares it both a
device and workspace member. There is no bearer secret or follow-up join; the
poc-13 two-family flow collapses to the direct-key form settled for poc-16.
"""
from core.fact import Fact, Need
from .._policy import FamilyPolicy, Self, SidOffer, author_selectors
from .._commands import offer_source
from . import signature

TAG = "device_invite"
POLICY = FamilyPolicy(
    suppression=(Self(),),
    authority_liveness_guards=("member", "device"),
    principal_offers=(
        SidOffer("member", "member"),
        SidOffer("device_key", "device"),
    ),
)


# SHAPE
def device_invite(workspace, pk, user, device_pk, label, ts):
    if pk == device_pk:
        raise ValueError("a device grant must target another key")
    return Fact(
        TAG, ts,
        author_selectors(POLICY, {}) + [
         ["offer", "member", device_pk],
         ["offer", "device_key", device_pk],
         ["offer", "device", user, device_pk]],
        {"pk": pk, "user": user, "device": device_pk, "label": label},
        workspace)


# NEEDS
def needs(f):
    body = f.body
    signer = body.get("pk", "")
    user = body.get("user", "")
    return (
        Need("author", "author", f.fid, signer),
        Need("member", "member", signer),
        Need(
            "device", "device_key", signer, None,
            (("device", user, signer),),
        ),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "user", "device", "label"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == device_invite(
                f.ws, body["pk"], body["user"], body["device"],
                body["label"], f.ts)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS — build a fact, admit it, stop.
def grant(node, workspace, user, device_pk, label):
    """Idempotently fill one ``(workspace, admitting key, device)`` cell."""
    with node.lock:
        secret, public = node.identity(workspace)
        member = offer_source(node, workspace, "member", public)
        device_source = offer_source(
            node, workspace, "device_key", public,
            requires=(("device", user, public),))
        if member is None or device_source is None:
            raise ValueError("local identity is not a device-set member")
        # Timestamps order facts but do not establish causality. Reuse the
        # immutable workspace anchor's timestamp so this logical grant has
        # stable bytes even if an authority proof winner later changes;
        # refs/needs and close() carry the actual relation.
        ts = node.fact_of(workspace, workspace).ts
        item = device_invite(
            workspace, public, user, device_pk, label, ts)
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
        node.ingest_new(workspace, [signed, item], deps)
        return item.fid


# QUERIES — device roster observations belong to auth.device.devices.
