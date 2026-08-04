"""facts/auth/device_removal.py — removal of one enrolled device key.

Device authority is an ordinary fact relation: a direct member owns itself,
and ``device_invite`` offers ``device_key(device, owner)`` for a secondary
device. This action names that exact relation as a Need and activates the
target's ``device:<pk>`` suppression ID. Core therefore needs no device-role
table or special authorization branch.
"""

from core.fact import Fact, Need
from core.shape import valid_fid
from .._commands import member_source, offer_source, publish
from .._identity import actor_needs
from .._policy import ADMIN, OWNER, FamilyPolicy, SidOffer
from . import signature
from .device import devices


TAG = "device_removal"
POLICY = FamilyPolicy(
    control_fact=True,
    action_offers=(SidOffer("removed", "device"),),
)


# SHAPE
def device_removal(
        workspace, pk, target, owner, mode, ts, actor=None):
    actor = pk if actor is None else actor
    return Fact(
        TAG,
        ts,
        [["offer", "removed", target]],
        {"actor": actor, "mode": mode, "owner": owner, "pk": pk},
        workspace,
    )


# NEEDS — OWNER and ADMIN are explicit alternative authority modes.
def needs(fact):
    body = fact.body
    pk = body.get("pk", "")
    actor = body.get("actor", "")
    owner = body.get("owner", "")
    offers = fact.offers()
    target = offers[0][1] if len(offers) == 1 \
        and offers[0][0] == "removed" \
        and offers[0][2] == "" else ""
    required = actor_needs(fact, pk, actor)
    if body.get("mode") == ADMIN:
        required += (Need("actor_admin", "admin", actor),)
    return required + (
        Need("target_device", "device_key", target, owner),
    )


# VALIDATE
def validate(fact, _ctx):
    try:
        body = fact.body
        if set(body) != {"actor", "mode", "owner", "pk"} \
                or len(fact.offers()) != 1:
            return False
        name, target, empty = fact.offers()[0]
        pk, actor = body["pk"], body["actor"]
        owner, mode = body["owner"], body["mode"]
        return name == "removed" and empty == "" \
            and all(valid_fid(value) for value in (
                pk, actor, owner, target)) \
            and mode in {OWNER, ADMIN} \
            and (mode != OWNER or actor == owner) \
            and fact == device_removal(
                fact.ws, pk, target, owner, mode, fact.ts, actor)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


def _device_owner(node, workspace, target):
    roster = devices(node, workspace)
    exact = [row for row in roster if row["pk"] == target]
    if len(exact) > 1:
        raise ValueError("device has ambiguous ownership")
    if exact:
        return exact[0]["pk"], exact[0]["user"]
    named = [row for row in roster if row["label"] == target]
    if not named:
        raise ValueError(f"no device {target!r}")
    if len(named) != 1:
        raise ValueError(f"ambiguous device label {target!r}")
    return named[0]["pk"], named[0]["user"]


# COMMANDS
def remove(node, workspace, target):
    """Remove a device by exact public key or unique current label."""
    target_pk, target_owner = _device_owner(node, workspace, target)
    secret, public = node.identity(workspace)
    actor_member, actor = member_source(node, workspace, public)
    if actor_member is None:
        raise ValueError("publishing device is not owned by a member")
    mode = OWNER if actor == target_owner else ADMIN
    if mode == ADMIN and offer_source(
            node, workspace, "admin", actor) is None:
        raise ValueError("only the device owner or an admin may remove it")
    ts = node.now_ms()
    item = device_removal(
        workspace,
        public,
        target_pk,
        target_owner,
        mode,
        ts,
        actor,
    )
    signed = signature.signature(secret, public, item, ts)
    return publish(node, workspace, item, signed)


# QUERIES — device visibility remains owned by auth.device.devices.
CLI = {"auth.device_removal.remove": remove}
