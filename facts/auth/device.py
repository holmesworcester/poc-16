"""facts/auth/device.py — a member's self-bound primary device.

An enrolled member may bind its own signing key into a flat device set. This
is the poc-13 device authority edge with poc-10 transport atoms omitted; all
devices are equal peers and the fact carries no endpoint policy.
"""
from core.fact import Fact, Need
from .._policy import FamilyPolicy, Self, SidOffer, author_selectors
from .._commands import offer_source, publish
from . import signature

TAG = "device"
POLICY = FamilyPolicy(
    suppression=(Self(),),
    authority_liveness_guards=("member",),
    principal_offers=(SidOffer("device_key", "device"),),
)


# SHAPE
def device(workspace, pk, label, ts):
    return Fact(
        TAG, ts,
        author_selectors(POLICY, {}) + [
         ["offer", "device_key", pk],
         ["offer", "device", pk, pk]],
        {"pk": pk, "label": label}, workspace)


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
        body = f.body
        return set(body) == {"pk", "label"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == device(f.ws, body["pk"], body["label"], f.ts)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS — build a fact, admit it, stop.
def bind(node, workspace, label):
    from core.node import now_ms

    secret, public = node.identity(workspace)
    if offer_source(
            node, workspace, "device_key", public) is not None:
        raise ValueError("local identity is already in a device set")
    ts = now_ms()
    item = device(workspace, public, label, ts)
    return publish(
        node, workspace, item,
        signature.signature(secret, public, item, ts))


# QUERIES
def devices(node, workspace, user=None):
    with node.lock:
        chosen = {}
        for rank, fact in node.select_ranked(workspace, "device"):
            body = fact.body
            if fact.t == TAG:
                row = body.get("pk"), body.get("pk"), body.get("label")
            elif fact.t == "device_invite":
                row = (
                    body.get("user"), body.get("device"), body.get("label"))
            else:
                continue
            user_pk, device_pk, label = row
            choice = (rank, fact.fid)
            if device_pk and label and (
                    device_pk not in chosen
                    or choice < chosen[device_pk][0]):
                chosen[device_pk] = (choice, user_pk, label)
        rows = [
            (user_pk, device_pk, label)
            for device_pk, (_, user_pk, label) in chosen.items()
            if user is None or user_pk == user
        ]
    return [
        {"user": user_pk, "pk": device_pk, "label": label}
        for user_pk, device_pk, label in sorted(rows)
    ]
