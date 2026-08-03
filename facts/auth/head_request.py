"""facts/auth/head_request.py — an exact writer-head update request."""
from core.fact import Fact, Need
from core.shape import valid_fid
from .._policy import FamilyPolicy

TAG = "head_request"
POLICY = FamilyPolicy()


# SHAPE
def head_request(workspace, device, owner, base_head, head, exp, ts):
    return Fact(
        TAG,
        ts,
        [],
        {
            "base_head": "" if base_head is None else base_head,
            "device": device,
            "exp": exp,
            "head": head,
            "owner": owner,
        },
        workspace,
    )


# NEEDS
def needs(f):
    body = f.body
    device = body.get("device", "")
    owner = body.get("owner", "")
    direct = (
        Need("author", "author", f.fid, device),
        Need("member", "member", device, owner),
    )
    return direct if device == owner else direct + (
        Need("device", "device_key", device, owner),)


# VALIDATE
def validate(f, _ctx):
    try:
        body = f.body
        return set(body) == {
                "base_head", "device", "exp", "head", "owner"} \
            and all(valid_fid(body[key]) for key in (
                "device", "head", "owner")) \
            and (body["base_head"] == ""
                 or valid_fid(body["base_head"])) \
            and type(body["exp"]) is int \
            and f == head_request(
                f.ws,
                body["device"],
                body["owner"],
                body["base_head"] or None,
                body["head"],
                body["exp"],
                f.ts,
            )
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = False


# COMMANDS — proof construction belongs to the writer client composition.


# QUERIES — the gate asks the family to interpret one kernel-minted receipt.
def authorize_head(view, valid, stream, writer, proposed_head, trusted_now):
    """Authorize the exact request against pinned current authority state."""
    body = valid.fact.body
    if valid.fact.t != TAG or writer != body["device"] \
            or proposed_head != body["head"] \
            or body["exp"] < trusted_now:
        return None
    expected = {"author", "member"}
    if body["device"] != body["owner"]:
        expected.add("device")
    edges = {edge.role: edge.fid for edge in valid.edges}
    if set(edges) != expected:
        return None
    supplied = {fact.fid: fact for fact in stream}
    required = {
        "member": ("member", body["device"], body["owner"]),
    }
    if body["device"] != body["owner"]:
        required["device"] = (
            "device_key", body["device"], body["owner"])
    for role, offer in required.items():
        provider = supplied.get(edges[role])
        if provider is None or offer not in provider.offers():
            return None
        try:
            current = view.fact_of(provider.fid)
        except ValueError:
            return None
        if current != provider or not view.fact_active(provider.fid):
            return None
    return (
        body["device"],
        body["owner"],
        body["base_head"] or None,
    )
