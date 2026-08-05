"""facts/auth/head_request.py — device-signed exact writer-head lookup."""

from core.fact import Fact
from core.shape import valid_fid
from .._policy import FamilyPolicy
from . import _access


TAG = "head_request"
POLICY = FamilyPolicy()


# SHAPE
def head_request(
        workspace, device, owner, base_head, head, exp, basis, ts):
    return Fact(
        TAG, ts, [],
        {
            "base_head": "" if base_head is None else base_head,
            "basis": basis,
            "device": device,
            "exp": exp,
            "head": head,
            "owner": owner,
        },
        workspace,
    )


# NEEDS
def needs(fact):
    return _access.needs(fact)


# VALIDATE
def validate(fact, _ctx):
    try:
        body = fact.body
        return set(body) == {
                "base_head", "basis", "device", "exp", "head", "owner"} \
            and all(valid_fid(body[key]) for key in (
                "device", "head", "owner")) \
            and (body["base_head"] == "" or valid_fid(body["base_head"])) \
            and (body["basis"] == "" or valid_fid(body["basis"])) \
            and type(body["exp"]) is int \
            and fact == head_request(
                fact.ws, body["device"], body["owner"],
                body["base_head"] or None, body["head"], body["exp"],
                body["basis"], fact.ts)
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = False


# COMMANDS
def payload(
        node, workspace, owner, base_head, head, exp, basis, ts,
        *, closures=()):
    """Build the minimal outer-device-signed exact-head request."""
    _secret, device = node.identity(workspace)
    item = head_request(
        workspace, device, owner, base_head, head, exp, basis, ts)
    return (item,)


# QUERIES
def lookup(fact, writer, trusted_now, *, purpose=None, proposed_head=None):
    body = fact.body
    if fact.t != TAG or writer != body["device"] \
            or proposed_head != body["head"] or body["exp"] < trusted_now:
        return None
    return (
        _access.lookup_claim(body["device"], body["owner"]),
        body["basis"],
        body["base_head"] or None,
    )
