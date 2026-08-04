"""facts/auth/removal_path_request.py — historical path request."""

from core.fact import Fact
from core.shape import valid_fid
from .._policy import FamilyPolicy
from . import _access, signature
from ._proof import historical_owner, identity_closure


TAG = "removal_path_request"
POLICY = FamilyPolicy()


# SHAPE
def removal_path_request(workspace, device, owner, exp, ts):
    return Fact(
        TAG, ts, [],
        {"device": device, "owner": owner, "exp": exp},
        workspace,
    )


# NEEDS
def needs(fact):
    return _access.needs(fact)


# VALIDATE
def validate(fact, _ctx):
    try:
        body = fact.body
        return set(body) == {"device", "owner", "exp"} \
            and valid_fid(body["device"]) \
            and valid_fid(body["owner"]) \
            and type(body["exp"]) is int \
            and fact == removal_path_request(
                fact.ws, body["device"], body["owner"],
                body["exp"], fact.ts)
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = False


# COMMANDS
def payload(node, workspace, exp, ts, *, owner=None, closures=()):
    """Build the device-signed historical-membership proof closure."""
    secret, device = node.identity(workspace)
    owner = historical_owner(node, workspace, device) \
        if owner is None else owner
    item = removal_path_request(workspace, device, owner, exp, ts)
    signed = signature.signature(secret, device, item, ts)
    return identity_closure(
        node, workspace, item, signed, closures=closures)


# QUERIES
def authorize_path(valid, stream, writer, trusted_now):
    if valid.fact.t != TAG or valid.fact.body["exp"] < trusted_now:
        return None
    return _access.claim(valid, stream, writer)
