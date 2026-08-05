"""facts/auth/request.py — device-signed lookup or admission request."""

from core.fact import Fact
from core.shape import valid_fid
from .._policy import FamilyPolicy
from . import _access, signature
from ._proof import historical_owner, identity_closure


TAG = "req"
POLICY = FamilyPolicy()
PURPOSES = frozenset({"sync"})


# SHAPE
def request(workspace, device, owner, verb, exp, basis, ts):
    return Fact(
        TAG, ts, [],
        {
            "device": device,
            "owner": owner,
            "verb": verb,
            "exp": exp,
            "basis": basis,
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
        return set(body) == {"basis", "device", "owner", "verb", "exp"} \
            and valid_fid(body["device"]) \
            and valid_fid(body["owner"]) \
            and (body["basis"] == "" or valid_fid(body["basis"])) \
            and isinstance(body["verb"], str) and body["verb"] \
            and type(body["exp"]) is int \
            and fact == request(
                fact.ws, body["device"], body["owner"], body["verb"],
                body["exp"], body["basis"], fact.ts)
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = False


# COMMANDS
def payload(
        node, workspace, verb, exp, ts, *, basis="", admission=False,
        closures=()):
    secret, device = node.identity(workspace)
    owner = historical_owner(node, workspace, device)
    item = request(
        workspace, device, owner, verb, exp, basis, ts)
    if not admission:
        return (item,)
    signed = signature.signature(secret, device, item, ts)
    return identity_closure(
        node, workspace, item, signed, closures=closures)


PROOF_COMMANDS = {purpose: payload for purpose in PURPOSES}


# QUERIES
def lookup(fact, writer, trusted_now, *, purpose="sync", proposed_head=None):
    """Read the outer-device-bound request without evaluating its chain."""
    body = fact.body
    if fact.t != TAG or writer != body["device"] \
            or purpose not in PURPOSES or body["verb"] != purpose \
            or body["exp"] < trusted_now or proposed_head is not None:
        return None
    return _access.lookup_claim(body["device"], body["owner"]), \
        body["basis"], body["verb"]


def authorize_admission(
        valid, stream, trusted_now, *, purpose="sync", writer=None):
    """Evaluate the positive chain only while creating an UNKNOWN row."""
    body = valid.fact.body
    if valid.fact.t != TAG or purpose not in PURPOSES \
            or body["verb"] != purpose or body["exp"] < trusted_now:
        return None
    identity = _access.claim(valid, stream, writer)
    return None if identity is None else (identity, body["verb"])
