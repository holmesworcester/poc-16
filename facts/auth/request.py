"""facts/auth/request.py — current removal-path proof of workspace access."""

import base64

from core.fact import Fact
from core.removal_path import verify_clear
from core.shape import valid_fid
from .._policy import FamilyPolicy
from . import _access, signature
from ._proof import historical_owner, identity_closure


TAG = "req"
POLICY = FamilyPolicy()
PURPOSES = frozenset({"sync"})


# SHAPE
def _encoded_path(raw):
    if not isinstance(raw, bytes):
        raise ValueError("removal path bytes")
    return base64.b64encode(raw).decode("ascii")


def request(workspace, device, owner, verb, exp, removal_path, ts):
    return Fact(
        TAG, ts, [],
        {
            "device": device,
            "owner": owner,
            "verb": verb,
            "exp": exp,
            "path": _encoded_path(removal_path),
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
        path = base64.b64decode(body["path"], validate=True)
        return set(body) == {"device", "owner", "verb", "exp", "path"} \
            and valid_fid(body["device"]) \
            and valid_fid(body["owner"]) \
            and isinstance(body["verb"], str) and body["verb"] \
            and type(body["exp"]) is int \
            and fact == request(
                fact.ws, body["device"], body["owner"], body["verb"],
                body["exp"], path, fact.ts)
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = False


# COMMANDS
def payload(node, workspace, verb, exp, ts, *, removal_path):
    secret, device = node.identity(workspace)
    owner = historical_owner(node, workspace, device)
    item = request(
        workspace, device, owner, verb, exp, removal_path, ts)
    signed = signature.signature(secret, device, item, ts)
    return identity_closure(node, workspace, item, signed)


PROOF_COMMANDS = {purpose: payload for purpose in PURPOSES}


# QUERIES
def authorize(view, valid, stream, trusted_now, *, purpose="sync", writer=None):
    body = valid.fact.body
    if valid.fact.t != TAG or purpose not in PURPOSES \
            or body["verb"] != purpose or body["exp"] < trusted_now:
        return None
    identity = _access.claim(valid, stream, writer)
    if identity is None:
        return None
    path = base64.b64decode(body["path"], validate=True)
    verify_clear(view, path, identity.scopes)
    return identity.device, body["verb"]
