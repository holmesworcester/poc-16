"""facts/auth/head_request.py — current-proof exact writer-head request."""

import base64

from core.fact import Fact
from core.removal_path import verify_clear
from core.shape import valid_fid
from .._policy import FamilyPolicy
from . import _access, signature
from ._proof import identity_closure


TAG = "head_request"
POLICY = FamilyPolicy()


# SHAPE
def head_request(
        workspace, device, owner, base_head, head, exp, removal_path, ts):
    if not isinstance(removal_path, bytes):
        raise ValueError("removal path bytes")
    return Fact(
        TAG, ts, [],
        {
            "base_head": "" if base_head is None else base_head,
            "device": device,
            "exp": exp,
            "head": head,
            "owner": owner,
            "path": base64.b64encode(removal_path).decode("ascii"),
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
        return set(body) == {
                "base_head", "device", "exp", "head", "owner", "path"} \
            and all(valid_fid(body[key]) for key in (
                "device", "head", "owner")) \
            and (body["base_head"] == "" or valid_fid(body["base_head"])) \
            and type(body["exp"]) is int \
            and fact == head_request(
                fact.ws, body["device"], body["owner"],
                body["base_head"] or None, body["head"], body["exp"],
                path, fact.ts)
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = False


# COMMANDS
def payload(
        node, workspace, owner, base_head, head, exp, removal_path, ts,
        *, closures=()):
    """Build the device-signed current-path head proof closure."""
    secret, device = node.identity(workspace)
    item = head_request(
        workspace, device, owner, base_head, head, exp, removal_path, ts)
    signed = signature.signature(secret, device, item, ts)
    return identity_closure(
        node, workspace, item, signed, closures=closures)


# QUERIES
def authorize_head(view, valid, stream, writer, proposed_head, trusted_now):
    body = valid.fact.body
    if valid.fact.t != TAG or proposed_head != body["head"] \
            or body["exp"] < trusted_now:
        return None
    identity = _access.claim(valid, stream, writer)
    if identity is None:
        return None
    path = base64.b64decode(body["path"], validate=True)
    verify_clear(view, path, identity.scopes)
    return (
        identity.device,
        identity.owner,
        body["base_head"] or None,
        identity.scopes,
    )
