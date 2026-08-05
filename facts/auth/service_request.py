"""facts/auth/service_request.py — exact ephemeral service-bound request."""

import facts

from core.fact import Fact, Need
from core.limits import MAX_REMOVAL_PATH_SCOPES, PayloadTooLarge
from core.shape import valid_fid
from core.suppression import scoped_id
from .._policy import FamilyPolicy, Parent, author_selectors
from . import _access, service_binding, signature
from ._proof import historical_owner, identity_closure


TAG = "service_req"
PURPOSE = "service-binding"
POLICY = FamilyPolicy(suppression=(Parent("binding"),))


# SHAPE
def service_request(
        workspace, device, owner, binding, operations, provider, capability,
        cell, exp, basis, ts):
    if not all(valid_fid(value) for value in (
            workspace, device, owner, binding, operations, cell)) \
            or basis and not valid_fid(basis):
        raise ValueError("service request binding")
    if service_binding.binding_cell(
            operations, provider, capability, owner) != cell:
        raise ValueError("service request cell")
    return Fact(
        TAG,
        ts,
        author_selectors(POLICY, {"binding": binding}),
        {
            "basis": basis,
            "binding": binding,
            "capability": capability,
            "cell": cell,
            "device": device,
            "exp": exp,
            "operations": operations,
            "owner": owner,
            "provider": provider,
        },
        workspace,
    )


# NEEDS
def needs(fact):
    body = fact.body
    return _access.needs(fact) + (
        Need(
            "binding",
            service_binding.OFFER,
            body.get("owner", ""),
            body.get("cell", ""),
        ),
    )


# VALIDATE
def validate(fact, _context):
    try:
        body = fact.body
        return set(body) == {
            "basis", "binding", "capability", "cell", "device", "exp",
            "operations", "owner", "provider",
        } and not fact.refs() and type(body["exp"]) is int \
            and service_binding.binding_cell(
                body["operations"], body["provider"], body["capability"],
                body["owner"]) == body["cell"] \
            and fact == service_request(
                fact.ws,
                body["device"],
                body["owner"],
                body["binding"],
                body["operations"],
                body["provider"],
                body["capability"],
                body["cell"],
                body["exp"],
                body["basis"],
                fact.ts,
            )
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = False


# COMMANDS
def payload(
        node, workspace, _purpose, exp, ts, *, binding, basis="",
        admission=False, closures=()):
    secret, device = node.identity(workspace)
    owner = historical_owner(node, workspace, device)
    selected = node.fact_of(workspace, binding)
    if selected is None or selected.t != service_binding.TAG \
            or selected.body.get("owner") != owner:
        raise ValueError("service binding proof")
    cell = service_binding.binding_cell(
        selected.body["operations"],
        selected.body["provider"],
        selected.body["capability"],
        owner,
    )
    item = service_request(
        workspace, device, owner, binding,
        selected.body["operations"],
        selected.body["provider"],
        selected.body["capability"],
        cell, exp, basis, ts)
    if not admission:
        return (item,)
    signed = signature.signature(secret, device, item, ts)
    return identity_closure(
        node, workspace, item, signed, closures=closures)


PROOF_COMMANDS = {PURPOSE: payload}


# QUERIES
def _claim(
        workspace, device, owner, binding, operations, provider, capability,
        cell):
    identity = _access.lookup_claim(device, owner)
    shaped = service_request(
        workspace, device, owner, binding,
        operations, provider, capability, cell, 0, "", 0)
    scopes = tuple(sorted(
        set(identity.scopes)
        | facts.fact_scopes(shaped)
        | {scoped_id("service-binding", cell)}
    ))
    if len(scopes) > MAX_REMOVAL_PATH_SCOPES:
        raise PayloadTooLarge("service identity has too many removal scopes")
    return identity._replace(scopes=scopes)


def lookup(fact, writer, trusted_now, *, purpose=None, proposed_head=None):
    body = fact.body
    if purpose != PURPOSE or proposed_head is not None \
            or writer != body["device"] or body["exp"] < trusted_now:
        return None
    return _claim(
        fact.ws,
        body["device"],
        body["owner"],
        body["binding"],
        body["operations"],
        body["provider"],
        body["capability"],
        body["cell"],
    ), body["basis"], PURPOSE


def authorize_admission(
        valid, stream, trusted_now, *, purpose, writer=None):
    body = valid.fact.body
    if purpose != PURPOSE or body["exp"] < trusted_now:
        return None
    identity = _access.claim(
        valid, stream, writer, extra_roles=("binding",))
    edges = {edge.role: edge.fid for edge in valid.edges}
    supplied = {fact.fid: fact for fact in stream}
    binding = supplied.get(edges.get("binding"))
    if identity is None or binding is None \
            or binding.t != service_binding.TAG \
            or binding.fid != body["binding"] \
            or binding.body.get("owner") != identity.owner \
            or service_binding.binding_cell(
                binding.body.get("operations"),
                binding.body.get("provider"),
                binding.body.get("capability"),
                identity.owner,
            ) != body["cell"]:
        return None
    return _claim(
        valid.fact.ws,
        identity.device,
        identity.owner,
        binding.fid,
        binding.body["operations"],
        binding.body["provider"],
        binding.body["capability"],
        body["cell"],
    ), PURPOSE
