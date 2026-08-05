"""facts/auth/service_binding.py — workspace-approved service capability."""

from core.crypto import h
from core.fact import Fact, Need, canon
from core.limits import MAX_ATOM_VALUE_BYTES, valid_bounded_text
from core.shape import valid_fid
from .._commands import member_source, offer_source, publish
from .._identity import actor_needs
from .._policy import DELETE_SELF, FamilyPolicy, Self, author_selectors
from . import signature


TAG = "service_binding"
OFFER = "service.binding"
PROVIDERS = frozenset(("aws", "cloudflare"))
POLICY = FamilyPolicy(
    control_fact=True,
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_field="owner",
    authority_liveness_guards=("member", "service_member"),
)


# SHAPE
def binding_cell(operations, provider, capability, owner):
    if not valid_fid(operations) or not valid_fid(owner) \
            or provider not in PROVIDERS \
            or not valid_bounded_text(capability, MAX_ATOM_VALUE_BYTES):
        raise ValueError("service binding address")
    return h(canon([
        "poc16-service-binding-v1",
        operations,
        provider,
        capability,
        owner,
    ]))


def service_binding(
        workspace, pk, administrator, owner, operations, provider,
        capability, ts):
    if not all(valid_fid(value) for value in (
            workspace, pk, administrator, owner, operations)) \
            or workspace == operations:
        raise ValueError("service binding workspace")
    cell = binding_cell(operations, provider, capability, owner)
    return Fact(
        TAG,
        ts,
        author_selectors(POLICY, {}) + [
            ["offer", OFFER, owner, cell],
        ],
        {
            "administrator": administrator,
            "capability": capability,
            "operations": operations,
            "owner": owner,
            "pk": pk,
            "provider": provider,
        },
        workspace,
    )


# NEEDS
def needs(fact):
    body = fact.body
    pk = body.get("pk", "")
    administrator = body.get("administrator", "")
    owner = body.get("owner", "")
    return actor_needs(fact, pk, administrator) + (
        Need("administrator", "admin", administrator),
        Need("service_member", "member", owner, owner),
    )


# VALIDATE
def validate(fact, _context):
    try:
        body = fact.body
        return set(body) == {
            "administrator", "capability", "operations", "owner", "pk",
            "provider",
        } and fact == service_binding(
            fact.ws,
            body["pk"],
            body["administrator"],
            body["owner"],
            body["operations"],
            body["provider"],
            body["capability"],
            fact.ts,
        )
    except (KeyError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def bind(node, workspace, owner, operations, provider, capability):
    secret, public = node.identity(workspace)
    member, administrator = member_source(node, workspace, public)
    if member is None or offer_source(
            node, workspace, "admin", administrator) is None \
            or offer_source(
                node, workspace, "member", owner, owner) is None:
        raise ValueError("service binding requires an admin and live service")
    timestamp = node.now_ms()
    item = service_binding(
        workspace,
        public,
        administrator,
        owner,
        operations,
        provider,
        capability,
        timestamp,
    )
    signed = signature.signature(secret, public, item, timestamp)
    return publish(node, workspace, item, signed)


# QUERIES
def bindings(node, workspace, operations=None):
    return [
        {"fid": fact.fid, **fact.body}
        for fact in node.by_type(workspace, TAG)
        if operations is None or fact.body["operations"] == operations
    ]


def leave(node, workspace, binding):
    from ..content import delete

    return delete.remove(node, workspace, binding)


CLI = {
    "auth.service.bind": bind,
    "auth.service.leave": leave,
    "auth.service.list": bindings,
}
