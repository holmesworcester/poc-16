"""The one executable policy registry for every fact family.

Handlers own shape-specific validation.  This module owns the cross-family
rules that must not be inferred from arbitrary refs or fields: named
dependency roles, suppression inheritance, direct action targets, ownership,
one-time authorization guards, and continuing authority liveness.
"""
from dataclasses import dataclass

from core.suppression import (
    ANCESTOR,
    PARENT,
    SELF,
    ancestor_selector,
    parent_selector,
    selector_markers,
    self_selector,
)

NEVER = None
OWNER = "owner"
ADMIN = "admin"
CONTENT_DELETE = "content.delete"


@dataclass(frozen=True)
class SelectorRule:
    kind: str
    path: tuple[str, ...] = ()


def Self():
    return SelectorRule(SELF)


def Parent(role):
    return SelectorRule(PARENT, (role,))


def Ancestor(*path):
    if len(path) < 2:
        raise ValueError("an ancestor path needs at least two roles")
    return SelectorRule(ANCESTOR, tuple(path))


@dataclass(frozen=True)
class DirectTarget:
    action: str
    selector: str
    modes: tuple[str, ...]


@dataclass(frozen=True)
class FamilyPolicy:
    ref_roles: tuple[str, ...] = ()
    need_roles: tuple[str, ...] = ()
    suppression: tuple[SelectorRule, ...] | None = NEVER
    direct_targets: tuple[DirectTarget, ...] = ()
    owner_edge: str | None = None
    authorization_guards: tuple[str, ...] = ()
    authority_liveness_guards: tuple[str, ...] = ()


DELETE_SELF = (
    DirectTarget(CONTENT_DELETE, SELF, (OWNER, ADMIN)),
)

# This table is intentionally keyed by wire tag rather than importing handler
# modules.  facts.__init__ checks exact coverage after the router is assembled.
POLICIES = {
    "workspace": FamilyPolicy(),
    "signature": FamilyPolicy(),
    "user_invite": FamilyPolicy(
        need_roles=("author", "member"),
        authorization_guards=("member",),
    ),
    "user": FamilyPolicy(
        ref_roles=("invite",),
        need_roles=("author",),
        suppression=(Self(),),
    ),
    "admin": FamilyPolicy(
        need_roles=("author", "grantor_admin", "grantee_member"),
        authorization_guards=("grantor_admin",),
        # A committed delegated-admin offer lives exactly as long as its
        # grantee membership.  Grantor authority is an admission-time guard,
        # not ambient liveness inherited from the whole proof closure.
        authority_liveness_guards=("grantee_member",),
    ),
    "device": FamilyPolicy(
        need_roles=("author", "member"),
        suppression=(Self(),),
        authorization_guards=("member",),
        authority_liveness_guards=("member",),
    ),
    "device_invite": FamilyPolicy(
        need_roles=("author", "member", "device"),
        suppression=(Self(),),
        authorization_guards=("member", "device"),
        authority_liveness_guards=("member", "device"),
    ),
    "evict": FamilyPolicy(
        need_roles=("author", "admin"),
        authorization_guards=("admin",),
    ),
    "req": FamilyPolicy(
        need_roles=("author", "member"),
        authorization_guards=("member",),
    ),
    "msg": FamilyPolicy(
        need_roles=("author", "member"),
        suppression=(Self(),),
        direct_targets=DELETE_SELF,
        owner_edge="member",
        authorization_guards=("member",),
    ),
    "file_bao": FamilyPolicy(
        need_roles=("author", "member"),
        suppression=(Self(), Parent("member")),
        direct_targets=DELETE_SELF,
        owner_edge="member",
        authorization_guards=("member",),
    ),
    "chunk": FamilyPolicy(
        ref_roles=("file",),
        need_roles=("author", "member"),
        suppression=(
            Self(),
            Parent("file"),
            Ancestor("file", "member"),
        ),
        direct_targets=DELETE_SELF,
        owner_edge="member",
        authorization_guards=("member",),
    ),
    "delete": FamilyPolicy(
        ref_roles=("target",),
        need_roles=("author", "actor_authority"),
        authorization_guards=("actor_authority",),
    ),
}


def policy_for(tag):
    return POLICIES.get(tag)


def _edge_map(edges):
    out = {}
    for edge in edges:
        if edge.role in out:
            raise ValueError(f"duplicate dependency role {edge.role!r}")
        out[edge.role] = edge.fid
    return out


def _follow(ctx, edges, path):
    current = _edge_map(edges).get(path[0])
    if current is None:
        raise ValueError(f"missing dependency role {path[0]!r}")
    for role in path[1:]:
        current = ctx.edge_source(current, role)
        if current is None:
            raise ValueError(f"missing dependency path {'/'.join(path)!r}")
    return current


def expected_selectors(tag, edges, ctx):
    """Canonical selector atoms independently recomputed at admission."""
    policy = policy_for(tag)
    if policy is None:
        return None
    if policy.suppression is NEVER:
        return ()
    direct = _edge_map(edges)
    out = []
    for rule in policy.suppression:
        if rule.kind == SELF:
            out.append(self_selector())
        elif rule.kind == PARENT:
            fid = direct.get(rule.path[0])
            if fid is None:
                raise ValueError(f"missing dependency role {rule.path[0]!r}")
            out.append(parent_selector(rule.path[0], fid))
        elif rule.kind == ANCESTOR:
            out.append(ancestor_selector("/".join(rule.path),
                                         _follow(ctx, edges, rule.path)))
        else:
            raise ValueError("unknown selector policy")
    return tuple(out)


def author_selectors(tag, edges):
    """Build the selector atoms an honest family constructor must serialize.

    ``edges`` maps a direct role (``member`` or ``file``) and, for an
    ancestor, its slash-separated path (``file/member``) to exact fids.
    Admission still derives these values independently.
    """
    policy = POLICIES[tag]
    if policy.suppression is NEVER:
        return []
    out = []
    for rule in policy.suppression:
        path = "/".join(rule.path)
        if rule.kind == SELF:
            out.append(self_selector())
        elif rule.kind == PARENT:
            out.append(parent_selector(path, edges[path]))
        elif rule.kind == ANCESTOR:
            out.append(ancestor_selector(path, edges[path]))
    return out


def validate_fact_policy(fact, edges, ctx):
    policy = policy_for(fact.t)
    if policy is None:
        return True  # test-only/extension families keep their own contract
    try:
        return tuple(selector_markers(fact)) == expected_selectors(
            fact.t, edges, ctx)
    except (KeyError, TypeError, ValueError):
        return False


def allows_direct_target(target_tag, action, selector, mode):
    policy = policy_for(target_tag)
    return policy is not None and any(
        row.action == action
        and row.selector == selector
        and mode in row.modes
        for row in policy.direct_targets
    )


def member_principal(db_or_ctx, provider_fid, actor_key):
    """Derive the durable owner principal of one exact member provider.

    Direct membership owns itself.  A device_invite also offers
    ``device(owner, device_key)``; that authenticated offer makes every
    device in the set share the owner's principal without trusting a field
    supplied by a delete proposal.
    """
    offers_from = db_or_ctx.offers_from if hasattr(db_or_ctx, "offers_from") \
        else lambda source, name: db_or_ctx.execute(
            "SELECT a0, a1 FROM offers WHERE src=? AND name=? "
            "ORDER BY a0, a1", (source, name)).fetchall()
    members = offers_from(provider_fid, "member")
    if (actor_key, "") not in members:
        return None
    owners = {
        owner for owner, device in offers_from(provider_fid, "device")
        if device == actor_key
    }
    if len(owners) > 1:
        return None
    return next(iter(owners), actor_key)
