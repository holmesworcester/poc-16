"""The one executable policy registry for every fact family.

Handlers own shape-specific validation.  This module owns the cross-family
rules that must not be inferred from arbitrary refs or fields: named
dependency roles, suppression inheritance, direct action targets, ownership,
and continuing authority liveness.
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
class SidOffer:
    """An offer whose a0 value reserves or activates a typed suppression id."""

    name: str
    namespace: str


@dataclass(frozen=True)
class FamilyPolicy:
    suppression: tuple[SelectorRule, ...] | None = NEVER
    direct_targets: tuple[DirectTarget, ...] = ()
    owner_field: str | None = None
    authority_liveness_guards: tuple[str, ...] = ()
    principal_offers: tuple[SidOffer, ...] = ()
    action_offers: tuple[SidOffer, ...] = ()


DELETE_SELF = (
    DirectTarget(CONTENT_DELETE, SELF, (OWNER, ADMIN)),
)


def validate_family_policy(policy):
    """Reject registry declarations which violate global authority rules."""
    if not isinstance(policy, FamilyPolicy):
        raise ValueError("family policy type")
    for target in policy.direct_targets:
        if not isinstance(target, DirectTarget):
            raise ValueError("direct target policy")
        if target.action != CONTENT_DELETE:
            continue
        modes = set(target.modes)
        if target.selector != SELF \
                or not target.modes \
                or len(modes) != len(target.modes) \
                or not modes <= {OWNER, ADMIN}:
            raise ValueError("direct deletion policy")
        if ADMIN not in modes:
            raise ValueError("direct deletion must allow ADMIN")
        if OWNER in modes and not policy.owner_field:
            raise ValueError("OWNER deletion needs an owner field")
        self_rules = sum(
            rule == Self()
            for rule in policy.suppression or ()
        )
        if self_rules != 1:
            raise ValueError(
                "direct SELF target needs exactly one Self() "
                "suppression selector")
    return policy


def _edge_map(edges):
    out = {}
    for edge in edges:
        if edge.role in out:
            raise ValueError(f"duplicate dependency role {edge.role!r}")
        out[edge.role] = edge.fid
    return out


def _selectors(policy, resolve):
    if policy.suppression is NEVER:
        return []
    out = []
    for rule in policy.suppression:
        path = "/".join(rule.path)
        if rule.kind == SELF:
            out.append(self_selector())
        elif rule.kind == PARENT:
            out.append(parent_selector(path, resolve(rule.path)))
        elif rule.kind == ANCESTOR:
            out.append(ancestor_selector(path, resolve(rule.path)))
        else:
            raise ValueError("unknown selector policy")
    return out


def expected_selectors(policy, edges, ctx):
    """Canonical selector atoms independently recomputed at admission."""
    direct = _edge_map(edges)

    def resolve(path):
        current = direct.get(path[0])
        if current is None:
            raise ValueError(f"missing dependency role {path[0]!r}")
        for role in path[1:]:
            current = ctx.edge_source(current, role)
            if current is None:
                raise ValueError(f"missing dependency path {'/'.join(path)!r}")
        return current

    return tuple(_selectors(policy, resolve))


def author_selectors(policy, edges):
    """Serialize selectors from constructor-supplied canonical path ids."""
    return _selectors(policy, lambda path: edges["/".join(path)])


def validate_fact_policy(policy, fact, edges, ctx):
    try:
        return tuple(selector_markers(fact)) == expected_selectors(
            policy, edges, ctx)
    except (KeyError, TypeError, ValueError):
        return False


def allows_direct_target(policy, action, selector, mode):
    return any(
        row.action == action
        and row.selector == selector
        and mode in row.modes
        for row in policy.direct_targets
    )


def member_principal(db_or_ctx, provider_fid, actor_key):
    """Read the durable principal from one exact ``member(key, owner)`` offer."""
    offers_from = db_or_ctx.offers_from if hasattr(db_or_ctx, "offers_from") \
        else lambda source, name: db_or_ctx.execute(
            "SELECT k0, k1 FROM fact_index WHERE src=? AND kind=? "
            "ORDER BY k0, k1", (source, name)).fetchall()
    owners = {
        owner
        for key, owner in offers_from(provider_fid, "member")
        if key == actor_key and owner
    }
    return next(iter(owners)) if len(owners) == 1 else None
