"""The one executable policy registry for every fact family.

Handlers own shape-specific validation.  This module owns the cross-family
rules that must not be inferred from arbitrary refs or fields: named
dependency roles, suppression inheritance, direct action targets, ownership,
and continuing authority liveness.
"""
from dataclasses import dataclass
from typing import Protocol

from core.limits import MAX_ATOM_NAME_BYTES, valid_bounded_text
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


class FactContext(Protocol):
    """The immutable relationship reads shared by families and authoring."""

    anchor: str

    def fact_of(self, fid): ...

    def offers_from(self, source, name): ...

    def resolve_offer(self, name, a0, a1=None, source=None): ...


@dataclass(frozen=True)
class SelectorRule:
    kind: str
    path: tuple[str, ...] = ()
    via_refs: bool = False


def Self():
    return SelectorRule(SELF)


def Parent(role):
    return SelectorRule(PARENT, (role,))


def Ancestor(*path):
    """Declare a suppression path made entirely of immutable named refs."""
    if len(path) < 2:
        raise ValueError("an ancestor path needs at least two roles")
    return SelectorRule(ANCESTOR, tuple(path), via_refs=True)


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
    control_fact: bool = False
    suppression: tuple[SelectorRule, ...] | None = NEVER
    direct_targets: tuple[DirectTarget, ...] = ()
    owner_field: str | None = None
    authority_liveness_guards: tuple[str, ...] = ()
    principal_offers: tuple[SidOffer, ...] = ()
    # Extra cells reserved CLEAR without making the fact itself depend on
    # them. A direct member can reserve its primary device cell while member
    # liveness remains independent of removal of that one device.
    clear_offers: tuple[SidOffer, ...] = ()
    action_offers: tuple[SidOffer, ...] = ()


DELETE_SELF = (
    DirectTarget(CONTENT_DELETE, SELF, (OWNER, ADMIN)),
)


def validate_family_policy(policy):
    """Fail closed on every generic declaration before family registration."""
    if not isinstance(policy, FamilyPolicy):
        raise ValueError("family policy type")
    if type(policy.control_fact) is not bool:
        raise ValueError("control fact must be bool")

    selectors = policy.suppression
    if selectors is not NEVER:
        if not isinstance(selectors, tuple) or not selectors:
            raise ValueError("suppression policy must be a nonempty tuple")
        seen = set()
        for rule in selectors:
            if not isinstance(rule, SelectorRule) \
                    or not isinstance(rule.path, tuple) \
                    or not all(
                        _name(role) and "/" not in role
                        for role in rule.path
                    ) \
                    or rule.path and not _name("/".join(rule.path)):
                raise ValueError("suppression selector policy")
            valid = (
                rule.kind == SELF
                and not rule.path
                and rule.via_refs is False
            ) or (
                rule.kind == PARENT
                and len(rule.path) == 1
                and rule.via_refs is False
            ) or (
                rule.kind == ANCESTOR
                and len(rule.path) >= 2
                and rule.via_refs is True
            )
            if not valid:
                raise ValueError("suppression selector policy")
            identity = (rule.kind, rule.path)
            if identity in seen:
                raise ValueError("duplicate suppression selector")
            seen.add(identity)

    if not isinstance(policy.direct_targets, tuple):
        raise ValueError("direct targets must be a tuple")
    targets = set()
    for target in policy.direct_targets:
        if not isinstance(target, DirectTarget):
            raise ValueError("direct target policy")
        if not isinstance(target.modes, tuple) \
                or not all(
                    isinstance(mode, str) for mode in target.modes
                ):
            raise ValueError("direct target modes must be a tuple")
        modes = set(target.modes)
        if target.action != CONTENT_DELETE \
                or target.selector != SELF \
                or not target.modes \
                or len(modes) != len(target.modes) \
                or not modes <= {OWNER, ADMIN}:
            raise ValueError("direct deletion policy")
        identity = (target.action, target.selector)
        if identity in targets:
            raise ValueError("duplicate direct target")
        targets.add(identity)
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

    if policy.owner_field is not None and not _name(policy.owner_field):
        raise ValueError("owner field policy")
    _roles(
        policy.authority_liveness_guards,
        "authority liveness guards",
    )
    principal = _offers(policy.principal_offers, "principal offers")
    clear = _offers(policy.clear_offers, "clear offers")
    actions = _offers(policy.action_offers, "action offers")
    if (principal | clear) & actions:
        raise ValueError("clear/action offer name conflict")
    return policy


def _name(value):
    return valid_bounded_text(value, MAX_ATOM_NAME_BYTES)


def _roles(rows, label):
    if not isinstance(rows, tuple):
        raise ValueError(f"{label} must be a tuple")
    if not all(_name(role) for role in rows):
        raise ValueError(f"{label} role")
    if len(rows) != len(set(rows)):
        raise ValueError(f"duplicate {label} role")


def _offers(rows, label):
    if not isinstance(rows, tuple):
        raise ValueError(f"{label} must be a tuple")
    names = set()
    for row in rows:
        if not isinstance(row, SidOffer) \
                or not _name(row.name) \
                or not _name(row.namespace) \
                or ":" in row.namespace:
            raise ValueError(f"{label} declaration")
        if row.name in names:
            raise ValueError(f"duplicate {label} name")
        names.add(row.name)
    return names


def _selectors(policy, resolve):
    if policy.suppression is NEVER:
        return []
    out = []
    for rule in policy.suppression:
        path = "/".join(rule.path)
        if rule.kind == SELF:
            out.append(self_selector())
        elif rule.kind == PARENT:
            out.append(parent_selector(path, resolve(rule)))
        elif rule.kind == ANCESTOR:
            out.append(ancestor_selector(path, resolve(rule)))
        else:
            raise ValueError("unknown selector policy")
    return out


def expected_selectors(policy, fact, edges, ctx):
    """Canonical selector atoms independently recomputed at admission."""
    direct = {edge.role: edge.fid for edge in edges}

    def ref(parent, role):
        matches = {
            fid for edge_role, fid in parent.refs()
            if edge_role == role
        } if parent is not None else set()
        return next(iter(matches)) if len(matches) == 1 else None

    def resolve(rule):
        path = rule.path
        current = ref(fact, path[0]) if rule.via_refs \
            else direct.get(path[0])
        if current is None:
            raise ValueError(f"missing dependency role {path[0]!r}")
        for role in path[1:]:
            current = ref(ctx.fact_of(current), role)
            if current is None:
                raise ValueError(f"missing dependency path {'/'.join(path)!r}")
        return current

    return tuple(_selectors(policy, resolve))


def author_selectors(policy, edges):
    """Serialize selectors from constructor-supplied canonical path ids."""
    return _selectors(policy, lambda rule: edges["/".join(rule.path)])


def validate_fact_policy(policy, fact, edges, ctx):
    try:
        return tuple(selector_markers(fact)) == expected_selectors(
            policy, fact, edges, ctx)
    except (KeyError, TypeError, ValueError):
        return False


def allows_direct_target(policy, action, selector, mode):
    return any(
        row.action == action
        and row.selector == selector
        and mode in row.modes
        for row in policy.direct_targets
    )
