"""The fact-family registry is the fail-fast policy compilation door."""

from types import SimpleNamespace

import pytest

import facts
from core.fact import Fact
from core.suppression import ANCESTOR, PARENT, SELF
from facts import _policy


def family(policy, tag="synthetic"):
    return SimpleNamespace(TAG=tag, POLICY=policy)


def compile_policy(policy):
    return facts.compile_families((
        facts.auth.workspace,
        family(policy),
    ))


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        ("control_fact", 1, "control fact must be bool"),
        ("suppression", [], "nonempty tuple"),
        ("suppression", (), "nonempty tuple"),
        ("suppression", ("self",), "selector policy"),
        (
            "suppression",
            (_policy.SelectorRule(PARENT, ["parent"]),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.SelectorRule(SELF, ("parent",)),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.SelectorRule(SELF, via_refs=True),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.SelectorRule(PARENT),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.SelectorRule(PARENT, ("one", "two")),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.Parent("ambiguous/role"),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.Ancestor("a" * 70, "b" * 70),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.SelectorRule(ANCESTOR, ("one",), via_refs=True),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.SelectorRule(ANCESTOR, ("one", "two")),),
            "selector policy",
        ),
        (
            "suppression",
            (_policy.Parent("parent"), _policy.Parent("parent")),
            "duplicate suppression",
        ),
        ("direct_targets", [], "must be a tuple"),
        ("direct_targets", ("delete",), "direct target policy"),
        (
            "direct_targets",
            (_policy.DirectTarget("unknown", SELF, (_policy.ADMIN,)),),
            "direct deletion policy",
        ),
        (
            "direct_targets",
            (
                _policy.DirectTarget(
                    _policy.CONTENT_DELETE, PARENT, (_policy.ADMIN,)),
            ),
            "direct deletion policy",
        ),
        (
            "direct_targets",
            (
                _policy.DirectTarget(
                    _policy.CONTENT_DELETE, SELF, ()),
            ),
            "direct deletion policy",
        ),
        (
            "direct_targets",
            (
                _policy.DirectTarget(
                    _policy.CONTENT_DELETE,
                    SELF,
                    (_policy.ADMIN, _policy.ADMIN),
                ),
            ),
            "direct deletion policy",
        ),
        (
            "direct_targets",
            (
                _policy.DirectTarget(
                    _policy.CONTENT_DELETE, SELF, [_policy.ADMIN]),
            ),
            "modes must be a tuple",
        ),
        (
            "direct_targets",
            (_policy.DELETE_SELF[0], _policy.DELETE_SELF[0]),
            "duplicate direct target",
        ),
        ("owner_field", "", "owner field policy"),
        ("authority_liveness_guards", [], "must be a tuple"),
        ("authority_liveness_guards", ("",), "guards role"),
        ("authority_liveness_guards", (1,), "guards role"),
        (
            "authority_liveness_guards",
            ("member", "member"),
            "duplicate authority",
        ),
        ("principal_offers", [], "must be a tuple"),
        ("principal_offers", ("member",), "declaration"),
        (
            "principal_offers",
            (_policy.SidOffer("", "member"),),
            "declaration",
        ),
        (
            "principal_offers",
            (_policy.SidOffer("member", ""),),
            "declaration",
        ),
        (
            "principal_offers",
            (_policy.SidOffer("member", "bad:namespace"),),
            "declaration",
        ),
        (
            "principal_offers",
            (
                _policy.SidOffer("member", "member"),
                _policy.SidOffer("member", "other"),
            ),
            "duplicate principal",
        ),
        ("action_offers", [], "must be a tuple"),
        ("action_offers", ("removed",), "declaration"),
        (
            "action_offers",
            (_policy.SidOffer("", "member"),),
            "declaration",
        ),
        (
            "action_offers",
            (_policy.SidOffer("removed", ""),),
            "declaration",
        ),
        (
            "action_offers",
            (_policy.SidOffer("removed", "bad:namespace"),),
            "declaration",
        ),
        (
            "action_offers",
            (
                _policy.SidOffer("removed", "member"),
                _policy.SidOffer("removed", "other"),
            ),
            "duplicate action",
        ),
    ),
)
def test_registry_rejects_every_malformed_policy_field(
        field, value, error):
    values = {field: value}
    if field == "direct_targets" and value \
            and all(isinstance(row, _policy.DirectTarget) for row in value):
        values["suppression"] = (_policy.Self(),)
        values["owner_field"] = "owner"
    policy = _policy.FamilyPolicy(**values)

    with pytest.raises(ValueError, match=error):
        compile_policy(policy)


def test_registry_rejects_offer_role_ambiguity():
    policy = _policy.FamilyPolicy(
        principal_offers=(_policy.SidOffer("member", "member"),),
        action_offers=(_policy.SidOffer("member", "member"),),
    )

    with pytest.raises(ValueError, match="principal/action"):
        compile_policy(policy)


def test_registry_rejects_wrong_policy_type():
    with pytest.raises(ValueError, match="family policy type"):
        facts.compile_families((
            facts.auth.workspace,
            family("not a policy"),
        ))


def test_registry_rejects_cross_family_principal_namespace_conflict():
    first = family(
        _policy.FamilyPolicy(
            principal_offers=(_policy.SidOffer("account", "member"),)),
        "first",
    )
    second = family(
        _policy.FamilyPolicy(
            principal_offers=(_policy.SidOffer("account", "device"),)),
        "second",
    )

    with pytest.raises(ValueError, match="namespace conflict"):
        facts.compile_families((facts.auth.workspace, first, second))


def test_registry_accepts_complete_distinct_policy_and_production_inventory():
    policy = _policy.FamilyPolicy(
        control_fact=True,
        suppression=(
            _policy.Self(),
            _policy.Parent("parent"),
            _policy.Ancestor("parent", "grandparent"),
        ),
        authority_liveness_guards=("member", "device"),
        principal_offers=(
            _policy.SidOffer("member", "member"),
            _policy.SidOffer("device_key", "device"),
        ),
        action_offers=(
            _policy.SidOffer("removed", "member"),
            _policy.SidOffer("revoked", "device"),
        ),
    )

    compiled = compile_policy(policy)

    assert compiled["synthetic"].POLICY is policy
    assert facts.compile_families(facts.MODULES) == facts.FAMILIES


def test_offer_sid_derivation_has_no_silent_dictionary_overwrite():
    fact = Fact(
        "synthetic",
        1,
        [["offer", "slot", "value"]],
        {},
        "0" * 64,
    )
    declarations = (
        _policy.SidOffer("slot", "first"),
        _policy.SidOffer("slot", "second"),
    )

    assert facts._offer_sids(fact, declarations) == {
        "first:value",
        "second:value",
    }


def test_malformed_policy_stops_before_family_hooks_can_run():
    calls = []
    malformed = SimpleNamespace(
        TAG="malformed",
        POLICY=_policy.FamilyPolicy(
            authority_liveness_guards=("",)),
        needs=lambda fact: calls.append(fact),
        validate=lambda fact, ctx: calls.append((fact, ctx)),
        DURABLE=True,
    )

    with pytest.raises(ValueError, match="guards role"):
        facts.compile_families((facts.auth.workspace, malformed))

    assert calls == []
