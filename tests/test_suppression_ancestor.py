"""Ancestor suppression paths stay reconstructible without admission edges."""

from types import SimpleNamespace

import facts
from core.crypto import keypair
from core.fact import Fact, Need
from core.kernel import drain
from core.repository_snapshot import compile_snapshot
from core.suppression import suppkeys
from core.validated_set import ValidatedView
from facts import _policy


def module(tag, policy, validate, needs=lambda fact: ()):
    return SimpleNamespace(
        TAG=tag,
        POLICY=policy,
        DURABLE=True,
        needs=needs,
        validate=validate,
    )


def exact_shape(tag, ref_role=None, offer=None):
    def validate(fact, ctx):
        refs = fact.refs()
        offers = fact.offers()
        return fact.t == tag \
            and set(fact.body) == {"nonce"} \
            and (
                refs == [] if ref_role is None
                else len(refs) == 1 and refs[0][0] == ref_role
            ) \
            and (
                offers == [] if offer is None
                else len(offers) == 1 and offers[0][:2] == offer
            )
    return validate


def workspace_fact():
    secret, public = keypair()
    return facts.auth.workspace.workspace(
        secret, public, "ancestor-test", 1)


def install(monkeypatch, *modules):
    facts.compile_families((facts.auth.workspace, *modules))
    monkeypatch.setattr(
        facts,
        "FAMILIES",
        {**facts.FAMILIES, **{item.TAG: item for item in modules}},
    )


def lower_fid(original, make):
    for nonce in range(1, 10_000):
        candidate = make(nonce)
        if candidate.fid < original.fid:
            return candidate
    raise AssertionError("could not construct a lower provider fid")


def test_immutable_ref_ancestor_survives_a_lower_equivalent_provider(
        monkeypatch):
    """A stored leaf re-closes after the provider set grows."""
    policy = _policy.FamilyPolicy(
        suppression=(_policy.Ancestor("parent", "authority"),))
    grand_family = module(
        "ancestor_grand",
        _policy.FamilyPolicy(),
        exact_shape(
            "ancestor_grand",
            offer=("ancestor_authority", "root"),
        ),
    )
    parent_family = module(
        "ancestor_parent",
        _policy.FamilyPolicy(),
        exact_shape(
            "ancestor_parent",
            ref_role="authority",
            offer=("ancestor_parent", "shared"),
        ),
    )
    leaf_family = module(
        "ancestor_leaf",
        policy,
        exact_shape("ancestor_leaf", ref_role="parent"),
    )
    install(monkeypatch, grand_family, parent_family, leaf_family)

    genesis = workspace_fact()
    workspace = genesis.fid
    grandparent = Fact(
        grand_family.TAG,
        2,
        [["offer", "ancestor_authority", "root"]],
        {"nonce": "grandparent"},
        workspace,
    )
    parent = Fact(
        parent_family.TAG,
        3,
        [
            ["ref", "authority", grandparent.fid],
            ["offer", "ancestor_parent", "shared"],
        ],
        {"nonce": "original"},
        workspace,
    )
    leaf = Fact(
        leaf_family.TAG,
        4,
        _policy.author_selectors(
            policy,
            {"parent/authority": grandparent.fid},
        ) + [["ref", "parent", parent.fid]],
        {"nonce": "leaf"},
        workspace,
    )

    first = (genesis, grandparent, parent, leaf)
    assert drain(first, workspace).ok
    alternate = lower_fid(
        parent,
        lambda nonce: Fact(
            parent_family.TAG,
            4 + nonce,
            [
                ["ref", "authority", grandparent.fid],
                ["offer", "ancestor_parent", "shared"],
            ],
            {"nonce": f"alternate-{nonce}"},
            workspace,
        ),
    )
    assert alternate.fid < parent.fid
    assert alternate.offers() == parent.offers()
    grown = (genesis, grandparent, parent, alternate, leaf)
    assert drain(grown, workspace).ok

    compiled = compile_snapshot(
        workspace, {fact.fid: fact for fact in grown})
    objects = dict(compiled.outbox)
    view = ValidatedView(compiled.root, objects.get)
    closure = view.closure((leaf.fid,))

    assert tuple(fact.fid for fact in closure) == (
        grandparent.fid,
        parent.fid,
        leaf.fid,
    )
    assert alternate.fid not in {fact.fid for fact in closure}
    assert drain(closure, workspace).ok
    assert suppkeys(leaf) == {f"fact:{grandparent.fid}"}


def test_parent_selector_pins_an_exact_need_during_reconstruction(
        monkeypatch):
    policy = _policy.FamilyPolicy(
        suppression=(_policy.Parent("parent"),))
    parent_family = module(
        "selected_parent",
        _policy.FamilyPolicy(),
        exact_shape(
            "selected_parent",
            offer=("selected_parent", "shared"),
        ),
    )
    leaf_family = module(
        "selected_leaf",
        policy,
        exact_shape("selected_leaf"),
        needs=lambda fact: (
            Need("parent", "selected_parent", "shared"),
        ),
    )
    install(monkeypatch, parent_family, leaf_family)

    genesis = workspace_fact()
    original = Fact(
        parent_family.TAG,
        2,
        [["offer", "selected_parent", "shared"]],
        {"nonce": "original"},
        genesis.fid,
    )
    leaf = Fact(
        leaf_family.TAG,
        3,
        _policy.author_selectors(
            policy, {"parent": original.fid}),
        {"nonce": "leaf"},
        genesis.fid,
    )
    alternate = lower_fid(
        original,
        lambda nonce: Fact(
            parent_family.TAG,
            4 + nonce,
            [["offer", "selected_parent", "shared"]],
            {"nonce": f"alternate-{nonce}"},
            genesis.fid,
        ),
    )
    grown = (genesis, original, alternate, leaf)
    assert alternate.fid < original.fid
    assert drain(grown, genesis.fid).ok

    compiled = compile_snapshot(
        genesis.fid, {fact.fid: fact for fact in grown})
    view = ValidatedView(compiled.root, dict(compiled.outbox).get)
    closure = view.closure((leaf.fid,))

    assert tuple(fact.fid for fact in closure) == (
        original.fid,
        leaf.fid,
    )
    assert drain(closure, genesis.fid).ok


def test_ancestor_declaration_cannot_claim_an_interchangeable_need(
        monkeypatch):
    """The registry promise remains checked against actual immutable bytes."""
    policy = _policy.FamilyPolicy(
        suppression=(_policy.Ancestor("parent", "authority"),))
    parent_family = module(
        "need_parent",
        _policy.FamilyPolicy(),
        exact_shape(
            "need_parent",
            offer=("need_parent", "shared"),
        ),
    )
    leaf_family = module(
        "need_leaf",
        policy,
        exact_shape("need_leaf"),
        needs=lambda fact: (
            Need("parent", "need_parent", "shared"),
        ),
    )
    install(monkeypatch, parent_family, leaf_family)

    genesis = workspace_fact()
    parent = Fact(
        parent_family.TAG,
        2,
        [["offer", "need_parent", "shared"]],
        {"nonce": "provider"},
        genesis.fid,
    )
    leaf = Fact(
        leaf_family.TAG,
        3,
        _policy.author_selectors(
            policy,
            {"parent/authority": parent.fid},
        ),
        {"nonce": "unpinned"},
        genesis.fid,
    )

    judgment = drain((genesis, parent, leaf), genesis.fid)

    assert judgment.ok is False
    assert judgment.valids == ()
