"""Executable suppression, ownership, and liveness family contracts."""
from types import SimpleNamespace

import pytest

import facts
from core import indexes
from core.crypto import keypair
from core.fact import Fact
from full_peer.node import FullPeer
from core.suppression import (
    PARENT,
    SELF,
    parent_selector,
    self_selector,
)
from facts import _policy
from facts.auth.signature import signature
from facts.content import chunk as chunk_family
from facts.content import message as message_family

from .util import add_member, member_src, send_bytes


def test_one_registry_exhaustively_covers_the_router():
    assert all(module.POLICY is not None for module in facts.FAMILIES.values())
    assert facts.family_for("delete").POLICY.suppression is _policy.NEVER
    assert facts.family_for("evict").POLICY.suppression is _policy.NEVER

    kinds = {
        rule.kind
        for family in facts.FAMILIES.values()
        for rule in family.POLICY.suppression or ()
    }
    assert kinds == {SELF, PARENT}
    assert tuple(
        rule.kind
        for rule in facts.family_for("msg").POLICY.suppression
    ) == (SELF,)
    assert tuple(
        rule.kind
        for rule in facts.family_for("file_bao").POLICY.suppression
    ) == (SELF,)
    assert tuple(
        rule.kind
        for rule in facts.family_for("chunk").POLICY.suppression
    ) == (SELF, PARENT)
    for tag in ("msg", "file_bao", "chunk"):
        direct = facts.family_for(tag).POLICY.direct_targets
        assert direct
        assert all(
            row.action == _policy.CONTENT_DELETE
            and row.selector == SELF
            and set(row.modes) == {_policy.OWNER, _policy.ADMIN}
            for row in direct
        )

    admin_policy = facts.family_for("admin").POLICY
    assert not hasattr(admin_policy, "authorization_guards")
    assert admin_policy.authority_liveness_guards == ("grantee_member",)

    workspace = "0" * 64
    assert {
        need.role for need in facts.auth.admin.needs(
            facts.auth.admin.admin(workspace, "grantor", "grantee", 1))
    } == {"author", "grantor_admin", "grantee_member"}
    assert {
        need.role for need in facts.auth.removal.needs(
            facts.auth.removal.removal(workspace, "admin", "target", 1))
    } == {"author", "admin", "target_member"}
    assert {
        need.role for need in facts.content.message.needs(
            facts.content.message.message(
                workspace, "member", "general", "proof", 1))
    } == {"author", "member"}


def test_registry_rejects_duplicate_and_policyless_families():
    policy = _policy.FamilyPolicy()
    first = SimpleNamespace(TAG="example", POLICY=policy)
    duplicate = SimpleNamespace(TAG="example", POLICY=policy)
    policyless = SimpleNamespace(TAG="other")
    with pytest.raises(ValueError, match="duplicate"):
        facts.compile_families((first, duplicate))
    with pytest.raises(ValueError, match="own its policy"):
        facts.compile_families((policyless,))


@pytest.mark.parametrize(
    ("policy", "error"),
    (
        (
            _policy.FamilyPolicy(
                suppression=(_policy.Self(),),
                direct_targets=(
                    _policy.DirectTarget(
                        _policy.CONTENT_DELETE,
                        SELF,
                        (_policy.OWNER,),
                    ),
                ),
                owner_field="owner",
            ),
            "allow ADMIN",
        ),
        (
            _policy.FamilyPolicy(
                suppression=(_policy.Self(),),
                direct_targets=_policy.DELETE_SELF,
            ),
            "owner field",
        ),
    ),
)
def test_registry_rejects_direct_delete_authority_gaps(policy, error):
    family = SimpleNamespace(TAG="unsafe_delete_target", POLICY=policy)

    with pytest.raises(ValueError, match=error):
        facts.compile_families((family,))


@pytest.mark.parametrize(
    ("suppression", "error"),
    (
        (_policy.NEVER, "exactly one Self"),
        ((_policy.Parent("member"),), "exactly one Self"),
        (
            (_policy.SelectorRule(SELF, ("malformed",)),),
            "suppression selector",
        ),
        ((_policy.Self(), _policy.Self()), "duplicate suppression"),
    ),
)
def test_registry_rejects_direct_delete_without_one_self_selector(
        suppression, error):
    family = SimpleNamespace(
        TAG="undeclared_delete_target",
        POLICY=_policy.FamilyPolicy(
            suppression=suppression,
            direct_targets=_policy.DELETE_SELF,
            owner_field="owner",
        ),
    )

    with pytest.raises(ValueError, match=error):
        facts.compile_families((family,))


def test_registry_allows_one_self_selector_with_inherited_selectors():
    family = SimpleNamespace(
        TAG="declared_delete_target",
        POLICY=_policy.FamilyPolicy(
            suppression=(
                _policy.Self(),
                _policy.Parent("member"),
                _policy.Ancestor("member", "workspace"),
            ),
            direct_targets=_policy.DELETE_SELF,
            owner_field="owner",
        ),
    )

    compiled = facts.compile_families((facts.auth.workspace, family))
    assert compiled[family.TAG] is family


def test_new_principal_namespace_needs_no_core_change(monkeypatch):
    family = SimpleNamespace(
        TAG="example",
        POLICY=_policy.FamilyPolicy(
            principal_offers=(
                _policy.SidOffer("account_key", "account"),)),
    )
    monkeypatch.setitem(facts.FAMILIES, family.TAG, family)
    fact = Fact(
        family.TAG, 1, [["offer", "account_key", "public"]], {}, "0" * 64)
    assert facts.principal_sids(fact) == {"account:public"}


@pytest.mark.parametrize("atoms", [
    [],
    [self_selector(), parent_selector("member", "f" * 64)],
])
def test_runtime_policy_rejects_missing_and_extra_selectors(
        tmp_path, monkeypatch, atoms):
    """The registry check remains load-bearing if shape validation is lax."""
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    secret, public = node.identity(workspace)
    malformed = Fact(
        "msg", 10, atoms,
        {"pk": public, "chan": "general", "text": "hostile"},
        workspace,
    )
    signed = signature(secret, public, malformed, malformed.ts)
    monkeypatch.setattr(message_family, "validate", lambda fact, ctx: True)

    with pytest.raises(ValueError, match="not admitted"):
        node.ingest_new(
            workspace, [signed, malformed], {
                signed.fid: [],
                malformed.fid: [
                    signed.fid, member_src(node, workspace, public)],
            })
    assert node.fact_of(workspace, malformed.fid) is None


def test_runtime_policy_rejects_a_forged_nonparent(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    descriptor_fid = send_bytes(
        node, workspace, "one.bin", b"ancestor", ts=10)
    original = node.by_type(workspace, "chunk")[0]
    atoms = [
        marker[:] if not (
            marker[0] == "supp" and marker[1] == PARENT
        ) else [*marker[:3], "f" * 64]
        for marker in original.atoms
    ]
    forged = Fact(original.t, 11, atoms, dict(original.body), workspace)
    secret, public = node.identity(workspace)
    signed = signature(secret, public, forged, forged.ts)
    monkeypatch.setattr(chunk_family, "validate", lambda fact, ctx: True)

    with pytest.raises(ValueError, match="not admitted"):
        node.ingest_new(
            workspace, [signed, forged], {
                signed.fid: [],
                forged.fid: [
                    descriptor_fid,
                    signed.fid,
                    member_src(node, workspace, public),
                ],
            })
    assert node.fact_of(workspace, forged.fid) is None


def test_sibling_device_owner_admin_and_foreign_member_modes(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    alice_secret, alice = node.identity(workspace)

    bob_secret, bob, _ = add_member(
        node, workspace, "Bob", ts=10,
        inviter=(alice_secret, alice))
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    facts.auth.device.bind(node, workspace, "bob-primary")

    devices = []
    for label in ("bob-phone", "bob-laptop"):
        secret, public = keypair()
        node.keychain.add_identity(secret)
        facts.auth.device_invite.grant(node, workspace, bob, public, label)
        devices.append((secret, public))

    node.bind_identity(workspace, devices[0][1])
    first = facts.content.message.post(node, workspace, "general", "owned on phone", ts=30)
    node.bind_identity(workspace, devices[1][1])
    owner_action = node.fact_of(
        workspace, facts.content.delete.remove(node, workspace, first, ts=31))
    assert owner_action.body["mode"] == _policy.OWNER

    node.bind_identity(workspace, devices[0][1])
    second = facts.content.message.post(node, workspace, "general", "owned on phone 2", ts=32)
    charlie_secret, charlie, _ = add_member(
        node, workspace, "Charlie", ts=40,
        inviter=(alice_secret, alice))
    node.keychain.add_identity(charlie_secret)
    node.bind_identity(workspace, charlie)
    with pytest.raises(
            ValueError, match="only the owner or an admin"):
        facts.content.delete.remove(node, workspace, second, ts=42)

    node.bind_identity(workspace, alice)
    admin_action = node.fact_of(
        workspace, facts.content.delete.remove(node, workspace, second, ts=43))
    assert admin_action.body["mode"] == _policy.ADMIN


def test_admin_deletes_every_registered_direct_delete_family(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "Bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    facts.auth.device.bind(node, workspace, "Bob phone")
    posted = facts.content.message.post(
        node, workspace, "general", "Bob's message", ts=20)
    descriptor = send_bytes(
        node, workspace, "bob.bin", b"Bob's bytes", ts=21)
    chunk = node.by_type(workspace, "chunk")[0].fid
    _, push_node = keypair()
    endpoint = facts.auth.push_endpoint.register(
        node,
        workspace,
        "1" * 64,
        push_node,
        "android",
        "poc16.mobile",
        "production",
        facts.auth.push_endpoint.encode_sealed_target(b"x" * 49),
        ts=22,
    )

    direct = {
        tag
        for tag, family in facts.FAMILIES.items()
        if any(
            target.action == _policy.CONTENT_DELETE
            for target in family.POLICY.direct_targets
        )
    }
    targets = {
        "msg": posted,
        "file_bao": descriptor,
        "chunk": chunk,
        "push_endpoint": endpoint,
    }
    assert set(targets) == direct

    node.bind_identity(workspace, founder)
    # A descriptor suppresses its chunks, so exercise the direct chunk target
    # first; every action still travels through the ordinary fact pipeline.
    for ts, tag in enumerate(
            ("chunk", "msg", "file_bao", "push_endpoint"), start=30):
        target = targets[tag]
        action_fid = facts.content.delete.remove(
            node, workspace, target, ts=ts)
        action = node.fact_of(workspace, action_fid)
        assert action.body == {
            "mode": _policy.ADMIN,
            "owner": bob,
            "pk": founder,
        }
        assert node.reader(workspace).worker().suppression(
            indexes.fact_key(target)
        ) == {
            "state": "active",
            "action": action_fid,
        }
