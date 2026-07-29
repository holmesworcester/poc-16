"""Executable suppression, ownership, and liveness family contracts."""
from types import SimpleNamespace

import pytest

import facts
from core import cmds
from core.crypto import keypair
from core.fact import Fact
from core.node import Node
from core.suppression import (
    ANCESTOR,
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
    assert kinds == {SELF, PARENT, ANCESTOR}
    for tag in ("msg", "file_bao", "chunk"):
        direct = facts.family_for(tag).POLICY.direct_targets
        assert direct
        assert all(
            row.action == _policy.CONTENT_DELETE
            and row.selector == SELF
            and set(row.modes) == {_policy.OWNER, _policy.ADMIN}
            for row in direct
        )

    admin = facts.family_for("admin").POLICY
    assert admin.authorization_guards == ("grantor_admin",)
    assert admin.authority_liveness_guards == ("grantee_member",)


def test_registry_rejects_duplicate_and_policyless_families():
    policy = _policy.FamilyPolicy()
    first = SimpleNamespace(TAG="example", POLICY=policy)
    duplicate = SimpleNamespace(TAG="example", POLICY=policy)
    policyless = SimpleNamespace(TAG="other")
    with pytest.raises(ValueError, match="duplicate"):
        facts.compile_families((first, duplicate))
    with pytest.raises(ValueError, match="own its policy"):
        facts.compile_families((policyless,))


def test_new_principal_namespace_needs_no_core_change(monkeypatch):
    family = SimpleNamespace(
        TAG="example",
        POLICY=_policy.FamilyPolicy(
            principal_offers=(
                _policy.SidOffer("account_key", "account"),)),
    )
    monkeypatch.setitem(facts.FAMILIES, family.TAG, family)
    fact = Fact(
        family.TAG, 1, [["offer", "account_key", "public"]], {})
    assert facts.principal_sids(fact) == {"account:public"}


@pytest.mark.parametrize("atoms", [
    [],
    [self_selector(), parent_selector("member", "f" * 64)],
])
def test_runtime_policy_rejects_missing_and_extra_selectors(
        tmp_path, monkeypatch, atoms):
    """The registry check remains load-bearing if shape validation is lax."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    secret, public = node.identity(workspace)
    malformed = Fact(
        "msg", 10, atoms,
        {"pk": public, "chan": "general", "text": "hostile"},
    )
    signed = signature(secret, public, malformed, malformed.ts)
    monkeypatch.setattr(message_family, "validate", lambda fact, ctx: True)

    with pytest.raises(ValueError, match="outside the canonical set"):
        node.ingest_new(
            workspace, [signed, malformed], {
                signed.fid: [],
                malformed.fid: [
                    signed.fid, member_src(node, workspace, public)],
            })
    assert node.fact_of(workspace, malformed.fid) is None


def test_runtime_policy_rejects_a_forged_nonancestor(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    descriptor_fid = send_bytes(
        node, workspace, "one.bin", b"ancestor", ts=10)
    original = next(
        node.fact_of(workspace, fid)
        for (fid,) in node.idx(workspace).execute(
            "SELECT fid FROM facts WHERE t='chunk'")
    )
    atoms = [
        marker[:] if not (
            marker[0] == "supp" and marker[1] == ANCESTOR
        ) else [*marker[:3], "f" * 64]
        for marker in original.atoms
    ]
    forged = Fact(original.t, 11, atoms, dict(original.body))
    secret, public = node.identity(workspace)
    signed = signature(secret, public, forged, forged.ts)
    monkeypatch.setattr(chunk_family, "validate", lambda fact, ctx: True)

    with pytest.raises(ValueError, match="outside the canonical set"):
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
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    alice_secret, alice = node.identity(workspace)

    bob_secret, bob, _ = add_member(
        node, workspace, "Bob", ts=10,
        inviter=(alice_secret, alice))
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    cmds.bind_device(node, workspace, "bob-primary")

    devices = []
    for label in ("bob-phone", "bob-laptop"):
        secret, public = keypair()
        node.keychain.add_identity(secret)
        cmds.grant_device(node, workspace, bob, public, label)
        devices.append((secret, public))

    node.bind_identity(workspace, devices[0][1])
    first = cmds.post(node, workspace, "general", "owned on phone", ts=30)
    node.bind_identity(workspace, devices[1][1])
    owner_action = node.fact_of(
        workspace, cmds.remove(node, workspace, first, ts=31))
    assert owner_action.body["mode"] == _policy.OWNER

    node.bind_identity(workspace, devices[0][1])
    second = cmds.post(node, workspace, "general", "owned on phone 2", ts=32)
    charlie_secret, charlie, _ = add_member(
        node, workspace, "Charlie", ts=40,
        inviter=(alice_secret, alice))
    node.keychain.add_identity(charlie_secret)
    node.bind_identity(workspace, charlie)
    with pytest.raises(
            ValueError, match="only the owner or an admin"):
        cmds.remove(node, workspace, second, ts=42)

    node.bind_identity(workspace, alice)
    admin_action = node.fact_of(
        workspace, cmds.remove(node, workspace, second, ts=43))
    assert admin_action.body["mode"] == _policy.ADMIN
