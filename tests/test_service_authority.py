"""Two-community service authority and provider convergence tests."""
import asyncio

import pytest

import facts
from core.access import AccessGate, LookupActive
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import keypair
from core.object_store import SyncStoreAdapter
from core.removal_path import decode as decode_removal_path
from infrastructure.authority import (
    CapabilityReconciler,
    InstalledCapability,
    ServiceGrant,
    authorize_service,
)
from core.store import FsStore
from facts import _policy
from facts.auth.request import request
from facts.auth.removal import removal as member_removal
from facts.auth.service_binding import binding_cell, service_binding
from facts.auth.service_request import service_request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from facts.content.delete import delete
from full_peer.node import FullPeer
from tests.util import add_member


def run(awaitable):
    return asyncio.run(awaitable)


def signed(secret, writer, root, closure):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, writer, closure))


def community(founder_secret, founder, service_secret, service, name, ts):
    root = workspace(founder_secret, founder, name, ts)
    invite_secret, invite_public = keypair()
    invited = user_invite(root.fid, founder, invite_public, ts + 1)
    invited_signature = signature(
        founder_secret, founder, invited, ts + 1)
    joined = user(
        invited, invite_secret, service, "service", ts + 2)
    joined_signature = signature(
        service_secret, service, joined, ts + 2)
    return root, (
        root, invited_signature, invited, joined_signature, joined)


def service_world(*, provider="aws", capability="workspace-role"):
    founder_secret, founder = keypair()
    service_secret, service = keypair()
    operations, operations_membership = community(
        founder_secret, founder, service_secret, service, "operations", 1)
    target, target_membership = community(
        founder_secret, founder, service_secret, service, "target", 20)
    cell = binding_cell(
        operations.fid, provider, capability, service)
    binding = service_binding(
        target.fid,
        founder,
        founder,
        service,
        operations.fid,
        provider,
        capability,
        24,
    )
    binding_signature = signature(
        founder_secret, founder, binding, 24)
    return {
        "founder_secret": founder_secret,
        "founder": founder,
        "service_secret": service_secret,
        "service": service,
        "operations": operations,
        "operations_membership": operations_membership,
        "target": target,
        "target_membership": target_membership,
        "binding": binding,
        "binding_signature": binding_signature,
        "cell": cell,
        "provider": provider,
        "capability": capability,
    }


def target_proof(world, *, basis="", admission=True, ts=30):
    item = service_request(
        world["target"].fid,
        world["service"],
        world["service"],
        world["binding"].fid,
        world["binding"].body["administrator"],
        world["operations"].fid,
        world["provider"],
        world["capability"],
        world["cell"],
        1_000,
        basis,
        ts,
    )
    closure = (item,) if not admission else (
        *world["target_membership"],
        world["binding_signature"],
        world["binding"],
        signature(world["service_secret"], world["service"], item, ts),
        item,
    )
    return signed(
        world["service_secret"], world["service"],
        world["target"], closure)


def operations_proof(world, *, basis="", admission=True, ts=31):
    item = request(
        world["operations"].fid,
        world["service"],
        world["service"],
        "service",
        1_000,
        basis,
        ts,
    )
    closure = (item,) if not admission else (
        *world["operations_membership"],
        signature(world["service_secret"], world["service"], item, ts),
        item,
    )
    return signed(
        world["service_secret"], world["service"],
        world["operations"], closure)


def gates(tmp_path, world):
    # The target exercises the local synchronous store. The operations gate
    # exercises the same AccessGate over the awaited adapter used at hosted
    # boundaries; neither path has a parallel authority implementation.
    target = AccessGate(
        world["target"].fid, FsStore(tmp_path / "local-target"))
    operations = AccessGate(
        world["operations"].fid,
        SyncStoreAdapter(FsStore(tmp_path / "hosted-operations")),
    )
    return target, operations


def test_family_commands_bind_list_and_owner_leave_through_ordinary_facts(
        tmp_path):
    node = FullPeer(str(tmp_path / "peer"))
    operations = facts.auth.workspace.create(node, "operations", ts=1)
    target = facts.auth.workspace.create(node, "target", ts=10)
    service_secret, service = keypair()
    add_member(
        node, operations, "service", ts=2,
        member_identity=(service_secret, service))
    add_member(
        node, target, "service", ts=11,
        member_identity=(service_secret, service))

    binding = facts.auth.service_binding.bind(
        node, target, service, operations, "aws", "workspace-role")
    assert facts.auth.service_binding.bindings(
        node, target, operations) == [{
            "fid": binding,
            "administrator": node.identity_id(target),
            "capability": "workspace-role",
            "operations": operations,
            "owner": service,
            "pk": node.identity_id(target),
            "provider": "aws",
        }]

    node.keychain.add_identity(service_secret)
    node.bind_identity(target, service)
    removal = facts.auth.service_binding.leave(node, target, binding)
    assert node.fact_of(target, removal).t == "delete"
    assert facts.auth.service_binding.bindings(node, target) == []


def test_local_and_hosted_gates_authorize_exact_same_service_then_go_warm(
        tmp_path):
    world = service_world()
    target, operations = gates(tmp_path, world)
    grant = run(authorize_service(
        target, operations,
        target_proof(world), operations_proof(world), 100))
    assert grant == ServiceGrant(
        world["target"].fid,
        world["operations"].fid,
        world["service"],
        world["service"],
        world["binding"].fid,
        "aws",
        "workspace-role",
    )

    target_tip = run(target.state.pin()).root_oid
    operations_tip = run(operations.state.pin()).root_oid
    assert run(authorize_service(
        target, operations,
        target_proof(world, basis=target_tip, admission=False),
        operations_proof(
            world, basis=operations_tip, admission=False),
        100,
    )) == grant

    # A warm request cannot retain the admitted binding fid while rewriting
    # its provider capability. The derived cell was separately admitted and
    # the forged cell is UNKNOWN, forcing a positive proof that cannot close.
    forged = dict(world)
    forged["capability"] = "administrator"
    forged["cell"] = binding_cell(
        forged["operations"].fid,
        forged["provider"],
        forged["capability"],
        forged["service"],
    )
    assert run(authorize_service(
        target, operations,
        target_proof(forged, admission=False, ts=35),
        operations_proof(
            world, basis=operations_tip, admission=False, ts=36),
        100,
    )) is None

    # Cross-wiring either independently signed community proof fails closed.
    foreign = service_world(provider="cloudflare", capability="r2-prefix")
    assert run(authorize_service(
        target, operations,
        target_proof(world, basis=target_tip, admission=False),
        operations_proof(foreign),
        100,
    )) is None


def test_warm_lookup_cannot_recombine_one_binding_with_another_cell(
        tmp_path):
    first = service_world(capability="workspace-role")
    target, operations = gates(tmp_path, first)
    assert run(authorize_service(
        target, operations,
        target_proof(first), operations_proof(first), 100)) is not None

    second = dict(first)
    second["capability"] = "database-reader"
    second["cell"] = binding_cell(
        second["operations"].fid,
        second["provider"],
        second["capability"],
        second["service"],
    )
    second["binding"] = service_binding(
        second["target"].fid,
        second["founder"],
        second["founder"],
        second["service"],
        second["operations"].fid,
        second["provider"],
        second["capability"],
        25,
    )
    second["binding_signature"] = signature(
        second["founder_secret"], second["founder"],
        second["binding"], 25)
    assert run(authorize_service(
        target, operations,
        target_proof(second, ts=32),
        operations_proof(second, admission=False, ts=33),
        100,
    )).capability == "database-reader"

    removed = delete(
        second["target"].fid,
        second["service"],
        second["binding"].key,
        _policy.OWNER,
        40,
        second["service"],
        second["service"],
    )
    removed_signature = signature(
        second["service_secret"], second["service"], removed, 40)
    control = signed(
        second["service_secret"], second["service"], second["target"], (
            *second["target_membership"],
            second["binding_signature"],
            second["binding"],
            removed_signature,
            removed,
        ))
    assert run(target.state.apply_control(
        control, second["service"])).status == "applied"

    # Both rows existed independently in the old lookup shape: binding A was
    # CLEAR and cell B had been admitted.  Their composite was never admitted.
    forged = dict(second)
    forged["binding"] = first["binding"]
    forged["binding_signature"] = first["binding_signature"]
    assert run(authorize_service(
        target, operations,
        target_proof(forged, admission=False, ts=41),
        operations_proof(forged, admission=False, ts=42),
        100,
    )) is None


def test_approving_administrator_removal_revokes_warm_binding(tmp_path):
    world = service_world()
    target, operations = gates(tmp_path, world)
    assert run(authorize_service(
        target, operations,
        target_proof(world), operations_proof(world), 100)) is not None

    evicted = member_removal(
        world["target"].fid,
        world["founder"],
        world["founder"],
        40,
        world["founder"],
    )
    evicted_signature = signature(
        world["founder_secret"], world["founder"], evicted, 40)
    control = signed(
        world["founder_secret"], world["founder"], world["target"], (
            world["target"],
            evicted_signature,
            evicted,
        ))
    assert run(target.state.apply_control(
        control, world["founder"])).status == "applied"

    # A third-party authority guard denies without returning that member's
    # removal path. Only removal of the requesting subject may disclose one.
    assert run(authorize_service(
        target, operations,
        target_proof(world, admission=False, ts=41),
        operations_proof(world, admission=False, ts=42),
        100,
    )) is None


def test_target_leave_revokes_and_fresh_binding_rejoins(tmp_path):
    world = service_world()
    target, operations = gates(tmp_path, world)
    grant = run(authorize_service(
        target, operations,
        target_proof(world), operations_proof(world), 100))
    adapter = MemoryCapabilities()
    reconciler = CapabilityReconciler(adapter)
    credential = run(reconciler.reconcile((grant,))).ensured[0]

    removal = delete(
        world["target"].fid,
        world["service"],
        world["binding"].key,
        _policy.OWNER,
        40,
        world["service"],
        world["service"],
    )
    removal_signature = signature(
        world["service_secret"], world["service"], removal, 40)
    control = signed(
        world["service_secret"], world["service"], world["target"], (
            *world["target_membership"],
            world["binding_signature"],
            world["binding"],
            removal_signature,
            removal,
        ))
    assert run(target.state.apply_control(
        control, world["service"])).status == "applied"
    with pytest.raises(LookupActive) as denied:
        run(authorize_service(
            target, operations,
            target_proof(world, admission=False),
            operations_proof(world, admission=False),
            100,
        ))
    disclosed = {
        sid for sid, _proof in decode_removal_path(
            denied.value.path).proofs
    }
    assert facts.principal_sid(
        "member", world["binding"].body["administrator"]) not in disclosed
    assert "fact:" + world["binding"].fid in disclosed
    assert run(reconciler.reconcile(())).revoked == (credential,)
    assert not adapter.accepts(credential.handle)

    replacement = service_binding(
        world["target"].fid,
        world["founder"],
        world["founder"],
        world["service"],
        world["operations"].fid,
        world["provider"],
        world["capability"],
        41,
    )
    world["binding"] = replacement
    world["binding_signature"] = signature(
        world["founder_secret"], world["founder"], replacement, 41)
    rejoined = run(authorize_service(
        target, operations,
        target_proof(world, ts=42),
        operations_proof(
            world, basis=run(operations.state.pin()).root_oid,
            admission=False, ts=43),
        100,
    ))
    assert rejoined.binding != grant.binding
    assert rejoined.capability == grant.capability
    replacement_credential = run(
        reconciler.reconcile((rejoined,))).ensured[0]
    assert adapter.accepts(replacement_credential.handle)


def test_operations_removal_revokes_and_rotated_service_rejoins(tmp_path):
    world = service_world()
    target, operations = gates(tmp_path, world)
    grant = run(authorize_service(
        target, operations,
        target_proof(world), operations_proof(world), 100))
    adapter = MemoryCapabilities()
    reconciler = CapabilityReconciler(adapter)
    credential = run(reconciler.reconcile((grant,))).ensured[0]

    evicted = member_removal(
        world["operations"].fid,
        world["founder"],
        world["service"],
        40,
        world["founder"],
    )
    evicted_signature = signature(
        world["founder_secret"], world["founder"], evicted, 40)
    control = signed(
        world["founder_secret"], world["founder"],
        world["operations"], (
            *world["operations_membership"],
            evicted_signature,
            evicted,
        ))
    assert run(operations.state.apply_control(
        control, world["founder"])).status == "applied"
    with pytest.raises(LookupActive):
        run(authorize_service(
            target, operations,
            target_proof(world, admission=False),
            operations_proof(world, admission=False),
            100,
        ))
    assert run(reconciler.reconcile(())).revoked == (credential,)

    # Member removal is terminal for that principal. A fresh key accepts new
    # invitations in both communities and receives a fresh exact binding.
    service_secret, service = keypair()
    _, operations_membership = community(
        world["founder_secret"], world["founder"],
        service_secret, service, "operations", 1)
    _, target_membership = community(
        world["founder_secret"], world["founder"],
        service_secret, service, "target", 20)
    world.update({
        "service_secret": service_secret,
        "service": service,
        "operations_membership": operations_membership,
        "target_membership": target_membership,
    })
    world["cell"] = binding_cell(
        world["operations"].fid,
        world["provider"],
        world["capability"],
        service,
    )
    world["binding"] = service_binding(
        world["target"].fid,
        world["founder"],
        world["founder"],
        service,
        world["operations"].fid,
        world["provider"],
        world["capability"],
        50,
    )
    world["binding_signature"] = signature(
        world["founder_secret"], world["founder"],
        world["binding"], 50)
    rejoined = run(authorize_service(
        target, operations,
        target_proof(world, ts=51),
        operations_proof(world, ts=52),
        100,
    ))
    assert rejoined.owner == service
    assert rejoined.binding != grant.binding
    assert run(reconciler.reconcile((rejoined,))).ensured


class MemoryCapabilities:
    def __init__(self):
        self.rows = {}
        self.calls = []
        self.serial = 0
        self.fail_revoke = False
        self.lose_ensure_response = False
        self.lose_revoke_response = False

    async def inventory(self):
        return tuple(self.rows[key] for key in sorted(self.rows))

    async def ensure(self, grant):
        self.serial += 1
        row = InstalledCapability(
            grant.binding,
            grant.fingerprint,
            f"credential-{self.serial}",
        )
        self.rows[row.binding] = row
        self.calls.append(("ensure", row.handle))
        if self.lose_ensure_response:
            self.lose_ensure_response = False
            raise RuntimeError("provider lost ensure response")
        return row

    async def revoke(self, row):
        self.calls.append(("revoke", row.handle))
        if self.fail_revoke:
            raise RuntimeError("provider unavailable")
        assert self.rows.pop(row.binding) == row
        if self.lose_revoke_response:
            self.lose_revoke_response = False
            raise RuntimeError("provider lost revoke response")

    def accepts(self, handle):
        return any(row.handle == handle for row in self.rows.values())


def test_reconciliation_is_idempotent_and_revokes_stale_credentials_first():
    world = service_world()
    grant = ServiceGrant(
        world["target"].fid,
        world["operations"].fid,
        world["service"],
        world["service"],
        world["binding"].fid,
        world["provider"],
        world["capability"],
    )
    adapter = MemoryCapabilities()
    reconciler = CapabilityReconciler(adapter)

    first = run(reconciler.reconcile((grant,)))
    credential = first.ensured[0]
    assert adapter.accepts(credential.handle)
    assert run(reconciler.reconcile((grant,))).ensured == ()
    assert adapter.calls == [("ensure", credential.handle)]

    revoked = run(reconciler.reconcile(()))
    assert revoked.revoked == (credential,)
    assert not adapter.accepts(credential.handle)
    assert run(reconciler.reconcile(())).revoked == ()

    stale = InstalledCapability(
        grant.binding, "0" * 64, "stale-credential")
    adapter.rows[grant.binding] = stale
    repaired = run(reconciler.reconcile((grant,)))
    assert repaired.revoked == (stale,)
    assert repaired.ensured[0].fingerprint == grant.fingerprint
    assert adapter.calls[-2:] == [
        ("revoke", "stale-credential"),
        ("ensure", repaired.ensured[0].handle),
    ]


def test_reconciliation_never_widens_when_stale_revocation_fails():
    world = service_world()
    grant = ServiceGrant(
        world["target"].fid,
        world["operations"].fid,
        world["service"],
        world["service"],
        world["binding"].fid,
        world["provider"],
        world["capability"],
    )
    adapter = MemoryCapabilities()
    stale = InstalledCapability(
        grant.binding, "0" * 64, "stale-credential")
    adapter.rows[grant.binding] = stale
    adapter.fail_revoke = True

    with pytest.raises(RuntimeError, match="provider unavailable"):
        run(CapabilityReconciler(adapter).reconcile((grant,)))
    assert adapter.rows == {grant.binding: stale}
    assert adapter.calls == [("revoke", "stale-credential")]


def test_reconciliation_converges_after_applied_effect_responses_are_lost():
    world = service_world()
    grant = ServiceGrant(
        world["target"].fid,
        world["operations"].fid,
        world["service"],
        world["service"],
        world["binding"].fid,
        world["provider"],
        world["capability"],
    )
    adapter = MemoryCapabilities()
    reconciler = CapabilityReconciler(adapter)

    adapter.lose_ensure_response = True
    with pytest.raises(RuntimeError, match="lost ensure response"):
        run(reconciler.reconcile((grant,)))
    created = tuple(adapter.rows.values())
    assert len(created) == 1
    assert run(reconciler.reconcile((grant,))).current == created
    assert adapter.calls == [("ensure", created[0].handle)]

    adapter.lose_revoke_response = True
    with pytest.raises(RuntimeError, match="lost revoke response"):
        run(reconciler.reconcile(()))
    assert adapter.rows == {}
    assert run(reconciler.reconcile(())).current == ()
    assert adapter.calls[-1] == ("revoke", created[0].handle)
