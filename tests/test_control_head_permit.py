"""Crash-safe exact permits for control-bearing writer-head transitions."""

import asyncio
import pytest

from core.access import AccessGate
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.object_store import ABSENT
from core.removal_path import ProofRefreshRequired, RemovalDenied
from core.removal_state import ControlHeadPlan, ControlPilePlan
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.writer_head import (
    WriterBinding,
    decode_slot_at,
    head_slot_key,
    writer_store_binding,
)
from core.writer_repository import (
    HeadGrant,
    OpaqueHeadGate,
    OwnerPublisher,
    WriterLog,
)
from facts.auth.head_request import head_request
from facts.auth.removal import removal
from facts.auth.removal_path_request import removal_path_request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace


PERMIT_SECRET = b"exact control-head permit secret" * 2


def run(awaitable):
    return asyncio.run(awaitable)


def signed(secret, writer, root, closure):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, writer, closure))


def founder_world():
    secret, founder = keypair()
    root = workspace(secret, founder, "terminal workspace", 1)
    return secret, founder, root


def historical_proof(secret, writer, root, closure, *, exp=1_000):
    item = removal_path_request(
        root.fid, writer, writer, exp, 20)
    item_signature = signature(secret, writer, item, 20)
    return signed(
        secret, writer, root, (*closure, item_signature, item))


def exact_head_proof(
        secret, writer, root, closure, path, head, base=None, *, exp=1_000):
    item = head_request(
        root.fid, writer, writer, base, head, exp, path, 21)
    item_signature = signature(secret, writer, item, 21)
    return signed(
        secret, writer, root, (*closure, item_signature, item))


def self_removal_pile(secret, writer, root, *, ts=30):
    action = removal(root.fid, writer, writer, ts)
    action_signature = signature(secret, writer, action, ts)
    return action, signed(
        secret, writer, root, (root, action_signature, action))


def establish_opaque_head(store, label):
    raw = label.encode()
    oid = h(raw)
    store.put_if_absent("obj/" + oid, raw)
    return oid


async def value_at(gate, sid):
    pin = await gate.state.pin()
    proof = None if pin is None else await pin.proof(sid)
    return None if proof is None else pin.verify(sid, proof)


def test_zero_effect_plan_cannot_mint_an_alternate_ordinary_head_permit():
    with pytest.raises(ValueError, match="control head plan"):
        ControlHeadPlan(
            h(b"workspace"),
            h(b"writer"),
            (ControlPilePlan(h(b"evidence-only pile"), ()),),
            1,
        )


async def issued_terminal(tmp_path, label="terminal"):
    secret, founder, root = founder_world()
    store = FsStore(str(tmp_path / label))
    gate = AccessGate(root.fid, store)
    bootstrap = signed(secret, founder, root, (root,))
    assert (await gate.state.bootstrap(bootstrap)).status == "applied"
    path = await gate.removal_path(
        historical_proof(secret, founder, root, (root,)), 10)
    proposed = establish_opaque_head(store, label + " head")
    proof = exact_head_proof(
        secret, founder, root, (root,), path, proposed)
    action, control = self_removal_pile(secret, founder, root)
    permit = await gate.issue_head_permit(
        proof, proposed, (control,), 10, PERMIT_SECRET)
    return secret, founder, root, store, gate, proposed, action, control, permit


def test_self_removal_is_applied_before_one_final_head(tmp_path):
    async def scenario():
        (_secret, founder, root, store, gate, proposed,
         action, control, permit) = await issued_terminal(tmp_path)
        member_sid = scoped_id("member", founder)

        assert isinstance(permit, bytes)
        assert (await value_at(gate, member_sid)) == suppression_slot()
        key = head_slot_key(root.fid, founder)
        assert store.read_versioned(key) is ABSENT

        grant = await gate.authorize_permitted_head(
            permit, proposed, (control,), PERMIT_SECRET)
        assert grant is not None
        assert (await value_at(gate, member_sid)) == suppression_slot(
            action.fid)
        # Returning the typed grant is still effect-free with respect to the
        # writer slot: removal necessarily precedes its separate CAS.
        assert store.read_versioned(key) is ABSENT

        advanced = await OpaqueHeadGate(
            store, gate.authorize_head).advance_grant(grant)
        assert advanced.status == "applied"
        slot = decode_slot_at(key, store.get(key))
        assert (slot.head, slot.removal_root) == (
            proposed, grant.removal_root)

        fresh = await gate.removal_path(
            historical_proof(
                _secret, founder, root, (root,)), 40)
        later = establish_opaque_head(store, "later")
        with pytest.raises(RemovalDenied):
            await gate.authorize_head(
                exact_head_proof(
                    _secret, founder, root, (root,), fresh,
                    later, base=proposed),
                later,
                40,
            )

    run(scenario())


def test_held_permit_recovers_crash_and_same_head_preserves_first_root(
        tmp_path):
    async def scenario():
        (_secret, founder, root, store, gate, proposed,
         _action, control, permit) = await issued_terminal(
             tmp_path, "crash")
        key = head_slot_key(root.fid, founder)

        # Simulate a process dying after the removal CAS but before head CAS.
        abandoned = await gate.authorize_permitted_head(
            permit, proposed, (control,), PERMIT_SECRET)
        first_root = abandoned.removal_root
        assert store.read_versioned(key) is ABSENT

        recovered = await gate.authorize_permitted_head(
            permit, proposed, (control,), PERMIT_SECRET)
        head_gate = OpaqueHeadGate(store, gate.authorize_head)
        assert (await head_gate.advance_grant(recovered)).status == "applied"
        accepted = decode_slot_at(key, store.get(key))
        assert accepted.removal_root == first_root

        # An unrelated later tree update changes the fresh grant's audit root.
        # Exact replay remains noop and preserves the original accepted slot.
        assert (await gate.state.tree.apply(((
            scoped_id("member", h(b"unrelated member")),
            suppression_slot(),
        ),))).status == "applied"
        replay_grant = await gate.authorize_permitted_head(
            permit, proposed, (control,), PERMIT_SECRET)
        assert replay_grant.removal_root != first_root
        replay = await head_gate.advance_grant(replay_grant)
        assert replay.status == "noop"
        assert replay.slot == accepted
        assert decode_slot_at(key, store.get(key)) == accepted

    run(scenario())


def test_removed_writer_cannot_issue_a_new_control_head_permit(tmp_path):
    async def scenario():
        secret, founder, root = founder_world()
        store = FsStore(str(tmp_path / "stale"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            secret, founder, root, (root,)))).status == "applied"
        historical = historical_proof(
            secret, founder, root, (root,))
        stale_path = await gate.removal_path(historical, 10)
        proposed = establish_opaque_head(store, "stale proposed")
        proof = exact_head_proof(
            secret, founder, root, (root,), stale_path, proposed)
        _action, control = self_removal_pile(secret, founder, root)

        assert (await gate.state.tree.apply(((
            scoped_id("member", founder),
            suppression_slot(h(b"another admin removed founder")),
        ),))).status == "applied"
        with pytest.raises(ProofRefreshRequired):
            await gate.issue_head_permit(
                proof, proposed, (control,), 10, PERMIT_SECRET)

        current_path = await gate.removal_path(historical, 10)
        current_proof = exact_head_proof(
            secret, founder, root, (root,), current_path, proposed)
        with pytest.raises(RemovalDenied):
            await gate.issue_head_permit(
                current_proof, proposed, (control,), 10, PERMIT_SECRET)

    run(scenario())


def test_permit_binds_mac_head_and_exact_ordered_control_effects(tmp_path):
    async def scenario():
        (_secret, founder, _root, _store, gate, proposed,
         _action, control, permit) = await issued_terminal(
             tmp_path, "binding")
        changed = bytearray(permit)
        changed[len(changed) // 2] ^= 1
        with pytest.raises(ValueError):
            await gate.authorize_permitted_head(
                bytes(changed), proposed, (control,), PERMIT_SECRET)
        with pytest.raises(ValueError):
            await gate.authorize_permitted_head(
                permit, proposed, (control,), b"wrong" * 8)
        assert await gate.authorize_permitted_head(
            permit, h(b"different head"), (control,), PERMIT_SECRET) is None

        # A second valid pile has different bytes and effects; neither may be
        # substituted or appended after issuance.
        other_action, other = self_removal_pile(
            _secret, founder, _root, ts=31)
        assert other_action.fid != _action.fid
        assert await gate.authorize_permitted_head(
            permit, proposed, (other,), PERMIT_SECRET) is None
        assert await gate.authorize_permitted_head(
            permit, proposed, (control, other), PERMIT_SECRET) is None
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot()

    run(scenario())


def test_generic_permit_applies_multiple_admin_controls_and_stays_current(
        tmp_path):
    async def scenario():
        founder_secret, founder, root = founder_world()
        invite_secret, invite_public = keypair()
        invite = user_invite(root.fid, founder, invite_public, 2)
        invite_signature = signature(
            founder_secret, founder, invite, 2)
        member_secret, member = keypair()
        joined = user(invite, invite_secret, member, "member", 3)
        joined_signature = signature(member_secret, member, joined, 3)
        membership = (
            root, invite_signature, invite, joined_signature, joined)
        store = FsStore(str(tmp_path / "generic"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            founder_secret, founder, root, (root,)))).status == "applied"

        path = await gate.removal_path(historical_proof(
            founder_secret, founder, root, (root,)), 10)
        proposed = establish_opaque_head(store, "generic head")
        proof = exact_head_proof(
            founder_secret, founder, root, (root,), path, proposed)
        # First reserve the joined member's CLEAR state, then activate it in a
        # separately closed admin pile under one exact head permit.
        action = removal(root.fid, founder, member, 30)
        action_signature = signature(
            founder_secret, founder, action, 30)
        removal_pile = signed(
            founder_secret,
            founder,
            root,
            (*membership, action_signature, action),
        )
        # Every control pile in a hosted owner suffix has the same outer
        # writer. Repackage the joined member closure under the publishing
        # admin's outer pile signature without changing fact authorship.
        membership_pile = signed(
            founder_secret, founder, root, membership)
        piles = (membership_pile, removal_pile)
        permit = await gate.issue_head_permit(
            proof, proposed, piles, 10, PERMIT_SECRET)
        grant = await gate.authorize_permitted_head(
            permit, proposed, piles, PERMIT_SECRET)

        assert grant is not None
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot()
        assert (await value_at(
            gate, scoped_id("member", member))) == suppression_slot(
                action.fid)
        assert (await OpaqueHeadGate(
            store, gate.authorize_head).advance_grant(grant)).status \
            == "applied"

    run(scenario())


def test_concurrent_caller_removal_after_issue_does_not_revoke_exact_permit(
        tmp_path):
    async def scenario():
        founder_secret, founder, root = founder_world()
        invite_secret, invite_public = keypair()
        invite = user_invite(root.fid, founder, invite_public, 2)
        invite_signature = signature(
            founder_secret, founder, invite, 2)
        member_secret, member = keypair()
        joined = user(invite, invite_secret, member, "member", 3)
        joined_signature = signature(member_secret, member, joined, 3)
        membership = (
            root, invite_signature, invite, joined_signature, joined)
        store = FsStore(str(tmp_path / "concurrent-removal"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            founder_secret, founder, root, (root,)))).status == "applied"
        path = await gate.removal_path(historical_proof(
            founder_secret, founder, root, (root,)), 10)
        proposed = establish_opaque_head(store, "preauthorized admin head")
        proof = exact_head_proof(
            founder_secret, founder, root, (root,), path, proposed)
        action = removal(root.fid, founder, member, 30)
        action_signature = signature(
            founder_secret, founder, action, 30)
        control = signed(
            founder_secret,
            founder,
            root,
            (*membership, action_signature, action),
        )
        permit = await gate.issue_head_permit(
            proof, proposed, (control,), 10, PERMIT_SECRET)

        # Authorization linearized above. A later removal cannot amplify this
        # exact capability, nor may it strand its already bound operation.
        concurrent_action = h(b"concurrent founder removal")
        assert (await gate.state.tree.apply(((
            scoped_id("member", founder),
            suppression_slot(concurrent_action),
        ),))).status == "applied"
        grant = await gate.authorize_permitted_head(
            permit, proposed, (control,), PERMIT_SECRET)
        assert grant is not None
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot(
                concurrent_action)
        assert (await value_at(
            gate, scoped_id("member", member))) == suppression_slot(
                action.fid)
        assert (await OpaqueHeadGate(
            store, gate.authorize_head).advance_grant(grant)).status \
            == "applied"

    run(scenario())


def test_two_preissued_terminal_heads_share_base_but_only_one_cas_wins(
        tmp_path):
    async def scenario():
        secret, founder, root = founder_world()
        store = FsStore(str(tmp_path / "competing"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            secret, founder, root, (root,)))).status == "applied"
        path = await gate.removal_path(historical_proof(
            secret, founder, root, (root,)), 10)
        _action, control = self_removal_pile(secret, founder, root)
        heads = tuple(
            establish_opaque_head(store, f"candidate {index}")
            for index in range(2))
        proofs = tuple(
            exact_head_proof(
                secret, founder, root, (root,), path, head)
            for head in heads)
        permits = tuple([
            await gate.issue_head_permit(
                proof, head, (control,), 10, PERMIT_SECRET)
            for proof, head in zip(proofs, heads)
        ])
        grants = tuple([
            await gate.authorize_permitted_head(
                permit, head, (control,), PERMIT_SECRET)
            for permit, head in zip(permits, heads)
        ])
        head_gate = OpaqueHeadGate(store, gate.authorize_head)
        first = await head_gate.advance_grant(grants[0])
        second = await head_gate.advance_grant(grants[1])

        assert first.status == "applied"
        assert second.status == "retryable"
        slot = decode_slot_at(
            head_slot_key(root.fid, founder),
            store.get(head_slot_key(root.fid, founder)),
        )
        assert slot.head == heads[0]

    run(scenario())


def test_owner_publisher_reuses_one_permit_after_terminal_commit_409(
        tmp_path):
    async def scenario():
        secret, founder, root = founder_world()
        local = FsStore(str(tmp_path / "terminal-publisher-local"))
        remote = FsStore(str(tmp_path / "terminal-publisher-remote"))
        binding = WriterBinding(
            root.fid,
            founder,
            founder,
            writer_store_binding(root.fid, founder),
        )
        writer = WriterLog(
            root.fid,
            founder,
            founder,
            binding.store,
            secret,
            local,
        )
        action, _raw = self_removal_pile(secret, founder, root)
        action_signature = signature(secret, founder, action, action.ts)
        update = await writer.prepare(((root, action_signature, action),))
        await writer.establish(update)

        async def local_authorize(_proof, proposed, _now):
            return HeadGrant(
                root.fid, founder, None, proposed, h(b"local removal"))

        assert (await OpaqueHeadGate(
            local, local_authorize).advance(
                b"local", update.head_oid, 10)).status == "applied"

        access = AccessGate(root.fid, remote)
        assert (await access.state.bootstrap(signed(
            secret, founder, root, (root,)))).status == "applied"
        head_gate = OpaqueHeadGate(remote, access.authorize_head)
        issues = []
        commits = []

        async def make_proof(base, proposed):
            path = await access.removal_path(historical_proof(
                secret, founder, root, (root,)), 10)
            return exact_head_proof(
                secret, founder, root, (root,), path, proposed, base)

        async def issue(proof, proposed, controls):
            permit = await access.issue_head_permit(
                proof, proposed, controls, 10, PERMIT_SECRET)
            issues.append(permit)
            return permit

        async def commit(permit, proposed, controls):
            commits.append((permit, controls))
            grant = await access.authorize_permitted_head(
                permit, proposed, controls, PERMIT_SECRET)
            assert (await value_at(
                access, scoped_id("member", founder))) == suppression_slot(
                    action.fid)
            if len(commits) == 1:
                # Model the typed HTTP 409/lost response after removal CAS.
                # A fresh issuance is now impossible, so only the held exact
                # permit can finish this terminal head.
                return "retryable"
            return await head_gate.advance_grant(grant, proposed)

        async def ordinary_advance(_proof, _proposed):
            raise AssertionError("control head used ordinary authorization")

        published = await OwnerPublisher(
            root.fid,
            founder,
            binding,
            local,
            remote,
            make_proof,
            issue,
            commit,
            ordinary_advance,
            lambda _attempt: None,
        ).publish()

        assert published.status == "applied"
        assert len(issues) == 1
        assert len(commits) == 2
        assert commits[0][0] is commits[1][0] is issues[0]
        assert commits[0][1] is commits[1][1]
        slot = decode_slot_at(
            head_slot_key(root.fid, founder),
            remote.get(head_slot_key(root.fid, founder)),
        )
        assert slot.head == update.head_oid

    run(scenario())
