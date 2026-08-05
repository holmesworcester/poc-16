"""Crash-safe exact permits for control-bearing writer-head transitions."""

import asyncio

import pytest

import facts
from core.access import (
    AccessGate,
    ControlHeadRetry,
    LookupActive,
    LookupRefresh,
)
from core.close import (
    decode_signed_pile,
    encode_signed_pile,
    make_signed_pile,
)
from core.crypto import h, keypair
from core.head_permit import decode as decode_permit
from core.limits import (
    MAX_HEAD_CONTROL_FACTS,
    MAX_HEAD_REMOVAL_UPDATES,
    PayloadTooLarge,
)
from core.object_store import ABSENT, REMOVAL_ROOT_KEY
from core.removal_state import ControlHeadPlan
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
from facts.auth.admin import admin
from facts.auth.head_request import head_request
from facts.auth.removal import removal
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace


PERMIT_SECRET = b"exact control-head permit secret" * 2


def run(awaitable):
    return asyncio.run(awaitable)


class OverlapCasStore:
    """Awaited store that fails unless two selected CAS calls really overlap."""

    def __init__(self, backing):
        self.backing = backing
        self.selected = None
        self.expected = []
        self.failure = None
        self.release = asyncio.Event()
        self.selected_read = None
        self.reads = []
        self.read_failure = None
        self.read_release = asyncio.Event()

    def overlap(self, key):
        self.selected = key

    def overlap_reads(self, key):
        self.selected_read = key

    async def get_bounded(self, key, maximum):
        return self.backing.get_bounded(key, maximum)

    async def copy_pile_object(self, oid, maximum, write):
        return self.backing.copy_pile_object(oid, maximum, write)

    async def has(self, key):
        return self.backing.has(key)

    async def read_versioned(self, key):
        opened = self.backing.read_versioned(key)
        if key == self.selected_read and not self.read_release.is_set():
            self.reads.append(opened)
            if len(self.reads) == 1:
                asyncio.get_running_loop().call_soon(
                    self._check_read_overlap)
            elif len(self.reads) == 2:
                self.read_release.set()
            await self.read_release.wait()
            if self.read_failure is not None:
                raise self.read_failure
        return opened

    async def put_if_absent(self, key, value):
        return self.backing.put_if_absent(key, value)

    async def cas(self, key, token, value):
        if key == self.selected and not self.release.is_set():
            self.expected.append(token)
            if len(self.expected) == 1:
                asyncio.get_running_loop().call_soon(self._check_overlap)
            elif len(self.expected) == 2:
                self.release.set()
            await self.release.wait()
            if self.failure is not None:
                raise self.failure
        return self.backing.cas(key, token, value)

    def _check_overlap(self):
        if len(self.expected) != 2:
            self.failure = AssertionError(
                "same-base control commits serialized before slot CAS")
            self.release.set()

    def _check_read_overlap(self):
        if len(self.reads) != 2:
            self.read_failure = AssertionError(
                "same-root control commits serialized before freshness read")
            self.read_release.set()

    async def list_page(self, prefix, cursor=None, limit=256):
        return self.backing.list_page(prefix, cursor, limit)


def signed(secret, writer, root, closure):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, writer, closure))


def founder_world():
    secret, founder = keypair()
    root = workspace(secret, founder, "terminal workspace", 1)
    return secret, founder, root


def exact_head_proof(
        secret, writer, root, closure, basis, head, base=None, *, exp=1_000):
    item = head_request(
        root.fid, writer, writer, base, head, exp, basis, 21)
    return signed(secret, writer, root, (item,))


def self_removal_pile(secret, writer, root, *, ts=30):
    action = removal(root.fid, writer, writer, ts)
    action_signature = signature(secret, writer, action, ts)
    return action, signed(
        secret, writer, root, (root, action_signature, action))


def joined_member(founder_secret, founder, root, index):
    invite_secret, invite_public = keypair()
    invite = user_invite(
        root.fid, founder, invite_public, 100 + 3 * index)
    invite_signature = signature(
        founder_secret, founder, invite, invite.ts)
    member_secret, member = keypair()
    joined = user(
        invite, invite_secret, member, f"member {index}", invite.ts + 1)
    joined_signature = signature(
        member_secret, member, joined, joined.ts)
    return member_secret, member, (
        root, invite_signature, invite, joined_signature, joined)


def establish_opaque_head(store, label):
    raw = label.encode()
    oid = h(raw)
    store.put_if_absent("obj/" + oid, raw)
    return oid


async def establish_control_head(
        tmp_path, store, secret, writer, root, controls, label):
    """Build the real signed dual-tree head declared by exact control piles."""
    source = FsStore(str(tmp_path / (label + "-writer")))
    log = WriterLog(
        root.fid,
        writer,
        writer,
        writer_store_binding(root.fid, writer),
        secret,
        source,
    )
    closures = tuple(decode_signed_pile(raw).facts for raw in controls)
    update = await log.prepare(closures)
    await log.establish(update, store)
    return update.head_oid


async def value_at(gate, sid):
    pin = await gate.state.pin()
    proof = None if pin is None else await pin.proof(sid)
    return None if proof is None else pin.verify(sid, proof)


async def issued_terminal(tmp_path, label="terminal"):
    secret, founder, root = founder_world()
    store = FsStore(str(tmp_path / label))
    gate = AccessGate(root.fid, store)
    bootstrap = signed(secret, founder, root, (root,))
    assert (await gate.state.bootstrap(bootstrap)).status == "applied"
    basis = (await gate.state.pin()).root_oid
    action, control = self_removal_pile(secret, founder, root)
    proposed = await establish_control_head(
        tmp_path, store, secret, founder, root, (control,), label)
    proof = exact_head_proof(
        secret, founder, root, (root,), basis, proposed)
    permit = await gate.issue_head_permit(
        proof, proposed, (control,), 10, PERMIT_SECRET)
    head_gate = OpaqueHeadGate(store, gate.authorize_head)
    return (
        secret, founder, root, store, gate, head_gate,
        proposed, action, control, permit,
    )


def test_zero_effect_plan_cannot_mint_an_alternate_ordinary_head_permit():
    with pytest.raises(ValueError, match="control head plan"):
        ControlHeadPlan(
            h(b"workspace"), h(b"writer"), (), 1, 1, 1)


def test_self_removal_is_applied_before_one_final_head(tmp_path):
    async def scenario():
        (secret, founder, root, store, gate, head_gate,
         proposed, action, _control, permit) = await issued_terminal(tmp_path)
        member_sid = scoped_id("member", founder)
        key = head_slot_key(root.fid, founder)
        assert isinstance(permit, bytes)
        assert store.read_versioned(key) is ABSENT

        result = await gate.commit_head_permit(
            head_gate, permit, proposed, PERMIT_SECRET)

        assert result.status == "applied"
        assert (await value_at(gate, member_sid)) == suppression_slot(
            action.fid)
        slot = decode_slot_at(key, store.get(key))
        assert (slot.head, slot.removal_root) == (
            proposed, result.slot.removal_root)

        fresh = (await gate.state.pin()).root_oid
        later = establish_opaque_head(store, "later")
        with pytest.raises(LookupActive):
            await gate.authorize_head(
                exact_head_proof(
                    secret, founder, root, (root,), fresh,
                    later, base=proposed),
                later,
                40,
            )

    run(scenario())


def test_signed_control_tree_requires_permit_and_exact_declared_piles(
        tmp_path):
    async def scenario():
        (secret, founder, root, _store, gate, _head_gate,
         proposed, _action, control, permit) = await issued_terminal(
             tmp_path, "declared-controls")
        path = (await gate.state.pin()).root_oid
        proof = exact_head_proof(
            secret, founder, root, (root,), path, proposed)

        # The signed secondary tree makes the ordinary route fail closed.
        assert await gate.authorize_head(proof, proposed, 10) is None
        # A valid but unrelated control closure cannot be attached to this
        # head: permit issuance must match its exact declared suffix.
        unrelated = signed(secret, founder, root, (root,))
        assert await gate.issue_head_permit(
            proof, proposed, (unrelated,), 10, PERMIT_SECRET) is None
        assert isinstance(permit, bytes)
        assert h(control) != h(unrelated)

    run(scenario())


def test_exact_permit_resumes_after_apply_before_slot_cas_process_loss(tmp_path):
    async def scenario():
        (_secret, founder, root, store, gate, head_gate,
         proposed, action, _control, raw) = await issued_terminal(
             tmp_path, "crash")
        permit = decode_permit(raw, PERMIT_SECRET)
        key = head_slot_key(root.fid, founder)
        # Model loss after the irreversible ACI join but before final CAS.
        assert (await gate.state.apply_updates(permit.updates)).status \
            == "applied"
        assert store.read_versioned(key) is ABSENT
        joined_root = (await gate.state.pin()).root_oid
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot(
                action.fid)

        recovered = await gate.commit_head_permit(
            head_gate, raw, proposed, PERMIT_SECRET)
        assert recovered.status == "applied"
        accepted = decode_slot_at(key, store.get(key))
        assert accepted.removal_root == joined_root

        # A later unrelated root advance does not rewrite the accepted slot.
        assert (await gate.state.tree.apply(((
            scoped_id("member", h(b"unrelated member")),
            suppression_slot(),
        ),))).status == "applied"
        replay = await gate.commit_head_permit(
            head_gate, raw, proposed, PERMIT_SECRET)
        assert replay.status == "noop"
        assert decode_slot_at(key, store.get(key)) == accepted
        assert h(raw) == accepted.permit

    run(scenario())


def test_removed_writer_cannot_issue_a_new_control_head_permit(tmp_path):
    async def scenario():
        secret, founder, root = founder_world()
        store = FsStore(str(tmp_path / "stale"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            secret, founder, root, (root,)))).status == "applied"
        stale_path = (await gate.state.pin()).root_oid
        proposed = establish_opaque_head(store, "stale proposed")
        proof = exact_head_proof(
            secret, founder, root, (root,), stale_path, proposed)
        _action, control = self_removal_pile(secret, founder, root)

        assert (await gate.state.tree.apply(((
            scoped_id("member", founder),
            suppression_slot(h(b"another admin removed founder")),
        ),))).status == "applied"
        with pytest.raises(LookupActive):
            await gate.issue_head_permit(
                proof, proposed, (control,), 10, PERMIT_SECRET)

        current_path = (await gate.state.pin()).root_oid
        current_proof = exact_head_proof(
            secret, founder, root, (root,), current_path, proposed)
        with pytest.raises(LookupActive):
            await gate.issue_head_permit(
                current_proof, proposed, (control,), 10, PERMIT_SECRET)

    run(scenario())


def test_permit_binds_rows_head_secret_and_not_app_projection(
        tmp_path, monkeypatch):
    async def scenario():
        (_secret, founder, _root, _store, gate, head_gate,
         proposed, action, _control, permit) = await issued_terminal(
             tmp_path, "binding")
        changed = bytearray(permit)
        changed[len(changed) // 2] ^= 1
        with pytest.raises(ValueError):
            await gate.commit_head_permit(
                head_gate, bytes(changed), proposed, PERMIT_SECRET)
        with pytest.raises(ValueError):
            await gate.commit_head_permit(
                head_gate, permit, proposed, b"wrong" * 8)
        assert await gate.commit_head_permit(
            head_gate, permit, h(b"different head"), PERMIT_SECRET) is None
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot()

        # Closed-pile semantics run only during issuance. Neither a replay
        # version bump nor a disabled evaluator can change an issued permit.
        monkeypatch.setattr(facts, "APP_VERSION", facts.APP_VERSION + 1)
        monkeypatch.setattr(
            gate.state,
            "plan_control",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("commit re-evaluated control piles")),
        )
        result = await gate.commit_head_permit(
            head_gate, permit, proposed, PERMIT_SECRET)
        assert result.status == "applied"
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot(
                action.fid)

    run(scenario())


def test_generic_permit_joins_multiple_control_sinks_once(tmp_path):
    async def scenario():
        founder_secret, founder, root = founder_world()
        _member_secret, member, membership = joined_member(
            founder_secret, founder, root, 1)
        store = FsStore(str(tmp_path / "generic"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            founder_secret, founder, root, (root,)))).status == "applied"
        path = (await gate.state.pin()).root_oid
        action = removal(root.fid, founder, member, 300)
        action_signature = signature(
            founder_secret, founder, action, action.ts)
        membership_pile = signed(
            founder_secret, founder, root, membership)
        removal_pile = signed(
            founder_secret, founder, root,
            (*membership, action_signature, action))
        proposed = await establish_control_head(
            tmp_path,
            store,
            founder_secret,
            founder,
            root,
            (membership_pile, removal_pile),
            "generic",
        )
        proof = exact_head_proof(
            founder_secret, founder, root, (root,), path, proposed)
        permit = await gate.issue_head_permit(
            proof, proposed, (membership_pile, removal_pile),
            10, PERMIT_SECRET)

        result = await gate.commit_head_permit(
            OpaqueHeadGate(store, gate.authorize_head),
            permit,
            proposed,
            PERMIT_SECRET,
        )

        assert result.status == "applied"
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot()
        assert (await value_at(
            gate, scoped_id("member", member))) == suppression_slot(
                action.fid)

    run(scenario())


def test_stale_removal_permit_joins_after_another_device_advances_root(
        tmp_path):
    async def scenario():
        founder_secret, founder, root = founder_world()
        _member_secret, member, membership = joined_member(
            founder_secret, founder, root, 1)
        store = FsStore(str(tmp_path / "concurrent-removal"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            founder_secret, founder, root, (root,)))).status == "applied"
        path = (await gate.state.pin()).root_oid
        action = removal(root.fid, founder, member, 300)
        action_signature = signature(
            founder_secret, founder, action, action.ts)
        control = signed(
            founder_secret, founder, root,
            (*membership, action_signature, action))
        proposed = await establish_control_head(
            tmp_path,
            store,
            founder_secret,
            founder,
            root,
            (control,),
            "preauthorized-admin",
        )
        proof = exact_head_proof(
            founder_secret, founder, root, (root,), path, proposed)
        permit = await gate.issue_head_permit(
            proof, proposed, (control,), 10, PERMIT_SECRET)

        concurrent_action = h(b"concurrent founder removal")
        assert (await gate.state.tree.apply(((
            scoped_id("member", founder),
            suppression_slot(concurrent_action),
        ),))).status == "applied"
        result = await gate.commit_head_permit(
            OpaqueHeadGate(store, gate.authorize_head),
            permit,
            proposed,
            PERMIT_SECRET,
        )
        assert result.status == "applied"
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot(
                concurrent_action)
        assert (await value_at(
            gate, scoped_id("member", member))) == suppression_slot(
                action.fid)
        assert store.read_versioned(
            head_slot_key(root.fid, founder)) is not ABSENT

    run(scenario())


def test_stale_clear_permit_cannot_introduce_authority(tmp_path):
    async def scenario():
        founder_secret, founder, root = founder_world()
        _member_secret, member, membership = joined_member(
            founder_secret, founder, root, 1)
        store = FsStore(str(tmp_path / "stale-clear"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            founder_secret, founder, root, (root,)))).status == "applied"
        path = (await gate.state.pin()).root_oid
        control = signed(founder_secret, founder, root, membership)
        proposed = await establish_control_head(
            tmp_path,
            store,
            founder_secret,
            founder,
            root,
            (control,),
            "stale-clear-candidate",
        )
        proof = exact_head_proof(
            founder_secret, founder, root, (root,), path, proposed)
        permit = await gate.issue_head_permit(
            proof, proposed, (control,), 10, PERMIT_SECRET)
        decoded = decode_permit(permit, PERMIT_SECRET)
        assert any(value["state"] == "clear"
                   for _sid, value in decoded.updates)

        assert (await gate.state.tree.apply(((
            scoped_id("member", h(b"concurrent removal target")),
            suppression_slot(h(b"concurrent removal action")),
        ),))).status == "applied"
        with pytest.raises(ControlHeadRetry, match="root is stale"):
            await gate.commit_head_permit(
                OpaqueHeadGate(store, gate.authorize_head),
                permit,
                proposed,
                PERMIT_SECRET,
            )
        assert await value_at(gate, scoped_id("member", member)) is None
        assert store.read_versioned(
            head_slot_key(root.fid, founder)) is ABSENT

    run(scenario())


def test_two_device_mutual_removals_both_land_after_delayed_commit(
        tmp_path):
    async def scenario():
        founder_secret, founder, root = founder_world()
        second_secret, second, membership = joined_member(
            founder_secret, founder, root, 1)
        elevated = admin(root.fid, founder, second, 200)
        elevated_signature = signature(
            founder_secret, founder, elevated, elevated.ts)
        second_authority = (
            *membership, elevated_signature, elevated)
        store = FsStore(str(tmp_path / "mutual-removal"))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            founder_secret, founder, root, (root,)))).status == "applied"
        admission = request(
            root.fid, second, second, "sync", 1_000, "", 210)
        admission_signature = signature(
            second_secret, second, admission, admission.ts)
        admitted = await gate.authorize_access(signed(
            second_secret,
            second,
            root,
            (*second_authority, admission_signature, admission),
        ), 220)
        assert admitted is not None
        basis = (await gate.state.pin()).root_oid

        founder_action = removal(
            root.fid, founder, second, 300)
        founder_action_signature = signature(
            founder_secret, founder, founder_action, founder_action.ts)
        founder_control = signed(
            founder_secret,
            founder,
            root,
            (*membership, founder_action_signature, founder_action),
        )
        second_action = removal(
            root.fid, second, founder, 301)
        second_action_signature = signature(
            second_secret, second, second_action, second_action.ts)
        second_control = signed(
            second_secret,
            second,
            root,
            (*second_authority, second_action_signature, second_action),
        )
        proposed = (
            await establish_control_head(
                tmp_path, store, founder_secret, founder, root,
                (founder_control,), "founder-mutual-removal"),
            await establish_control_head(
                tmp_path, store, second_secret, second, root,
                (second_control,), "second-mutual-removal"),
        )
        proofs = (
            exact_head_proof(
                founder_secret, founder, root, (root,), basis,
                proposed[0]),
            exact_head_proof(
                second_secret, second, root, second_authority, basis,
                proposed[1]),
        )
        permits = (
            await gate.issue_head_permit(
                proofs[0], proposed[0], (founder_control,), 220,
                PERMIT_SECRET),
            await gate.issue_head_permit(
                proofs[1], proposed[1], (second_control,), 220,
                PERMIT_SECRET),
        )
        for permit in permits:
            decoded = decode_permit(permit, PERMIT_SECRET)
            assert decoded.removal_root == basis
            assert all(value["state"] == "active"
                       for _sid, value in decoded.updates)

        head_gate = OpaqueHeadGate(store, gate.authorize_head)
        first = await gate.commit_head_permit(
            head_gate, permits[0], proposed[0], PERMIT_SECRET)
        # This commit deliberately begins only after the first root and head
        # are durable. It exercises stale-root recovery, not an overlapping
        # CAS whose in-turn retry happens to hide the schedule.
        second_result = await gate.commit_head_permit(
            head_gate, permits[1], proposed[1], PERMIT_SECRET)
        assert (first.status, second_result.status) == (
            "applied", "applied")
        assert (await value_at(
            gate, scoped_id("member", second))) == suppression_slot(
                founder_action.fid)
        assert (await value_at(
            gate, scoped_id("member", founder))) == suppression_slot(
                second_action.fid)
        for device, head, accepted in zip(
                (founder, second), proposed, (first, second_result)):
            slot = decode_slot_at(
                head_slot_key(root.fid, device),
                store.get(head_slot_key(root.fid, device)),
            )
            assert slot.head == head
            assert slot.removal_root == accepted.slot.removal_root

    run(scenario())


def test_two_same_base_permits_apply_fail_safe_rows_then_one_head_wins(tmp_path):
    async def scenario():
        secret, founder, root = founder_world()
        members = tuple(
            joined_member(secret, founder, root, index)
            for index in range(2))
        store = OverlapCasStore(FsStore(str(tmp_path / "competing")))
        gate = AccessGate(root.fid, store)
        assert (await gate.state.bootstrap(signed(
            secret, founder, root, (root,)))).status == "applied"
        path = (await gate.state.pin()).root_oid
        heads, permits, actions = [], [], []
        for index, (_member_secret, member, closure) in enumerate(members):
            action = removal(root.fid, founder, member, 400 + index)
            action_signature = signature(
                secret, founder, action, action.ts)
            controls = (
                signed(secret, founder, root, closure),
                signed(secret, founder, root,
                       (*closure, action_signature, action)),
            )
            head = await establish_control_head(
                tmp_path,
                store,
                secret,
                founder,
                root,
                controls,
                f"candidate-{index}",
            )
            heads.append(head)
            proof = exact_head_proof(
                secret, founder, root, (root,), path, head)
            permits.append(await gate.issue_head_permit(
                proof, head, controls, 10, PERMIT_SECRET))
            actions.append(action)
        heads = tuple(heads)

        head_gate = OpaqueHeadGate(store, gate.authorize_head)
        key = head_slot_key(root.fid, founder)
        store.overlap_reads(REMOVAL_ROOT_KEY)
        store.overlap(key)
        results = await asyncio.gather(*(
            gate.commit_head_permit(
                head_gate, permit, head, PERMIT_SECRET)
            for permit, head in zip(permits, heads)
        ))
        assert sorted(result.status for result in results) \
            == ["applied", "conflict"]
        assert len(store.expected) == 2
        assert store.expected[0] == store.expected[1] is ABSENT
        assert len(store.reads) == 2
        assert store.reads[0] == store.reads[1]
        winner = next(
            index for index, result in enumerate(results)
            if result.status == "applied")
        winner_sid = scoped_id("member", members[winner][1])
        assert await value_at(gate, winner_sid) == suppression_slot(
            actions[winner].fid)
        for index, (_secret, member, _closure) in enumerate(members):
            assert await value_at(
                gate, scoped_id("member", member)) == suppression_slot(
                    actions[index].fid)
        slot = decode_slot_at(
            key,
            store.backing.get(key),
        )
        assert slot.head == heads[winner]

    run(scenario())


def test_ordinary_same_base_can_win_after_control_effects_before_cas(
        tmp_path):
    async def scenario():
        (_secret, founder, root, store, gate, head_gate,
         proposed, _action, _control, raw) = await issued_terminal(
             tmp_path, "ordinary-race")
        permit = decode_permit(raw, PERMIT_SECRET)
        ordinary = establish_opaque_head(store, "ordinary loser")
        # Inject the competing ordinary CAS at the exact crash point between
        # the control effect and its one final slot CAS.
        assert (await gate.state.apply_updates(permit.updates)).status \
            == "applied"
        plain = await head_gate.advance_grant(HeadGrant(
            root.fid, founder, None, ordinary, permit.removal_root))
        control = await gate.commit_head_permit(
            head_gate, raw, proposed, PERMIT_SECRET)
        assert (plain.status, control.status) == ("applied", "conflict")
        assert (await value_at(
            gate, scoped_id("member", founder)))["state"] == "active"
        accepted = decode_slot_at(
            head_slot_key(root.fid, founder),
            store.get(head_slot_key(root.fid, founder)),
        )
        assert accepted.head == ordinary

    run(scenario())


def test_aggregate_control_fact_and_row_bounds_are_exact(tmp_path):
    secret, founder, root = founder_world()
    store = FsStore(str(tmp_path / "bounds"))
    gate = AccessGate(root.fid, store)
    root_pile = signed(secret, founder, root, (root,))
    _action, removal_pile = self_removal_pile(secret, founder, root)

    # 84 three-fact removals plus four one-fact roots is exactly 256 facts.
    exact = (removal_pile,) * 84 + (root_pile,) * 4
    plan = gate.state.plan_control(exact, founder)
    assert plan.fact_count == MAX_HEAD_CONTROL_FACTS
    with pytest.raises(PayloadTooLarge, match="control facts"):
        gate.state.plan_control(
            (removal_pile,) * 85 + (root_pile,) * 2, founder)

    membership_piles = tuple(
        signed(secret, founder, root, joined_member(
            secret, founder, root, index)[2])
        for index in range(MAX_HEAD_REMOVAL_UPDATES + 1)
    )
    # Each admission reserves member, device, and exact subject binding.
    exact_rows = (root_pile, membership_piles[0])
    assert len(gate.state.plan_control(exact_rows, founder).updates) \
        == MAX_HEAD_REMOVAL_UPDATES
    with pytest.raises(PayloadTooLarge, match="removal updates"):
        gate.state.plan_control(
            (*exact_rows, membership_piles[1]), founder)


def test_owner_publisher_reuses_only_the_issued_permit_after_retry(tmp_path):
    async def scenario():
        secret, founder, root = founder_world()
        local = FsStore(str(tmp_path / "publisher-local"))
        remote = FsStore(str(tmp_path / "publisher-remote"))
        binding = WriterBinding(
            root.fid, founder, founder,
            writer_store_binding(root.fid, founder))
        writer = WriterLog(
            root.fid, founder, founder, binding.store, secret, local)
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
        issues, commits = [], []

        async def make_proof(base, proposed):
            path = (await access.state.pin()).root_oid
            return exact_head_proof(
                secret, founder, root, (root,), path, proposed, base)

        async def issue(proof, proposed, controls):
            permit = await access.issue_head_permit(
                proof, proposed, controls, 10, PERMIT_SECRET)
            issues.append(permit)
            return permit

        async def commit(permit, proposed):
            commits.append(permit)
            result = await access.commit_head_permit(
                head_gate, permit, proposed, PERMIT_SECRET)
            # Model a lost first response after the exact operation completed.
            return "retryable" if len(commits) == 1 else result

        published = await OwnerPublisher(
            root.fid,
            founder,
            binding,
            local,
            remote,
            make_proof,
            issue,
            commit,
            lambda *_args: (_ for _ in ()).throw(
                AssertionError("control head used ordinary authorization")),
            lambda _attempt: None,
        ).publish()

        assert published.status == "noop"
        assert len(issues) == 1
        assert commits[0] is commits[1] is issues[0]
        assert decode_slot_at(
            head_slot_key(root.fid, founder),
            remote.get(head_slot_key(root.fid, founder)),
        ).head == update.head_oid

    run(scenario())
