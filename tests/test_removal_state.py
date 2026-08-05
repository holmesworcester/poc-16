"""Recipient removal state from exact original signed control piles."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from core.close import encode_signed_pile, make_signed_pile, signed_pile_oid
from core.crypto import h, keypair
from core.limits import MAX_CONTROL_APPLY_ATTEMPTS
from core.object_store import ABSENT, REMOVAL_ROOT_KEY
from core.removal_state import RecipientRemovalState
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.removal_tree import RemovalTree
from core.writer_head import (
    HeadSlot,
    WriterBinding,
    decode_slot_at,
    encode_head,
    encode_slot,
    head_oid,
    head_slot_key,
    make_head,
    writer_store_binding,
)
from core.writer_repository import (
    FactConsumer,
    HeadGrant,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
from core.writer_tree import build_tree, leaf_row
from facts.auth.device import device as device_fact
from facts.auth.device_invite import device_invite
from facts.auth.removal import removal
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from facts.content.message import message
from tests.shared_bucket import ScriptedBucket


def run(awaitable):
    return asyncio.run(awaitable)


@dataclass(frozen=True)
class World:
    founder_secret: object
    founder: str
    root: object
    member_secret: object
    member: str
    membership: tuple


def world():
    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, "workspace", 1)
    invite_secret, invite_public = keypair()
    invite = user_invite(root.fid, founder, invite_public, 2)
    invite_sig = signature(founder_secret, founder, invite, 2)
    member_secret, member = keypair()
    joined = user(invite, invite_secret, member, "member", 3)
    joined_sig = signature(member_secret, member, joined, 3)
    return World(
        founder_secret,
        founder,
        root,
        member_secret,
        member,
        (root, invite_sig, invite, joined_sig, joined),
    )


def signed(secret, writer, root, closure):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, writer, closure))


async def value_at(state, sid):
    pin = await state.pin()
    if pin is None:
        return None
    proof = await pin.proof(sid)
    return None if proof is None else pin.verify(sid, proof)


async def accept_one(store, secret, writer, owner, root, closure):
    log = WriterLog(
        root.fid,
        writer,
        owner,
        writer_store_binding(root.fid, writer),
        secret,
        store,
    )
    update = await log.prepare((closure,))
    await log.establish(update)

    async def authorize(_proof, proposed_head, _trusted_now):
        return HeadGrant(
            root.fid,
            writer,
            update.base_head,
            proposed_head,
            h(b"accepted removal view"),
        )

    advanced = await OpaqueHeadGate(store, authorize).advance(
        b"discarded test proof", update.head_oid, 10)
    assert advanced.status == "applied"
    return update


class PileHandle:
    """Give the deterministic shared bucket its ordinary pile data plane."""

    def __init__(self, handle):
        self.handle = handle

    def __getattr__(self, name):
        return getattr(self.handle, name)

    def copy_pile_object(self, oid, maximum, write):
        raw = self.handle.get_bounded("obj/" + oid, maximum)
        if raw is None:
            return None
        write(raw)
        return len(raw)


def test_founder_and_joined_member_bootstrap_from_original_clear_piles(
        tmp_path):
    value = world()
    cases = (
        ("founder", value.founder_secret, value.founder, (value.root,)),
        ("joined", value.member_secret, value.member, value.membership),
    )
    for label, secret, writer, closure in cases:
        state = RecipientRemovalState(
            value.root.fid, FsStore(str(tmp_path / label)))
        outcome = run(state.bootstrap(signed(
            secret, writer, value.root, closure)))

        assert outcome.status == "applied"
        assert outcome.root_oid == run(state.pin()).root_oid
        assert run(value_at(
            state, scoped_id("member", writer))) == suppression_slot()
        assert run(state.bootstrap(signed(
            secret, writer, value.root, closure))).status == "noop"


def test_bootstrap_rejects_secondary_device_content_and_active_state(
        tmp_path):
    value = world()
    primary = device_fact(
        value.root.fid, value.founder, "primary", 4)
    primary_sig = signature(
        value.founder_secret, value.founder, primary, 4)
    secondary_secret, secondary = keypair()
    grant = device_invite(
        value.root.fid, value.founder, secondary, "phone", 5)
    grant_sig = signature(
        value.founder_secret, value.founder, grant, 5)
    secondary_pile = signed(
        secondary_secret,
        secondary,
        value.root,
        (value.root, primary_sig, primary, grant_sig, grant),
    )

    ordinary = message(
        value.root.fid, value.founder, "general", "hello", 6)
    ordinary_sig = signature(
        value.founder_secret, value.founder, ordinary, 6)
    mixed_pile = signed(
        value.founder_secret,
        value.founder,
        value.root,
        (value.root, ordinary_sig, ordinary),
    )

    evicted = removal(
        value.root.fid, value.founder, value.member, 7)
    evicted_sig = signature(
        value.founder_secret, value.founder, evicted, 7)
    active_pile = signed(
        value.founder_secret,
        value.founder,
        value.root,
        (*value.membership, evicted_sig, evicted),
    )

    for label, pile in (
            ("secondary", secondary_pile),
            ("mixed", mixed_pile),
            ("active", active_pile)):
        state = RecipientRemovalState(
            value.root.fid, FsStore(str(tmp_path / label)))
        assert run(state.bootstrap(pile)).status == "rejected"
        assert run(state.pin()) is None


def test_accepted_historical_admin_removal_restarts_and_replays(tmp_path):
    value = world()
    store = FsStore(str(tmp_path / "recipient"))
    state = RecipientRemovalState(value.root.fid, store)
    assert run(state.bootstrap(signed(
        value.member_secret,
        value.member,
        value.root,
        value.membership,
    ))).status == "applied"

    evicted = removal(
        value.root.fid, value.founder, value.member, 4)
    evicted_sig = signature(
        value.founder_secret, value.founder, evicted, 4)
    removal_pile = signed(
        value.founder_secret,
        value.founder,
        value.root,
        (*value.membership, evicted_sig, evicted),
    )

    applied = run(state.apply_control(removal_pile, value.founder))
    assert applied.status == "applied"
    assert run(value_at(
        state,
        scoped_id("member", value.member),
    )) == suppression_slot(evicted.fid)

    restarted = RecipientRemovalState(value.root.fid, FsStore(
        str(tmp_path / "recipient")))
    assert run(restarted.pin()).root_oid == applied.root_oid
    assert run(restarted.apply_control(
        removal_pile, value.founder)).status == "noop"
    assert run(restarted.apply_control(
        b"not a pile", value.founder)).status == "rejected"
    assert run(restarted.pin()).root_oid == applied.root_oid


def test_forged_accepted_pile_binding_is_rejected_without_state(tmp_path):
    value = world()
    attacker_secret, attacker = keypair()
    hostile = signed(
        attacker_secret, attacker, value.root, (value.root,))
    store = FsStore(str(tmp_path / "forged"))
    state = RecipientRemovalState(value.root.fid, store)

    outcome = run(state.apply_control(hostile, value.founder))

    assert outcome.status == "rejected"
    assert outcome.root_oid is None
    assert run(state.pin()) is None


def test_access_like_pile_is_discarded_without_mutating_existing_state(
        tmp_path):
    value = world()
    state = RecipientRemovalState(
        value.root.fid, FsStore(str(tmp_path / "recipient")))
    assert run(state.bootstrap(signed(
        value.member_secret,
        value.member,
        value.root,
        value.membership,
    ))).status == "applied"
    before = run(state.pin()).root_oid
    access = request(
        value.root.fid,
        value.member,
        value.member,
        "sync",
        1_000,
        "",
        8,
    )
    access_sig = signature(
        value.member_secret, value.member, access, 8)
    proof = signed(
        value.member_secret,
        value.member,
        value.root,
        (*value.membership, access_sig, access),
    )

    assert run(state.bootstrap(proof)).status == "rejected"
    assert run(state.pin()).root_oid == before


def test_partial_stale_advance_is_retryable_and_idempotent():
    value = world()
    bucket = ScriptedBucket()
    recipient_store = PileHandle(bucket.handle("recipient"))
    recipient = RecipientRemovalState(value.root.fid, recipient_store)
    assert run(recipient.bootstrap(signed(
        value.founder_secret,
        value.founder,
        value.root,
        (value.root,),
    ))).status == "applied"

    primary = device_fact(
        value.root.fid, value.member, "member primary", 4)
    primary_sig = signature(
        value.member_secret, value.member, primary, 4)
    primary_pile = signed(
        value.member_secret,
        value.member,
        value.root,
        (*value.membership, primary_sig, primary),
    )

    # One whole control plan performs one aggregate root CAS.
    paused = bucket.pause(
        "recipient", "cas", REMOVAL_ROOT_KEY, nth=1)
    other_sid = scoped_id("member", h(b"concurrent member"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        advancing = pool.submit(
            run, recipient.apply_control(primary_pile, value.member))
        paused.wait()
        concurrent = RemovalTree(
            value.root.fid, PileHandle(bucket.handle("concurrent")))
        assert run(concurrent.apply((
            (other_sid, suppression_slot()),
        ))).status == "applied"
        paused.release.set()
        outcome = advancing.result()

    assert outcome.status == "retryable"
    assert outcome.root_oid == run(recipient.pin()).root_oid
    # The aggregate plan is all-or-nothing at the recipient root.  A stale
    # root CAS publishes none of this pile's cells; retry applies them all.
    assert run(value_at(
        recipient,
        scoped_id("member", value.member),
    )) is None
    assert run(value_at(
        recipient,
        scoped_id("device", value.member),
    )) is None
    assert run(value_at(recipient, other_sid)) == suppression_slot()

    assert run(recipient.apply_control(
        primary_pile, value.member)).status == "applied"
    assert run(recipient.apply_control(
        primary_pile, value.member)).status == "noop"
    assert run(value_at(
        recipient,
        scoped_id("device", value.member),
    )) == suppression_slot()
    assert bucket.assert_valid_history()


def test_mirror_retries_pre_cas_control_application_in_the_same_turn(
        tmp_path):
    value = world()
    source = FsStore(str(tmp_path / "source"))
    target = FsStore(str(tmp_path / "target"))
    state = RecipientRemovalState(value.root.fid, target)
    assert run(state.bootstrap(signed(
        value.member_secret,
        value.member,
        value.root,
        value.membership,
    ))).status == "applied"
    evicted = removal(
        value.root.fid, value.founder, value.member, 4)
    evicted_sig = signature(
        value.founder_secret, value.founder, evicted, 4)
    run(accept_one(
        source,
        value.founder_secret,
        value.founder,
        value.founder,
        value.root,
        (*value.membership, evicted_sig, evicted),
    ))
    consumer = FactConsumer(value.root.fid)
    calls = []

    class InterruptedState:
        def plan_control(self, raws, device):
            return state.plan_control(raws, device)

        async def apply_plan(self, plan):
            calls.append((plan.writer, plan.updates))
            if len(calls) == 1:
                return type("Retryable", (), {"status": "retryable"})()
            return await state.apply_plan(plan)

    def exact_binding(workspace_id, device, _removal_root, candidate):
        return WriterBinding(
            workspace_id, device, candidate.owner, candidate.store)

    mirror = RepositoryMirror(
        value.root.fid,
        target,
        exact_binding,
        consumer,
        control_state=InterruptedState(),
    )

    replay = run(mirror.sync_from(source))
    assert replay.errors == ()
    assert replay.changed == 1
    assert len(calls) == 2
    assert calls[0] == calls[1]
    assert calls[0][0] == value.founder
    assert consumer.projected_head(value.founder) is not None
    assert run(value_at(
        state,
        scoped_id("member", value.member),
    )) == suppression_slot(evicted.fid)


def test_mirror_finishes_interrupted_head_before_newer_source_head(tmp_path):
    """A crashed H1 control turn cannot wedge a later H2 sync."""
    value = world()
    source = FsStore(str(tmp_path / "source"))
    target = FsStore(str(tmp_path / "target"))
    state = RecipientRemovalState(value.root.fid, target)
    assert run(state.bootstrap(signed(
        value.member_secret,
        value.member,
        value.root,
        value.membership,
    ))).status == "applied"

    evicted = removal(
        value.root.fid, value.founder, value.member, 4)
    evicted_sig = signature(
        value.founder_secret, value.founder, evicted, 4)
    first = run(accept_one(
        source,
        value.founder_secret,
        value.founder,
        value.founder,
        value.root,
        (*value.membership, evicted_sig, evicted),
    ))
    calls = []

    class ContendedState:
        def plan_control(self, raws, device):
            return state.plan_control(raws, device)

        async def apply_plan(self, plan):
            calls.append(plan)
            return type("Retryable", (), {"status": "retryable"})()

    def exact_binding(workspace_id, device, _removal_root, candidate):
        return WriterBinding(
            workspace_id, device, candidate.owner, candidate.store)

    interrupted = RepositoryMirror(
        value.root.fid,
        target,
        exact_binding,
        FactConsumer(value.root.fid),
        control_state=ContendedState(),
    )
    stalled = run(interrupted.sync_from(source))

    slot_key = head_slot_key(value.root.fid, value.founder)
    assert target.get(slot_key) is None
    assert stalled.changed == stalled.piles == stalled.facts == 0
    assert stalled.errors and "control application" in stalled.errors[0][1]
    assert len(calls) == MAX_CONTROL_APPLY_ATTEMPTS

    later = message(
        value.root.fid, value.founder, "general", "after H1", 5)
    later_sig = signature(
        value.founder_secret, value.founder, later, 5)
    second = run(accept_one(
        source,
        value.founder_secret,
        value.founder,
        value.founder,
        value.root,
        (value.root, later_sig, later),
    ))
    assert second.base_head == first.head_oid

    # Model a process restart: the failed turn left no admission slot. The
    # immutable local objects plus the source's final slot are enough to replay
    # the idempotent control plan before accepting H2.
    restarted_state = RecipientRemovalState(value.root.fid, target)
    restarted_consumer = FactConsumer(value.root.fid)
    caught_up = run(RepositoryMirror(
        value.root.fid,
        target,
        exact_binding,
        restarted_consumer,
        control_state=restarted_state,
    ).sync_from(source))

    assert caught_up.errors == ()
    assert caught_up.changed == 1
    assert decode_slot_at(slot_key, target.get(slot_key)).head \
        == second.head_oid
    assert restarted_consumer.projected_head(value.founder) \
        == second.head_oid
    assert restarted_consumer.fact_bytes(later.fid) is not None
    assert run(value_at(
        restarted_state,
        scoped_id("member", value.member),
    )) == suppression_slot(evicted.fid)


def test_source_replay_finishes_apply_before_slot_crash(tmp_path):
    """Crash recovery recomputes the plan from immutable source bytes."""
    value = world()
    source = FsStore(str(tmp_path / "source"))
    target = FsStore(str(tmp_path / "target"))
    state = RecipientRemovalState(value.root.fid, target)
    assert run(state.bootstrap(signed(
        value.member_secret,
        value.member,
        value.root,
        value.membership,
    ))).status == "applied"
    evicted = removal(
        value.root.fid, value.founder, value.member, 4)
    evicted_sig = signature(
        value.founder_secret, value.founder, evicted, 4)
    update = run(accept_one(
        source,
        value.founder_secret,
        value.founder,
        value.founder,
        value.root,
        (*value.membership, evicted_sig, evicted),
    ))

    class ContendedState:
        def plan_control(self, raws, device):
            return state.plan_control(raws, device)

        async def apply_plan(self, _plan):
            return type("Retryable", (), {"status": "retryable"})()

    def exact_binding(workspace_id, device, _removal_root, candidate):
        return WriterBinding(
            workspace_id, device, candidate.owner, candidate.store)

    stalled = run(RepositoryMirror(
        value.root.fid,
        target,
        exact_binding,
        FactConsumer(value.root.fid),
        control_state=ContendedState(),
    ).sync_from(source))
    assert stalled.errors

    restarted_state = RecipientRemovalState(value.root.fid, target)
    restarted_consumer = FactConsumer(value.root.fid)
    recovered = run(RepositoryMirror(
        value.root.fid,
        target,
        exact_binding,
        restarted_consumer,
        control_state=restarted_state,
    ).sync_from(source))

    slot_key = head_slot_key(value.root.fid, value.founder)
    assert recovered.errors == ()
    assert recovered.changed == 1
    assert decode_slot_at(slot_key, target.get(slot_key)).head \
        == update.head_oid
    assert restarted_consumer.projected_head(value.founder) \
        == update.head_oid
    assert run(value_at(
        restarted_state,
        scoped_id("member", value.member),
    )) == suppression_slot(evicted.fid)


def test_same_base_mirrors_keep_fail_safe_loser_rows_and_one_projection(
        tmp_path):
    """Two relays expose one fork while both ACI removal plans survive."""
    value = world()

    invite_secret, invite_public = keypair()
    second_invite = user_invite(
        value.root.fid, value.founder, invite_public, 4)
    second_invite_sig = signature(
        value.founder_secret, value.founder, second_invite, 4)
    second_secret, second = keypair()
    second_user = user(
        second_invite, invite_secret, second, "second", 5)
    second_user_sig = signature(
        second_secret, second, second_user, 5)
    second_membership = (
        value.root,
        second_invite_sig,
        second_invite,
        second_user_sig,
        second_user,
    )

    first_action = removal(
        value.root.fid, value.founder, value.member, 6)
    first_signature = signature(
        value.founder_secret, value.founder, first_action, 6)
    second_action = removal(
        value.root.fid, value.founder, second, 7)
    second_signature = signature(
        value.founder_secret, value.founder, second_action, 7)

    first_source = FsStore(str(tmp_path / "first"))
    second_source = FsStore(str(tmp_path / "second"))
    first_update = run(accept_one(
        first_source,
        value.founder_secret,
        value.founder,
        value.founder,
        value.root,
        (*value.membership, first_signature, first_action),
    ))
    second_update = run(accept_one(
        second_source,
        value.founder_secret,
        value.founder,
        value.founder,
        value.root,
        (*second_membership, second_signature, second_action),
    ))
    assert first_update.head_oid != second_update.head_oid

    bucket = ScriptedBucket()
    target = PileHandle(bucket.handle("target"))
    state = RecipientRemovalState(value.root.fid, target)
    assert run(state.bootstrap(signed(
        value.founder_secret,
        value.founder,
        value.root,
        (value.root,),
    ))).status == "applied"
    consumer = FactConsumer(value.root.fid)

    def exact_binding(workspace_id, device, _removal_root, candidate):
        return WriterBinding(
            workspace_id, device, candidate.owner, candidate.store)

    mirrors = tuple(
        RepositoryMirror(
            value.root.fid,
            target,
            exact_binding,
            consumer,
            control_state=state,
        )
        for _ in range(2)
    )
    slot_key = head_slot_key(value.root.fid, value.founder)
    first_reservation = bucket.pause(
        "target", "cas", slot_key, nth=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run, mirrors[0].sync_from(first_source))
        first_reservation.wait()
        second_result = pool.submit(
            run, mirrors[1].sync_from(second_source)).result()
        first_reservation.release.set()
        first_result = first.result()

    results = (first_result, second_result)
    assert sum(result.changed for result in results) == 1
    assert sum(bool(result.errors) for result in results) == 1
    assert any(
        "concurrent local writer-slot update" in result.errors[0][1]
        for result in results if result.errors
    )

    installed = decode_slot_at(slot_key, target.get(slot_key)).head
    assert installed in {first_update.head_oid, second_update.head_oid}
    winner, loser = (
        (first_action, second_action)
        if installed == first_update.head_oid
        else (second_action, first_action)
    )
    winner_member = winner.offers()[0][1]
    loser_member = loser.offers()[0][1]
    assert run(value_at(
        state,
        scoped_id("member", winner_member),
    )) == suppression_slot(winner.fid)
    assert run(value_at(
        state,
        scoped_id("member", loser_member),
    )) == suppression_slot(loser.fid)
    assert consumer.projected_head(value.founder) == installed
    assert bucket.assert_valid_history()


def test_mirror_rejects_signed_mixed_control_and_content_before_state(
        tmp_path):
    """An action cannot hide inside a pile classified as ordinary content."""
    value = world()
    action = removal(
        value.root.fid, value.founder, value.member, 8)
    action_signature = signature(
        value.founder_secret, value.founder, action, 8)
    ordinary = message(
        value.root.fid, value.founder, "general", "mixed", 9)
    ordinary_signature = signature(
        value.founder_secret, value.founder, ordinary, 9)
    source = FsStore(str(tmp_path / "source"))
    mixed = signed(
        value.founder_secret,
        value.founder,
        value.root,
        (*value.membership,
         action_signature, action,
         ordinary_signature, ordinary),
    )
    pile_oid = signed_pile_oid(mixed)
    source.put_if_absent("obj/" + pile_oid, mixed)

    def emit(raw):
        oid = h(raw)
        source.put_if_absent("obj/" + oid, raw)
        return oid

    # Model a malicious but correctly signed writer implementation which
    # omits the action from the head's control tree. A validating peer must
    # still reject the mixed semantic sinks before publishing any local state.
    tree = build_tree(
        value.root.fid,
        value.founder,
        (leaf_row(1, pile_oid),),
        emit,
    )
    head = make_head(
        value.founder_secret,
        value.root.fid,
        value.founder,
        value.founder,
        1,
        tree,
        writer_store_binding(value.root.fid, value.founder),
    )
    head_raw = encode_head(head)
    candidate = head_oid(head_raw)
    source.put_if_absent("obj/" + candidate, head_raw)
    source.cas(
        head_slot_key(value.root.fid, value.founder),
        ABSENT,
        encode_slot(HeadSlot(
            value.root.fid,
            value.founder,
            candidate,
            h(b"untrusted source removal root"),
        )),
    )

    target = FsStore(str(tmp_path / "target"))
    state = RecipientRemovalState(value.root.fid, target)
    assert run(state.bootstrap(signed(
        value.founder_secret,
        value.founder,
        value.root,
        (value.root,),
    ))).status == "applied"
    consumer = FactConsumer(value.root.fid)

    def exact_binding(workspace_id, device, _removal_root, candidate):
        return WriterBinding(
            workspace_id, device, candidate.owner, candidate.store)

    result = run(RepositoryMirror(
        value.root.fid,
        target,
        exact_binding,
        consumer,
        control_state=state,
    ).sync_from(source))

    assert result.changed == result.piles == result.facts == 0
    assert result.errors and "control material needs one control-only sink" \
        in result.errors[0][1]
    assert target.get(head_slot_key(
        value.root.fid, value.founder)) is None
    assert run(value_at(
        state,
        scoped_id("member", value.member),
    )) is None
    assert consumer.fact_ids() == ()
