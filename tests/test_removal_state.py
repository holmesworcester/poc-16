"""Recipient removal state from exact original signed control piles."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from core.close import encode_signed_pile, make_signed_pile, signed_pile_oid
from core.crypto import h, keypair
from core.object_store import REMOVAL_ROOT_KEY
from core.removal_state import RecipientRemovalState
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.suppression_tree import SuppressionTree
from core.writer_head import WriterBinding, writer_store_binding
from core.writer_repository import (
    FactConsumer,
    HeadGrant,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
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
            None,
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
        b"discarded path",
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

    paused = bucket.pause(
        "recipient", "cas", REMOVAL_ROOT_KEY, nth=2)
    other_sid = scoped_id("member", h(b"concurrent member"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        advancing = pool.submit(
            run, recipient.apply_control(primary_pile, value.member))
        paused.wait()
        concurrent = SuppressionTree(
            value.root.fid, PileHandle(bucket.handle("concurrent")))
        assert run(concurrent.apply((
            (other_sid, suppression_slot()),
        ))).status == "applied"
        paused.release.set()
        outcome = advancing.result()

    assert outcome.status == "retryable"
    assert outcome.root_oid == run(recipient.pin()).root_oid
    assert run(value_at(
        recipient,
        scoped_id("member", value.member),
    )) == suppression_slot()
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


def test_mirror_retries_pre_cas_control_application_without_a_cursor(
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

    async def interrupted(raw, device):
        calls.append((signed_pile_oid(raw), device))
        if len(calls) == 1:
            return type("Retryable", (), {"status": "retryable"})()
        return await state.apply_control(raw, device)

    def exact_binding(workspace_id, device, _removal_root, candidate):
        return WriterBinding(
            workspace_id, device, candidate.owner, candidate.store)

    mirror = RepositoryMirror(
        value.root.fid,
        target,
        exact_binding,
        consumer,
        apply_control=interrupted,
    )

    first = run(mirror.sync_from(source))
    assert first.changed == 0
    assert first.errors and "control application" in first.errors[0][1]
    assert consumer.projected_head(value.founder) is None
    assert run(value_at(
        state, scoped_id("member", value.member))) == suppression_slot()

    replay = run(mirror.sync_from(source))
    assert replay.errors == ()
    control_oid = signed_pile_oid(signed(
        value.founder_secret,
        value.founder,
        value.root,
        (*value.membership, evicted_sig, evicted),
    ))
    assert calls == [
        (control_oid, value.founder),
        (control_oid, value.founder),
    ]
    assert consumer.projected_head(value.founder) is not None
    assert run(value_at(
        state,
        scoped_id("member", value.member),
    )) == suppression_slot(evicted.fid)
