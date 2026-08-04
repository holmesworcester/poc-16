"""Replayable removal-root schedules through the real access and head gates."""

import asyncio
from concurrent.futures import ThreadPoolExecutor

from core.access import AccessGate
from core.crypto import h
from core.suppression import scoped_id, suppression_slot
from core.writer_head import (
    WriterBinding,
    decode_slot_at,
    head_slot_key,
    writer_store_binding,
)
from core.writer_repository import HeadGrant, OpaqueHeadGate, WriterLog
from facts.auth.signature import signature
from facts.content.message import message
from tests.shared_bucket import ScriptedBucket
from tests.test_control_head_permit import (
    exact_head_proof,
    founder_world,
    historical_proof,
    self_removal_pile,
    signed,
)


def run(awaitable):
    return asyncio.run(awaitable)


def test_two_bootstraps_have_one_root_winner_then_fair_retry_converges():
    seed = 0xB00757A9
    secret, founder, root = founder_world()
    bootstrap = signed(secret, founder, root, (root,))
    bucket = ScriptedBucket(seed=seed)
    first = AccessGate(root.fid, bucket.handle("bootstrap-a"))
    second = AccessGate(root.fid, bucket.handle("bootstrap-b"))
    delayed = bucket.pause(
        "bootstrap-a", "cas", "removal", when="before")

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(run, first.state.bootstrap(bootstrap))
        delayed.wait()
        b = pool.submit(run, second.state.bootstrap(bootstrap))
        winner = b.result(timeout=5)
        delayed.release.set()
        loser = a.result(timeout=5)

    assert (winner.status, loser.status) == ("applied", "retryable"), \
        f"seed={seed:#x} history={bucket.history!r}"
    repaired = run(first.state.bootstrap(bootstrap))
    assert repaired.status == "noop"
    assert repaired.root_oid == winner.root_oid
    assert sum(
        event.op == "cas" and event.key == "removal"
        and getattr(event.result, "token", None) is not None
        for event in bucket.history
    ) == 1
    assert bucket.assert_valid_history()


def test_ordinary_grant_pins_before_concurrent_removal_and_mutates_one_slot():
    seed = 0x6A4A7
    secret, founder, root = founder_world()
    bucket = ScriptedBucket(seed=seed)
    publisher_store = bucket.handle("publisher")
    remover_store = bucket.handle("remover")
    access = AccessGate(root.fid, publisher_store)
    remover = AccessGate(root.fid, remover_store)
    bootstrap = signed(secret, founder, root, (root,))
    assert run(access.state.bootstrap(bootstrap)).status == "applied"

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
        publisher_store,
    )
    initial = run(writer.prepare(((root,),)))
    run(writer.establish(initial))
    issue_pin = run(access.state.pin())
    head_gate = OpaqueHeadGate(publisher_store, access.authorize_head)
    installed = run(head_gate.advance_control(HeadGrant(
        root.fid,
        founder,
        None,
        initial.head_oid,
        issue_pin.root_oid,
    ), h(b"setup control permit"), issue_pin.root_oid))
    assert installed.status == "applied"

    item = message(root.fid, founder, "general", "pinned race", 50)
    item_signature = signature(secret, founder, item, item.ts)
    ordinary = run(writer.prepare(((root, item_signature, item),)))
    run(writer.establish(ordinary))
    path = run(access.removal_path(
        historical_proof(secret, founder, root, (root,)), 10))
    proof = exact_head_proof(
        secret,
        founder,
        root,
        (root,),
        path,
        ordinary.head_oid,
        base=initial.head_oid,
    )

    pinned = bucket.pause(
        "publisher", "read_versioned", "removal", when="after")
    with ThreadPoolExecutor(max_workers=1) as pool:
        deciding = pool.submit(
            run, access.authorize_head(proof, ordinary.head_oid, 10))
        pinned.wait()
        action, control = self_removal_pile(secret, founder, root, ts=60)
        removed = run(remover.state.apply_control(control, founder))
        assert removed.status == "applied"
        pinned.release.set()
        grant = deciding.result(timeout=5)

    assert isinstance(grant, HeadGrant)
    assert grant.removal_root == issue_pin.root_oid
    assert removed.root_oid != grant.removal_root
    advanced = run(head_gate.advance_grant(grant))
    assert advanced.status == "applied"
    key = head_slot_key(root.fid, founder)
    accepted = decode_slot_at(key, publisher_store.get(key))
    assert accepted.head == ordinary.head_oid
    assert accepted.removal_root == issue_pin.root_oid
    assert bucket.handle("auditor").list(
        f"heads/{root.fid}/") == [key]

    current = run(remover.state.pin())
    removal_proof = run(current.proof(scoped_id("member", founder)))
    assert current.verify(
        scoped_id("member", founder), removal_proof,
    ) == suppression_slot(action.fid)
    assert bucket.assert_valid_history(), \
        f"seed={seed:#x} history={bucket.history!r}"
