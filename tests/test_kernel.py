"""Adversarial kernel tests: the judge rejects what it must, whole units."""
import sqlite3

import pytest

from core.close import close
from core.crypto import keypair, sign
from core.fact import Fact
from facts.auth.admin import admin
from facts.auth.device import device
from facts.auth.device_invite import device_invite
from facts.auth.removal import removal
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from facts.content.message import message
from core.kernel import (
    SCHEMA,
    Global,
    drain,
    evaluate,
    resolve_deps,
    validate,
)
from core.node import now_ms


@pytest.fixture
def anchor_chain():
    sk, pk = keypair()
    g = workspace(sk, pk, "alice", now_ms())
    return sk, pk, g


def judge(facts, anchor, g=None):
    if g is None:
        return validate(facts, anchor)
    globals_ = set(g)
    if not any(name == "now" for name, _ in globals_):
        globals_.add(Global("now", now_ms()))
    return evaluate(facts, anchor, globals_)


def test_genesis_and_msg(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "hi", ts)
    s = signature(sk, pk, m, ts)
    assert judge([g, s, m], g.fid)


def test_wrong_anchor_rejects(anchor_chain):
    """Workspace scope: a foreign genesis rejects inside the predicate."""
    sk, pk, g = anchor_chain
    assert not judge([g], "0" * 64)


def test_bad_sig_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "hi", ts)
    other_sk, _ = keypair()
    forged = Fact("signature", ts, [["offer", "author", m.fid, pk]],
                  {"sig": sign(other_sk, m.fid)})
    assert not judge([g, forged, m], g.fid)


def test_nonmember_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    esk, epk = keypair()
    ts = now_ms()
    m = message(epk, "c", "intruder", ts)
    s = signature(esk, epk, m, ts)
    assert not judge([g, s, m], g.fid)


def test_unresolved_ref_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    dangling = Fact("user", ts, [["ref", ts, "f" * 64], ["offer", "member", pk]],
                    {"name": "x", "pk": pk, "countersig": "00"})
    assert not judge([g, dangling], g.fid)


def test_offer_smuggling_rejects(anchor_chain):
    """A msg cannot mint auth offers: family offer names are closed."""
    sk, pk, g = anchor_chain
    esk, epk = keypair()
    ts = now_ms()
    evil = Fact("msg", ts, [["offer", "admin", epk]],
                {"pk": pk, "chan": "c", "text": "x"})
    s = signature(sk, pk, evil, ts)
    assert not judge([g, s, evil], g.fid)


def test_all_or_nothing(anchor_chain):
    """A valid fact sinks with its bad batch; it returns on the next walk."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    good = message(pk, "c", "good", ts)
    sg = signature(sk, pk, good, ts)
    esk, epk = keypair()
    bad = message(epk, "c", "bad", ts)
    sb = signature(esk, epk, bad, ts)
    result = drain([g, sg, good, sb, bad], g.fid)
    assert not result.ok and result.valids == ()


def test_evict_needs_admin(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    isk, ipk = keypair()
    inv = user_invite(pk, ipk, ts)
    si = signature(sk, pk, inv, ts)
    bsk, bpk = keypair()
    j = user(inv, isk, bpk, "bob", ts)
    sj = signature(bsk, bpk, j, ts)
    ev = removal(bpk, pk, ts)  # bob (mere member) tries to evict alice
    se = signature(bsk, bpk, ev, ts)
    assert judge([g, si, inv, sj, j], g.fid)
    assert not judge([g, si, inv, sj, j, se, ev], g.fid)


def test_member_can_invite_but_nonmember_cannot(anchor_chain):
    """A joined member extends authority; an unrelated signer cannot."""
    founder_sk, founder_pk, root = anchor_chain
    ts = now_ms()
    first_invite_sk, first_invite_pk = keypair()
    first_invite = user_invite(founder_pk, first_invite_pk, ts + 1)
    first_invite_sig = signature(
        founder_sk, founder_pk, first_invite, ts + 1)
    member_sk, member_pk = keypair()
    member = user(
        first_invite, first_invite_sk, member_pk, "bob", ts + 2)
    member_sig = signature(member_sk, member_pk, member, ts + 2)
    base = [root, first_invite_sig, first_invite, member_sig, member]

    _, next_invite_pk = keypair()
    member_invite = user_invite(member_pk, next_invite_pk, ts + 3)
    member_invite_sig = signature(
        member_sk, member_pk, member_invite, ts + 3)
    assert judge(base + [member_invite_sig, member_invite], root.fid)

    outsider_sk, outsider_pk = keypair()
    _, forged_invite_pk = keypair()
    forged = user_invite(outsider_pk, forged_invite_pk, ts + 3)
    forged_sig = signature(outsider_sk, outsider_pk, forged, ts + 3)
    assert not judge(base + [forged_sig, forged], root.fid)


def test_device_set_peers_can_directly_grant_known_keys(anchor_chain):
    founder_sk, founder_pk, root = anchor_chain
    ts = now_ms()
    primary = device(founder_pk, "phone", ts + 1)
    primary_sig = signature(founder_sk, founder_pk, primary, ts + 1)

    sibling_sk, sibling_pk = keypair()
    sibling = device_invite(
        founder_pk, founder_pk, sibling_pk, "laptop", ts + 2)
    sibling_sig = signature(founder_sk, founder_pk, sibling, ts + 2)
    first = [root, primary_sig, primary, sibling_sig, sibling]
    assert judge(first, root.fid)

    _, third_pk = keypair()
    third = device_invite(
        sibling_pk, founder_pk, third_pk, "tablet", ts + 3)
    third_sig = signature(sibling_sk, sibling_pk, third, ts + 3)
    assert judge(first + [third_sig, third], root.fid)

    outsider_sk, outsider_pk = keypair()
    forged = device_invite(
        outsider_pk, founder_pk, third_pk, "forged", ts + 3)
    forged_sig = signature(outsider_sk, outsider_pk, forged, ts + 3)
    assert not judge(first + [forged_sig, forged], root.fid)


def test_authority_facts_cannot_satisfy_their_own_prerequisite(anchor_chain):
    founder_sk, founder_pk, root = anchor_chain
    ts = now_ms()
    primary = device(founder_pk, "phone", ts + 1)
    primary_sig = signature(founder_sk, founder_pk, primary, ts + 1)

    self_device = Fact(
        "device_invite",
        ts + 2,
        [
            ["offer", "member", founder_pk],
            ["offer", "device", founder_pk, founder_pk],
        ],
        {
            "pk": founder_pk,
            "user": founder_pk,
            "device": founder_pk,
            "label": "self",
        },
    )
    self_device_sig = signature(
        founder_sk, founder_pk, self_device, ts + 2)
    assert not judge(
        [root, primary_sig, primary, self_device_sig, self_device],
        root.fid)

    self_admin = Fact(
        "admin",
        ts + 2,
        [["offer", "admin", founder_pk]],
        {"pk": founder_pk, "target": founder_pk},
    )
    self_admin_sig = signature(
        founder_sk, founder_pk, self_admin, ts + 2)
    assert not judge([root, self_admin_sig, self_admin], root.fid)


def test_mutual_authority_grants_still_close_to_an_acyclic_pile(
        anchor_chain):
    founder_secret, founder, root = anchor_chain
    ts = now_ms()

    invite_secret, invite_public = keypair()
    invitation = user_invite(founder, invite_public, ts + 1)
    invitation_sig = signature(
        founder_secret, founder, invitation, ts + 1)
    bob_secret, bob = keypair()
    joined = user(invitation, invite_secret, bob, "bob", ts + 2)
    joined_sig = signature(bob_secret, bob, joined, ts + 2)
    promote_bob = admin(founder, bob, ts + 3)
    promote_bob_sig = signature(
        founder_secret, founder, promote_bob, ts + 3)
    promote_founder = admin(bob, founder, ts + 4)
    promote_founder_sig = signature(
        bob_secret, bob, promote_founder, ts + 4)
    admin_stream = [
        root,
        invitation_sig,
        invitation,
        joined_sig,
        joined,
        promote_bob_sig,
        promote_bob,
        promote_founder_sig,
        promote_founder,
    ]

    primary = device(founder, "phone", ts + 1)
    primary_sig = signature(founder_secret, founder, primary, ts + 1)
    laptop_secret, laptop = keypair()
    laptop_grant = device_invite(
        founder, founder, laptop, "laptop", ts + 2)
    laptop_grant_sig = signature(
        founder_secret, founder, laptop_grant, ts + 2)
    founder_back_grant = device_invite(
        laptop, founder, founder, "founder-again", ts + 3)
    founder_back_grant_sig = signature(
        laptop_secret, laptop, founder_back_grant, ts + 3)
    device_stream = [
        root,
        primary_sig,
        primary,
        laptop_grant_sig,
        laptop_grant,
        founder_back_grant_sig,
        founder_back_grant,
    ]

    for stream in (admin_stream, device_stream):
        db = sqlite3.connect(":memory:")
        db.executescript(SCHEMA)
        result = drain(stream, root.fid, db=db)
        assert result.ok
        by_fid = {fact.fid: fact for fact in stream}
        closed = close(
            stream,
            lambda fid: resolve_deps(by_fid[fid], db) or [],
            by_fid.get,
        )
        # The delivery-order theorem (was test_suppression_proof
        # .assert_closed): every explicit dependency precedes the fact that
        # needs it in a serialized unit, with no duplicates.
        positions = {fact.fid: index for index, fact in enumerate(closed)}
        assert len(positions) == len(closed)
        assert all(
            ref in positions and positions[ref] < positions[fact.fid]
            for fact in closed for _, ref in fact.refs()
        )
        assert drain(closed, root.fid).ok
        db.close()


def test_request_gate_uses_only_ephemeral_time_metadata(anchor_chain):
    """Suppression moved to authenticated slots; globals cannot mask facts."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "still valid", ts)
    s = signature(sk, pk, m, ts)
    rq = request(pk, "sync", ts + 9999, ts)
    sr = signature(sk, pk, rq, ts)
    globals_ = {Global("removal", pk), Global("now", ts)}
    assert validate([g, s, m], g.fid)                  # persistent: globals-blind
    assert judge([g, sr, rq], g.fid, g=globals_)
    assert judge([g, sr, rq], g.fid, g=set())


def test_drain_does_not_emit_removal_globals(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    ev = removal(pk, pk, ts)
    se = signature(sk, pk, ev, ts)
    result = drain([g, se, ev], g.fid)
    assert result.ok
    assert result.globals == frozenset()
    assert isinstance(validate([g, se, ev], g.fid), bool)


def test_order_matters_seen_set(anchor_chain):
    """The seen-set rule: providers must precede dependents in the stream."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "hi", ts)
    s = signature(sk, pk, m, ts)
    assert not judge([g, m, s], g.fid)  # sig after its dependent: unmet need


def test_single_judge_loop():
    """kernel._judge is THE one judging loop (was test_engine's law over
    hoist+kernel; the hoist half died with the tree): a single for-loop,
    reached from kernel()."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / "core"
    module = ast.parse((root / "kernel.py").read_text())
    defs = {
        node.name: node for node in module.body
        if isinstance(node, ast.FunctionDef)
    }

    assert sum(isinstance(node, ast.For)
               for node in ast.walk(defs["_judge"])) == 1
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_judge"
        for node in ast.walk(defs["kernel"])
    )
