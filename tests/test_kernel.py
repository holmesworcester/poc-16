"""Adversarial kernel tests: the judge rejects what it must, whole units."""

import pytest

import facts
from core.close import close
from core.crypto import keypair, sign
from core.fact import Fact, Need
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
    drain,
    validate,
)
from core.node import now_ms
from facts._policy import FamilyPolicy


@pytest.fixture
def anchor_chain():
    sk, pk = keypair()
    g = workspace(sk, pk, "alice", now_ms())
    return sk, pk, g


def judge(facts, anchor):
    return validate(facts, anchor)


def test_genesis_and_msg(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(g.fid, pk, "c", "hi", ts)
    s = signature(sk, pk, m, ts)
    assert judge([g, s, m], g.fid)


def test_wrong_anchor_rejects(anchor_chain):
    """Workspace scope: a foreign genesis rejects inside the predicate."""
    sk, pk, g = anchor_chain
    assert not judge([g], "0" * 64)


def test_bad_sig_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(g.fid, pk, "c", "hi", ts)
    other_sk, _ = keypair()
    forged = Fact("signature", ts, [["offer", "author", m.fid, pk]],
                  {"sig": sign(other_sk, m.fid)}, g.fid)
    assert not judge([g, forged, m], g.fid)


def test_nonmember_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    esk, epk = keypair()
    ts = now_ms()
    m = message(g.fid, epk, "c", "intruder", ts)
    s = signature(esk, epk, m, ts)
    assert not judge([g, s, m], g.fid)


def test_unresolved_ref_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    dangling = Fact("user", ts, [["ref", ts, "f" * 64], ["offer", "member", pk]],
                    {"name": "x", "pk": pk, "countersig": "00"}, g.fid)
    assert not judge([g, dangling], g.fid)


def test_offer_smuggling_rejects(anchor_chain):
    """A msg cannot mint auth offers: family offer names are closed."""
    sk, pk, g = anchor_chain
    esk, epk = keypair()
    ts = now_ms()
    evil = Fact("msg", ts, [["offer", "admin", epk]],
                {"pk": pk, "chan": "c", "text": "x"}, g.fid)
    s = signature(sk, pk, evil, ts)
    assert not judge([g, s, evil], g.fid)


def test_all_or_nothing(anchor_chain):
    """A valid fact sinks with its bad batch; it returns on the next walk."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    good = message(g.fid, pk, "c", "good", ts)
    sg = signature(sk, pk, good, ts)
    esk, epk = keypair()
    bad = message(g.fid, epk, "c", "bad", ts)
    sb = signature(esk, epk, bad, ts)
    result = drain([g, sg, good, sb, bad], g.fid)
    assert not result.ok and result.valids == ()


def test_evict_needs_admin(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    isk, ipk = keypair()
    inv = user_invite(g.fid, pk, ipk, ts)
    si = signature(sk, pk, inv, ts)
    bsk, bpk = keypair()
    j = user(inv, isk, bpk, "bob", ts)
    sj = signature(bsk, bpk, j, ts)
    ev = removal(
        g.fid, bpk, pk, ts)  # bob (mere member) tries to evict alice
    se = signature(bsk, bpk, ev, ts)
    assert judge([g, si, inv, sj, j], g.fid)
    assert not judge([g, si, inv, sj, j, se, ev], g.fid)


def test_member_can_invite_but_nonmember_cannot(anchor_chain):
    """A joined member extends authority; an unrelated signer cannot."""
    founder_sk, founder_pk, root = anchor_chain
    ts = now_ms()
    first_invite_sk, first_invite_pk = keypair()
    first_invite = user_invite(
        root.fid, founder_pk, first_invite_pk, ts + 1)
    first_invite_sig = signature(
        founder_sk, founder_pk, first_invite, ts + 1)
    member_sk, member_pk = keypair()
    member = user(
        first_invite, first_invite_sk, member_pk, "bob", ts + 2)
    member_sig = signature(member_sk, member_pk, member, ts + 2)
    base = [root, first_invite_sig, first_invite, member_sig, member]

    _, next_invite_pk = keypair()
    member_invite = user_invite(
        root.fid, member_pk, next_invite_pk, ts + 3)
    member_invite_sig = signature(
        member_sk, member_pk, member_invite, ts + 3)
    assert judge(base + [member_invite_sig, member_invite], root.fid)

    outsider_sk, outsider_pk = keypair()
    _, forged_invite_pk = keypair()
    forged = user_invite(
        root.fid, outsider_pk, forged_invite_pk, ts + 3)
    forged_sig = signature(outsider_sk, outsider_pk, forged, ts + 3)
    assert not judge(base + [forged_sig, forged], root.fid)


def test_device_set_peers_can_directly_grant_known_keys(anchor_chain):
    founder_sk, founder_pk, root = anchor_chain
    ts = now_ms()
    primary = device(root.fid, founder_pk, "phone", ts + 1)
    primary_sig = signature(founder_sk, founder_pk, primary, ts + 1)

    sibling_sk, sibling_pk = keypair()
    sibling = device_invite(
        root.fid, founder_pk, founder_pk, sibling_pk, "laptop", ts + 2)
    sibling_sig = signature(founder_sk, founder_pk, sibling, ts + 2)
    first = [root, primary_sig, primary, sibling_sig, sibling]
    assert judge(first, root.fid)

    _, third_pk = keypair()
    third = device_invite(
        root.fid, sibling_pk, founder_pk, third_pk, "tablet", ts + 3)
    third_sig = signature(sibling_sk, sibling_pk, third, ts + 3)
    assert judge(first + [third_sig, third], root.fid)

    outsider_sk, outsider_pk = keypair()
    forged = device_invite(
        root.fid, outsider_pk, founder_pk, third_pk, "forged", ts + 3)
    forged_sig = signature(outsider_sk, outsider_pk, forged, ts + 3)
    assert not judge(first + [forged_sig, forged], root.fid)


def test_authority_facts_cannot_satisfy_their_own_prerequisite(anchor_chain):
    founder_sk, founder_pk, root = anchor_chain
    ts = now_ms()
    primary = device(root.fid, founder_pk, "phone", ts + 1)
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
        root.fid,
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
        root.fid,
    )
    self_admin_sig = signature(
        founder_sk, founder_pk, self_admin, ts + 2)
    assert not judge([root, self_admin_sig, self_admin], root.fid)


def test_mutual_authority_grants_still_close_to_an_acyclic_pile(
        anchor_chain):
    founder_secret, founder, root = anchor_chain
    ts = now_ms()

    invite_secret, invite_public = keypair()
    invitation = user_invite(root.fid, founder, invite_public, ts + 1)
    invitation_sig = signature(
        founder_secret, founder, invitation, ts + 1)
    bob_secret, bob = keypair()
    joined = user(invitation, invite_secret, bob, "bob", ts + 2)
    joined_sig = signature(bob_secret, bob, joined, ts + 2)
    promote_bob = admin(root.fid, founder, bob, ts + 3)
    promote_bob_sig = signature(
        founder_secret, founder, promote_bob, ts + 3)
    promote_founder = admin(root.fid, bob, founder, ts + 4)
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

    primary = device(root.fid, founder, "phone", ts + 1)
    primary_sig = signature(founder_secret, founder, primary, ts + 1)
    laptop_secret, laptop = keypair()
    laptop_grant = device_invite(
        root.fid, founder, founder, laptop, "laptop", ts + 2)
    laptop_grant_sig = signature(
        founder_secret, founder, laptop_grant, ts + 2)
    founder_back_grant = device_invite(
        root.fid, laptop, founder, founder, "founder-again", ts + 3)
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
        result = drain(stream, root.fid)
        assert result.ok
        by_fid = {fact.fid: fact for fact in stream}
        deps = {
            valid.fact.fid: tuple(edge.fid for edge in valid.edges)
            for valid in result.valids
        }
        closed = close(
            stream,
            lambda fid: deps[fid],
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


def test_request_time_is_not_persistent_kernel_state(anchor_chain):
    """Expiry is enforced by the Worker grant, not immutable fact validity."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(g.fid, pk, "c", "still valid", ts)
    s = signature(sk, pk, m, ts)
    rq = request(g.fid, pk, "sync", ts + 9999, ts)
    sr = signature(sk, pk, rq, ts)
    assert validate([g, s, m], g.fid)
    assert judge([g, sr, rq], g.fid)


def test_drain_returns_only_valids(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    ev = removal(g.fid, pk, pk, ts)
    se = signature(sk, pk, ev, ts)
    result = drain([g, se, ev], g.fid)
    assert result.ok
    assert len(result.valids) == 3
    assert isinstance(validate([g, se, ev], g.fid), bool)


def test_order_matters_seen_set(anchor_chain):
    """The seen-set rule: providers must precede dependents in the stream."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(g.fid, pk, "c", "hi", ts)
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


def test_later_provider_does_not_readjudicate_an_accepted_fact(monkeypatch):
    """Provider choice belongs to each closed-pile judgment, not storage."""
    tag = "test_interchangeable_provider"
    anchor = "a" * 64

    class RewireFamily:
        TAG = tag
        POLICY = FamilyPolicy()
        DURABLE = True

        @staticmethod
        def needs(fact):
            return (Need("provider", "test.provider", "target"),) \
                if fact.body.get("consumer") else ()

        @staticmethod
        def validate(fact, _ctx):
            return fact.t == tag

    real_family_for = facts.family_for
    monkeypatch.setattr(
        facts,
        "family_for",
        lambda candidate: RewireFamily
        if candidate == tag else real_family_for(candidate),
    )

    first = Fact(
        tag, 1,
        [["offer", "test.provider", "target"]],
        {"provider": "first"},
        anchor,
    )
    second = Fact(
        tag, 2,
        [["offer", "test.provider", "target"]],
        {"provider": "second"},
        anchor,
    )
    consumer = Fact(
        tag, 3, [], {"consumer": True}, anchor)

    accepted = drain([first, consumer], anchor)
    later = drain([second], anchor)

    assert accepted.ok
    assert accepted.valids[-1].fact == consumer
    assert later.ok
    # There is intentionally no whole-set projection call here: both durable
    # receipts join storage and neither can revoke the other.
