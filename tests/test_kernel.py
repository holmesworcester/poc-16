"""Adversarial kernel tests: the judge rejects what it must, whole units."""
import sqlite3

import pytest

from tinyp2p.close import close
from tinyp2p.crypto import keypair, sign
from tinyp2p.fact import Fact
from tinyp2p.facts.auth.admin import admin
from tinyp2p.facts.auth.device import device
from tinyp2p.facts.auth.device_invite import device_invite
from tinyp2p.facts.auth.removal import removal
from tinyp2p.facts.auth.request import request
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.facts.auth.workspace import workspace
from tinyp2p.facts.content.message import message
from tinyp2p.kernel import (
    SCHEMA,
    Global,
    drain,
    evaluate,
    resolve_deps,
    validate,
)
from tinyp2p.node import now_ms


@pytest.fixture
def anchor_chain():
    sk, pk = keypair()
    g = workspace(sk, pk, "alice", now_ms())
    return sk, pk, g


def judge(facts, anchor, g=None):
    return validate(facts, anchor) if g is None else evaluate(facts, anchor, g)


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
        assert drain(closed, root.fid).ok
        db.close()


def test_removal_gates_requests_only(anchor_chain):
    """Validity is globals-blind; only the ephemeral family reads removal."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "still valid", ts)
    s = signature(sk, pk, m, ts)
    rq = request(pk, "sync", ts + 9999, ts)
    sr = signature(sk, pk, rq, ts)
    globals_ = {Global("removal", pk)}
    assert validate([g, s, m], g.fid)                  # persistent: globals-blind
    assert not judge([g, sr, rq], g.fid, g=globals_)   # ephemeral: refused
    assert judge([g, sr, rq], g.fid, g=set())


def test_removed_member_cannot_launder_a_mint_through_a_fresh_user(
        anchor_chain):
    founder_secret, founder, root = anchor_chain
    ts = now_ms()

    bob_invite_secret, bob_invite_public = keypair()
    bob_invite = user_invite(founder, bob_invite_public, ts + 1)
    bob_invite_sig = signature(
        founder_secret, founder, bob_invite, ts + 1)
    bob_secret, bob = keypair()
    bob_user = user(
        bob_invite, bob_invite_secret, bob, "bob", ts + 2)
    bob_user_sig = signature(bob_secret, bob, bob_user, ts + 2)

    carol_invite_secret, carol_invite_public = keypair()
    carol_invite = user_invite(bob, carol_invite_public, ts + 3)
    carol_invite_sig = signature(
        bob_secret, bob, carol_invite, ts + 3)
    carol_secret, carol = keypair()
    carol_user = user(
        carol_invite, carol_invite_secret, carol, "carol", ts + 4)
    carol_user_sig = signature(
        carol_secret, carol, carol_user, ts + 4)
    access = request(carol, "sync", ts + 10_000, ts + 5)
    access_sig = signature(carol_secret, carol, access, ts + 5)
    stream = [
        root,
        bob_invite_sig,
        bob_invite,
        bob_user_sig,
        bob_user,
        carol_invite_sig,
        carol_invite,
        carol_user_sig,
        carol_user,
        access_sig,
        access,
    ]

    assert validate(stream, root.fid)
    assert not evaluate(
        stream, root.fid, {Global("removal", bob)})
    _, unrelated = keypair()
    assert evaluate(
        stream, root.fid, {Global("removal", unrelated)})


def test_removed_device_issuer_invalidates_its_descendant_mint(
        anchor_chain):
    founder_secret, founder, root = anchor_chain
    ts = now_ms()
    primary = device(founder, "phone", ts + 1)
    primary_sig = signature(founder_secret, founder, primary, ts + 1)

    laptop_secret, laptop = keypair()
    laptop_grant = device_invite(
        founder, founder, laptop, "laptop", ts + 2)
    laptop_grant_sig = signature(
        founder_secret, founder, laptop_grant, ts + 2)
    tablet_secret, tablet = keypair()
    tablet_grant = device_invite(
        laptop, founder, tablet, "tablet", ts + 3)
    tablet_grant_sig = signature(
        laptop_secret, laptop, tablet_grant, ts + 3)
    access = request(tablet, "sync", ts + 10_000, ts + 4)
    access_sig = signature(tablet_secret, tablet, access, ts + 4)
    stream = [
        root,
        primary_sig,
        primary,
        laptop_grant_sig,
        laptop_grant,
        tablet_grant_sig,
        tablet_grant,
        access_sig,
        access,
    ]

    assert validate(stream, root.fid)
    assert not evaluate(
        stream, root.fid, {Global("removal", laptop)})


def test_drain_emits_removal_global_only(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    ev = removal(pk, pk, ts)
    se = signature(sk, pk, ev, ts)
    result = drain([g, se, ev], g.fid)
    assert result.ok
    assert result.globals == {Global("removal", pk)}
    assert isinstance(validate([g, se, ev], g.fid), bool)


def test_order_matters_seen_set(anchor_chain):
    """The seen-set rule: providers must precede dependents in the stream."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "hi", ts)
    s = signature(sk, pk, m, ts)
    assert not judge([g, m, s], g.fid)  # sig after its dependent: unmet need
