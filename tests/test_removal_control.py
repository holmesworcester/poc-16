"""Fact-owned extraction for recipient removal state."""

import pytest

import facts
from core.crypto import h, keypair
from core.kernel import drain
from core.suppression import scoped_id, suppression_slot
from facts.auth._access import subject_sid
from facts.auth.removal import removal
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from facts.content.message import message


def world():
    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, "workspace", 1)
    invite_secret, invite_public = keypair()
    invite = user_invite(root.fid, founder, invite_public, 2)
    invite_sig = signature(founder_secret, founder, invite, 2)
    member_secret, member = keypair()
    joined = user(invite, invite_secret, member, "member", 3)
    joined_sig = signature(member_secret, member, joined, 3)
    membership = (root, invite_sig, invite, joined_sig, joined)
    return founder_secret, founder, root, member_secret, member, membership


def judged(stream, anchor):
    judgment = drain(stream, anchor)
    assert judgment.ok, judgment.failure
    return judgment


def test_founder_and_joined_member_closures_project_only_the_semantic_sink():
    _founder_secret, founder, root, _member_secret, member, membership = world()
    founder_judgment = judged((root,), root.fid)
    assert facts.bootstrap_member(
        founder_judgment, (root,), founder) == root
    assert dict(facts.removal_state_updates(
        founder_judgment, (root,))) == {
            scoped_id("device", founder): suppression_slot(),
            scoped_id("member", founder): suppression_slot(),
            subject_sid(founder, founder): suppression_slot(),
        }

    joined_judgment = judged(membership, root.fid)
    assert facts.control_evaluation(joined_judgment, membership) == membership
    assert facts.bootstrap_member(
        joined_judgment, membership, member) == membership[-1]
    assert facts.control_sink(joined_judgment, membership) == membership[-1]
    assert dict(facts.removal_state_updates(
        joined_judgment, membership)) == {
            scoped_id("device", member): suppression_slot(),
            scoped_id("member", member): suppression_slot(),
            subject_sid(member, member): suppression_slot(),
        }


def test_valid_removal_activates_its_exact_member_sid():
    founder_secret, founder, root, _member_secret, member, membership = world()
    item = removal(root.fid, founder, member, 4)
    item_sig = signature(founder_secret, founder, item, 4)
    stream = (*membership, item_sig, item)
    judgment = judged(stream, root.fid)
    assert dict(facts.removal_state_updates(judgment, stream)) == {
        scoped_id("member", member): suppression_slot(item.fid),
    }


def test_content_ephemeral_and_content_target_signature_reject_whole_control_pile():
    founder_secret, founder, root, _member_secret, _member, _membership = world()
    ordinary = message(root.fid, founder, "general", "hello", 5)
    ordinary_sig = signature(founder_secret, founder, ordinary, 5)
    ephemeral = request(
        root.fid, founder, founder, "sync", 100, "", 6)
    ephemeral_sig = signature(founder_secret, founder, ephemeral, 6)

    for stream in (
            (root, ordinary_sig, ordinary),
            (root, ephemeral_sig, ephemeral),
            (ordinary_sig,)):
        judgment = judged(stream, root.fid)
        with pytest.raises(ValueError, match="control|ordinary|non-durable"):
            facts.control_evaluation(judgment, stream)


def test_bootstrap_relabel_active_delta_and_route_overflow_fail(monkeypatch):
    founder_secret, founder, root, _member_secret, member, membership = world()
    judgment = judged(membership, root.fid)
    with pytest.raises(ValueError, match="direct member"):
        facts.bootstrap_member(judgment, membership, h(b"stranger"))

    item = removal(root.fid, founder, member, 7)
    item_sig = signature(founder_secret, founder, item, 7)
    active_stream = (*membership, item_sig, item)
    active = judged(active_stream, root.fid)
    assert any(value["state"] == "active" for _sid, value in
               facts.removal_state_updates(active, active_stream))

    original = facts.current_scopes
    monkeypatch.setattr(
        facts,
        "current_scopes",
        lambda fact: frozenset(
            scoped_id("member", h(f"overflow {index}".encode()))
            for index in range(6)
        ) if fact.fid == membership[-1].fid else original(fact),
    )
    with pytest.raises(ValueError, match="route budget"):
        facts.removal_state_updates(judgment, membership)


def test_independent_control_sinks_require_independent_closed_piles():
    founder_secret, founder, root, _member_secret, member, membership = world()
    first = removal(root.fid, founder, member, 7)
    first_sig = signature(founder_secret, founder, first, 7)
    second = removal(root.fid, founder, founder, 8)
    second_sig = signature(founder_secret, founder, second, 8)
    stream = (*membership, first_sig, first, second_sig, second)
    judgment = judged(stream, root.fid)

    with pytest.raises(ValueError, match="one semantic sink"):
        facts.removal_state_updates(judgment, stream)
