"""Explicit device-set authority without provider winners or rewiring."""

import pytest

import facts
from .util import signed_pile_facts, signed_pile_bytes
from core import fact_index
from core.crypto import keypair
from core.kernel import resolve_deps
from full_peer.node import FullPeer, now_ms
from facts.auth.device import bind, device, devices
from facts.auth.device_invite import grant
from facts.auth.request import payload as request_payload
from facts.auth.signature import signature

from .util import (
    add_member,
    all_fids,
    closed_subset,
    deliver,
    inject_device_claim,
    member_src,
)


def test_direct_grant_admits_a_known_key_without_a_join(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice")
    bind(node, workspace, "phone")
    user = node.pk

    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    first = grant(node, workspace, user, laptop, "laptop")
    granted = node.fact_of(workspace, first)
    dependencies = [
        node.fact_of(workspace, fid)
        for fid in resolve_deps(granted, node.sql(workspace))
    ]
    assert {fact.t for fact in dependencies} \
        == {"signature", "workspace", "device"}
    assert granted.ts == node.fact_of(workspace, workspace).ts
    facts_after_first = len(node.sql(workspace).fact_ids())
    assert grant(node, workspace, user, laptop, "laptop") == first
    assert len(node.sql(workspace).fact_ids()) == facts_after_first
    with pytest.raises(ValueError, match="already enrolled"):
        grant(node, workspace, user, laptop, "duplicate")

    members = {
        row["pk"]: row["role"]
        for row in facts.auth.user.members(node, workspace)
    }
    assert members[laptop] == "device"
    assert {row["pk"] for row in devices(node, workspace, user)} \
        == {user, laptop}

    node.bind_identity(workspace, laptop)
    fid = facts.content.message.post(
        node, workspace, "general", "authored by laptop")
    posted = node.fact_of(workspace, fid)
    assert posted.body["pk"] == laptop
    assert posted.body["owner"] == user


def test_direct_grant_retry_after_restart_is_the_same_fact(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice")
    bind(node, workspace, "phone")
    user = node.pk
    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)

    first = grant(node, workspace, user, laptop, "laptop")
    fact_count = len(node.sql(workspace).fact_ids())
    node.idx(workspace).close()

    reopened = FullPeer(node.dir)
    assert grant(reopened, workspace, user, laptop, "laptop") == first
    assert len(reopened.sql(workspace).fact_ids()) == fact_count


def test_duplicate_provider_does_not_change_an_idempotent_grant(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder_secret, founder = node.identity(workspace)
    bind(node, workspace, "phone")

    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    first = grant(node, workspace, founder, laptop, "laptop")

    alternate = device(workspace, founder, "alternate-phone", 10_000)
    alternate_sig = signature(
        founder_secret, founder, alternate, alternate.ts)
    node.ingest_new(
        workspace,
        [alternate_sig, alternate],
        {
            alternate_sig.fid: (),
            alternate.fid: (
                alternate_sig.fid,
                member_src(node, workspace, founder),
            ),
        },
    )

    before = node.sql(workspace).fact_ids()
    assert grant(node, workspace, founder, laptop, "laptop") == first
    assert node.sql(workspace).fact_ids() == before
    assert node.fact_of(workspace, alternate.fid) == alternate


def test_any_device_set_peer_can_grant_the_next_sibling(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice")
    bind(node, workspace, "phone")
    user = node.pk

    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    grant(node, workspace, user, laptop, "laptop")
    node.bind_identity(workspace, laptop)

    tablet_secret, tablet = keypair()
    node.keychain.add_identity(tablet_secret)
    grant(node, workspace, user, tablet, "tablet")

    assert {row["pk"] for row in devices(node, workspace, user)} \
        == {user, laptop, tablet}
    assert {row["pk"] for row in facts.auth.user.members(node, workspace)} \
        >= {user, laptop, tablet}


def test_device_commands_reject_existing_members_and_bindings(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice")
    bind(node, workspace, "phone")
    with pytest.raises(ValueError, match="already in a device set"):
        bind(node, workspace, "renamed phone")

    _, bob, _ = add_member(node, workspace, "bob")
    with pytest.raises(ValueError, match="already enrolled"):
        grant(node, workspace, node.pk, bob, "captured bob")


def _two_principals(node, workspace):
    founder_secret, founder = node.identity(workspace)
    bind(node, workspace, "alice-phone")
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    bind(node, workspace, "bob-phone")
    return founder_secret, founder, bob_secret, bob


def test_conflicting_device_claims_are_distinct_explicit_addresses(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder_secret, founder, bob_secret, bob = _two_principals(
        node, workspace)
    sibling_secret, sibling = keypair()
    node.keychain.add_identity(sibling_secret)

    # Each authored pile belongs to the device whose writer log signs it.
    node.bind_identity(workspace, founder)
    alice_claim = inject_device_claim(
        node, workspace, founder_secret, founder, founder, sibling,
        "alice-sibling", 100)
    node.bind_identity(workspace, bob)
    bob_claim = inject_device_claim(
        node, workspace, bob_secret, bob, bob, sibling,
        "bob-sibling", 101)

    assert node.sql(workspace).resolve_offer(
        "member", sibling, founder
    ) == alice_claim.fid
    assert node.sql(workspace).resolve_offer(
        "member", sibling, bob
    ) == bob_claim.fid
    assert {
        (row["user"], row["pk"])
        for row in devices(node, workspace)
        if row["pk"] == sibling
    } == {(founder, sibling), (bob, sibling)}

    # Commands with an explicit user remain unambiguous. Commands which would
    # have to guess an owner fail before authoring bytes.
    node.bind_identity(workspace, sibling)
    _, child = keypair()
    child_fid = grant(
        node, workspace, bob, child, "bob-side child")
    assert node.fact_of(workspace, child_fid).body["user"] == bob
    with pytest.raises(ValueError, match="ambiguous member ownership"):
        facts.content.message.post(
            node, workspace, "general", "must name an owner")


def test_later_provider_cannot_prune_a_valid_descendant(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    founder_secret, founder, bob_secret, bob = _two_principals(
        source, workspace)
    common = closed_subset(source, workspace, all_fids(source, workspace))

    target_secret, target = keypair()
    source.keychain.add_identity(target_secret)
    bob_claim = inject_device_claim(
        source, workspace, bob_secret, bob, bob, target, "bob-target", 100)
    source.bind_identity(workspace, target)
    _, child = keypair()
    child_claim = inject_device_claim(
        source, workspace, target_secret, target, bob, child,
        "bob-child", 101)
    bob_chain = closed_subset(
        source, workspace, (bob_claim.fid, child_claim.fid))

    source.bind_identity(workspace, founder)
    alice_claim = inject_device_claim(
        source, workspace, founder_secret, founder, founder, target,
        "alice-target", 102)
    alice_pile = closed_subset(source, workspace, (alice_claim.fid,))

    # Independent closed units remain independent wire piles.
    assert len(source.sender(workspace).pack_batches((
        signed_pile_facts(bob_chain, workspace),
        signed_pile_facts(alice_pile, workspace),
    ))) == 2

    peers = []
    for name, order in (
            ("bob-first", (bob_chain, alice_pile)),
            ("alice-first", (alice_pile, bob_chain))):
        peer = FullPeer(str(tmp_path / name))
        deliver(peer, workspace, common)
        for pile in order:
            deliver(peer, workspace, pile)
        peers.append(peer)

    for peer in (source, *peers):
        assert peer.fact_of(workspace, bob_claim.fid) == bob_claim
        assert peer.fact_of(workspace, alice_claim.fid) == alice_claim
        assert peer.fact_of(workspace, child_claim.fid) == child_claim
        assert [fact.fid for fact in peer.select(
            workspace, "device_key", target, bob)] == [bob_claim.fid]
        assert [fact.fid for fact in peer.select(
            workspace, "device_key", target, founder)] == [alice_claim.fid]
    assert all_fids(source, workspace) \
        == all_fids(peers[0], workspace) \
        == all_fids(peers[1], workspace)
    assert source.store(workspace).get("root") \
        == peers[0].store(workspace).get("root") \
        == peers[1].store(workspace).get("root")


def test_later_provider_cannot_change_stored_owner_or_delete_authority(
        tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    founder_secret, founder, bob_secret, bob = _two_principals(
        source, workspace)
    common = closed_subset(source, workspace, all_fids(source, workspace))

    target_secret, target = keypair()
    source.keychain.add_identity(target_secret)
    bob_claim = inject_device_claim(
        source, workspace, bob_secret, bob, bob, target, "bob-target", 100)
    source.bind_identity(workspace, target)
    posted = facts.content.message.post(
        source, workspace, "general", "immutable ownership", ts=110)
    deletion = facts.content.delete.remove(
        source, workspace, posted, ts=120)
    bob_pile = closed_subset(
        source, workspace, (bob_claim.fid, posted, deletion))

    source.bind_identity(workspace, founder)
    alice_claim = inject_device_claim(
        source, workspace, founder_secret, founder, founder, target,
        "alice-target", 130)
    alice_pile = closed_subset(source, workspace, (alice_claim.fid,))

    peers = []
    for name, order in (
            ("delete-first", (bob_pile, alice_pile)),
            ("conflict-first", (alice_pile, bob_pile))):
        peer = FullPeer(str(tmp_path / name))
        deliver(peer, workspace, common)
        for pile in order:
            deliver(peer, workspace, pile)
        peers.append(peer)

    for peer in (source, *peers):
        target_fact = peer.fact_of(workspace, posted)
        action = peer.fact_of(workspace, deletion)
        assert target_fact.body["owner"] == bob
        assert action.body == {
            "pk": target,
            "owner": bob,
            "mode": facts._policy.OWNER,
        }
        assert peer.fact_of(workspace, alice_claim.fid) == alice_claim
        sid = "fact:" + posted
        assert peer.suppression_active(workspace, sid)
        assert peer.idx(workspace).execute(
            "SELECT src FROM fact_index WHERE kind=? AND k0=?",
            (fact_index.ACTION_INDEX, sid),
        ).fetchone() == (deletion,)
        assert facts.content.message.messages(peer, workspace) == []


def test_removed_owner_disables_child_mint_and_delegated_admin(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    _, dave, _ = add_member(node, workspace, "dave", ts=20)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    bind(node, workspace, "bob-phone")

    child_secret, child = keypair()
    node.keychain.add_identity(child_secret)
    grant(node, workspace, bob, child, "bob-child")
    node.bind_identity(workspace, child)
    now = now_ms()
    request = signed_pile_bytes(request_payload(
        node, workspace, "sync", now + 60_000, now))

    node.bind_identity(workspace, founder)
    facts.auth.admin.grant(node, workspace, child)
    facts.auth.removal.evict(node, workspace, bob)

    assert node.authorize_access(workspace, request, "sync") is None
    child_row = next(
        row for row in facts.auth.user.members(node, workspace)
        if row["pk"] == child)
    assert child_row["role"] == "device"
    assert child_row["evicted"] is True
    node.bind_identity(workspace, child)
    with pytest.raises(ValueError, match="not a workspace admin"):
        facts.auth.removal.evict(node, workspace, dave)
