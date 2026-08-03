"""Running contracts for indexed suppression actions and ingress screening."""
import asyncio
import os

import pytest

import facts
from core import fact_index
from core.close import close
from .util import signed_pile_bytes
from core.crypto import keypair, load_sk
from core.kernel import resolve_deps
from full_peer.node import FullPeer
from facts.auth.removal import removal
from facts.auth.signature import signature
from facts.content.message import message

from .util import (
    add_member,
    all_fids,
    author_msg,
    closed_subset,
    deliver,
    inject_device_claim,
    member_src,
    visible_fids,
)


def _action_rows(node, workspace):
    actions = node.idx(workspace).execute(
        "SELECT k0, src FROM fact_index "
        "WHERE kind=? ORDER BY k0",
        (fact_index.ACTION_INDEX,),
    ).fetchall()
    return list(actions)


def _signed_pile(node, workspace, fact, signed, deps):
    incoming = {fact.fid: fact, signed.fid: signed}
    fact_of = lambda fid: incoming.get(fid) or node.fact_of(workspace, fid)
    return signed_pile_bytes(close(
        [signed, fact],
        lambda fid: deps[fid] if fid in deps else (
            resolve_deps(fact_of(fid), node.sql(workspace)) or ()),
        fact_of,
    ))


def _author_eviction(node, workspace, target, ts):
    secret, public = node.identity(workspace)
    item = removal(workspace, public, target, ts)
    signed = signature(secret, public, item, ts)
    admin = node.sql(workspace).resolve_offer("admin", public)
    target_member = node.sql(workspace).resolve_offer("member", target)
    node.ingest_new(
        workspace, [signed, item],
        {
            signed.fid: (),
            item.fid: (signed.fid, admin, target_member),
        })
    return item


def _ordered_action_world(path):
    """Fixed identities whose ts=41 action fid sorts below the ts=20 fid."""
    founder_secret = load_sk(f"{1:064x}")
    member_secret = load_sk(f"{2:064x}")
    member = member_secret.verify_key.encode().hex()
    node = FullPeer(str(path), initial_secret=founder_secret)
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    add_member(
        node,
        workspace,
        "bob",
        ts=10,
        member_identity=(member_secret, member),
    )
    return node, workspace, member_secret, member


def test_action_reverse_index_rebuilds_from_the_trees(tmp_path):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    target = facts.content.message.post(node, workspace, "general", "doomed", ts=10)
    facts.content.delete.remove(node, workspace, target, ts=20)
    expected_root = node.store(workspace).get("root")
    expected_actions = _action_rows(node, workspace)

    node.idx(workspace).close()
    os.unlink(directory / "ws" / f"{workspace}.idx.db")

    rebuilt = FullPeer(str(directory))
    assert _action_rows(rebuilt, workspace) == expected_actions
    assert rebuilt.store(workspace).get("root") == expected_root
    assert target not in visible_fids(rebuilt, workspace)


def test_historical_fact_survives_but_removed_member_cannot_author_now(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    provider = member_src(node, workspace, bob)
    eviction = facts.auth.removal.evict(node, workspace, bob)

    ts = node.fact_of(workspace, eviction).ts + 1
    item = message(workspace, bob, "general", "must not land", ts)
    signed = signature(bob_secret, bob, item, ts)
    pile = _signed_pile(
        node, workspace, item, signed,
        {signed.fid: (), item.fid: (signed.fid, provider)})
    deliver(node, workspace, pile)

    assert node.fact_of(workspace, item.fid) == item
    assert node.fact_of(workspace, item.fid) == item
    assert [row["fid"] for row in facts.content.message.messages(
        node, workspace)] == [item.fid]

    root = node.store(workspace).get("root")
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    with pytest.raises(ValueError, match="not a workspace member"):
        facts.content.message.post(
            node, workspace, "general", "cannot share now", ts=ts + 1)
    assert node.store(workspace).get("root") == root


def test_historical_admin_action_survives_but_removed_admin_cannot_author(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    _, carol, _ = add_member(node, workspace, "carol", ts=20)
    _, dave, _ = add_member(node, workspace, "dave", ts=21)
    admin_fid = facts.auth.admin.grant(node, workspace, bob)
    eviction = facts.auth.removal.evict(node, workspace, bob)

    ts = node.fact_of(workspace, eviction).ts + 1
    item = removal(workspace, bob, carol, ts)
    signed = signature(bob_secret, bob, item, ts)
    pile = _signed_pile(
        node, workspace, item, signed,
        {
            signed.fid: (),
            item.fid: (
                signed.fid,
                admin_fid,
                member_src(node, workspace, carol),
            ),
        })
    deliver(node, workspace, pile)

    assert node.fact_of(workspace, item.fid) == item
    assert node.fact_of(workspace, item.fid) == item
    assert node.suppression_active(
        workspace, facts.principal_sid("member", carol))

    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    with pytest.raises(ValueError, match="not a workspace admin"):
        facts.auth.removal.evict(node, workspace, dave)


def test_terminal_member_action_covers_a_future_provider(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bob_identity = add_member(node, workspace, "bob", ts=10)[:2]
    bob_secret, bob = bob_identity
    facts.auth.removal.evict(node, workspace, bob)

    _, rejoined, _ = add_member(
        node, workspace, "bob-again", ts=30,
        member_identity=(bob_secret, bob))
    assert rejoined == bob
    providers = node.idx(workspace).execute(
        "SELECT src FROM fact_index "
        "WHERE kind='member' AND k0=? ORDER BY src",
        (bob,)).fetchall()
    assert len(providers) == 2
    assert node.suppression_active(
        workspace, facts.principal_sid("member", bob))


def test_admitted_post_removal_fact_converges_in_both_delivery_orders(
        tmp_path):
    """A prior-sorting removal cannot rewrite historical fact admission."""
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    bob_secret, bob, _ = add_member(source, workspace, "bob", ts=10)
    base = closed_subset(source, workspace, all_fids(source, workspace))

    posted = author_msg(
        source, workspace, bob_secret, bob, "post-action", ts=30)
    message_pile = closed_subset(source, workspace, [posted.fid])
    action = _author_eviction(source, workspace, bob, 20)
    action_pile = closed_subset(source, workspace, [action.fid])

    peers = []
    for name, order in (
            ("fact-first", (message_pile, action_pile)),
            ("action-first", (action_pile, message_pile))):
        peer = FullPeer(str(tmp_path / name))
        peer.add_workspace(workspace, "alice", peers=[])
        deliver(peer, workspace, base)
        for ordinal, pile in enumerate(order):
            deliver(peer, workspace, pile)
            if name == "fact-first" and ordinal == 0:
                assert peer.fact_of(workspace, posted.fid) == posted
        peers.append(peer)

    assert all(
        peer.fact_of(workspace, posted.fid) == posted
        and peer.fact_of(workspace, posted.fid) == posted
        and [row["fid"] for row in facts.content.message.messages(
            peer, workspace)] == [posted.fid]
        and peer.suppression_active(
            workspace, facts.principal_sid("member", bob))
        for peer in peers
    )
    assert peers[0].store(workspace).get("root") \
        == peers[1].store(workspace).get("root") \
        == source.store(workspace).get("root")


def test_duplicate_action_uses_earliest_key_in_every_arrival_order(tmp_path):
    source, workspace, bob_secret, bob = _ordered_action_world(
        tmp_path / "source")
    base = closed_subset(source, workspace, all_fids(source, workspace))

    first = _author_eviction(source, workspace, bob, 20)
    first_pile = closed_subset(source, workspace, [first.fid])
    later = removal(
        workspace, source.identity_id(workspace), bob, 41)
    assert later.key > first.key
    assert later.fid < first.fid  # deliberately opposes key order
    secret, public = source.identity(workspace)
    later_sig = signature(secret, public, later, later.ts)
    source.ingest_new(
        workspace, [later_sig, later],
        {
            later_sig.fid: (),
            later.fid: (
                later_sig.fid,
                workspace,
                member_src(source, workspace, bob),
            ),
        })
    later_pile = closed_subset(source, workspace, [later.fid])

    posted = message(
        workspace, bob, "general", "between actions", 30)
    posted_sig = signature(bob_secret, bob, posted, 30)
    message_pile = _signed_pile(
        source, workspace, posted, posted_sig,
        {
            posted_sig.fid: (),
            posted.fid: (
                posted_sig.fid, member_src(source, workspace, bob)),
        },
    )

    roots = []
    for name, order in (
            ("early-first", (first_pile, later_pile)),
            ("late-first", (later_pile, first_pile))):
        peer = FullPeer(str(tmp_path / name))
        peer.add_workspace(workspace, "alice", peers=[])
        deliver(peer, workspace, base)
        for pile in (*order, message_pile):
            deliver(peer, workspace, pile)
        sid = facts.principal_sid("member", bob)
        assert peer.idx(workspace).execute(
            "SELECT src FROM fact_index WHERE kind=? AND k0=?",
            (fact_index.ACTION_INDEX, sid),
        ).fetchone() \
            == (first.fid,)
        assert peer.fact_of(workspace, posted.fid) == posted
        assert peer.fact_of(workspace, posted.fid) == posted
        roots.append(peer.store(workspace).get("root"))
    assert roots[0] == roots[1]


def test_fact_sync_joins_actions_without_fact_id_shortcuts(tmp_path):
    source, workspace, _, bob = _ordered_action_world(
        tmp_path / "source")
    founder_secret, founder = source.identity(workspace)
    common = closed_subset(source, workspace, all_fids(source, workspace))
    first = _author_eviction(source, workspace, bob, 20)

    destination = FullPeer(str(tmp_path / "destination"))
    destination.keychain.add_identity(founder_secret)
    destination.add_workspace(
        workspace, "alice", peers=[], identity=founder)
    deliver(destination, workspace, common)
    later = removal(workspace, founder, bob, 41)
    later_signature = signature(founder_secret, founder, later, 41)
    deliver(destination, workspace, _signed_pile(
        destination,
        workspace,
        later,
        later_signature,
        {
            later_signature.fid: (),
            later.fid: (
                later_signature.fid,
                destination.sql(workspace).resolve_offer("admin", founder),
                destination.sql(workspace).resolve_offer("member", bob),
            ),
        },
    ))
    assert later.key > first.key
    assert later.fid < first.fid  # the obsolete tuple-order shortcut

    result = asyncio.run(destination.mirror(workspace).sync_from(
        source.store(workspace)))

    assert result.errors == ()
    assert result.changed >= 1
    sid = facts.principal_sid("member", bob)
    assert destination.idx(workspace).execute(
        "SELECT src FROM fact_index WHERE kind=? AND k0=?",
        (fact_index.ACTION_INDEX, sid),
    ).fetchone() \
        == (first.fid,)


def test_child_device_admin_inherits_user_liveness(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    _, carol, _ = add_member(node, workspace, "carol", ts=20)

    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    facts.auth.device.bind(node, workspace, "bob-primary")
    child_secret, child = keypair()
    node.keychain.add_identity(child_secret)
    facts.auth.device_invite.grant(node, workspace, bob, child, "bob-child")

    node.bind_identity(workspace, founder)
    facts.auth.admin.grant(node, workspace, child)
    facts.auth.removal.evict(node, workspace, bob)

    node.bind_identity(workspace, child)
    with pytest.raises(ValueError, match="not a workspace admin"):
        facts.auth.removal.evict(node, workspace, carol)
    assert not node.suppression_active(
        workspace, facts.principal_sid("member", carol))


def test_fact_sync_carries_actions_and_their_projection(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    target = facts.content.message.post(source, workspace, "general", "doomed", ts=10)
    before = closed_subset(source, workspace, all_fids(source, workspace))

    destination = FullPeer(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "alice", peers=[])
    deliver(destination, workspace, before)
    action_fid = facts.content.delete.remove(source, workspace, target, ts=20)

    result = asyncio.run(destination.mirror(workspace).sync_from(
        source.store(workspace)))

    assert result.errors == ()
    assert _action_rows(destination, workspace)[0][:2] == (
        f"fact:{target}", action_fid)
    assert target not in visible_fids(destination, workspace)
