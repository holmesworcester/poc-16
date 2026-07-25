"""Direct-key device grants and equal-peer runtime behavior."""
import sqlite3

import pytest

from tinyp2p import cmds
from tinyp2p import facts
from tinyp2p.close import close, encode_pile
from tinyp2p.crypto import keypair
from tinyp2p.facts.auth.device import bind, device, devices
from tinyp2p.facts.auth.device_invite import device_invite as device_invite_fact
from tinyp2p.facts.auth.device_invite import grant
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.facts.auth.workspace import workspace as workspace_fact
from tinyp2p.kernel import drain, offer_src, resolve_deps
from tinyp2p.node import Node, now_ms

from .util import add_member, all_fids, closed_subset, deliver, member_src


def _inject_device_claim(
        node, workspace, secret, public, user, target, label, ts):
    """Author a valid claim directly, bypassing command-side duplicate checks."""
    item = device_invite_fact(public, user, target, label, ts)
    signed = signature(secret, public, item, ts)
    device_source = offer_src(
        node.idx(workspace), "device_key", public,
        requires=(("device", user, public),))
    node.ingest_new(
        workspace,
        [signed, item],
        {
            signed.fid: [],
            item.fid: [
                signed.fid,
                member_src(node, workspace, public),
                device_source,
            ],
        },
    )
    return item


def test_direct_grant_admits_a_known_key_without_a_join(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    bind(node, workspace, "phone")
    user = node.pk

    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    first = grant(node, workspace, user, laptop, "laptop")
    facts_after_first = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    assert grant(node, workspace, user, laptop, "laptop") == first
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == facts_after_first
    with pytest.raises(ValueError, match="already enrolled"):
        grant(node, workspace, user, laptop, "duplicate")

    members = {row["pk"]: row["role"] for row in cmds.members(node, workspace)}
    assert members[laptop] == "device"
    assert {row["pk"] for row in devices(node, workspace, user)} \
        == {user, laptop}

    node.bind_identity(workspace, laptop)
    fid = cmds.post(node, workspace, "general", "authored by laptop")
    assert node.fact_of(workspace, fid).body["pk"] == laptop


def test_any_device_set_peer_can_grant_the_next_sibling(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
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
    assert {row["pk"] for row in cmds.members(node, workspace)} \
        >= {user, laptop, tablet}


def test_device_commands_reject_existing_members_and_bindings(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    bind(node, workspace, "phone")
    with pytest.raises(ValueError, match="already in a device set"):
        bind(node, workspace, "renamed phone")

    _, bob, _ = add_member(node, workspace, "bob")
    with pytest.raises(ValueError, match="already enrolled"):
        grant(node, workspace, node.pk, bob, "captured bob")


def test_duplicate_device_projection_uses_the_smallest_fact_id():
    secret, public = keypair()
    root = workspace_fact(secret, public, "alice", 1)
    first = device(public, "phone", 2)
    first_sig = signature(secret, public, first, 2)
    second = device(public, "tablet", 3)
    second_sig = signature(secret, public, second, 3)

    observed = []
    for stream in (
            [root, first_sig, first, second_sig, second],
            [root, second_sig, second, first_sig, first]):
        result = drain(stream, root.fid)
        assert result.ok
        db = sqlite3.connect(":memory:")
        db.executescript(facts.APP_SCHEMA)
        for valid in result.valids:
            facts.materialize(db, root.fid, valid)
        observed.append(db.execute(
            "SELECT user, pk, label, source FROM devices").fetchall())
        db.close()

    winner = min((first, second), key=lambda fact: fact.fid)
    assert observed[0] == observed[1] == [
        (public, public, winner.body["label"], winner.fid)]


def test_bearer_user_precedes_device_role_in_every_arrival_order():
    founder_secret, founder = keypair()
    root = workspace_fact(founder_secret, founder, "alice", 1)
    primary = device(founder, "phone", 2)
    primary_sig = signature(founder_secret, founder, primary, 2)

    invite_secret, invite_public = keypair()
    invitation = user_invite(founder, invite_public, 3)
    invitation_sig = signature(founder_secret, founder, invitation, 3)
    bob_secret, bob = keypair()
    joined = user(invitation, invite_secret, bob, "Bob", 4)
    joined_sig = signature(bob_secret, bob, joined, 4)
    direct = device_invite_fact(
        founder, founder, bob, "laptop", 5)
    direct_sig = signature(founder_secret, founder, direct, 5)

    prefix = [root, primary_sig, primary]
    bearer = [invitation_sig, invitation, joined_sig, joined]
    device_grant = [direct_sig, direct]
    observed = []
    for stream in (
            prefix + bearer + device_grant,
            prefix + device_grant + bearer):
        result = drain(stream, root.fid)
        assert result.ok
        db = sqlite3.connect(":memory:")
        db.executescript(facts.APP_SCHEMA)
        for valid in result.valids:
            facts.materialize(db, root.fid, valid)
        observed.append(db.execute(
            "SELECT name, role FROM members WHERE ws=? AND pk=?",
            (root.fid, bob)).fetchone())
        db.close()

    assert observed == [("Bob", "member"), ("Bob", "member")]


def test_conflicting_device_claim_uses_one_winner_for_reads_and_authority(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    founder_secret, founder = node.identity(workspace)
    cmds.bind_device(node, workspace, "alice-phone")

    bob_secret, bob, _ = add_member(node, workspace, "bob")
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    cmds.bind_device(node, workspace, "bob-phone")

    sibling_secret, sibling = keypair()
    node.keychain.add_identity(sibling_secret)
    grants = []
    for ordinal, (secret, public, user) in enumerate((
            (founder_secret, founder, founder),
            (bob_secret, bob, bob),
    )):
        item = device_invite_fact(
            public, user, sibling, f"{user[:8]}-sibling", 100 + ordinal)
        signed = signature(secret, public, item, 100 + ordinal)
        device_source = node.idx(workspace).execute(
            "SELECT o.src FROM offers o JOIN proofs p ON p.fid=o.src "
            "WHERE o.name='device_key' AND o.a0=? "
            "ORDER BY p.rank, o.src LIMIT 1",
            (public,),
        ).fetchone()[0]
        node.ingest_new(
            workspace, [signed, item],
            {
                signed.fid: [],
                item.fid: [
                    signed.fid,
                    member_src(node, workspace, public),
                    device_source,
                ],
            },
        )
        grants.append(item)

    projected = devices(node, workspace)
    sibling_row = next(row for row in projected if row["pk"] == sibling)
    assert sibling_row["user"] == founder

    node.bind_identity(workspace, sibling)
    _, another = keypair()
    with pytest.raises(ValueError, match="not a device-set member"):
        grant(node, workspace, bob, another, "must-not-use-losing-claim")

    winner = node.idx(workspace).execute(
        "SELECT o.src FROM offers o JOIN proofs p ON p.fid=o.src "
        "WHERE o.name='device_key' AND o.a0=? "
        "ORDER BY p.rank, o.src LIMIT 1",
        (sibling,),
    ).fetchone()[0]
    assert winner == grants[0].fid


def test_conflicting_authority_converges_to_one_finite_subset(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    founder_secret, founder = node.identity(workspace)
    cmds.bind_device(node, workspace, "alice-phone")

    bob_secret, bob, _ = add_member(node, workspace, "bob")
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    cmds.bind_device(node, workspace, "bob-phone")
    common = closed_subset(node, workspace, all_fids(node, workspace))

    target_secret, target = keypair()
    node.keychain.add_identity(target_secret)
    target_claim = _inject_device_claim(
        node, workspace, bob_secret, bob, bob, target, "target", 100)
    node.bind_identity(workspace, target)
    _, child = keypair()
    child_claim = _inject_device_claim(
        node, workspace, target_secret, target, bob, child, "child", 101)
    assert target_claim.fid in resolve_deps(child_claim, node.idx(workspace))
    target_chain = closed_subset(
        node, workspace, [target_claim.fid, child_claim.fid])

    # This claim is independently valid and shallower than Bob's claim for
    # target. In the union it makes target's child grant lose the required
    # (Bob, target) co-offer.
    conflict = device_invite_fact(
        founder, founder, target, "alice-target", 102)
    conflict_sig = signature(founder_secret, founder, conflict, 102)
    conflict_deps = {
        conflict_sig.fid: [],
        conflict.fid: [
            conflict_sig.fid,
            member_src(node, workspace, founder),
            offer_src(
                node.idx(workspace), "device_key", founder,
                requires=(("device", founder, founder),)),
        ],
    }
    new = {fact.fid: fact for fact in (conflict_sig, conflict)}

    def conflict_deps_of(fid):
        if fid in conflict_deps:
            return conflict_deps[fid]
        return resolve_deps(
            node.fact_of(workspace, fid), node.idx(workspace))

    standalone = close(
        [conflict_sig, conflict],
        conflict_deps_of,
        lambda fid: new.get(fid) or node.fact_of(workspace, fid),
    )
    assert drain(standalone, workspace).ok
    conflict_pile = encode_pile(standalone)

    # The second peer sees the conflict first and the Bob chain second; the
    # first peer sees them in the opposite order.
    peer = Node(str(tmp_path / "peer"))
    deliver(peer, workspace, common)
    peer.turn(workspace)
    deliver(peer, workspace, conflict_pile)
    peer.turn(workspace)
    deliver(peer, workspace, target_chain)
    peer.turn(workspace)

    accepted = node.ingest_new(
        workspace, [conflict_sig, conflict], conflict_deps)
    assert any(valid.fact.fid == conflict.fid for valid in accepted)

    for current in (node, peer):
        assert current.fact_of(workspace, conflict.fid) == conflict
        assert current.fact_of(workspace, target_claim.fid) == target_claim
        assert current.fact_of(workspace, child_claim.fid) is None
        assert current.app.execute(
            "SELECT 1 FROM devices WHERE ws=? AND pk=?",
            (workspace, child)).fetchone() is None
        assert current.store(workspace).list("pile/") == []
    assert all_fids(node, workspace) == all_fids(peer, workspace)
    assert node.store(workspace).get("root") \
        == peer.store(workspace).get("root")

    # Canonical pruning cannot poison later turns.
    assert node.store(workspace).list("pile/") == []
    posted = cmds.post(node, workspace, "general", "still authorized")
    assert node.fact_of(workspace, posted) is not None


def test_conflict_does_not_discard_an_unrelated_pile(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    founder_secret, founder = node.identity(workspace)
    cmds.bind_device(node, workspace, "alice-phone")

    bob_secret, bob, _ = add_member(node, workspace, "bob")
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    cmds.bind_device(node, workspace, "bob-phone")

    target_secret, target = keypair()
    target_claim = _inject_device_claim(
        node, workspace, bob_secret, bob, bob, target, "target", 100)
    _, child = keypair()
    child_claim = _inject_device_claim(
        node, workspace, target_secret, target, bob, child, "child", 101)

    conflict = device_invite_fact(
        founder, founder, target, "alice-target", 102)
    conflict_sig = signature(founder_secret, founder, conflict, 102)
    deps = {
        conflict_sig.fid: [],
        conflict.fid: [
            conflict_sig.fid,
            member_src(node, workspace, founder),
            offer_src(
                node.idx(workspace), "device_key", founder,
                requires=(("device", founder, founder),)),
        ],
    }
    new = {fact.fid: fact for fact in (conflict_sig, conflict)}
    conflict_pile = encode_pile(close(
        [conflict_sig, conflict],
        lambda fid: deps[fid] if fid in deps else resolve_deps(
            node.fact_of(workspace, fid), node.idx(workspace)),
        lambda fid: new.get(fid) or node.fact_of(workspace, fid),
    ))
    deliver(node, workspace, conflict_pile, member="attacker00000000")

    node.bind_identity(workspace, founder)
    posted = cmds.post(
        node, workspace, "general", "honest same turn", ts=200)

    assert node.fact_of(workspace, posted) is not None
    assert [message["text"] for message in cmds.msgs(node, workspace)] \
        == ["honest same turn"]
    assert node.fact_of(workspace, conflict.fid) == conflict
    assert node.fact_of(workspace, target_claim.fid) == target_claim
    assert node.fact_of(workspace, child_claim.fid) is None


def test_rank_only_shadow_reconciles_the_device_projection(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "root")
    root_secret, root = node.identity(workspace)

    q_secret, q, _ = add_member(node, workspace, "q")
    short_secret, short, _ = add_member(
        node, workspace, "short", inviter=(q_secret, q))

    deep_secret, deep, _ = add_member(node, workspace, "d1")
    for name in ("d2", "d3", "deep"):
        deep_secret, deep, _ = add_member(
            node, workspace, name, inviter=(deep_secret, deep))

    for secret, public, label in (
            (short_secret, short, "short-primary"),
            (deep_secret, deep, "deep-primary")):
        node.keychain.add_identity(secret)
        node.bind_identity(workspace, public)
        cmds.bind_device(node, workspace, label)

    _, target = keypair()
    deep_claim = _inject_device_claim(
        node, workspace, deep_secret, deep, deep, target, "from-deep", 200)
    short_claim = _inject_device_claim(
        node, workspace, short_secret, short, short, target, "from-short", 201)
    assert node.app.execute(
        "SELECT user, source FROM devices WHERE ws=? AND pk=?",
        (workspace, target)).fetchone() == (short, short_claim.fid)

    # Rejoining the deep member directly from root adds only signature,
    # invitee, and member offers. It shortens the old deep device claim's
    # proof enough to become the canonical target winner.
    invite_secret, invite_public = keypair()
    ts = now_ms() + 10
    invitation = user_invite(root, invite_public, ts)
    invitation_sig = signature(root_secret, root, invitation, ts)
    rejoined = user(
        invitation, invite_secret, deep, "deep-direct", ts + 1)
    rejoined_sig = signature(deep_secret, deep, rejoined, ts + 1)
    fresh = node.ingest_new(
        workspace,
        [invitation_sig, invitation, rejoined_sig, rejoined],
        {
            invitation_sig.fid: [],
            invitation.fid: [
                invitation_sig.fid,
                member_src(node, workspace, root),
            ],
            rejoined_sig.fid: [],
            rejoined.fid: [invitation.fid, rejoined_sig.fid],
        },
    )

    assert fresh
    assert not any(
        name == "device_key"
        for valid in fresh
        for name, _, _ in valid.fact.offers())
    assert node.app.execute(
        "SELECT user, source FROM devices WHERE ws=? AND pk=?",
        (workspace, target)).fetchone() == (deep, deep_claim.fid)
