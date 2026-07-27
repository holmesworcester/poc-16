"""Direct-key device grants and equal-peer runtime behavior."""
import sqlite3

import pytest

import facts

from core import cmds, mint
import core.sync as sync_module
from core.close import close, encode_pile
from core.crypto import keypair, load_sk
from facts.auth.device import bind, device, devices
from facts.auth.device_invite import device_invite as device_invite_fact
from facts.auth.device_invite import grant
from facts.auth.request import payload as request_payload
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace as workspace_fact
from core.kernel import drain, evaluate, offer_src, resolve_deps
from core.node import Node, now_ms

from .util import add_member, all_fids, closed_subset, deliver, member_src
from .util import inject_device_claim as _inject_device_claim


def _materialize(db, workspace, valid):
    """Unit-test seam for the pump-owned source/rank ledger."""
    db.execute(
        "INSERT INTO projected VALUES(?,?,?,0)",
        (workspace, valid.fact.fid, valid.fact.t))
    facts.materialize(db, workspace, valid)


def test_direct_grant_admits_a_known_key_without_a_join(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    bind(node, workspace, "phone")
    user = node.pk

    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    first = grant(node, workspace, user, laptop, "laptop")
    granted = node.fact_of(workspace, first)
    dependencies = [
        node.fact_of(workspace, fid)
        for fid in resolve_deps(granted, node.idx(workspace))
    ]
    assert {fact.t for fact in dependencies} \
        == {"signature", "workspace", "device"}
    assert granted.ts == node.fact_of(workspace, workspace).ts
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


def test_direct_grant_retry_after_restart_reconstructs_the_same_fact(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    bind(node, workspace, "phone")
    user = node.pk
    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)

    first = grant(node, workspace, user, laptop, "laptop")
    fact_count = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    node.idx(workspace).close()
    node.app.close()

    reopened = Node(node.dir)
    assert grant(reopened, workspace, user, laptop, "laptop") == first
    assert reopened.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == fact_count


def test_direct_grant_retry_survives_an_authority_winner_change(tmp_path):
    # Deterministic identities: the alternate-device search below must beat
    # ``original_device`` by fid within 256 tries, which an unlucky random
    # founder key can defeat (the known full-run flake).
    node = Node(str(tmp_path / "node"), initial_secret=load_sk(f"{7:064x}"))
    workspace = cmds.create(node, "alice", ts=1)
    founder_secret, founder = node.identity(workspace)
    bind(node, workspace, "phone")
    original_device = offer_src(
        node.idx(workspace), "device_key", founder)

    laptop_secret = load_sk(f"{8:064x}")
    laptop = laptop_secret.verify_key.encode().hex()
    node.keychain.add_identity(laptop_secret)
    first = grant(node, workspace, founder, laptop, "laptop")

    # A same-rank duplicate can change the canonical authority source by fid.
    # Its timestamp is deliberately different: retry identity must not depend
    # on whichever proof currently wins.
    alternate = None
    for ordinal in range(256):
        candidate = device(founder, f"alternate-{ordinal}", 10_000 + ordinal)
        if candidate.fid < original_device:
            alternate = candidate
            break
    assert alternate is not None
    alternate_sig = signature(
        founder_secret, founder, alternate, alternate.ts)
    node.ingest_new(
        workspace,
        [alternate_sig, alternate],
        {
            alternate_sig.fid: [],
            alternate.fid: [
                alternate_sig.fid,
                member_src(node, workspace, founder),
            ],
        },
    )
    assert offer_src(
        node.idx(workspace), "device_key", founder) == alternate.fid

    fact_count = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    assert grant(node, workspace, founder, laptop, "laptop") == first
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == fact_count


def test_device_authored_write_does_not_rebuild_the_roster(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    founder = node.identity_id(workspace)

    laptop_secret, laptop = keypair()
    node.keychain.add_identity(laptop_secret)
    grant(node, workspace, founder, laptop, "laptop")
    node.bind_identity(workspace, laptop)

    statements = []
    node.app.set_trace_callback(statements.append)
    try:
        cmds.post(node, workspace, "general", "ordinary device write", ts=10)
    finally:
        node.app.set_trace_callback(None)

    normalized = [" ".join(statement.lower().split())
                  for statement in statements]
    assert not any(statement.startswith(
        ("delete from device_rows", "delete from member_rows"))
        for statement in normalized)
    assert {row["pk"] for row in devices(node, workspace, founder)} \
        == {founder, laptop}


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
            _materialize(db, root.fid, valid)
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
            _materialize(db, root.fid, valid)
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
    child_secret, child = keypair()
    node.keychain.add_identity(child_secret)
    child_claim = _inject_device_claim(
        node, workspace, target_secret, target, bob, child, "child", 101)
    assert target_claim.fid in resolve_deps(child_claim, node.idx(workspace))
    node.bind_identity(workspace, child)
    ts = now_ms()
    stale_request = request_payload(
        node, workspace, "sync", ts + 120_000, ts)
    door = node.globals(workspace) | {("now", ts)}
    assert evaluate(stale_request, workspace, door)
    node.bind_identity(workspace, target)
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
    assert not evaluate(
        stale_request,
        workspace,
        door,
        canonical_db=node.idx(workspace),
    )

    for current in (node, peer):
        assert current.fact_of(workspace, conflict.fid) == conflict
        assert current.fact_of(workspace, target_claim.fid) == target_claim
        assert current.fact_of(workspace, child_claim.fid) is None
        assert current.app.execute(
            "SELECT 1 FROM devices WHERE ws=? AND pk=?",
            (workspace, child)).fetchone() is None
        assert current.store(workspace).list("pile/") == []
        seen = set()
        for op, fid in current.idx(workspace).execute(
                "SELECT op, fid FROM log ORDER BY seq"):
            if op == "+":
                seen.add(fid)
            else:
                assert fid in seen
    assert all_fids(node, workspace) == all_fids(peer, workspace)
    assert node.store(workspace).get("root") \
        == peer.store(workspace).get("root")

    # Canonical pruning cannot poison later turns.
    assert node.store(workspace).list("pile/") == []
    posted = cmds.post(node, workspace, "general", "still authorized")
    assert node.fact_of(workspace, posted) is not None


def test_diverged_equivalent_member_winners_can_mint_to_each_other(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "root", ts=1)
    root_secret, root = source.identity(workspace)
    bob_secret, bob = keypair()
    candidates = []
    for ordinal in range(2):
        invite_secret, invite_public = keypair()
        invitation = user_invite(
            root, invite_public, 10 + 2 * ordinal)
        invitation_sig = signature(
            root_secret, root, invitation, invitation.ts)
        joined = user(
            invitation, invite_secret, bob, f"bob-{ordinal}",
            11 + 2 * ordinal)
        joined_sig = signature(
            bob_secret, bob, joined, joined.ts)
        candidates.append(
            (joined.fid, invitation_sig, invitation, joined_sig, joined))
    original_chain, rejoin_chain = (
        max(candidates, key=lambda item: item[0]),
        min(candidates, key=lambda item: item[0]),
    )
    (
        _,
        original_invitation_sig,
        original_invitation,
        original_joined_sig,
        original,
    ) = original_chain
    source.ingest_new(
        workspace,
        [
            original_invitation_sig,
            original_invitation,
            original_joined_sig,
            original,
        ],
        {
            original_invitation_sig.fid: [],
            original_invitation.fid: [
                original_invitation_sig.fid,
                member_src(source, workspace, root),
            ],
            original_joined_sig.fid: [],
            original.fid: [
                original_invitation.fid,
                original_joined_sig.fid,
            ],
        },
    )
    common = closed_subset(source, workspace, all_fids(source, workspace))

    remote = Node(str(tmp_path / "remote"))
    remote.add_workspace(workspace, "root", peers=[])
    deliver(remote, workspace, common)
    remote.turn(workspace)

    source.keychain.add_identity(bob_secret)
    source.bind_identity(workspace, bob)
    _, invitation_sig, invitation, rejoined_sig, rejoined = rejoin_chain
    source.ingest_new(
        workspace,
        [invitation_sig, invitation, rejoined_sig, rejoined],
        {
            invitation_sig.fid: [],
            invitation.fid: [
                invitation_sig.fid,
                member_src(source, workspace, root),
            ],
            rejoined_sig.fid: [],
            rejoined.fid: [invitation.fid, rejoined_sig.fid],
        },
    )
    assert member_src(source, workspace, bob) == rejoined.fid
    assert member_src(remote, workspace, bob) == original.fid

    remote.keychain.add_identity(bob_secret)
    remote.bind_identity(workspace, bob)
    ts = now_ms()
    source_request = request_payload(
        source, workspace, "sync", ts + 120_000, ts)
    remote_request = request_payload(
        remote, workspace, "sync", ts + 120_000, ts)

    assert evaluate(
        source_request,
        workspace,
        remote.globals(workspace) | {("now", ts)},
        canonical_db=remote.idx(workspace),
    )
    assert evaluate(
        remote_request,
        workspace,
        source.globals(workspace) | {("now", ts)},
        canonical_db=source.idx(workspace),
    )
    source_root = source.store(workspace).get("root")
    remote_root = remote.store(workspace).get("root")
    assert mint.stateless(
        encode_pile(source_request), remote_root,
        lambda oid: remote.store(workspace).get("obj/" + oid), ts)
    assert mint.stateless(
        encode_pile(remote_request), source_root,
        lambda oid: source.store(workspace).get("obj/" + oid), ts)


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


def test_rank_only_shadow_projection_survives_retry_and_stale_replay(
        tmp_path, monkeypatch):
    from core import node as runtime

    original_pump = runtime.pump
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
    deep_item = short_item = None
    for ordinal in range(1024):
        candidate_deep = device_invite_fact(
            deep, deep, target, f"from-deep-{ordinal}", 200)
        candidate_short = device_invite_fact(
            short, short, target, f"from-short-{ordinal}", 201)
        if candidate_short.fid < candidate_deep.fid:
            deep_item, short_item = candidate_deep, candidate_short
            break
    assert deep_item is not None and short_item is not None
    deep_claim = _inject_device_claim(
        node, workspace, deep_secret, deep, deep, target,
        deep_item.body["label"], deep_item.ts)
    short_claim = _inject_device_claim(
        node, workspace, short_secret, short, short, target,
        short_item.body["label"], short_item.ts)
    assert deep_claim == deep_item
    assert short_claim == short_item
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
    deps = {
        invitation_sig.fid: [],
        invitation.fid: [
            invitation_sig.fid,
            member_src(node, workspace, root),
        ],
        rejoined_sig.fid: [],
        rejoined.fid: [invitation.fid, rejoined_sig.fid],
    }
    new = {
        fact.fid: fact
        for fact in (invitation_sig, invitation, rejoined_sig, rejoined)
    }
    stream = close(
        list(new.values()),
        lambda fid: deps[fid] if fid in deps else resolve_deps(
            node.fact_of(workspace, fid), node.idx(workspace)),
        lambda fid: new.get(fid) or node.fact_of(workspace, fid),
    )
    pile = encode_pile(stream)
    deliver(node, workspace, pile, member="crash00000000000")

    # Model a process death after the manifest/index commit but before the app
    # transaction. The retained ingress pile must repair the lagging projection
    # on retry even though every fact is now already present in the index.
    def crash_after_commit(*args, **kwargs):
        raise RuntimeError("simulated projection crash")

    monkeypatch.setattr(runtime, "pump", crash_after_commit)
    with pytest.raises(RuntimeError, match="simulated projection crash"):
        node.turn(workspace)
    monkeypatch.setattr(runtime, "pump", original_pump)

    assert offer_src(
        node.idx(workspace), "device_key", target) == deep_claim.fid
    assert node.app.execute(
        "SELECT user, source FROM devices WHERE ws=? AND pk=?",
        (workspace, target)).fetchone() == (short, short_claim.fid)
    assert node.store(workspace).list("pile/")

    fresh = node.turn(workspace)

    assert fresh
    assert not any(
        name == "device_key"
        for valid in fresh
        for name, _, _ in valid.fact.offers())
    assert node.app.execute(
        "SELECT user, source FROM devices WHERE ws=? AND pk=?",
        (workspace, target)).fetchone() == (deep, deep_claim.fid)

    # A late duplicate delivery of the lower-fid but rank-losing claim is a
    # projection no-op once this manifest generation has been materialized.
    deliver(
        node,
        workspace,
        closed_subset(node, workspace, [short_claim.fid]),
        member="stale00000000000",
    )
    node.turn(workspace)
    assert node.app.execute(
        "SELECT user, source FROM devices WHERE ws=? AND pk=?",
        (workspace, target)).fetchone() == (deep, deep_claim.fid)


def test_late_rank_change_restores_pruned_authority_in_every_arrival_order(
        tmp_path):
    """A fact that temporarily loses its device-set proof must not be lost.

    The short claim first beats the deep claim and orphans its child. A later
    direct rejoin shortens the deep proof enough to win again. Both delivery
    orders, including an index rebuild while the child is quarantined, must
    publish the same restored set.
    """
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "root", ts=1)
    root_secret, root = source.identity(workspace)

    q_secret, q, _ = add_member(source, workspace, "q", ts=10)
    short_secret, short, _ = add_member(
        source, workspace, "short", inviter=(q_secret, q), ts=20)
    deep_secret, deep, _ = add_member(
        source, workspace, "d1", ts=30)
    for ordinal, name in enumerate(("d2", "d3", "deep")):
        deep_secret, deep, _ = add_member(
            source, workspace, name, inviter=(deep_secret, deep),
            ts=40 + 10 * ordinal)

    for secret, public, label in (
            (short_secret, short, "short-primary"),
            (deep_secret, deep, "deep-primary")):
        source.keychain.add_identity(secret)
        source.bind_identity(workspace, public)
        cmds.bind_device(source, workspace, label)

    target_secret, target = keypair()
    source.keychain.add_identity(target_secret)
    deep_claim = _inject_device_claim(
        source, workspace, deep_secret, deep, deep, target,
        "from-deep", 200)
    source.bind_identity(workspace, target)
    _, child = keypair()
    child_claim = _inject_device_claim(
        source, workspace, target_secret, target, deep, child,
        "child", 201)
    deep_pile = closed_subset(
        source, workspace, [deep_claim.fid, child_claim.fid])

    short_claim = _inject_device_claim(
        source, workspace, short_secret, short, short, target,
        "from-short", 400)
    short_pile = closed_subset(source, workspace, [short_claim.fid])
    assert source.fact_of(workspace, child_claim.fid) is None
    assert source.store(workspace).has(
        "quarantine/" + child_claim.fid)

    invite_secret, invite_public = keypair()
    invitation = user_invite(root, invite_public, 500)
    invitation_sig = signature(root_secret, root, invitation, 500)
    rejoined = user(
        invitation, invite_secret, deep, "deep-direct", 501)
    rejoined_sig = signature(deep_secret, deep, rejoined, 501)
    rejoin_deps = {
        invitation_sig.fid: [],
        invitation.fid: [
            invitation_sig.fid,
            member_src(source, workspace, root),
        ],
        rejoined_sig.fid: [],
        rejoined.fid: [invitation.fid, rejoined_sig.fid],
    }
    source.ingest_new(
        workspace,
        [invitation_sig, invitation, rejoined_sig, rejoined],
        rejoin_deps,
    )
    rejoin_pile = closed_subset(source, workspace, [rejoined.fid])
    assert source.fact_of(workspace, child_claim.fid) == child_claim

    # Quarantine bodies remain as recovery material after restoration. Normal
    # signatures must consult the in-memory offer index, not list and decode
    # the retained history twice per post (merge + commit).
    retained_reads = []
    store = source.store(workspace)
    original_get, original_list = store.get, store.list

    def tracked_get(key):
        if key.startswith("quarantine/"):
            retained_reads.append(("get", key))
        return original_get(key)

    def tracked_list(prefix):
        if prefix == "quarantine/":
            retained_reads.append(("list", prefix))
        return original_list(prefix)

    store.get, store.list = tracked_get, tracked_list
    try:
        ordinary = [
            cmds.post(source, workspace, "general", f"after-restore-{ordinal}")
            for ordinal in range(2)
        ]
    finally:
        store.get, store.list = original_get, original_list
    assert not retained_reads
    ordinary_pile = closed_subset(source, workspace, ordinary)

    first = Node(str(tmp_path / "first"))
    for ordinal, pile in enumerate((deep_pile, short_pile)):
        deliver(
            first, workspace, pile,
            member=f"first{ordinal}".ljust(16, "a"))
        first.turn(workspace)
    assert first.fact_of(workspace, child_claim.fid) is None
    assert first.store(workspace).has(
        "quarantine/" + child_claim.fid)

    # Both SQLite databases are derived. Rebuilding the fact index from the
    # manifest must retain the local, previously kernel-valid quarantine.
    first.idx(workspace).executescript(
        "DELETE FROM facts; DELETE FROM offers; DELETE FROM proofs; "
        "DELETE FROM globals; DELETE FROM meta;")
    first.idx(workspace).commit()
    first.rebuild(workspace)
    assert first.fact_of(workspace, child_claim.fid) is None
    deliver(first, workspace, rejoin_pile, member="first2aaaaaaaaaa")
    first.turn(workspace)
    deliver(first, workspace, ordinary_pile, member="first3aaaaaaaaaa")
    first.turn(workspace)

    second = Node(str(tmp_path / "second"))
    for ordinal, pile in enumerate(
            (deep_pile, rejoin_pile, short_pile)):
        deliver(
            second, workspace, pile,
            member=f"second{ordinal}".ljust(16, "a"))
        second.turn(workspace)
    deliver(second, workspace, ordinary_pile, member="second3aaaaaaaaa")
    second.turn(workspace)

    for current in (source, first, second):
        assert current.fact_of(workspace, child_claim.fid) == child_claim
        assert current.app.execute(
            "SELECT user FROM devices WHERE ws=? AND pk=?",
            (workspace, child)).fetchone() == (deep,)
    assert all_fids(source, workspace) \
        == all_fids(first, workspace) \
        == all_fids(second, workspace)
    assert source.store(workspace).get("root") \
        == first.store(workspace).get("root") \
        == second.store(workspace).get("root")


def test_restoration_forces_a_followup_walk_for_the_restored_fact(
        tmp_path, monkeypatch):
    """A pull that restores quarantine must not leave a valid 304 cache."""
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "root", ts=1)
    root_secret, root = source.identity(workspace)

    q_secret, q, _ = add_member(source, workspace, "q", ts=10)
    short_secret, short, _ = add_member(
        source, workspace, "short", inviter=(q_secret, q), ts=20)
    deep_secret, deep, _ = add_member(source, workspace, "d1", ts=30)
    for ordinal, name in enumerate(("d2", "d3", "deep")):
        deep_secret, deep, _ = add_member(
            source,
            workspace,
            name,
            inviter=(deep_secret, deep),
            ts=40 + 10 * ordinal,
        )

    for secret, public, label in (
            (short_secret, short, "short-primary"),
            (deep_secret, deep, "deep-primary")):
        source.keychain.add_identity(secret)
        source.bind_identity(workspace, public)
        cmds.bind_device(source, workspace, label)

    target_secret, target = keypair()
    source.keychain.add_identity(target_secret)
    deep_claim = _inject_device_claim(
        source, workspace, deep_secret, deep, deep, target,
        "from-deep", 200)
    source.bind_identity(workspace, target)
    _, child = keypair()
    child_claim = _inject_device_claim(
        source, workspace, target_secret, target, deep, child,
        "child", 201)
    child_signature = next(
        fid for fid in resolve_deps(child_claim, source.idx(workspace))
        if source.fact_of(workspace, fid).t == "signature")
    deep_pile = closed_subset(
        source, workspace, [deep_claim.fid, child_claim.fid])
    target_pile = closed_subset(source, workspace, [deep_claim.fid])
    child_signature_pile = closed_subset(
        source, workspace, [child_signature])

    short_claim = _inject_device_claim(
        source, workspace, short_secret, short, short, target,
        "from-short", 400)
    short_pile = closed_subset(source, workspace, [short_claim.fid])
    assert source.fact_of(workspace, child_claim.fid) is None

    invite_secret, invite_public = keypair()
    invitation = user_invite(root, invite_public, 500)
    invitation_sig = signature(root_secret, root, invitation, 500)
    rejoined = user(
        invitation, invite_secret, deep, "deep-direct", 501)
    rejoined_sig = signature(deep_secret, deep, rejoined, 501)
    source.ingest_new(
        workspace,
        [invitation_sig, invitation, rejoined_sig, rejoined],
        {
            invitation_sig.fid: [],
            invitation.fid: [
                invitation_sig.fid,
                member_src(source, workspace, root),
            ],
            rejoined_sig.fid: [],
            rejoined.fid: [invitation.fid, rejoined_sig.fid],
        },
    )
    rejoin_pile = closed_subset(source, workspace, [rejoined.fid])
    assert source.fact_of(workspace, child_claim.fid) == child_claim

    local = Node(str(tmp_path / "local"))
    for pile in (deep_pile, short_pile):
        deliver(local, workspace, pile)
        local.turn(workspace)
    assert local.fact_of(workspace, child_claim.fid) is None

    remote = Node(str(tmp_path / "remote"))
    for pile in (target_pile, child_signature_pile, short_pile):
        deliver(remote, workspace, pile)
        remote.turn(workspace)
    assert all_fids(local, workspace) == all_fids(remote, workspace)

    class LocalPeer:
        def __init__(self, node, ws, url):
            self.node, self.ws, self.url = node, ws, url
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None):
            current = remote.store(self.ws).get("root")
            current_etag = remote.store(self.ws).etag("root")
            return None if etag == current_etag else (
                current, current_etag)

        def obj(self, object_hash):
            return remote.store(self.ws).get("obj/" + object_hash)

        def put_pile(self, body):
            deliver(remote, self.ws, body)
            remote.turn(self.ws)

    monkeypatch.setattr(sync_module, "Peer", LocalPeer)
    url = "local://remote"
    assert sync_module.sync(local, workspace, url) == (0, 0)
    assert (workspace, url) in local.sync_cache

    deliver(remote, workspace, rejoin_pile)
    remote.turn(workspace)
    assert remote.fact_of(workspace, child_claim.fid) is None

    pulled, _ = sync_module.sync(local, workspace, url)
    assert pulled
    assert local.fact_of(workspace, child_claim.fid) == child_claim
    assert (workspace, url) not in local.sync_cache

    _, pushed = sync_module.sync(local, workspace, url)
    assert pushed
    assert remote.fact_of(workspace, child_claim.fid) == child_claim
    assert all_fids(local, workspace) == all_fids(remote, workspace)
