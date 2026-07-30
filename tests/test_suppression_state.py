"""Running contracts for indexed suppression actions and ingress screening."""
import json
import os

import pytest

import facts
from core import suppression_state
from core.close import close, encode_pile
from core.crypto import h, keypair
from core.kernel import offer_src, resolve_deps
from core.node import Node
from core import sync as sync_module
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
        "SELECT sid, fid FROM actions ORDER BY sid").fetchall()
    candidates = node.reader(workspace).candidates()
    return [
        (sid, fid, candidates.fact_record(fid)["admission"])
        for sid, fid in actions
    ]


def _signed_pile(node, workspace, fact, signed, deps):
    incoming = {fact.fid: fact, signed.fid: signed}
    fact_of = lambda fid: incoming.get(fid) or node.fact_of(workspace, fid)
    return encode_pile(close(
        [signed, fact],
        lambda fid: deps[fid] if fid in deps else (
            resolve_deps(fact_of(fid), node.idx(workspace)) or ()),
        fact_of,
    ))


def _author_eviction(node, workspace, target, ts):
    secret, public = node.identity(workspace)
    item = removal(workspace, public, target, ts)
    signed = signature(secret, public, item, ts)
    admin = offer_src(node.idx(workspace), "admin", public)
    node.ingest_new(
        workspace, [signed, item],
        {signed.fid: (), item.fid: (signed.fid, admin)})
    return item


def test_composite_root_has_no_legacy_removal_object(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    target = facts.content.message.post(node, workspace, "general", "doomed", ts=10)
    action_fid = facts.content.delete.remove(node, workspace, target, ts=20)

    root = json.loads(node.store(workspace).get("root"))
    assert set(root) == {
        "anchor", "layout_seed", "maps", "stamp"}
    assert set(root["maps"]) == {
        "authority", "fact", "fact_order", "supp"}
    assert "removals" not in root
    assert _action_rows(node, workspace)[0][:2] == (
        f"fact:{target}", action_fid)


def test_action_reverse_index_rebuilds_from_the_trees(tmp_path):
    directory = tmp_path / "node"
    node = Node(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    target = facts.content.message.post(node, workspace, "general", "doomed", ts=10)
    facts.content.delete.remove(node, workspace, target, ts=20)
    expected_root = node.store(workspace).get("root")
    expected_actions = _action_rows(node, workspace)

    node.idx(workspace).close()
    os.unlink(directory / "ws" / f"{workspace}.idx.db")

    rebuilt = Node(str(directory))
    assert _action_rows(rebuilt, workspace) == expected_actions
    assert rebuilt.store(workspace).get("root") == expected_root
    assert target not in visible_fids(rebuilt, workspace)


def test_evicted_member_cannot_launder_a_valid_signed_fact(tmp_path):
    node = Node(str(tmp_path / "node"))
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

    node.turn(workspace)
    assert node.candidate_of(workspace, item.fid) == item
    assert node.fact_of(workspace, item.fid) is None
    assert node.store(workspace).list("pile/") == []
    assert node.ingress_failures(workspace) == []


def test_delegated_admin_liveness_follows_grantee_not_grantor(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    _, carol, _ = add_member(node, workspace, "carol", ts=20)
    admin_fid = facts.auth.admin.grant(node, workspace, bob)
    eviction = facts.auth.removal.evict(node, workspace, bob)

    ts = node.fact_of(workspace, eviction).ts + 1
    item = removal(workspace, bob, carol, ts)
    signed = signature(bob_secret, bob, item, ts)
    pile = _signed_pile(
        node, workspace, item, signed,
        {signed.fid: (), item.fid: (signed.fid, admin_fid)})
    deliver(node, workspace, pile)

    node.turn(workspace)
    assert node.candidate_of(workspace, item.fid) == item
    assert node.fact_of(workspace, item.fid) is None
    assert not suppression_state.active(
        node.idx(workspace), facts.principal_sid("member", carol))


def test_terminal_member_action_covers_a_future_provider(tmp_path):
    node = Node(str(tmp_path / "node"))
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
    assert suppression_state.active(
        node.idx(workspace),
        facts.principal_sid("member", bob))


def test_guard_screening_converges_in_both_delivery_orders(tmp_path):
    """An earlier action deactivates a later fact even when it arrives last."""
    source = Node(str(tmp_path / "source"))
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
        peer = Node(str(tmp_path / name))
        peer.add_workspace(workspace, "alice", peers=[])
        deliver(peer, workspace, base)
        peer.turn(workspace)
        for pile in order:
            deliver(peer, workspace, pile)
            peer.turn(workspace)
        peers.append(peer)

    assert all(
        peer.candidate_of(workspace, posted.fid) == posted
        and peer.fact_of(workspace, posted.fid) is None
        and facts.content.message.messages(peer, workspace) == []
        for peer in peers
    )
    assert peers[0].store(workspace).get("root") \
        == peers[1].store(workspace).get("root") \
        == source.store(workspace).get("root")


def test_duplicate_action_uses_earliest_key_in_every_arrival_order(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    bob_secret, bob, _ = add_member(source, workspace, "bob", ts=10)
    base = closed_subset(source, workspace, all_fids(source, workspace))

    first = _author_eviction(source, workspace, bob, 20)
    first_pile = closed_subset(source, workspace, [first.fid])
    later = next(
        removal(workspace, source.identity_id(workspace), bob, ts)
        for ts in range(41, 500)
        if removal(
            workspace, source.identity_id(workspace), bob, ts
        ).fid < first.fid
    )
    secret, public = source.identity(workspace)
    later_sig = signature(secret, public, later, later.ts)
    source.ingest_new(
        workspace, [later_sig, later],
        {later_sig.fid: (), later.fid: (later_sig.fid, workspace)})
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
        peer = Node(str(tmp_path / name))
        peer.add_workspace(workspace, "alice", peers=[])
        deliver(peer, workspace, base)
        peer.turn(workspace)
        for pile in (*order, message_pile):
            deliver(peer, workspace, pile)
            peer.turn(workspace)
        sid = facts.principal_sid("member", bob)
        assert peer.idx(workspace).execute(
            "SELECT fid FROM actions WHERE sid=?", (sid,)).fetchone() \
            == (first.fid,)
        assert peer.candidate_of(workspace, posted.fid) == posted
        assert peer.fact_of(workspace, posted.fid) is None
        roots.append(peer.store(workspace).get("root"))
    assert roots[0] == roots[1]


def test_candidate_sync_compares_witnesses_not_fact_id_order(tmp_path):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    founder_secret, founder = source.identity(workspace)
    _, bob, _ = add_member(source, workspace, "bob", ts=10)
    common = closed_subset(source, workspace, all_fids(source, workspace))
    first = _author_eviction(source, workspace, bob, 20)

    destination = Node(str(tmp_path / "destination"))
    destination.keychain.add_identity(founder_secret)
    destination.add_workspace(
        workspace, "alice", peers=[], identity=founder)
    deliver(destination, workspace, common)
    destination.turn(workspace)
    later_ts = next(
        ts for ts in range(41, 500)
        if removal(
            workspace, destination.identity_id(workspace), bob, ts
        ).fid < first.fid
    )
    later = _author_eviction(destination, workspace, bob, later_ts)
    assert later.fid < first.fid  # the obsolete tuple-order shortcut

    store = source.store(workspace)
    root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    pulled, pushed, pending = sync_module.reconcile_candidates(
        destination, workspace, None, root, fetch, deliver=False,
    )

    assert (pulled, pushed, pending) == (1, 0, True)
    sid = facts.principal_sid("member", bob)
    assert destination.idx(workspace).execute(
        "SELECT fid FROM actions WHERE sid=?", (sid,)).fetchone() \
        == (first.fid,)


def test_action_witness_remains_historical_across_current_provider_rewire(
        tmp_path):
    """Current dependency settlement never rewrites historical admission."""
    base = Node(str(tmp_path / "base"))
    workspace = facts.auth.workspace.create(base, "alice", ts=1)
    founder_secret, founder = base.identity(workspace)
    facts.auth.device.bind(base, workspace, "alice-primary")
    common = closed_subset(base, workspace, all_fids(base, workspace))

    target_secret, target = keypair()
    peers = []
    for name, label, claim_ts in (
            ("left", "left-claim", 100),
            ("right", "right-claim", 101)):
        peer = Node(str(tmp_path / name))
        peer.keychain.add_identity(founder_secret)
        peer.keychain.add_identity(target_secret)
        peer.add_workspace(
            workspace, "alice", peers=[], identity=founder)
        deliver(peer, workspace, common)
        peer.turn(workspace)
        claim = inject_device_claim(
            peer, workspace, founder_secret, founder, founder,
            target, label, claim_ts)

        peer.bind_identity(workspace, target)
        posted = facts.content.message.post(
            peer, workspace, "general", "same immutable message", ts=200)
        peer.bind_identity(workspace, founder)
        deletion = facts.content.delete.remove(peer, workspace, posted, ts=210)
        peers.append((peer, claim, posted, deletion))

    left, right = peers
    assert left[2:] == right[2:]
    left_evidence = _action_rows(left[0], workspace)[0][2]
    right_evidence = _action_rows(right[0], workspace)[0][2]
    assert left_evidence != right_evidence

    left_claim = closed_subset(left[0], workspace, [left[1].fid])
    right_claim = closed_subset(right[0], workspace, [right[1].fid])
    deliver(left[0], workspace, right_claim)
    left[0].turn(workspace)
    deliver(right[0], workspace, left_claim)
    right[0].turn(workspace)

    evidence = [
        _action_rows(peer, workspace)[0][2]
        for peer, _, _, _ in peers
    ]
    assert evidence == [left_evidence, right_evidence]
    assert left[0].store(workspace).get("root") \
        != right[0].store(workspace).get("root")

    # Joining the lower complete witness is a FactTree-only transition. The
    # direct eligible order and the two semantic projections do not change.
    lower = 0 if evidence[0] < evidence[1] else 1
    source, target_peer = peers[lower][0], peers[1 - lower][0]
    selected = source.reader(workspace).candidates().verify(left[3])
    raw = encode_pile(selected.facts, workspace=workspace)
    before = json.loads(target_peer.store(workspace).get("root"))
    deliver(target_peer, workspace, raw)
    target_peer.turn(workspace)
    after = json.loads(target_peer.store(workspace).get("root"))

    assert before["maps"]["fact_order"] == after["maps"]["fact_order"]
    assert before["maps"]["fact"] != after["maps"]["fact"]
    assert before["maps"]["supp"] == after["maps"]["supp"]
    assert before["maps"]["authority"] == after["maps"]["authority"]
    assert _action_rows(target_peer, workspace)[0][2] == evidence[lower]
    full = target_peer.store(workspace).get("root")
    target_peer.rebuild(workspace)
    assert target_peer.store(workspace).get("root") == full

    for peer, _, posted, _ in peers:
        peer.rebuild(workspace)
        assert _action_rows(peer, workspace)[0][2] == evidence[lower]
        assert posted not in visible_fids(peer, workspace)


def test_child_device_admin_inherits_user_liveness(tmp_path):
    node = Node(str(tmp_path / "node"))
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
    with pytest.raises(ValueError, match="outside the canonical set"):
        facts.auth.removal.evict(node, workspace, carol)
    assert not suppression_state.active(
        node.idx(workspace), facts.principal_sid("member", carol))


def test_candidate_proof_sync_carries_actions_and_their_projection(
        tmp_path, monkeypatch):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    target = facts.content.message.post(source, workspace, "general", "doomed", ts=10)
    before = closed_subset(source, workspace, all_fids(source, workspace))

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "alice", peers=[])
    deliver(destination, workspace, before)
    destination.turn(workspace)
    action_fid = facts.content.delete.remove(source, workspace, target, ts=20)

    class LocalPeer:
        accepts_push = True

        def __init__(self, node, ws, url):
            self.node, self.ws = node, ws
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None, **_options):
            return (
                source.store(self.ws).get("root"),
                h(source.store(self.ws).get("root")),
            )

        def obj(self, oid, **_options):
            return source.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            return tuple(self.obj(oid) for oid in oids)

        def put_pile(self, raw):
            source.receive_pile(self.ws, "peer", raw)

        def put_obj(self, oid, raw):
            source.receive_object(self.ws, oid, raw)

    monkeypatch.setattr(sync_module, "Peer", LocalPeer)
    sync_module.sync(destination, workspace, "local")

    assert _action_rows(destination, workspace)[0][:2] == (
        f"fact:{target}", action_fid)
    assert target not in visible_fids(destination, workspace)


def test_one_poisoned_candidate_witness_lands_honest_state_without_caching(
        tmp_path, monkeypatch):
    source = Node(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    poisoned_target = facts.content.message.post(
        source, workspace, "general", "poison witness", ts=10)
    honest_target = facts.content.message.post(
        source, workspace, "general", "honest witness", ts=11)
    before = closed_subset(source, workspace, all_fids(source, workspace))

    destination = Node(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "alice", peers=[])
    deliver(destination, workspace, before)
    destination.turn(workspace)

    facts.content.delete.remove(source, workspace, poisoned_target, ts=20)
    facts.content.delete.remove(source, workspace, honest_target, ts=21)
    rows = {
        sid: (fid, evidence)
        for sid, fid, evidence in _action_rows(source, workspace)
    }
    poisoned_sid = f"fact:{poisoned_target}"
    honest_sid = f"fact:{honest_target}"
    poisoned_evidence = rows[poisoned_sid][1]
    store = source.store(workspace)

    class PoisonedPeer:
        accepts_push = False
        poisoned = True

        def __init__(self, node, ws, url):
            self.ws = ws
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None, **_options):
            raw = store.get("root")
            current = h(raw)
            return None if etag == current else (raw, current)

        def obj(self, oid, **_options):
            return b"not the claimed object" \
                if self.poisoned and oid == poisoned_evidence \
                else store.get("obj/" + oid)

        def objs(self, oids):
            return tuple(self.obj(oid) for oid in oids)

    monkeypatch.setattr(sync_module, "Peer", PoisonedPeer)
    url = "local://poisoned"
    with pytest.raises(ValueError, match="unresolved candidate difference"):
        sync_module.sync(destination, workspace, url)

    assert suppression_state.active(
        destination.idx(workspace), honest_sid)
    assert not suppression_state.active(
        destination.idx(workspace), poisoned_sid)
    assert honest_target not in visible_fids(destination, workspace)
    assert poisoned_target in visible_fids(destination, workspace)
    assert (workspace, url) not in destination.sync_cache

    PoisonedPeer.poisoned = False
    assert sync_module.sync(destination, workspace, url) == (1, 0)
    assert suppression_state.active(
        destination.idx(workspace), poisoned_sid)
    assert destination.store(workspace).get("root") == store.get("root")
