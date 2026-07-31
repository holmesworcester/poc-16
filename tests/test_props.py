"""Load-bearing properties of the three-role repository architecture.

PileSender may use the disposable SQL projection to author a closed pile.
RepositoryApplier alone turns an exact pile into a CAS'd repository root.
RepositoryReader pins that published root and has no mutation authority.

The properties below exercise those production roles directly:

* every validated residence can be reassembled as an independently valid pile;
* arrival order, turn batching, suppression, and stragglers converge;
* root/object integrity failures never advance or retire work;
* pre-CAS, ambiguous-CAS, and post-CAS crashes have exact replay behavior;
* restart rebuilds only local presentation state; and
* concurrent appliers retain and rebase the CAS loser.
"""
import asyncio
import json
import os
import random
import sqlite3

import pytest

import facts

from core import snapshot
from core.close import decode_pile
from core.crypto import keypair, load_sk
from core.fact import Fact, canon
from core.kernel import drain
from full_peer.node import FullPeer, now_ms
from core.object_store import OutcomeUnknown
from full_peer.pile_sender import PileSender
from core.repository_applier import (
    RepositoryAnchorPending,
    RepositoryApplier,
)
from core.repository_reader import RepositoryReader
from core.store import FsStore
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.content.message import message

from . import util as test_util
from .util import (
    add_member,
    all_fids,
    author_msg,
    closed_subset,
    member_src,
    send_bytes,
)


MEMBER = "feed7feed7feed7f"


def run(awaitable):
    return asyncio.run(awaitable)


def reader_for(store, workspace, root_bytes=None):
    """Construct the exact DB-free read role over one pinned root."""
    root_bytes = store.get("root") if root_bytes is None else root_bytes
    assert root_bytes is not None
    return RepositoryReader(
        workspace,
        root_bytes,
        lambda oid: store.get("obj/" + oid),
    )


def stage_apply(applier, raw, member=MEMBER, **options):
    source = run(applier.stage(member, raw))
    return source, run(applier.apply(source, **options))


def units_of(node, workspace):
    """A fresh valid closure for each stored fact through RepositoryReader."""
    validated = node.reader(workspace).validated()
    for fid in validated.fact_ids():
        yield fid, validated.closure((fid,))


def fact_pile(node, workspace, fid):
    """Pack one reader-assembled current closure through PileSender."""
    unit = node.reader(workspace).validated().closure((fid,))
    return node.sender(workspace).pack(unit)


def message_pile(node, workspace, text, ts):
    """Author without receiving: PileSender closes one ordinary message."""
    secret, public = node.identity(workspace)
    item = message(workspace, public, "general", text, ts)
    signed = signature(secret, public, item, ts)
    raw = node.sender(workspace).pile(
        (signed, item),
        {
            signed.fid: (),
            item.fid: (
                signed.fid,
                member_src(node, workspace, public),
            ),
        },
    )
    return item, raw


def close_indexes(node):
    for projection in node._sql.values():
        projection.db.close()


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Alice's node with members, mixed authors, a blob, and suppression."""
    monkeypatch.setattr("full_peer.node.now_ms", lambda: 2_000_000)
    identities = iter(range(2, 10))

    def deterministic_keypair():
        secret = load_sk(f"{next(identities):064x}")
        return secret, secret.verify_key.encode().hex()

    monkeypatch.setattr(test_util, "keypair", deterministic_keypair)
    node = FullPeer(
        str(tmp_path / "alice"),
        initial_secret=load_sk(f"{1:064x}"),
    )
    workspace = facts.auth.workspace.create(node, "alice", ts=1_000_000)
    t0 = 1_000_010
    bob_secret, bob, _ = add_member(
        node, workspace, "bob", t0 + 1)
    carol_secret, carol, _ = add_member(
        node, workspace, "carol", t0 + 2)
    rng = random.Random(16)
    actors = [
        (node.sk, node.pk),
        (bob_secret, bob),
        (carol_secret, carol),
    ]
    for ordinal in range(8):
        secret, public = rng.choice(actors)
        author_msg(
            node,
            workspace,
            secret,
            public,
            f"m{ordinal}",
            t0 + 10 + ordinal,
        )
    send_bytes(
        node, workspace, "blob.bin",
        rng.randbytes(4_096), ts=t0 + 30)
    facts.auth.removal.evict(node, workspace, carol)
    return node, workspace


def test_paths_are_piles_through_repository_reader(world):
    """Every freshly assembled closure judges alone from an empty kernel."""
    node, workspace = world
    count = 0
    for fid, stream in units_of(node, workspace):
        result = drain(stream, workspace)
        assert result.ok, f"closure failed the kernel: {fid}"
        count += 1
    assert count >= 2


def test_history_independence_across_order_and_turn_batching(
        tmp_path, world):
    """Random exact-pile order and batching preserve the validated-fact join."""
    source, workspace = world
    expected_root = source.reader(workspace).root_bytes
    expected_fids = set(
        source.reader(workspace).validated().fact_ids())
    selected = [
        source.sender(workspace).pack(stream)
        for _, stream in units_of(source, workspace)
    ]

    for seed in range(2):
        rng = random.Random(seed)
        store = FsStore(str(tmp_path / f"recipient-{seed}"))
        applier = RepositoryApplier(workspace, store)
        shuffled = selected[:]
        rng.shuffle(shuffled)
        position = 0
        while position < len(shuffled):
            take = rng.randint(1, 7)
            for raw in shuffled[position:position + take]:
                run(applier.stage(f"peer{seed}", raw))
            position += take
            report = run(applier.turn())
            # Opaque generation ids may put a non-anchor closure ahead of the
            # workspace closure. That is retryable work, not rejection.
            for item in report:
                if item.error is None:
                    continue
                assert isinstance(item.error, RepositoryAnchorPending)
                assert str(item.error) == \
                    "repository anchor fact is not available yet"
                assert store.get(item.source) is not None

        # The anchor has now arrived. Discharge any closure that was attempted
        # before it, independent of its generation key's LIST position.
        for _ in range(len(selected) + 1):
            if not store.list("pile/"):
                break
            report = run(applier.turn())
            assert all(item.error is None for item in report)
        else:
            pytest.fail("retained validated-fact piles did not drain")

        reader = reader_for(store, workspace)
        assert reader.root_bytes == expected_root
        assert set(reader.validated().fact_ids()) == expected_fids
        assert store.list("pile/") == []


def test_sender_authors_but_only_applier_advances_root(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    sender = node.sender(workspace)
    applier = node.applier(workspace)
    assert isinstance(sender, PileSender)
    assert isinstance(applier, RepositoryApplier)

    root = node.reader(workspace).root_bytes
    item, raw = message_pile(
        node, workspace, "role separation", ts=10)

    assert node.store(workspace).get("root") == root
    assert node.store(workspace).list("pile/") == []
    source = run(applier.stage(MEMBER, raw))
    assert node.store(workspace).get("root") == root
    assert node.store(workspace).get(source) == raw

    result = run(applier.apply(source))
    assert result.status == "applied"
    assert result.retired is True
    assert node.store(workspace).get(source) is None
    assert node.reader(workspace).validated().fact(item.fid) == item


def test_cold_applier_and_reader_are_database_free(
        tmp_path, monkeypatch):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    facts.content.message.post(source, workspace, "general", "database-free", ts=10)
    raw = closed_subset(
        source, workspace, all_fids(source, workspace))
    expected = source.reader(workspace).root_bytes
    store = FsStore(str(tmp_path / "hosted"))

    def sql_is_forbidden(*_args, **_kwargs):
        raise AssertionError("repository role touched SQLite")

    monkeypatch.setattr(sqlite3, "connect", sql_is_forbidden)
    applier = RepositoryApplier(workspace, store)
    _, result = stage_apply(applier, raw)

    assert result.status == "applied"
    assert reader_for(store, workspace).root_bytes == expected
    assert reader_for(store, workspace).worker().fact_active(workspace)


def test_repository_reader_remains_pinned_during_later_apply(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    pinned = node.reader(workspace)
    item, raw = message_pile(node, workspace, "later root", ts=10)

    _, result = stage_apply(node.applier(workspace), raw)
    assert result.status == "applied"
    with pytest.raises(ValueError, match="missing validated fact"):
        pinned.validated().fact(item.fid)

    current = node.reader(workspace)
    assert current.etag != pinned.etag
    assert current.validated().fact(item.fid) == item
    assert not any(
        name in RepositoryReader.__dict__
        for name in ("apply", "cas", "delete", "list", "put", "turn")
    )


def test_restart_rebuilds_presentation_from_reader_without_changing_root(
        tmp_path, world):
    node, workspace = world
    expected_root = node.reader(workspace).root_bytes
    expected_messages = [
        row["text"] for row in facts.content.message.messages(node, workspace)]
    index_path = (
        tmp_path / "alice" / "ws" / f"{workspace}.idx.db")

    close_indexes(node)
    os.unlink(index_path)
    reopened = FullPeer(node.dir)

    assert reopened.reader(workspace).root_bytes == expected_root
    assert [row["text"] for row in facts.content.message.messages(
        reopened, workspace)] == expected_messages
    assert reopened.store(workspace).get("root") == expected_root


def test_projection_rebuild_rejects_a_corrupted_reachable_object(world):
    node, workspace = world
    store = node.store(workspace)
    root = store.get("root")
    validated = node.reader(workspace).validated()
    fid = validated.fact_ids()[0]
    store._replace("obj/" + validated.fact_oid(fid), b"corrupt")

    with pytest.raises(ValueError, match="object integrity"):
        node.reader(workspace).validated().fact(fid)
    with pytest.raises(ValueError, match="object integrity"):
        node.rebuild(workspace)
    assert store.get("root") == root


def test_reader_rejects_forged_root_metadata_without_building_a_root(world):
    node, workspace = world
    store = node.store(workspace)
    honest = store.get("root")
    body = json.loads(honest)
    body["maps"][snapshot.FACT_ORDER]["count"] += 1
    forged = canon(body)

    reader = RepositoryReader(
        workspace,
        forged,
        lambda oid: store.get("obj/" + oid),
    )
    with pytest.raises(ValueError, match="noncanonical repository projection"):
        reader.all_facts()
    assert store.get("root") == honest


def test_applier_retains_exact_work_when_base_root_is_corrupt(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = message_pile(
        node, workspace, "blocked by corrupt base", ts=10)
    store = node.store(workspace)
    root = store.get("root")
    view = node.reader(workspace).validated()
    store._replace(
        "obj/" + view.fact_oid(workspace), b"corrupt")
    source = run(node.applier(workspace).stage(MEMBER, raw))

    with pytest.raises(ValueError, match="object integrity"):
        run(node.applier(workspace).apply(source))

    assert store.get("root") == root
    assert store.get(source) == raw
    assert item.fid not in view.fact_ids()


def test_applier_cannot_mint_a_root_without_the_workspace_anchor(tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    target = message(
        workspace, author.pk, "general", "detached", ts=10)
    detached = signature(author.sk, author.pk, target, ts=10)
    raw = author.sender(workspace).pack((detached,))
    store = FsStore(str(tmp_path / "rootless"))
    applier = RepositoryApplier(workspace, store)
    source = run(applier.stage(MEMBER, raw))

    with pytest.raises(
            RepositoryAnchorPending,
            match="repository anchor fact"):
        run(applier.apply(source))

    assert store.get("root") is None
    assert store.get(source) == raw
    assert store.list("obj/") == []

    _, anchored = stage_apply(
        applier, fact_pile(author, workspace, workspace))
    retried = run(applier.apply(source))

    assert anchored.status == "applied"
    assert retried.status == "applied"
    assert store.get(source) is None
    assert reader_for(store, workspace).validated().fact(
        detached.fid) == detached


def test_pre_cas_crash_retains_work_and_cold_retry_applies(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = message_pile(
        node, workspace, "survives pre-CAS", ts=10)
    store = node.store(workspace)
    root = store.get("root")
    applier = node.applier(workspace)
    source = run(applier.stage(MEMBER, raw))
    original_cas = store.cas

    def unavailable_before_cas(*_args, **_kwargs):
        raise OutcomeUnknown("simulated request loss before CAS")

    monkeypatch.setattr(store, "cas", unavailable_before_cas)
    with pytest.raises(OutcomeUnknown, match="before CAS"):
        run(applier.apply(source))

    assert store.get("root") == root
    assert store.get(source) == raw
    monkeypatch.setattr(store, "cas", original_cas)

    result = run(RepositoryApplier(
        workspace, store).apply(source))
    assert result.status == "applied"
    assert result.retired is True
    assert store.get(source) is None
    assert reader_for(store, workspace).validated().fact(item.fid) == item


def test_ambiguous_cas_is_confirmed_before_exact_retirement(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = message_pile(
        node, workspace, "confirmed CAS", ts=10)
    store = node.store(workspace)
    applier = node.applier(workspace)
    source = run(applier.stage(MEMBER, raw))
    original_cas = store.cas

    def applied_but_response_lost(key, token, value):
        original_cas(key, token, value)
        raise OutcomeUnknown("simulated lost CAS response")

    monkeypatch.setattr(store, "cas", applied_but_response_lost)
    result = run(applier.apply(source))

    assert result.status == "confirmed"
    assert result.retired is True
    assert store.get(source) is None
    assert reader_for(store, workspace).validated().fact(item.fid) == item


def test_post_cas_crash_replays_as_noop_after_process_restart(tmp_path):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = message_pile(
        node, workspace, "after-CAS replay", ts=10)
    store = node.store(workspace)
    applier = node.applier(workspace)
    source = run(applier.stage(MEMBER, raw))
    applied = run(applier.apply(source, retire=False))

    assert applied.status == "applied"
    assert applied.retired is False
    assert store.get(source) == raw
    assert node.reader(workspace).validated().fact(item.fid) == item

    close_indexes(node)
    reopened = FullPeer(str(directory))
    report = run(reopened.applier(workspace).turn())

    assert len(report) == 1
    assert report[0].error is None
    assert report[0].result.status == "noop"
    assert report[0].result.retired is True
    assert reopened.store(workspace).get(source) is None
    reopened.rebuild(workspace)
    assert [row["text"] for row in facts.content.message.messages(
        reopened, workspace)] == ["after-CAS replay"]


def test_failed_turn_keeps_old_root_and_retries_same_generation(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = message_pile(
        node, workspace, "turn retry", ts=10)
    store = node.store(workspace)
    old_reader = node.reader(workspace)
    source = run(node.applier(workspace).stage(MEMBER, raw))
    original_cas = store.cas

    def fail_cas(*_args, **_kwargs):
        raise RuntimeError("simulated root-store outage")

    monkeypatch.setattr(store, "cas", fail_cas)
    node.turn(workspace)

    assert store.get("root") == old_reader.root_bytes
    assert store.get(source) == raw
    assert node.ingress_attempt_failures(workspace)[0]["source"] == source
    with pytest.raises(ValueError, match="missing validated fact"):
        old_reader.validated().fact(item.fid)

    monkeypatch.setattr(store, "cas", original_cas)
    node.turn(workspace)
    assert store.get(source) is None
    assert node.ingress_attempt_failures(workspace) == []
    assert node.reader(workspace).validated().fact(item.fid) == item


def test_concurrent_appliers_rebase_without_retiring_the_cas_loser(
        tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    bootstrap_raw = closed_subset(
        author, workspace, all_fids(author, workspace))
    first, first_raw = message_pile(
        author, workspace, "concurrent A", ts=10)
    second, second_raw = message_pile(
        author, workspace, "concurrent B", ts=11)

    # Establish the reference root through the full P2P composition.
    author.receive_pile(workspace, MEMBER, first_raw)
    author.receive_pile(workspace, MEMBER, second_raw)
    expected = author.reader(workspace).root_bytes

    store = FsStore(str(tmp_path / "shared"))
    bootstrap = RepositoryApplier(workspace, store)
    _, bootstrapped = stage_apply(bootstrap, bootstrap_raw)
    assert bootstrapped.status == "applied"

    worker_a = RepositoryApplier(workspace, store)
    worker_b = RepositoryApplier(workspace, store)
    source_a = run(worker_a.stage("worker-a", first_raw))
    source_b = run(worker_b.stage("worker-b", second_raw))
    proposal_a = run(worker_a.propose(first_raw))
    proposal_b = run(worker_b.propose(second_raw))

    won = run(worker_a.commit(source_a, first_raw, proposal_a))
    lost = run(worker_b.commit(source_b, second_raw, proposal_b))
    assert won.status == "applied"
    assert lost.status == "stale"
    assert store.get(source_a) == first_raw
    assert store.get(source_b) == second_raw

    retried = run(RepositoryApplier(
        workspace, store).apply(source_b))
    assert retried.status == "applied"
    assert retried.retired is True
    recovered = run(RepositoryApplier(
        workspace, store).apply(source_a))
    assert recovered.status == "noop"
    assert recovered.retired is True

    reader = reader_for(store, workspace)
    assert reader.root_bytes == expected
    assert reader.validated().fact(first.fid) == first
    assert reader.validated().fact(second.fid) == second
    assert store.list("pile/") == []


def test_suppression_is_authenticated_and_reader_pinned(tmp_path):
    node, workspace, targets, _ = test_util.suppression_world(
        tmp_path / "node")
    pinned = node.reader(workspace)
    pinned_worker = pinned.worker()
    removed = {targets[index] for index in (1, 4, 6)}

    for target in targets:
        assert pinned_worker.fact_active(target) is (target not in removed)

    survivor = targets[0]
    assert pinned_worker.fact_active(survivor)
    facts.content.delete.remove(node, workspace, survivor, ts=300)

    assert pinned.worker().fact_active(survivor)
    assert not node.reader(workspace).worker().fact_active(survivor)
    assert node.reader(workspace).validated().fact(survivor).fid == survivor


def test_suppression_converges_in_both_pile_orders(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    base = closed_subset(
        source, workspace, all_fids(source, workspace))
    target = facts.content.message.post(
        source, workspace, "general", "suppressed", ts=10)
    target_raw = fact_pile(source, workspace, target)
    action = facts.content.delete.remove(source, workspace, target, ts=20)
    action_raw = fact_pile(source, workspace, action)
    expected = source.reader(workspace).root_bytes

    roots = []
    for name, order in (
            ("target-first", (target_raw, action_raw)),
            ("action-first", (action_raw, target_raw))):
        store = FsStore(str(tmp_path / name))
        applier = RepositoryApplier(workspace, store)
        stage_apply(applier, base)
        for raw in order:
            stage_apply(applier, raw)
        reader = reader_for(store, workspace)
        assert not reader.worker().fact_active(target)
        roots.append(reader.root_bytes)

    assert roots == [expected, expected]


def test_straggler_replay_converges_byte_for_byte(tmp_path, world):
    source, workspace = world
    before = closed_subset(
        source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "recipient"))
    applier = RepositoryApplier(workspace, store)
    stage_apply(applier, before)
    assert reader_for(store, workspace).root_bytes \
        == source.reader(workspace).root_bytes

    validated = source.reader(workspace).validated()
    old = min(
        validated.fact(fid).ts
        for fid in validated.fact_ids()
    ) + 5
    fact = author_msg(
        source,
        workspace,
        source.sk,
        source.pk,
        "late straggler",
        ts=old,
    )
    stage_apply(
        applier,
        fact_pile(source, workspace, fact.fid),
    )

    assert reader_for(store, workspace).root_bytes \
        == source.reader(workspace).root_bytes


def test_add_member_builds_a_monotone_delegation_chain(tmp_path):
    """PileSender follows the real member-authority spine."""
    node = FullPeer(str(tmp_path / "chain"))
    workspace = facts.auth.workspace.create(node, "alice")
    ts = now_ms()
    bob_secret, bob, bob_fact = add_member(
        node, workspace, "bob", ts=ts + 1)
    _, _, carol = add_member(
        node,
        workspace,
        "carol",
        inviter=(bob_secret, bob),
        ts=ts + 3,
    )

    invite_fid = carol.refs()[0][1]
    invitation = node.reader(workspace).validated().fact(invite_fid)
    closure = node.reader(workspace).validated().closure((invite_fid,))
    assert bob_fact.fid in {fact.fid for fact in closure}
    assert bob_fact.ts < invitation.ts < carol.ts

    stream = decode_pile(
        fact_pile(node, workspace, carol.fid),
        workspace,
    )
    assert drain(stream, workspace).ok

    outsider = keypair()
    with pytest.raises(ValueError, match="not a workspace member"):
        add_member(
            node, workspace, "mallory",
            inviter=outsider, ts=ts + 5)
    with pytest.raises(ValueError, match="must follow"):
        add_member(
            node, workspace, "late-bob",
            inviter=(bob_secret, bob), ts=bob_fact.ts)


def test_rejoining_key_cannot_shadow_its_invite_into_a_cycle(tmp_path):
    node = FullPeer(str(tmp_path / "shadow"))
    workspace = facts.auth.workspace.create(node, "alice")
    bob_secret, bob_public, original = add_member(
        node, workspace, "bob")
    base_ts = now_ms() + 10

    for offset in range(1000):
        invite_secret, invite_public = keypair()
        invitation = user_invite(
            workspace,
            bob_public,
            invite_public,
            base_ts + 2 * offset,
        )
        recursive = user(
            invitation,
            invite_secret,
            bob_public,
            "bob-again",
            base_ts + 2 * offset + 1,
        )
        if recursive.fid < original.fid:
            break
    else:
        raise AssertionError(
            "could not construct a lower-fid recursive user")

    invitation_sig = signature(
        bob_secret, bob_public, invitation, invitation.ts)
    recursive_sig = signature(
        bob_secret, bob_public, recursive, recursive.ts)
    node.sender(workspace).send(
        (invitation_sig, invitation, recursive_sig, recursive),
        {
            invitation_sig.fid: (),
            invitation.fid: (
                invitation_sig.fid,
                member_src(node, workspace, bob_public),
            ),
            recursive_sig.fid: (),
            recursive.fid: (
                invitation.fid,
                recursive_sig.fid,
            ),
        },
    )

    closure = node.reader(workspace).validated().closure((invitation.fid,))
    assert original.fid in {fact.fid for fact in closure}
    for _, stream in units_of(node, workspace):
        assert drain(stream, workspace).ok


def test_detached_signature_applies_without_a_full_projection_scan(world):
    node, workspace = world
    target = message(
        workspace,
        node.pk,
        "general",
        "signed before delivery",
        3_100_000,
    )
    detached = signature(
        node.sk, node.pk, target, 3_100_000)
    raw = node.sender(workspace).pack((detached,))
    _, result = stage_apply(node.applier(workspace), raw)

    assert result.status == "applied"
    assert node.reader(workspace).validated().fact(
        detached.fid) == detached


def test_duplicate_fact_join_is_history_independent(tmp_path, world):
    node, workspace = world
    target = author_msg(
        node, workspace, node.sk, node.pk,
        "duplicate target", now_ms())
    duplicate = signature(
        node.sk, node.pk, target, now_ms() + 1_000)
    _, result = stage_apply(
        node.applier(workspace),
        node.sender(workspace).pack((duplicate,)),
    )
    assert result.status == "applied"

    expected = node.reader(workspace).root_bytes
    store = FsStore(str(tmp_path / "cold"))
    applier = RepositoryApplier(workspace, store)
    shuffled = [
        node.sender(workspace).pack(stream)
        for _, stream in units_of(node, workspace)
    ]
    random.Random(91).shuffle(shuffled)
    for raw in shuffled:
        run(applier.stage(MEMBER, raw))

    for _ in range(len(shuffled) + 1):
        report = run(applier.turn())
        assert all(
            item.error is None
            or isinstance(item.error, RepositoryAnchorPending)
            for item in report
        )
        if not store.list("pile/"):
            break
    else:
        raise AssertionError("retained pre-anchor closures did not converge")

    reader = reader_for(store, workspace)
    assert reader.root_bytes == expected
    assert reader.validated().fact(duplicate.fid) == duplicate


def test_root_contains_only_reader_maps_and_anchor(world):
    node, workspace = world
    root = json.loads(node.reader(workspace).root_bytes)
    assert set(root) == {
        "anchor", "layout_seed", "maps", "stamp"}
    assert set(root["maps"]) == {"fact", "fact_order", "supp"}
    assert "globals" not in root and "actions" not in root


def test_poison_piles_are_rejected_with_evidence_and_retired(world):
    node, workspace = world
    store = node.store(workspace)
    before = node.reader(workspace).root_bytes
    poisons = [
        Fact(
            "msg", now_ms(), [["offer"]],
            {"pk": node.pk, "chan": "c", "text": "x"}, workspace),
        Fact(
            "msg", now_ms(), [[]],
            {"pk": node.pk, "chan": "c", "text": "x"}, workspace),
        Fact(
            "signature", now_ms(),
            [["offer", "author", "de", node.pk]], {}, workspace),
        Fact(
            "workspace", now_ms(),
            [["offer", "member", node.pk]], {}, workspace),
    ]

    for poison in poisons:
        raw = node.sender(workspace).pack((poison,))
        source, result = stage_apply(
            node.applier(workspace), raw)
        assert result.status == "rejected"
        assert result.retired is True
        assert result.rejection is not None
        assert store.get(source) is None
        assert store.get(
            "failed/pile/" + result.rejection.payload) == raw

    assert node.reader(workspace).root_bytes == before
    assert store.list("pile/") == []


def test_poison_cannot_wedge_honest_work_in_the_same_turn(world):
    node, workspace = world
    item, honest = message_pile(
        node, workspace, "survivor", ts=3_200_000)
    poison = b"{}"
    applier = node.applier(workspace)
    poison_source = run(applier.stage("poison", poison))
    honest_source = run(applier.stage("honest", honest))

    report = run(applier.turn())
    by_source = {entry.source: entry for entry in report}

    assert by_source[poison_source].error is None
    assert by_source[poison_source].result.status == "rejected"
    assert by_source[honest_source].error is None
    assert by_source[honest_source].result.status == "applied"
    assert node.store(workspace).list("pile/") == []
    assert node.reader(workspace).validated().fact(item.fid) == item


def test_ephemeral_request_never_enters_validated_repository(world):
    node, workspace = world
    ts = now_ms()
    ephemeral = request(
        workspace, node.pk, "sync", ts + 9_999, ts)
    signed = signature(node.sk, node.pk, ephemeral, ts)
    member = node.sql(workspace).resolve_offer("member", node.pk)
    chain = decode_pile(
        fact_pile(node, workspace, member),
        workspace,
    )
    raw = node.sender(workspace).pack(
        tuple(chain) + (signed, ephemeral))
    _, result = stage_apply(node.applier(workspace), raw)

    # The detached signature is durable and may advance the root; the request
    # it authenticates is deliberately ephemeral and must never become a
    # validated repository.
    assert result.status == "applied"
    assert result.retired is True
    validated = node.reader(workspace).validated()
    assert validated.fact(signed.fid) == signed
    assert ephemeral.fid not in validated.fact_ids()
