"""The three repository roles over one adversarial shared bucket."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest

import facts

from core import indexes
from full_peer import bao_native as bao
from core.close import close
from core.crypto import h, keypair
from full_peer.node import FullPeer
from core.object_store import Applied, OutcomeUnknown
from core.repository_applier import RepositoryApplier
from core.repository_reader import RepositoryReader
from core.store import FsStore
from facts import _policy
from facts.auth import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.content.delete import delete
from facts.content.message import message

from .shared_bucket import ScriptedBucket
from .util import add_member, inject_device_claim, member_src, send_bytes


MEMBER = "feed7feed7feed7f"


def run(awaitable):
    return asyncio.run(awaitable)


def _snapshot(store):
    return {key: store.get(key) for key in store.list("")}


def _attach_bucket(node, workspace, actor):
    """Move a coherent full node onto one shared repository store."""
    bucket = ScriptedBucket(_snapshot(node.store(workspace)))
    node._stores[workspace] = bucket.handle(actor)
    node._appliers.pop(workspace, None)
    return bucket


def _reader(workspace, store, root=None):
    root = store.get("root") if root is None else root
    assert root is not None
    return RepositoryReader(
        workspace, root, lambda oid: store.get("obj/" + oid))


def _stage_apply(applier, raw, member=MEMBER, **options):
    source = run(applier.stage(member, raw))
    return source, run(applier.apply(source, **options))


def _message_pile(node, workspace, text, ts):
    """Author one ordinary message through the SQL-permitted sender."""
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


def _signed_pile(node, workspace, item):
    """Author one signed family fact without receiving it."""
    secret, public = node.identity(workspace)
    signed = signature(secret, public, item, item.ts)
    provider = member_src(node, workspace, public)
    assert provider is not None
    raw = node.sender(workspace).pile(
        (signed, item),
        {
            signed.fid: (),
            item.fid: tuple(ref for _, ref in item.refs())
            + (signed.fid, provider),
        },
    )
    return raw, item


def _resident(reader):
    """Validated facts in one freshly assembled closure."""
    view = reader.validated()
    return view.closure(view.fact_ids())


def _commit_facts(workspace, commit):
    objects = dict(commit.objects)
    reader = RepositoryReader(
        workspace, commit.root, objects.get)
    # all_facts() traverses residences and rederives every authenticated map.
    return _resident(reader)


def test_concurrent_cold_appliers_retain_and_rebase_the_cas_loser(
        tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    first, first_raw = _message_pile(
        author, workspace, "alice", 10)
    second, second_raw = _message_pile(
        author, workspace, "bob", 11)
    bucket = ScriptedBucket(_snapshot(author.store(workspace)))
    store_a = bucket.handle("alice")
    store_b = bucket.handle("bob")
    worker_a = RepositoryApplier(workspace, store_a)
    worker_b = RepositoryApplier(workspace, store_b)
    source_a = run(worker_a.stage("alice", first_raw))
    source_b = run(worker_b.stage("bob", second_raw))

    proposal_a = run(worker_a.propose(source_a, h(first_raw), first_raw))
    proposal_b = run(worker_b.propose(source_b, h(second_raw), second_raw))
    assert proposal_a.base_token == proposal_b.base_token
    assert proposal_a.base_token.value.startswith("opaque:")

    won = run(worker_a.commit(source_a, h(first_raw), proposal_a))
    lost = run(worker_b.commit(source_b, h(second_raw), proposal_b))
    assert won.status == "applied"
    assert lost.status == "retryable"
    assert store_a.get(source_a) == first_raw
    assert store_b.get(source_b) == second_raw

    retried = run(RepositoryApplier(
        workspace, store_b).apply(source_b))
    assert retried.status == "applied"
    assert store_b.get(source_b) == second_raw
    assert store_a.get(source_a) == first_raw

    recovered = run(RepositoryApplier(
        workspace, store_a).apply(source_a))
    assert recovered.status == "noop"
    assert store_a.get(source_a) == first_raw
    reader = _reader(workspace, store_a)
    assert reader.validated().fact(first.fid) == first
    assert reader.validated().fact(second.fid) == second
    assert bucket.assert_valid_history()


def test_opaque_token_is_not_root_content_identity(tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    item, raw = _message_pile(
        author, workspace, "opaque CAS", 10)
    bucket = ScriptedBucket(_snapshot(author.store(workspace)))
    store = bucket.handle("writer")

    before = store.read_versioned("root")
    assert before.token.value.startswith("opaque:")
    assert before.token.value != h(before.value)

    _, result = _stage_apply(
        RepositoryApplier(workspace, store), raw)
    assert result.status == "applied"
    after = store.read_versioned("root")
    assert after.token.value.startswith("opaque:")
    assert after.token.value != h(after.value)
    assert after.token != before.token
    assert _reader(workspace, store).validated().fact(item.fid) == item
    assert bucket.assert_valid_history()


@pytest.mark.parametrize("applied_before_loss", (False, True))
def test_applier_reconciles_unknown_root_cas(
        tmp_path, monkeypatch, applied_before_loss):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = _message_pile(
        node, workspace, "survives ambiguity", 10)
    store = node.store(workspace)
    applier = node.applier(workspace)
    source = run(applier.stage(MEMBER, raw))
    real_cas, calls = store.cas, 0

    def ambiguous(key, token, value):
        nonlocal calls
        calls += 1
        if calls == 1:
            if applied_before_loss:
                assert isinstance(
                    real_cas(key, token, value), Applied)
            raise OutcomeUnknown("conditional response lost")
        return real_cas(key, token, value)

    monkeypatch.setattr(store, "cas", ambiguous)
    if applied_before_loss:
        result = run(applier.apply(source))
        assert result.status == "confirmed"
    else:
        assert run(applier.apply(source)).status == "retryable"
        assert store.get(source) == raw
        result = run(RepositoryApplier(
            workspace, store).apply(source))
        assert result.status == "applied"

    assert store.get(source) == raw
    assert calls == (1 if applied_before_loss else 2)
    assert _reader(workspace, store).validated().fact(item.fid) == item


def test_unknown_cas_followed_by_a_later_root_keeps_the_exact_pile(
        tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    first, first_raw = _message_pile(
        author, workspace, "ambiguous", 10)
    second, second_raw = _message_pile(
        author, workspace, "later winner", 11)
    bucket = ScriptedBucket(_snapshot(author.store(workspace)))
    alice_store = bucket.handle("alice")
    bob_store = bucket.handle("bob")
    alice = RepositoryApplier(workspace, alice_store)
    bob = RepositoryApplier(workspace, bob_store)
    source_a = run(alice.stage("alice", first_raw))
    source_b = run(bob.stage("bob", second_raw))

    lost_response = bucket.pause(
        "alice", "cas", "root", when="after")
    with ThreadPoolExecutor(max_workers=1) as pool:
        applying = pool.submit(run, alice.apply(source_a))
        lost_response.wait()
        later = run(RepositoryApplier(
            workspace, bob_store).apply(source_b))
        assert later.status == "applied"
        lost_response.error = OutcomeUnknown(
            "response lost after a later root won")
        lost_response.release.set()
        stale = applying.result(timeout=10)

    assert stale.status == "retryable"
    assert alice_store.get("root") == later.root
    assert alice_store.get(source_a) == first_raw
    assert bob_store.get(source_b) == second_raw

    replay = run(RepositoryApplier(
        workspace, alice_store).apply(source_a))
    assert replay.status == "noop"
    assert alice_store.get(source_a) == first_raw
    reader = _reader(workspace, alice_store)
    assert reader.validated().fact(first.fid) == first
    assert reader.validated().fact(second.fid) == second
    assert bucket.assert_valid_history()


def test_database_free_reader_stays_pinned_during_later_eviction(
        tmp_path, monkeypatch):
    writer = FullPeer(str(tmp_path / "writer"))
    workspace = facts.auth.workspace.create(writer, "alice", ts=1)
    founder = writer.identity_id(workspace)
    bob_secret, bob, _ = add_member(
        writer, workspace, "bob", ts=10)
    writer.keychain.add_identity(bob_secret)
    writer.bind_identity(workspace, bob)
    now = 100
    proof = writer.sender(workspace).pack(
        request.payload(
            writer, workspace, "sync", now + 60_000, now))
    writer.bind_identity(workspace, founder)
    bucket = _attach_bucket(writer, workspace, "writer")
    store = bucket.handle("reader")

    pinned_root = store.get("root")
    pinned = _reader(workspace, store, pinned_root)
    facts.auth.removal.evict(writer, workspace, bob)
    current_root = store.get("root")
    current = _reader(workspace, store, current_root)
    assert current_root != pinned_root

    def database_forbidden(*_args, **_kwargs):
        raise AssertionError("RepositoryReader opened SQLite")

    monkeypatch.setattr(sqlite3, "connect", database_forbidden)
    assert pinned.mint(proof, now) == (bob, "sync")
    assert current.mint(proof, now) is None

    events = [
        event for event in bucket.history
        if event.actor == "reader"
    ]
    assert [
        event.result for event in events
        if event.key == "root"
    ] == [pinned_root, current_root]
    assert all(
        event.key == "root" or event.key.startswith("obj/")
        for event in events
    )
    assert bucket.assert_valid_history()


def test_later_authority_changes_never_remove_validated_facts(
        tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "root", ts=1)
    root_secret, root = author.identity(workspace)
    q_secret, q, _ = add_member(
        author, workspace, "q", ts=10)
    short_secret, short, _ = add_member(
        author, workspace, "short", inviter=(q_secret, q), ts=20)
    deep_secret, deep, _ = add_member(
        author, workspace, "d1", ts=30)
    for ordinal, name in enumerate(("d2", "d3", "deep")):
        deep_secret, deep, _ = add_member(
            author,
            workspace,
            name,
            inviter=(deep_secret, deep),
            ts=40 + 10 * ordinal,
        )
    for secret, public, label in (
            (short_secret, short, "short-primary"),
            (deep_secret, deep, "deep-primary")):
        author.keychain.add_identity(secret)
        author.bind_identity(workspace, public)
        facts.auth.device.bind(author, workspace, label)

    target_secret, target = keypair()
    author.keychain.add_identity(target_secret)
    inject_device_claim(
        author, workspace, deep_secret, deep, deep, target,
        "from-deep", 200)
    bucket = _attach_bucket(author, workspace, "author")

    author.bind_identity(workspace, target)
    descriptor = send_bytes(
        author,
        workspace,
        "latent.bin",
        b"x" * (bao.WIDTH + 1),
        ts=201,
    )
    before = author.reader(workspace)
    before_facts = before.validated()
    chunk_fids = {
        fid
        for fid in before_facts.fact_ids()
        if before_facts.fact(fid).t == "chunk"
    }
    assert len(chunk_fids) == 2
    assert before_facts.fact(descriptor).fid == descriptor

    _, child = keypair()
    child_claim = inject_device_claim(
        author,
        workspace,
        target_secret,
        target,
        deep,
        child,
        "child",
        202,
    )
    inject_device_claim(
        author,
        workspace,
        short_secret,
        short,
        short,
        target,
        "from-short",
        400,
    )
    changed_root = author.store(workspace).get("root")
    changed = _reader(
        workspace, bucket.handle("cold-reader"), changed_root)
    changed_facts = changed.validated()
    for fid in (child_claim.fid, descriptor, *chunk_fids):
        assert changed_facts.fact(fid).fid == fid

    invite_secret, invite_public = keypair()
    invitation = user_invite(
        workspace, root, invite_public, 500)
    invitation_sig = signature(
        root_secret, root, invitation, 500)
    rejoined = user(
        invitation, invite_secret, deep, "deep-direct", 501)
    rejoined_sig = signature(
        deep_secret, deep, rejoined, 501)
    raw = author.sender(workspace).pile(
        (invitation_sig, invitation, rejoined_sig, rejoined),
        {
            invitation_sig.fid: (),
            invitation.fid: (
                invitation_sig.fid,
                member_src(author, workspace, root),
            ),
            rejoined_sig.fid: (),
            rejoined.fid: (
                invitation.fid,
                rejoined_sig.fid,
            ),
        },
    )
    cold = RepositoryApplier(
        workspace, bucket.handle("cold-applier"))
    _, result = _stage_apply(cold, raw)
    assert result.status == "applied"

    active = _reader(
        workspace, bucket.handle("reactivated"))
    active_facts = active.validated()
    for fid in (child_claim.fid, descriptor, *chunk_fids):
        assert active_facts.fact(fid).fid == fid
    for fid in chunk_fids:
        chunk = active_facts.fact(fid)
        assert active.object(chunk.body["cid"])
    assert bucket.assert_valid_history()


def test_concurrent_appliers_preserve_suppression_winner_and_serial_union(
        tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    target_fid = facts.content.message.post(
        author, workspace, "general", "target", ts=10)
    target = author.reader(workspace).validated().fact(target_fid)
    public = author.identity_id(workspace)
    proposals = [
        _signed_pile(
            author,
            workspace,
            delete(
                workspace,
                public,
                target.key,
                _policy.OWNER,
                ts,
            ),
        )
        for ts in range(20, 36)
    ]
    low = min(proposals, key=lambda pair: pair[1].key)
    high = max(proposals, key=lambda pair: pair[1].key)
    addition, addition_raw = _message_pile(
        author, workspace, "concurrent addition", 50)
    bucket = ScriptedBucket(_snapshot(author.store(workspace)))

    high_store = bucket.handle("high")
    _, first = _stage_apply(
        RepositoryApplier(workspace, high_store),
        high[0],
        member="high",
    )
    assert first.status == "applied"
    sid = indexes.fact_key(target_fid)
    assert _reader(
        workspace, high_store).worker().suppression(sid) == {
            "state": "active",
            "action": high[1].fid,
        }

    low_store = bucket.handle("low")
    addition_store = bucket.handle("addition")
    low_applier = RepositoryApplier(workspace, low_store)
    addition_applier = RepositoryApplier(
        workspace, addition_store)
    low_source = run(low_applier.stage("low", low[0]))
    addition_source = run(addition_applier.stage(
        "addition", addition_raw))
    low_proposal = run(low_applier.propose(
        low_source, h(low[0]), low[0]))
    addition_proposal = run(
        addition_applier.propose(
            addition_source, h(addition_raw), addition_raw))
    assert low_proposal.base_token == addition_proposal.base_token

    paused = bucket.pause("low", "cas", "root", when="before")
    with ThreadPoolExecutor(max_workers=1) as pool:
        losing = pool.submit(
            run,
            low_applier.commit(
                low_source, h(low[0]), low_proposal),
        )
        paused.wait()
        try:
            added = run(addition_applier.commit(
                addition_source,
                h(addition_raw),
                addition_proposal,
            ))
            assert added.status == "applied"
        finally:
            paused.release.set()
        stale = losing.result(timeout=10)
    assert stale.status == "retryable"
    assert low_store.get(low_source) == low[0]
    assert addition_store.get(addition_source) == addition_raw

    low_retry = run(RepositoryApplier(
        workspace, low_store).apply(low_source))
    assert low_retry.status == "applied"
    addition_replay = run(RepositoryApplier(
        workspace, addition_store).apply(addition_source))
    assert addition_replay.status == "noop"

    final_reader = _reader(workspace, low_store)
    assert final_reader.worker().suppression(sid) == {
        "state": "active",
        "action": low[1].fid,
    }
    final = _resident(final_reader)
    assert {fact.fid for fact in final} >= {
        workspace,
        target_fid,
        high[1].fid,
        low[1].fid,
        addition.fid,
    }

    winners = []
    for commit in bucket.commits:
        objects = dict(commit.objects)
        reader = RepositoryReader(
            workspace, commit.root, objects.get)
        slot = reader.worker().suppression(sid)
        if slot["state"] == "active":
            winners.append(slot["action"])
        _commit_facts(workspace, commit)
    assert high[1].fid in winners
    assert winners[-1] == low[1].fid

    serial_store = FsStore(str(tmp_path / "serial"))
    serial_raw = author.sender(workspace).pack(final)
    _, serial = _stage_apply(
        RepositoryApplier(workspace, serial_store),
        serial_raw,
        member="serial",
    )
    assert serial.status == "applied"
    assert serial_store.get("root") == final_reader.root_bytes
    assert _resident(_reader(
        workspace, serial_store)) == final
    assert bucket.assert_valid_history()
