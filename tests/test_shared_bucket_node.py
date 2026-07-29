"""Production publication and Worker reads over one adversarial bucket."""
from concurrent.futures import ThreadPoolExecutor
import json
import shutil
import sqlite3

import pytest

from core import bao, cmds, indexes, manifest, mint
from core.close import close, decode_pile, encode_pile
from core.crypto import h, keypair
from core.kernel import drain, offer_src, resolve_deps
from core.node import Node, resident
from core.publication import RootChanged
from core.worker import WorkerView
from facts import _policy
from facts.auth import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.content.delete import delete
from facts.content.message import message

from .shared_bucket import ScriptedBucket
from .util import add_member, inject_device_claim, member_src, send_bytes


def _closed_signed(node, workspace, item, *, role="member"):
    """Build the exact closed pile used by a family command, without turning."""
    secret, public = node.identity(workspace)
    signed = signature(secret, public, item, item.ts)
    provider = offer_src(node.idx(workspace), role, public)
    assert provider is not None
    new = {fact.fid: fact for fact in (signed, item)}
    deps = {
        signed.fid: (),
        item.fid: tuple(ref for _, ref in item.refs())
        + (signed.fid, provider),
    }

    def fact_of(fid):
        return new.get(fid) or node.fact_of(workspace, fid)

    def deps_of(fid):
        return deps[fid] if fid in deps else \
            (resolve_deps(fact_of(fid), node.idx(workspace)) or ())

    stream = close(
        new.values(), deps_of, fact_of,
    )
    raw = encode_pile(stream)
    judgment = drain(decode_pile(raw)[0], workspace)
    assert judgment.ok
    return raw, item


def _snapshot(store):
    return {key: store.get(key) for key in store.list("")}


def _shared_clones(seed, workspace, path, *actors):
    """Clone one coherent local index, then point every clone at one bucket."""
    initial = _snapshot(seed.store(workspace))
    for index in seed._idx.values():
        index.close()
    seed.app.close()

    bucket = ScriptedBucket(initial)
    nodes = []
    for actor in actors:
        target = path / actor
        shutil.copytree(seed.dir, target)
        node = Node(str(target))
        node._stores[workspace] = bucket.handle(actor)
        nodes.append(node)
    return bucket, nodes


def _commit_facts(workspace, commit):
    objects = dict(commit.objects)
    fetch = objects.get
    root = manifest.decode_root(commit.root)
    assert root.anchor == workspace
    stream = tuple(resident(root.manifest, fetch, workspace))

    view = WorkerView.from_root(commit.root, fetch)
    for name in indexes.TREE_NAMES:
        descriptor = root.trees[name]
        page = json.loads(fetch(descriptor["root"]))
        assert (page["count"], page["depth"]) == (
            descriptor["count"], descriptor["depth"])
        assert len(view._reader(name).items(
            max_pages=descriptor["count"])) == descriptor["count"]
    return stream


def _message_pile(node, workspace, text, ts):
    public = node.identity_id(workspace)
    return _closed_signed(
        node, workspace, message(public, "general", text, ts))


def test_losing_publication_keeps_the_winner_and_retries_from_that_root(
        tmp_path):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw_a, fact_a = _message_pile(seed, workspace, "alice", 10)
    raw_b, fact_b = _message_pile(seed, workspace, "bob", 11)
    bucket, (alice, bob) = _shared_clones(
        seed, workspace, tmp_path, "alice", "bob")

    def candidates(raw):
        judged = drain(decode_pile(raw)[0], workspace)
        assert judged.ok
        return tuple(valid.fact for valid in judged.valids)

    alice_plan = alice.merge(workspace, candidates(raw_a))
    bob_plan = bob.merge(workspace, candidates(raw_b))
    assert alice_plan.base_etag == bob_plan.base_etag

    alice_root = alice.commit(workspace, alice_plan)
    with pytest.raises(RootChanged, match="root changed"):
        bob.commit(workspace, bob_plan)
    assert bob.store(workspace).get("root") == alice_root

    bob._restore_authoritative_projections(workspace)
    retry = bob.merge(workspace, candidates(raw_b))
    final_root = bob.commit(workspace, retry)
    assert {fact.fid for fact in _commit_facts(
        workspace, bucket.commits[-1])} >= {
            workspace, fact_a.fid, fact_b.fid}
    assert bob.store(workspace).get("root") == final_root

    alice._sync_index(workspace)
    assert alice.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() \
        == (h(final_root),)
    assert bucket.assert_valid_history()


def test_post_cas_stamp_records_its_own_root_not_a_later_writers(tmp_path):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    raw_a, _ = _message_pile(seed, workspace, "alice", 10)
    raw_b, _ = _message_pile(seed, workspace, "bob", 11)
    bucket, (alice, bob) = _shared_clones(
        seed, workspace, tmp_path, "alice", "bob")

    def plan(node, raw):
        judged = drain(decode_pile(raw)[0], workspace)
        return node.merge(
            workspace, (valid.fact for valid in judged.valids))

    plan_a = plan(alice, raw_a)
    cas_won = bucket.pause("alice", "cas", "root", when="after")
    with ThreadPoolExecutor(max_workers=1) as pool:
        publishing = pool.submit(alice.commit, workspace, plan_a)
        cas_won.wait()
        root_a = alice.store(workspace).get("root")

        bob._sync_index(workspace)
        root_b = bob.commit(workspace, plan(bob, raw_b))
        assert root_b != root_a
        cas_won.release.set()
        assert publishing.result(timeout=5) == root_a

    # Alice may be stale, but its stamp is honest. It cannot falsely claim
    # that Bob's later root was the snapshot its own catalog compiled.
    assert alice.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (h(root_a),)
    assert alice.store(workspace).get("root") == root_b
    alice._sync_index(workspace)
    assert alice.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (h(root_b),)
    assert bucket.assert_valid_history()


def test_database_free_worker_mints_from_one_stale_but_complete_root(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    founder = seed.identity_id(workspace)
    bob_secret, bob, _ = add_member(seed, workspace, "bob", ts=10)
    seed.keychain.add_identity(bob_secret)
    seed.bind_identity(workspace, bob)
    now = 100
    proof = encode_pile(request.payload(
        seed, workspace, "sync", now + 60_000, now))
    seed.bind_identity(workspace, founder)
    bucket, (writer,) = _shared_clones(
        seed, workspace, tmp_path, "writer")
    reader = bucket.handle("reader")

    pinned = reader.get("root")
    cmds.evict(writer, workspace, bob)
    current = reader.get("root")
    assert current != pinned

    def database_forbidden(*_args, **_kwargs):
        raise AssertionError("CF Worker authorization opened SQLite")

    monkeypatch.setattr(sqlite3, "connect", database_forbidden)
    fetch = lambda oid: reader.get("obj/" + oid)
    assert mint.stateless(proof, pinned, fetch, now) == (bob, "sync")
    assert mint.stateless(proof, current, fetch, now) is None

    reader_events = [
        event for event in bucket.history if event.actor == "reader"]
    root_reads = [event for event in reader_events if event.key == "root"]
    assert [event.result for event in root_reads] == [pinned, current]
    assert all(
        event.key == "root" or event.key.startswith("obj/")
        for event in reader_events)
    assert bucket.assert_valid_history()


def test_rebuild_publishes_reactivated_local_receipts_instead_of_false_stamp(
        tmp_path):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "root", ts=1)
    root_secret, root = seed.identity(workspace)
    q_secret, q, _ = add_member(seed, workspace, "q", ts=10)
    short_secret, short, _ = add_member(
        seed, workspace, "short", inviter=(q_secret, q), ts=20)
    deep_secret, deep, _ = add_member(seed, workspace, "d1", ts=30)
    for ordinal, name in enumerate(("d2", "d3", "deep")):
        deep_secret, deep, _ = add_member(
            seed, workspace, name, inviter=(deep_secret, deep),
            ts=40 + 10 * ordinal)
    for secret, public, label in (
            (short_secret, short, "short-primary"),
            (deep_secret, deep, "deep-primary")):
        seed.keychain.add_identity(secret)
        seed.bind_identity(workspace, public)
        cmds.bind_device(seed, workspace, label)

    target_secret, target = keypair()
    seed.keychain.add_identity(target_secret)
    inject_device_claim(
        seed, workspace, deep_secret, deep, deep, target,
        "from-deep", 200)
    bucket, (alice, bob) = _shared_clones(
        seed, workspace, tmp_path, "alice", "bob")

    alice.bind_identity(workspace, target)
    descriptor = send_bytes(
        alice, workspace, "latent.bin", b"x" * (bao.WIDTH + 1), ts=201)
    before = cmds.files(alice, workspace)
    assert len(before) == 1
    assert before[0]["fid"] == descriptor
    assert (
        before[0]["have"], before[0]["total"], before[0]["complete"]
    ) == (2, 2, True)
    chunk_fids = {
        fid for (fid,) in alice.idx(workspace).execute(
            "SELECT fid FROM facts WHERE t='chunk'")
    }
    assert len(chunk_fids) == 2

    _, child = keypair()
    child_claim = inject_device_claim(
        alice, workspace, target_secret, target, deep, child, "child", 202)
    inject_device_claim(
        alice, workspace, short_secret, short, short, target,
        "from-short", 400)
    assert alice.candidate_of(workspace, child_claim.fid) == child_claim
    assert alice.fact_of(workspace, child_claim.fid) is None
    assert alice.candidate_of(workspace, descriptor) is not None
    assert alice.fact_of(workspace, descriptor) is None
    assert cmds.files(alice, workspace) == []

    bob._sync_index(workspace)
    assert bob.candidate_of(workspace, child_claim.fid) is None
    invite_secret, invite_public = keypair()
    invitation = user_invite(root, invite_public, 500)
    invitation_sig = signature(root_secret, root, invitation, 500)
    rejoined = user(
        invitation, invite_secret, deep, "deep-direct", 501)
    rejoined_sig = signature(deep_secret, deep, rejoined, 501)
    bob.ingest_new(
        workspace,
        [invitation_sig, invitation, rejoined_sig, rejoined],
        {
            invitation_sig.fid: (),
            invitation.fid: (
                invitation_sig.fid, member_src(bob, workspace, root)),
            rejoined_sig.fid: (),
            rejoined.fid: (invitation.fid, rejoined_sig.fid),
        },
    )
    bob_root = bob.store(workspace).get("root")
    bob_stream = _commit_facts(workspace, bucket.commits[-1])
    assert child_claim.fid not in {fact.fid for fact in bob_stream}

    alice._sync_index(workspace)
    union_root = alice.store(workspace).get("root")
    union_stream = _commit_facts(workspace, bucket.commits[-1])
    assert union_root != bob_root
    assert child_claim.fid in {fact.fid for fact in union_stream}
    assert descriptor in {fact.fid for fact in union_stream}
    assert alice.fact_of(workspace, child_claim.fid) == child_claim
    restored = cmds.files(alice, workspace)
    assert len(restored) == 1
    assert restored[0]["fid"] == descriptor
    assert (
        restored[0]["have"],
        restored[0]["total"],
        restored[0]["complete"],
    ) == (2, 2, True)
    arrivals = {
        fid for (fid,) in alice.idx(workspace).execute(
            "SELECT DISTINCT fid FROM log WHERE op='*'")
    }
    assert chunk_fids <= arrivals
    assert alice.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (h(union_root),)

    bob._sync_index(workspace)
    assert bob.store(workspace).get("root") == union_root
    assert bucket.assert_valid_history()


def test_concurrent_turns_preserve_every_tree_and_converge_to_serial_union(
        tmp_path):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    target_fid = cmds.post(
        seed, workspace, "general", "target", ts=10)
    target = seed.fact_of(workspace, target_fid)
    public = seed.identity_id(workspace)

    # Pick two valid proposals whose bucket order is the reverse of their
    # canonical action order. The second arrival must therefore replace the
    # first SuppTree winner rather than merely add another inactive proposal.
    proposals = [
        _closed_signed(
            seed, workspace,
            delete(public, target.key, _policy.OWNER, ts))
        for ts in range(20, 36)
    ]
    ordered = sorted((h(raw), item.key, raw, item) for raw, item in proposals)
    pair = next(
        (first, second)
        for offset, first in enumerate(ordered)
        for second in ordered[offset + 1:]
        if first[1] > second[1])
    first, second = pair
    message_raw, addition = _message_pile(
        seed, workspace, "concurrent addition", 50)

    bucket, (alice, bob) = _shared_clones(
        seed, workspace, tmp_path, "alice", "bob")
    for raw in (first[2], second[2], message_raw):
        alice.store(workspace).put(
            "pile/shared/" + h(raw), raw)

    paused = bucket.pause("alice", "cas", "root", when="before")
    with ThreadPoolExecutor(max_workers=2) as pool:
        losing = pool.submit(alice.turn, workspace)
        paused.wait()
        winning = pool.submit(bob.turn, workspace)
        winning.result(timeout=10)
        paused.release.set()
        with pytest.raises(RootChanged):
            losing.result(timeout=10)

    assert alice.store(workspace).list("pile/") == []
    streams = [
        _commit_facts(workspace, commit)
        for commit in bucket.commits
    ]
    final = streams[-1]
    assert {fact.fid for fact in final} >= {
        workspace, target_fid, first[3].fid, second[3].fid, addition.fid}

    sid = indexes.fact_key(target_fid)
    winners = []
    for commit in bucket.commits:
        objects = dict(commit.objects)
        view = WorkerView.from_root(commit.root, objects.get)
        slot = view.suppression(sid)
        if slot["state"] == "active":
            winners.append(slot["action"])
    assert first[3].fid in winners
    assert winners[-1] == second[3].fid

    final_root = alice.store(workspace).get("root")
    final_snapshot = manifest.decode_root(final_root)
    final_objects = dict(bucket.commits[-1].objects)
    serial = Node(str(tmp_path / "serial"))
    serial.store(workspace).put(
        "pile/serial/" + h(encode_pile(final)),
        encode_pile(final),
    )
    serial.turn(workspace)
    assert serial.store(workspace).get("root") == final_root
    assert tuple(resident(
        final_snapshot.manifest, final_objects.get, workspace)) == final
    assert bucket.assert_valid_history()


def test_foreign_root_cannot_clobber_a_different_snapshot(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    body = json.loads(node.store(workspace).get("root"))
    foreign = json.dumps({
        **body,
        "manifest": "0" * 64,
        "stamp": "future-layout",
    }, sort_keys=True, separators=(",", ":")).encode()
    node.store(workspace)._replace("root", foreign)

    with pytest.raises(ValueError, match="does not match"):
        node.rebuild(workspace)
    assert node.store(workspace).get("root") == foreign
