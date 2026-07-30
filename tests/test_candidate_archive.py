"""Authenticated retention and reconstruction of dormant fact candidates."""
import asyncio
import json

import pytest

import facts

from core import (
    admission_proof,
    catalog,
    indexes,
    merkle_map,
    repository_applier,
    repository_snapshot,
    snapshot,
)
from core.candidate_archive import CandidateView, reconstruct
from core.close import encode_pile
from core.crypto import h
from core.fact import canon, encode
from core.node import Node
from core.repository_applier import RepositoryApplier
from core.repository_reader import RepositoryReader
from core.store import FsStore
import core.sync as sync_module
from facts.auth.signature import signature
from facts.content.message import message

from .util import add_member, all_fids, closed_subset, deliver, member_src


def run(awaitable):
    return asyncio.run(awaitable)


def _stage_apply(applier, raw, member="feed7feed7feed7f", **options):
    source = run(applier.stage(member, raw))
    return source, run(applier.apply(source, **options))


def _closed_with(node, workspace, facts, dependencies):
    """Author a fixture pile through the SQL-permitted sender role."""
    return node.sender(workspace).pile(facts, dependencies)


def _message_pile(node, workspace, text, ts):
    secret, public = node.identity(workspace)
    item = message(workspace, public, "general", text, ts)
    signed = signature(secret, public, item, item.ts)
    return item, _closed_with(node, workspace, (signed, item), {
        signed.fid: (),
        item.fid: (
            signed.fid, member_src(node, workspace, public)),
    })


def _removed_member_messages(
        node, workspace, secret, public, member_provider, count, first_ts):
    authored, dependencies, messages = [], {}, []
    for ordinal in range(count):
        item = message(
            workspace, public, "general",
            f"dormant-{ordinal}", first_ts + ordinal)
        signed = signature(secret, public, item, item.ts)
        authored.extend((signed, item))
        messages.append(item)
        dependencies[signed.fid] = ()
        dependencies[item.fid] = (signed.fid, member_provider)
    return (
        _closed_with(node, workspace, authored, dependencies),
        tuple(messages),
    )


def _root_view(node, workspace):
    return node.reader(workspace).candidates()


def _reader(workspace, store, root=None):
    root = store.get("root") if root is None else root
    return RepositoryReader(
        workspace, root, lambda oid: store.get("obj/" + oid))


def _forged_archive(node, workspace, mutate):
    """Rebuild every authenticated tree honestly around one logical lie."""
    store = node.store(workspace)
    committed = snapshot.decode_root(store.get("root"))
    fetch = lambda oid: store.get("obj/" + oid)
    rows = {}
    for name in indexes.TREE_NAMES:
        descriptor = committed.maps[name]
        rows[name] = dict(merkle_map.Reader(
            descriptor["root"],
            committed.layout_seed,
            fetch,
            max_page_depth=descriptor["depth"],
        ).items(max_pages=max(1, 2 * descriptor["count"] - 1)))
    mutate(rows)

    objects = {}

    def emit(raw):
        oid = h(raw)
        objects[oid] = raw
        return oid

    trees = {}
    for name in indexes.TREE_NAMES:
        built = merkle_map.build(
            tuple(rows[name].items()), committed.layout_seed, emit)
        trees[name] = {
            "root": built.root,
            "count": built.count,
            "depth": built.page_depth,
        }
    root = snapshot.encode_root(
        workspace,
        {
            snapshot.FACT_ORDER: committed.maps[snapshot.FACT_ORDER],
            **trees,
        },
        seed=committed.layout_seed,
    )
    return root, lambda oid: objects[oid] if oid in objects else fetch(oid)


@pytest.mark.parametrize(
    "name",
    (snapshot.FACT_ORDER, *indexes.TREE_NAMES),
)
@pytest.mark.parametrize("field", ("count", "depth"))
def test_cold_reconstruction_rejects_forged_map_metadata(
        tmp_path, name, field):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "descriptor", ts=10)
    store = node.store(workspace)
    body = json.loads(store.get("root"))
    assert body["maps"][name]["root"]
    body["maps"][name][field] += 1
    forged = canon(body)

    with pytest.raises(ValueError, match="merkle map root metadata"):
        reconstruct(
            forged,
            lambda oid: store.get("obj/" + oid),
        )


@pytest.mark.parametrize("field", ("count", "depth"))
def test_candidate_sync_read_rejects_forged_fact_descriptor(
        tmp_path, field):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "descriptor", ts=10)
    store = node.store(workspace)
    body = json.loads(store.get("root"))
    descriptor = body["maps"][indexes.FACT]
    descriptor[field] += 1
    fetched = []

    def fetch(oid):
        fetched.append(oid)
        return store.get("obj/" + oid)

    forged = canon(body)
    for read in (
            lambda view: view.candidate_ids(),
            lambda view: view.fact_record(workspace)):
        fetched.clear()
        with pytest.raises(ValueError, match="merkle map root metadata"):
            read(CandidateView(forged, fetch))
        assert fetched == [descriptor["root"]]


@pytest.mark.parametrize(
    "name",
    (snapshot.FACT_ORDER, *indexes.TREE_NAMES),
)
@pytest.mark.parametrize("field", ("count", "depth"))
def test_repository_applier_rejects_forged_base_map_metadata(
        tmp_path, name, field):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "before forgery", ts=10)
    _, raw = _message_pile(
        node, workspace, "must not heal forged root", 20)
    store = node.store(workspace)
    body = json.loads(store.get("root"))
    body["maps"][name][field] += 1
    forged = canon(body)
    store._replace("root", forged)
    source = run(node.applier(workspace).stage(
        "forgedmetadata00", raw))
    objects = tuple(store.list("obj/"))

    with pytest.raises(ValueError, match="merkle map root metadata"):
        run(node.applier(workspace).apply(source))
    assert store.get("root") == forged
    assert store.get(source) == raw
    assert tuple(store.list("obj/")) == objects


def test_dormant_candidates_are_retained_paginated_and_cold_rebuilt(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    provider = member_src(node, workspace, bob)
    eviction = facts.auth.removal.evict(node, workspace, bob)
    first_ts = node.candidate_of(workspace, eviction).ts + 1
    raw, dormant = _removed_member_messages(
        node, workspace, bob_secret, bob, provider, 11, first_ts)
    applier = node.applier(workspace)
    source = run(applier.stage("hostile00000000", raw))
    store = node.store(workspace)

    # F10 covers every durable kernel Valid, not only current eligibility.
    # The old root has no FactRecord for this independently valid pile, so it
    # cannot authorize destructive retirement.
    with pytest.raises(ValueError, match="repository retirement receipt"):
        run(applier.retire(source, raw, None))
    assert store.get(source) == raw

    result = run(applier.apply(source))
    assert result.status == "applied"
    assert result.retired is True
    assert store.get(source) is None
    cold = _reader(workspace, store)
    for fact in dormant:
        assert cold.candidates().fact_record(fact.fid)["state"] == "dormant"
        assert cold.candidates().fact(fact.fid) == fact

    before_noop = store.get("root")
    _, replay = _stage_apply(applier, raw, member="hostile00000000")
    assert replay.status == "noop"
    assert replay.retired is True
    assert store.get("root") == before_noop

    live_fid = facts.content.message.post(
        node, workspace, "general", "one eligible", ts=first_ts + 100)
    view = _root_view(node, workspace)
    for fact in dormant:
        record = view.fact_record(fact.fid)
        assert record["state"] == "dormant"
        assert record["fact_oid"] == h(encode(fact))
        assert view.fact(fact.fid) == fact
        view.verify(fact.fid)

    worker = node.reader(workspace).worker()
    ordinary = worker.postings(
        catalog.TYPE_INDEX, "msg", "", limit=1)
    assert [(row.state, row.fid) for row in ordinary.rows] == [
        ("eligible", live_fid)]
    assert ordinary.cursor is None

    rows, cursor = [], None
    while True:
        page = worker.postings(
            catalog.TYPE_INDEX, "msg", "",
            after=cursor, limit=3, include_dormant=True)
        rows.extend(page.rows)
        cursor = page.cursor
        if cursor is None:
            break
    assert rows[0].state == "eligible"
    assert {row.fid for row in rows if row.state == "dormant"} == {
        fact.fid for fact in dormant}
    assert len(rows) == len(dormant) + 1

    expected_root = store.get("root")
    expected = _reader(workspace, store, expected_root).archive()
    assert set(expected.records) >= {fact.fid for fact in dormant}

    # A fresh recipient reader reconstructs dormant bodies and eligibility
    # using only the pinned root and immutable object fetches.
    rebuilt = _reader(workspace, store, expected_root)
    assert rebuilt.root_bytes == expected_root
    for fact in dormant:
        assert rebuilt.candidates().fact(fact.fid) == fact
        assert rebuilt.candidates().fact_record(fact.fid)[
            "state"] == "dormant"


@pytest.mark.parametrize(
    ("attack", "error"),
    (
        ("extra-supp-clear", "SuppTree projection"),
        ("forged-authority", "AuthorityTree projection"),
        ("eligible-to-dormant", "FactOrder projection"),
        ("dormant-to-eligible", "FactOrder projection"),
        ("rank-relabel", "eligible FactRecord judgment"),
        ("dependency-relabel", "eligible FactRecord judgment"),
        ("arbitrary-action-slot", "FactTree projection"),
        ("residence-mismatch", "FactOrder projection"),
        ("residence-missing", "FactOrder projection"),
    ),
)
def test_cold_reconstruction_rejects_authenticated_projection_lies(
        tmp_path, attack, error):
    """Hash-valid trees cannot substitute arbitrary state for derivation."""
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    live = facts.content.message.post(node, workspace, "general", "live record", ts=10)
    facts.content.delete.remove(node, workspace, live, ts=20)
    bob_secret, bob, _ = add_member(
        node, workspace, "bob", ts=30)
    provider = member_src(node, workspace, bob)
    eviction = facts.auth.removal.evict(node, workspace, bob)
    first_ts = node.candidate_of(workspace, eviction).ts + 1
    raw, dormant_messages = _removed_member_messages(
        node, workspace, bob_secret, bob, provider, 1, first_ts)
    _, admitted = _stage_apply(node.applier(workspace), raw)
    assert admitted.status == "applied"
    dormant = dormant_messages[0].fid

    def mutate(rows):
        fact_rows = rows[indexes.FACT]
        if attack == "extra-supp-clear":
            rows[indexes.SUPP]["forged:suppression"] = {"state": "clear"}
        elif attack == "forged-authority":
            address = next(iter(rows[indexes.AUTHORITY]))
            rows[indexes.AUTHORITY][address] = {
                "state": "provider", "fid": dormant, "rank": 0}
        elif attack == "eligible-to-dormant":
            record = fact_rows[indexes.fact_key(live)]
            record["state"], record["rank"] = "dormant", None
        elif attack == "dormant-to-eligible":
            record = fact_rows[indexes.fact_key(dormant)]
            record["state"], record["rank"] = "eligible", 0
        elif attack == "rank-relabel":
            fact_rows[indexes.fact_key(live)]["rank"] += 1
        elif attack == "dependency-relabel":
            fact_rows[indexes.fact_key(live)]["dependencies"] = []
        elif attack == "arbitrary-action-slot":
            fact_rows[indexes.action_key("forged:suppression")] = {
                "state": "clear"}
        elif attack == "residence-mismatch":
            fact_rows[indexes.fact_key(live)]["fact_oid"] = \
                fact_rows[indexes.fact_key(workspace)]["fact_oid"]
        elif attack == "residence-missing":
            fact_rows[indexes.fact_key(live)]["fact_oid"] = "0" * 64
        else:
            raise AssertionError(attack)

    forged, fetch = _forged_archive(node, workspace, mutate)
    with pytest.raises(ValueError, match=error):
        reconstruct(forged, fetch)


def test_admission_proofs_are_raw_free_and_hash_authenticated(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    marker = "raw-body-must-not-be-in-the-proof"
    fid = facts.content.message.post(node, workspace, "general", marker, ts=10)
    store = node.store(workspace)
    view = _root_view(node, workspace)
    record = view.fact_record(fid)
    proof_raw = store.get("obj/" + record["admission"])
    proof = json.loads(proof_raw)

    assert set(proof) == {"edges", "fid", "schema", "workspace"}
    assert proof["schema"] == admission_proof.SCHEMA
    assert marker.encode() not in proof_raw
    assert view.verify(fid).valids[-1].fact.fid == fid

    # A hash-addressed proof cannot be altered under the selected oid.
    store._replace("obj/" + record["admission"], proof_raw + b" ")
    with pytest.raises(ValueError, match="object integrity"):
        _root_view(node, workspace).verify(fid)
    store._replace("obj/" + record["admission"], proof_raw)


def test_admission_proof_traversal_enforces_every_budget_and_graph_guard(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    fid = facts.content.message.post(node, workspace, "general", "bounded proof", ts=10)
    store = node.store(workspace)
    view = _root_view(node, workspace)
    proof_oid = view.fact_record(fid)["admission"]
    verified = view.verify(fid)
    proof_oids = {oid for _, oid in verified.proofs}
    decoded = {
        oid: admission_proof.decode(store.get("obj/" + oid))
        for oid in proof_oids
    }

    def verify():
        return admission_proof.verify(
            workspace, fid, proof_oid, view.fact,
            lambda oid: store.get("obj/" + oid))

    nodes_limit = admission_proof.MAX_PROOF_NODES
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_NODES", len(proof_oids))
    verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_NODES", len(proof_oids) - 1)
    with pytest.raises(ValueError, match="node budget"):
        verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_NODES", nodes_limit)

    exact_fetches = 2 * len(proof_oids)
    fetch_limit = admission_proof.MAX_PROOF_FETCHES
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_FETCHES", exact_fetches)
    verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_FETCHES", exact_fetches - 1)
    with pytest.raises(ValueError, match="fetch budget"):
        verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_FETCHES", fetch_limit)

    def depth(oid):
        return 1 + max(
            (depth(edge[3]) for edge in decoded[oid].edges),
            default=0,
        )

    exact_depth = depth(proof_oid)
    depth_limit = admission_proof.MAX_PROOF_DEPTH
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_DEPTH", exact_depth)
    verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_DEPTH", exact_depth - 1)
    with pytest.raises(ValueError, match="depth budget"):
        verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_DEPTH", depth_limit)

    exact_bytes = (
        sum(len(store.get("obj/" + oid)) for oid in proof_oids)
        + sum(len(encode(fact)) for fact in verified.facts)
    )
    byte_limit = admission_proof.MAX_PROOF_BYTES
    monkeypatch.setattr(admission_proof, "MAX_PROOF_BYTES", exact_bytes)
    verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_BYTES", exact_bytes - 1)
    with pytest.raises(ValueError, match="byte budget"):
        verify()
    monkeypatch.setattr(admission_proof, "MAX_PROOF_BYTES", byte_limit)

    # The real database-free path also charges bounded FactTree pages and
    # residences fetched while resolving facts. Exact N succeeds; N-1 fails
    # for both dimensions on an otherwise identical cold view.
    def cold_verify():
        return CandidateView(
            store.get("root"),
            lambda oid: store.get("obj/" + oid),
        ).verify(fid)

    measured = cold_verify()
    reused = CandidateView(
        store.get("root"),
        lambda oid: store.get("obj/" + oid),
    )
    first_cold = reused.verify(fid)
    second_cold = reused.verify(fid)
    assert (first_cold.fetches, first_cold.bytes) == (
        second_cold.fetches, second_cold.bytes)
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_FETCHES", measured.fetches)
    cold_verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_FETCHES", measured.fetches - 1)
    with pytest.raises(ValueError, match="fetch budget"):
        cold_verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_FETCHES", fetch_limit)
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_BYTES", measured.bytes)
    cold_verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_BYTES", measured.bytes - 1)
    with pytest.raises(ValueError, match="byte budget"):
        cold_verify()
    monkeypatch.setattr(admission_proof, "MAX_PROOF_BYTES", byte_limit)

    exact_edges = max(len(node.edges) for node in decoded.values())
    edge_limit = admission_proof.MAX_PROOF_EDGES
    monkeypatch.setattr(admission_proof, "MAX_PROOF_EDGES", exact_edges)
    verify()
    monkeypatch.setattr(
        admission_proof, "MAX_PROOF_EDGES", exact_edges - 1)
    with pytest.raises(ValueError, match="edge budget"):
        verify()
    monkeypatch.setattr(admission_proof, "MAX_PROOF_EDGES", edge_limit)

    root_oid, left_oid, right_oid = "a" * 64, "b" * 64, "c" * 64
    root_fid, parent_fid = fid, workspace
    monkeypatch.setattr(
        admission_proof, "verified_object",
        lambda oid, _fetch: oid.encode())

    cyclic = {
        root_oid: admission_proof.ProofNode(
            workspace, root_fid,
            (("self", root_fid, "need", root_oid),)),
    }
    monkeypatch.setattr(
        admission_proof, "decode",
        lambda raw: cyclic[raw.decode()])
    with pytest.raises(ValueError, match="proof cycle"):
        admission_proof.verify(
            workspace, root_fid, root_oid,
            lambda _fid: None, lambda _oid: None)

    forked = {
        root_oid: admission_proof.ProofNode(
            workspace, root_fid,
            (
                ("left", parent_fid, "need", left_oid),
                ("right", parent_fid, "need", right_oid),
            )),
        left_oid: admission_proof.ProofNode(
            workspace, parent_fid, ()),
        right_oid: admission_proof.ProofNode(
            workspace, parent_fid, ()),
    }
    monkeypatch.setattr(
        admission_proof, "decode",
        lambda raw: forked[raw.decode()])
    with pytest.raises(ValueError, match="fid fork"):
        admission_proof.verify(
            workspace, root_fid, root_oid,
            lambda _fid: None, lambda _oid: None)

    # A shared node first visited by a shallow edge must not let a deeper
    # rejoining path evade the path-depth bound.
    mid_oid = "d" * 64
    shared_fid = "e" * 64
    mid_fid = "f" * 64
    rejoined = {
        root_oid: admission_proof.ProofNode(
            workspace, root_fid,
            (
                ("shallow", shared_fid, "need", left_oid),
                ("deep", mid_fid, "need", mid_oid),
            )),
        left_oid: admission_proof.ProofNode(
            workspace, shared_fid, ()),
        mid_oid: admission_proof.ProofNode(
            workspace, mid_fid,
            (("rejoin", shared_fid, "need", left_oid),)),
    }
    monkeypatch.setattr(
        admission_proof, "decode",
        lambda raw: rejoined[raw.decode()])
    monkeypatch.setattr(admission_proof, "MAX_PROOF_DEPTH", 2)
    with pytest.raises(ValueError, match="depth budget"):
        admission_proof.verify(
            workspace, root_fid, root_oid,
            lambda _fid: None, lambda _oid: None)


@pytest.mark.parametrize("dormant", (False, True))
def test_candidate_proof_min_join_converges_without_a_range_difference(
        tmp_path, monkeypatch, dormant):
    seed = Node(str(tmp_path / "seed"))
    workspace = facts.auth.workspace.create(seed, "alice", ts=1)
    bob_secret, bob, _ = add_member(seed, workspace, "bob", ts=10)
    provider = member_src(seed, workspace, bob)
    eviction = facts.auth.removal.evict(seed, workspace, bob) if dormant else None
    base = closed_subset(seed, workspace, all_fids(seed, workspace))

    item = message(
        workspace, bob, "general", "same candidate bytes",
        seed.candidate_of(workspace, eviction).ts + 1
        if eviction is not None else 20)
    first = signature(bob_secret, bob, item, item.ts)
    second = signature(bob_secret, bob, item, item.ts + 1)

    def message_pile(signed):
        return _closed_with(
            seed, workspace, (signed, item), {
                signed.fid: (),
                item.fid: (signed.fid, provider),
            })

    first_pile, second_pile = message_pile(first), message_pile(second)
    first_only = encode_pile((first,), workspace=workspace)
    second_only = encode_pile((second,), workspace=workspace)
    nodes = []
    for name, initial, alternate in (
            ("first", first_pile, second_only),
            ("second", second_pile, first_only)):
        current = Node(str(tmp_path / name))
        for pile in (base, initial, alternate):
            deliver(current, workspace, pile)
            current.turn(workspace)
        assert (current.fact_of(workspace, item.fid) is None) is dormant
        assert current.candidate_of(workspace, item.fid) == item
        nodes.append(current)
    local, remote = nodes
    local_snapshot = snapshot.decode_root(
        local.store(workspace).get("root"))
    remote_snapshot = snapshot.decode_root(
        remote.store(workspace).get("root"))
    assert local_snapshot.maps[snapshot.FACT_ORDER] \
        == remote_snapshot.maps[snapshot.FACT_ORDER]
    assert local.store(workspace).get("root") \
        != remote.store(workspace).get("root")
    assert _root_view(local, workspace).fact_record(
        item.fid)["admission"] != _root_view(
            remote, workspace).fact_record(item.fid)["admission"]

    class LocalPeer:
        accepts_push = True

        def __init__(self, node, ws, url):
            self.cache = node.sync_cache.setdefault((ws, url), {})
            self.ws = ws

        def root(self, etag=None):
            root = remote.store(self.ws).get("root")
            etag = h(root)
            return None if self.cache.get("etag") == etag else (root, etag)

        def obj(self, oid):
            return remote.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            return tuple(self.obj(oid) for oid in oids)

        def put_pile(self, raw):
            deliver(remote, self.ws, raw)
            remote.turn(self.ws)

        def put_obj(self, oid, raw):
            remote.store(self.ws).put_if_absent("obj/" + oid, raw)

    monkeypatch.setattr(sync_module, "Peer", LocalPeer)
    pulled, pushed = sync_module.sync(
        local, workspace, "local://remote")

    assert bool(pulled) != bool(pushed)
    assert local.store(workspace).get("root") \
        == remote.store(workspace).get("root")
    assert sync_module.sync(
        local, workspace, "local://remote") == (0, 0)


def test_registered_rootless_workspace_pulls_the_remote_candidate_archive(
        tmp_path, monkeypatch):
    remote = Node(str(tmp_path / "remote"))
    workspace = facts.auth.workspace.create(remote, "alice", ts=1)
    fid = facts.content.message.post(
        remote, workspace, "general", "rootless catch-up", ts=10)
    local = Node(str(tmp_path / "local"))
    local.add_workspace(workspace, "registered", peers=[])
    assert local.store(workspace).get("root") is None

    class PullOnlyPeer:
        accepts_push = False

        def __init__(self, node, ws, url):
            self.ws = ws
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None):
            raw = remote.store(self.ws).get("root")
            current = h(raw)
            return None if etag == current else (raw, current)

        def obj(self, oid):
            return remote.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            return tuple(self.obj(oid) for oid in oids)

    monkeypatch.setattr(sync_module, "Peer", PullOnlyPeer)

    assert sync_module.sync(
        local, workspace, "local://remote") == (1, 0)
    assert local.fact_of(workspace, fid) == remote.fact_of(workspace, fid)
    assert local.store(workspace).get("root") \
        == remote.store(workspace).get("root")


def test_compiler_omission_cannot_advance_root_or_retire_pile(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = _message_pile(
        node, workspace, "must be represented", 10)
    store = node.store(workspace)
    applier = node.applier(workspace)
    source = run(applier.stage("compiler000000", raw))
    root = store.get("root")
    objects = tuple(store.list("obj/"))
    compile_snapshot = repository_applier.compile_snapshot
    cas = store.cas
    cas_calls = []

    def omit(*args, **kwargs):
        result = compile_snapshot(*args, **kwargs)
        records = dict(result.records)
        records.pop(item.fid)
        return repository_snapshot.CompiledSnapshot(
            result.root,
            result.outbox,
            records,
            result.projection,
        )

    def observed_cas(*args, **kwargs):
        cas_calls.append((args, kwargs))
        return cas(*args, **kwargs)

    monkeypatch.setattr(repository_applier, "compile_snapshot", omit)
    monkeypatch.setattr(store, "cas", observed_cas)

    with pytest.raises(
            ValueError, match="repository proposal omitted admission"):
        run(applier.apply(source))
    assert store.get("root") == root
    assert store.get(source) == raw
    assert cas_calls == []
    assert tuple(store.list("obj/")) == objects
    with pytest.raises(ValueError, match="missing FactRecord"):
        _reader(workspace, store).candidates().fact_record(item.fid)


def test_f10_retirement_is_exact_per_generation_and_noop(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = _message_pile(node, workspace, "receipt", 10)
    store = node.store(workspace)
    applier = node.applier(workspace)
    first = run(applier.stage("first00000000000", raw))
    applied = run(applier.apply(first, retire=False))
    assert applied.status == "applied"
    assert store.get(first) == raw

    second = run(applier.stage("wrong00000000000", raw))
    noop = run(applier.apply(second))
    assert noop.status == "noop"
    assert noop.retired is True
    assert store.get(second) is None
    assert store.get(first) == raw

    # A cold applier can discharge the retained exact generation only by
    # proving its admitted candidate through the current root.
    replay = run(RepositoryApplier(workspace, store).apply(first))
    assert replay.status == "noop"
    assert replay.retired is True
    assert store.get(first) is None
    assert _reader(workspace, store).candidates().fact(item.fid) == item


def test_concurrent_appliers_rebase_without_retiring_the_stale_pile(
        tmp_path):
    seed = Node(str(tmp_path / "seed"))
    workspace = facts.auth.workspace.create(seed, "alice", ts=1)
    base = closed_subset(seed, workspace, all_fids(seed, workspace))
    first, first_raw = _message_pile(seed, workspace, "pile A", 10)
    second, second_raw = _message_pile(seed, workspace, "pile B", 11)

    store = FsStore(str(tmp_path / "shared"))
    bootstrap = RepositoryApplier(workspace, store)
    _, bootstrapped = _stage_apply(bootstrap, base)
    assert bootstrapped.status == "applied"

    worker_a = RepositoryApplier(workspace, store)
    worker_b = RepositoryApplier(workspace, store)
    source_a = run(worker_a.stage("worker0000000000", first_raw))
    source_b = run(worker_b.stage("worker0000000001", second_raw))
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
    assert store.get(source_b) is None
    assert store.get(source_a) == first_raw

    recovered = run(RepositoryApplier(
        workspace, store).apply(source_a))
    assert recovered.status == "noop"
    assert recovered.retired is True
    assert store.get(source_a) is None
    archive = _reader(workspace, store).archive()
    assert {first.fid, second.fid} <= set(archive.records)


def test_empty_closed_pile_retires_after_root_checked_noop(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    raw = encode_pile((), workspace=workspace)
    store = node.store(workspace)
    root = store.get("root")
    source, result = _stage_apply(
        node.applier(workspace), raw, member="empty0000000000")

    assert result.status == "noop"
    assert result.retired is True
    assert store.get(source) is None
    assert store.get("root") == root


def test_rootless_pile_retries_after_bootstrap_and_then_retires(tmp_path):
    seed = Node(str(tmp_path / "seed"))
    workspace = facts.auth.workspace.create(seed, "alice", ts=1)
    bootstrap = closed_subset(seed, workspace, all_fids(seed, workspace))

    store = FsStore(str(tmp_path / "rootless"))
    applier = RepositoryApplier(workspace, store)
    raw = encode_pile((), workspace=workspace)
    source = run(applier.stage("rootless00000000", raw))
    pending = run(applier.apply(source))
    assert pending.status == "rootless"
    assert pending.retired is False
    assert store.get("root") is None
    assert store.get(source) == raw

    _, bootstrapped = _stage_apply(
        applier, bootstrap, member="0000000000000000")
    assert bootstrapped.status == "applied"
    retried = run(RepositoryApplier(workspace, store).apply(source))

    assert store.get("root") is not None
    assert retried.status == "noop"
    assert retried.retired is True
    assert store.get(source) is None
    assert store.list("pile/") == []


def test_crash_after_apply_survives_a_later_root_advance(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    item, raw = _message_pile(
        node, workspace, "definite CAS", 10)
    later, later_raw = _message_pile(
        node, workspace, "later root", 11)
    store = node.store(workspace)
    applier = node.applier(workspace)
    source = run(applier.stage("applied000000000", raw))
    applied = run(applier.apply(source, retire=False))
    assert applied.status == "applied"
    assert store.get(source) == raw

    later_source, advanced = _stage_apply(
        RepositoryApplier(workspace, store),
        later_raw,
        member="later00000000000",
    )
    assert advanced.status == "applied"
    assert advanced.root != applied.root
    assert store.get(later_source) is None

    # Candidate retention is monotone. A cold replay after the later CAS
    # proves the first pile represented and retires only that generation.
    replay = run(RepositoryApplier(workspace, store).apply(source))
    assert replay.status == "noop"
    assert replay.retired is True
    assert store.get(source) is None
    reader = _reader(workspace, store)
    assert reader.candidates().fact(item.fid) == item
    assert reader.candidates().fact(later.fid) == later
