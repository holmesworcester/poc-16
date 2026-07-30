"""Authenticated retention and reconstruction of dormant fact candidates."""
import json
import os
from dataclasses import replace

import pytest

from core import (
    admission_proof,
    catalog,
    cmds,
    indexes,
    merkle_map,
    snapshot,
)
from core.candidate_archive import CandidateView, reconstruct
from core.close import close, encode_pile
from core.crypto import h
from core.fact import encode
from core.ingress import pile_source
from core.kernel import drain, resolve_deps
from core.node import Node
from core.publication import PublicationReceipt
import core.sync as sync_module
from core.worker import WorkerView
from facts.auth.signature import signature
from facts.content.message import message

from .util import add_member, all_fids, closed_subset, deliver, member_src


def _source(member, raw):
    return pile_source(member, raw, h(member.encode() + raw)[:32])


def _closed_with(node, workspace, facts, dependencies):
    new = {fact.fid: fact for fact in facts}

    def fact_of(fid):
        return new.get(fid) or node.candidate_of(workspace, fid)

    def deps_of(fid):
        if fid in dependencies:
            return dependencies[fid]
        fact = fact_of(fid)
        return resolve_deps(fact, node.idx(workspace)) or ()

    stream = close(facts, deps_of, fact_of)
    assert drain(stream, workspace).ok
    return encode_pile(stream, workspace=workspace)


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
    store = node.store(workspace)
    return CandidateView(
        store.get("root"), lambda oid: store.get("obj/" + oid))


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


def test_dormant_candidates_are_retained_paginated_and_cold_rebuilt(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    provider = member_src(node, workspace, bob)
    eviction = cmds.evict(node, workspace, bob)
    first_ts = node.candidate_of(workspace, eviction).ts + 1
    raw, dormant = _removed_member_messages(
        node, workspace, bob_secret, bob, provider, 11, first_ts)
    source = _source("hostile00000000", raw)
    node.store(workspace).put_if_absent(source, raw)

    # F10 covers every durable kernel Valid, not only current eligibility.
    # The old root has no FactRecord for this independently valid pile, so it
    # cannot authorize destructive retirement.
    with pytest.raises(ValueError, match="published ingress capability"):
        node._retire_published_ingress(
            workspace, source, raw, None)
    assert node.store(workspace).get(source) == raw

    node.turn(workspace)
    assert node.store(workspace).get(source) is None
    assert all(node.fact_of(workspace, fact.fid) is None for fact in dormant)
    assert all(
        node.candidate_of(workspace, fact.fid) == fact for fact in dormant)

    before_full = node.store(workspace).get("root")
    node.commit(workspace, reuse=False)
    assert node.store(workspace).get("root") == before_full

    live_fid = cmds.post(
        node, workspace, "general", "one eligible", ts=first_ts + 100)
    view = _root_view(node, workspace)
    for fact in dormant:
        record = view.fact_record(fact.fid)
        assert record["state"] == "dormant"
        assert record["fact_oid"] == h(encode(fact))
        assert view.fact(fact.fid) == fact
        view.verify(fact.fid)

    worker = WorkerView.from_root(
        node.store(workspace).get("root"),
        lambda oid: node.store(workspace).get("obj/" + oid),
    )
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

    expected_root = node.store(workspace).get("root")
    expected = reconstruct(
        expected_root,
        lambda oid: node.store(workspace).get("obj/" + oid),
    )
    assert set(expected.records) >= {fact.fid for fact in dormant}

    # SQLite is a rebuildable accelerator. The root, trees, proof DAGs, range
    # leaves, and dormant blobs alone reconstruct the same retained catalog.
    index_path = tmp_path / "node" / "ws" / f"{workspace}.idx.db"
    node.idx(workspace).close()
    node._idx.pop(workspace)
    os.unlink(index_path)
    node.rebuild(workspace)
    assert node.store(workspace).get("root") == expected_root
    assert all(
        node.candidate_of(workspace, fact.fid) == fact for fact in dormant)
    assert all(node.fact_of(workspace, fact.fid) is None for fact in dormant)


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
    workspace = cmds.create(node, "alice", ts=1)
    live = cmds.post(node, workspace, "general", "live record", ts=10)
    cmds.remove(node, workspace, live, ts=20)
    bob_secret, bob, _ = add_member(
        node, workspace, "bob", ts=30)
    provider = member_src(node, workspace, bob)
    eviction = cmds.evict(node, workspace, bob)
    first_ts = node.candidate_of(workspace, eviction).ts + 1
    raw, dormant_messages = _removed_member_messages(
        node, workspace, bob_secret, bob, provider, 1, first_ts)
    deliver(node, workspace, raw)
    node.turn(workspace)
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


def test_admission_proofs_are_raw_free_and_legacy_rows_are_not_blessed(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    marker = "raw-body-must-not-be-in-the-proof"
    fid = cmds.post(node, workspace, "general", marker, ts=10)
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

    # A locally retained pre-cut row with no kernel proof remains visible only
    # as distinguishable legacy data. Rebuild cannot infer admission from raw.
    secret, public = node.identity(workspace)
    legacy = message(workspace, public, "general", "proofless", 20)
    index = node.idx(workspace)
    index.execute(
        "INSERT INTO facts VALUES(?,?)", (legacy.fid, encode(legacy)))
    index.executemany(
        "INSERT INTO fact_index VALUES(?,?,?,?)",
        catalog.index_rows(legacy),
    )
    index.commit()
    root = store.get("root")
    assert node.candidate_of(workspace, legacy.fid) == legacy
    assert node.catalog(workspace).admitted(legacy.fid) is None

    node.rebuild(workspace)

    assert store.get("root") == root
    assert node.candidate_of(workspace, legacy.fid) == legacy
    assert node.catalog(workspace).admitted(legacy.fid) is None
    with pytest.raises(ValueError, match="missing FactRecord"):
        _root_view(node, workspace).fact_record(legacy.fid)


def test_admission_proof_traversal_enforces_every_budget_and_graph_guard(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    fid = cmds.post(node, workspace, "general", "bounded proof", ts=10)
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
    workspace = cmds.create(seed, "alice", ts=1)
    bob_secret, bob, _ = add_member(seed, workspace, "bob", ts=10)
    provider = member_src(seed, workspace, bob)
    eviction = cmds.evict(seed, workspace, bob) if dormant else None
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
    workspace = cmds.create(remote, "alice", ts=1)
    fid = cmds.post(
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
    workspace = cmds.create(node, "alice", ts=1)
    secret, public = node.identity(workspace)
    item = message(workspace, public, "general", "must be represented", 10)
    signed = signature(secret, public, item, item.ts)
    raw = _closed_with(node, workspace, (signed, item), {
        signed.fid: (),
        item.fid: (
            signed.fid, member_src(node, workspace, public)),
    })
    source = _source("compiler000000", raw)
    store = node.store(workspace)
    store.put_if_absent(source, raw)
    root = store.get("root")
    build = indexes.build
    cas = store.cas
    cas_calls = []

    def omit(*args, **kwargs):
        result = build(*args, **kwargs)
        return indexes.IndexBuild(
            result.seed,
            result.trees,
            result.represented - {item.fid},
        )

    def observed_cas(*args, **kwargs):
        cas_calls.append((args, kwargs))
        return cas(*args, **kwargs)

    monkeypatch.setattr(indexes, "build", omit)
    monkeypatch.setattr(store, "cas", observed_cas)

    assert node.turn(workspace) == []
    assert store.get("root") == root
    assert store.get(source) == raw
    assert cas_calls == []
    assert node.fact_of(workspace, item.fid) is None


def test_incremental_publication_does_not_enumerate_candidate_corpus(
        tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    monkeypatch.setattr(
        catalog.Catalog,
        "publication_ids",
        lambda *_args, **_kwargs: pytest.fail(
            "incremental publication enumerated all candidates"),
    )

    fid = cmds.post(
        node, workspace, "general", "point delta", ts=10)

    assert node.fact_of(workspace, fid) is not None


def test_incremental_publication_does_not_reensure_old_fact_bodies(
        tmp_path, monkeypatch):
    """A changed range inherits point residences from its pinned old root."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    for ts in range(2, 18):
        cmds.post(node, workspace, "general", f"old-{ts}", ts=ts)
    before = set(node.catalog(workspace).admitted_ids())
    old_objects = {
        "obj/" + h(encode(node.candidate_of(workspace, fid)))
        for fid in before
    }
    store = node.store(workspace)
    put_if_absent = store.put_if_absent
    creates = []

    def observed(key, raw):
        creates.append(key)
        return put_if_absent(key, raw)

    monkeypatch.setattr(store, "put_if_absent", observed)
    cmds.post(node, workspace, "general", "one delta", ts=20)

    after = set(node.catalog(workspace).admitted_ids())
    new_objects = {
        "obj/" + h(encode(node.candidate_of(workspace, fid)))
        for fid in after - before
    }
    assert old_objects.isdisjoint(creates)
    assert new_objects
    assert all(creates.count(key) == 1 for key in new_objects)


def test_exact_publication_receipt_binds_source_and_noop(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    secret, public = node.identity(workspace)
    item = message(workspace, public, "general", "receipt", 10)
    signed = signature(secret, public, item, item.ts)
    raw = _closed_with(node, workspace, (signed, item), {
        signed.fid: (),
        item.fid: (
            signed.fid, member_src(node, workspace, public)),
    })
    first = _source("first00000000000", raw)
    store = node.store(workspace)
    store.put_if_absent(first, raw)
    admission = node.admit_ingress(
        workspace, first, raw)

    receipt = node.commit_ingress(admission)
    assert receipt.outcome == "applied"

    wrong = _source("wrong00000000000", raw)
    store.put_if_absent(wrong, raw)
    with pytest.raises(ValueError, match="published ingress capability"):
        node._retire_published_ingress(
            workspace, wrong, raw, receipt)
    assert store.get(wrong) == raw
    node._retire_published_ingress(
        workspace, first, raw, receipt)
    assert store.get(first) is None

    admission = node.admit_ingress(
        workspace, wrong, raw)
    noop = node.commit_ingress(admission)
    assert noop.outcome == "noop"
    node._retire_published_ingress(
        workspace, wrong, raw, noop)
    assert store.get(wrong) is None


def test_caller_constructed_publication_receipt_cannot_retire_ingress(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    raw = encode_pile((), workspace=workspace)
    source = _source("forged0000000000", raw)
    store = node.store(workspace)
    store.put_if_absent(source, raw)

    forged = PublicationReceipt(
        workspace=workspace,
        root=store.get("root"),
        admitted=(),
        outcome="noop",
        source=source,
        payload=h(raw),
        generation=source.split("/")[2],
        issuer=object(),
    )
    with pytest.raises(ValueError, match="published ingress capability"):
        node._retire_published_ingress(
            workspace, source, raw, forged)
    assert store.get(source) == raw

    genuine = node.commit_ingress(
        node.admit_ingress(workspace, source, raw))
    # Copying all fields, including the hidden issuer, still does not mint a
    # second capability: only the exact object registered by commit_ingress
    # crosses the destructive door.
    copied = replace(genuine)
    with pytest.raises(ValueError, match="published ingress capability"):
        node._retire_published_ingress(
            workspace, source, raw, copied)
    assert store.get(source) == raw

    node._retire_published_ingress(
        workspace, source, raw, genuine)
    assert store.get(source) is None


def test_bound_admissions_cannot_cross_nodes_or_piles(
        tmp_path, monkeypatch):
    seed = Node(str(tmp_path / "seed"))
    workspace = cmds.create(seed, "alice", ts=1)
    secret, public = seed.identity(workspace)
    provider = member_src(seed, workspace, public)
    base = closed_subset(seed, workspace, all_fids(seed, workspace))
    raws = []
    for text, ts in (("pile A", 10), ("pile B", 11)):
        item = message(workspace, public, "general", text, ts)
        signed = signature(secret, public, item, item.ts)
        raws.append(_closed_with(seed, workspace, (signed, item), {
            signed.fid: (),
            item.fid: (signed.fid, provider),
        }))

    nodes, admissions, sources = [], [], []
    for ordinal, raw in enumerate(raws):
        node = Node(str(tmp_path / f"worker-{ordinal}"))
        node.add_workspace(workspace, "shared", [])
        deliver(node, workspace, base)
        node.turn(workspace)
        source = _source(f"worker{ordinal:010d}", raw)
        node.store(workspace).put_if_absent(source, raw)
        nodes.append(node)
        sources.append(source)
        admissions.append(node.admit_ingress(workspace, source, raw))

    first, second = nodes
    first_store, second_store = (
        first.store(workspace), second.store(workspace))
    first_root = first_store.get("root")
    first_objects = tuple(first_store.list("obj/"))
    cas = first_store.cas
    cas_calls = []

    def observed_cas(*args, **kwargs):
        cas_calls.append((args, kwargs))
        return cas(*args, **kwargs)

    monkeypatch.setattr(first_store, "cas", observed_cas)
    with pytest.raises(ValueError, match="bound ingress issuer"):
        first.commit_ingress(admissions[1])

    assert cas_calls == []
    assert first_store.get("root") == first_root
    assert tuple(first_store.list("obj/")) == first_objects
    assert first_store.get(sources[0]) == raws[0]
    assert second_store.get(sources[1]) == raws[1]

    first_receipt = first.commit_ingress(admissions[0])
    first._retire_published_ingress(
        workspace, sources[0], raws[0], first_receipt)
    assert first_store.get(sources[0]) is None
    assert second_store.get(sources[1]) == raws[1]


def test_empty_closed_pile_retires_under_typed_noop_receipt(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    raw = encode_pile((), workspace=workspace)
    source = _source("empty0000000000", raw)
    store = node.store(workspace)
    root = store.get("root")
    store.put_if_absent(source, raw)

    assert node.turn(workspace) == []

    assert store.get(source) is None
    assert store.get("root") == root


def test_applied_receipt_survives_a_later_root_advance(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    secret, public = node.identity(workspace)
    item = message(workspace, public, "general", "definite CAS", 10)
    signed = signature(secret, public, item, item.ts)
    raw = _closed_with(node, workspace, (signed, item), {
        signed.fid: (),
        item.fid: (
            signed.fid, member_src(node, workspace, public)),
    })
    source = _source("applied000000000", raw)
    store = node.store(workspace)
    store.put_if_absent(source, raw)
    receipt = node.commit_ingress(
        node.admit_ingress(workspace, source, raw))
    assert receipt.outcome == "applied"

    # Candidate retention is monotone. A second real publication cannot undo
    # the definite Applied event that discharged the first pile obligation.
    later = message(workspace, public, "general", "later root", 11)
    later_signature = signature(secret, public, later, later.ts)
    later_raw = _closed_with(node, workspace, (later_signature, later), {
        later_signature.fid: (),
        later.fid: (
            later_signature.fid, member_src(node, workspace, public)),
    })
    later_source = _source("later00000000000", later_raw)
    store.put_if_absent(later_source, later_raw)
    later_receipt = node.commit_ingress(
        node.admit_ingress(workspace, later_source, later_raw))
    assert later_receipt.root != receipt.root
    node._retire_published_ingress(
        workspace, source, raw, receipt)
    assert store.get(source) is None
    node._retire_published_ingress(
        workspace, later_source, later_raw, later_receipt)
