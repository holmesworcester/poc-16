"""Differential tests for the authenticated generic candidate routes."""
import random

import facts

from core import catalog, cmds, indexes, merkle_map, snapshot
from core.crypto import h, keypair
from core.fact import encode
from core.kernel import offer_src
from core.node import Node
from core.shape import fid_of
from core.suppression import TARGET
from core.worker import WorkerView
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature

from .util import add_member, inject_device_claim, send_bytes


def _view(node, workspace, fetched=None):
    store = node.store(workspace)

    def fetch(oid):
        if fetched is not None:
            fetched.append(oid)
        return store.get("obj/" + oid)

    return WorkerView.from_root(store.get("root"), fetch)


def _postings(view, kind, k0=None, k1=None, limit=17):
    rows, cursor, fetches = [], None, 0
    while True:
        page = view.postings(
            kind, k0, k1, after=cursor, limit=limit)
        rows.extend(page.rows)
        fetches += page.pages_read
        if page.cursor is None:
            return tuple(rows), fetches
        cursor = page.cursor


def _catalog_rows(node, workspace, kind, k0=None, k1=None):
    return tuple(
        (rank, fact.fid)
        for rank, fact in node.catalog(workspace).indexed(
            kind, k0, k1)
    )


def _canonical_root(node, workspace):
    """Reference full build independent of every incremental index path."""
    index = node.idx(workspace)
    seed, trees = indexes.build(
        workspace, index, lambda raw: h(raw),
    )
    order = snapshot.build_fact_order(
        (
            (fact.key, h(encode(fact)))
            for fact in (
                node.fact_of(workspace, fid_of(address))
                for address in node.keys(workspace)
            )
            if fact is not None
        ),
        seed,
        lambda raw: h(raw),
    )
    return snapshot.encode_root(
        workspace,
        {snapshot.FACT_ORDER: order, **trees},
        seed=seed,
    )


def _catalog_scopes(node, workspace, fid):
    fact = node.fact_of(workspace, fid)
    index = node.idx(workspace)

    def edges_of(source):
        return dict(index.execute(
            "SELECT role, dst FROM edges WHERE src=? ORDER BY role",
            (source,)))

    selectors = set(facts.fact_scopes(fact))
    liveness = set(facts.authority_scopes(
        fact, edges_of,
        lambda source: node.candidate_of(workspace, source),
    )) - selectors
    return selectors | liveness


def test_type_key_ref_and_offer_ranges_match_catalog_without_manifest_reads(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    message = cmds.post(
        node, workspace, "general", "indexed", ts=10)
    action = cmds.remove(node, workspace, message, ts=20)
    target = node.candidate_of(workspace, message)
    public = node.identity_id(workspace)
    fetched = []
    view = _view(node, workspace, fetched)

    cases = (
        (catalog.TYPE_INDEX, "msg", ""),
        (catalog.KEY_INDEX, target.key, ""),
        (catalog.REF_INDEX, TARGET, message),
        ("author", message, public),
    )
    depth = view.trees[indexes.FACT]["depth"]
    for kind, k0, k1 in cases:
        rows, _ = _postings(view, kind, k0, k1)
        assert tuple((row.rank, row.fid) for row in rows) \
            == _catalog_rows(node, workspace, kind, k0, k1)
        assert len(rows) >= 1
        assert view.postings(kind, k0, k1).pages_read \
            <= 2 * depth + len(rows) + 1

    assert view.fact_location(message) == target.key
    assert view.fact_location(action) \
        == node.candidate_of(workspace, action).key
    assert snapshot.decode_root(
        node.store(workspace).get("root")
    ).maps[snapshot.FACT_ORDER]["root"] not in fetched


def test_losing_then_winning_offer_rewires_reverse_dependency_posting(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    secret, public = node.identity(workspace)
    message = cmds.post(
        node, workspace, "general", "authority target", ts=10)
    target = node.fact_of(workspace, message)
    original = offer_src(
        node.idx(workspace), "author", message, public)
    lower = higher = None
    for timestamp in range(11, 10_000):
        candidate = signature(secret, public, target, timestamp)
        lower = candidate if lower is None and candidate.fid < original \
            else lower
        higher = candidate if higher is None and candidate.fid > original \
            else higher
        if lower is not None and higher is not None:
            break
    assert lower is not None and higher is not None

    node.ingest_new(workspace, [higher], {higher.fid: []})
    losing_view = _view(node, workspace)
    losing, _ = _postings(
        losing_view, "author", message, public)
    assert [(row.rank, row.fid) for row in losing] \
        == list(_catalog_rows(
            node, workspace, "author", message, public))
    assert offer_src(
        node.idx(workspace), "author", message, public) == original
    assert node.store(workspace).get("root") \
        == _canonical_root(node, workspace)

    node.ingest_new(workspace, [lower], {lower.fid: []})
    winning_view = _view(node, workspace)
    winning, _ = _postings(
        winning_view, "author", message, public)
    assert [(row.rank, row.fid) for row in winning] \
        == list(_catalog_rows(
            node, workspace, "author", message, public))
    assert winning[0].fid == lower.fid
    assert offer_src(
        node.idx(workspace), "author", message, public) == lower.fid

    old_dependents, _ = _postings(
        winning_view, indexes.DEPENDENCY_INDEX, original)
    new_dependents, _ = _postings(
        winning_view, indexes.DEPENDENCY_INDEX, lower.fid)
    assert message not in {row.fid for row in old_dependents}
    assert message in {row.fid for row in new_dependents}
    assert {row.fid for row in new_dependents} == {
        source for (source,) in node.idx(workspace).execute(
            "SELECT src FROM edges WHERE dst=? ORDER BY src",
            (lower.fid,))
    }
    assert node.store(workspace).get("root") \
        == _canonical_root(node, workspace)

    before = tuple((row.rank, row.fid) for row in winning)
    cmds.post(node, workspace, "general", "unrelated", ts=30)
    after, _ = _postings(
        _view(node, workspace), "author", message, public)
    assert tuple((row.rank, row.fid) for row in after) == before
    assert node.store(workspace).get("root") \
        == _canonical_root(node, workspace)


def test_scope_route_finds_suppression_cascade_and_next_active_offer(
        tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    founder_secret, founder = node.identity(workspace)
    first = send_bytes(
        node, workspace, "same-a.bin", b"same payload" * 2048, ts=20)
    first_fact = node.fact_of(workspace, first)
    bob_secret, bob, _ = add_member(
        node, workspace, "bob", ts=30)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    second = send_bytes(
        node, workspace, "same-b.bin", b"same payload" * 2048, ts=40)
    second_fact = node.fact_of(workspace, second)
    assert first_fact.body["root"] == second_fact.body["root"]
    root = first_fact.body["root"]

    before = _view(node, workspace)
    candidates, _ = _postings(before, "file", root)
    expected = sorted(_catalog_rows(node, workspace, "file", root))
    assert sorted((row.rank, row.fid) for row in candidates) == expected
    winner = min(candidates, key=lambda row: (row.rank, row.fid)).fid

    node.keychain.add_identity(founder_secret)
    node.bind_identity(workspace, founder)
    action = cmds.remove(node, workspace, winner, ts=100)
    after = _view(node, workspace)
    sid = indexes.fact_key(winner)
    assert after.suppression(sid) == {
        "state": "active", "action": action}

    scoped, _ = _postings(after, indexes.SCOPE_INDEX, sid, "")
    expected_scoped = {
        fid for (fid,) in node.idx(workspace).execute(
            "SELECT fid FROM proofs")
        if sid in _catalog_scopes(node, workspace, fid)
    }
    assert {row.fid for row in scoped} == expected_scoped
    assert winner in expected_scoped
    assert any(
        node.fact_of(workspace, fid).t == "chunk"
        for fid in expected_scoped)

    active = sorted(
        (row.rank, row.fid)
        for row in candidates if after.fact_active(row.fid)
    )
    selected = node.select_ranked(
        workspace, "file", root, include_suppressed=False)
    assert active
    assert active[0][1] != winner
    assert active == sorted(
        (rank, fact.fid) for rank, fact in selected)

    dependents, _ = _postings(
        after, indexes.DEPENDENCY_INDEX, winner)
    assert {row.fid for row in dependents} == {
        source for (source,) in node.idx(workspace).execute(
            "SELECT src FROM edges WHERE dst=? ORDER BY src",
            (winner,))
    }
    assert node.store(workspace).get("root") \
        == _canonical_root(node, workspace)


def test_authority_winner_cache_still_saves_conflict_range_fetches(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    secret, public = node.identity(workspace)
    message = cmds.post(
        node, workspace, "general", "many signatures", ts=10)
    target = node.fact_of(workspace, message)
    duplicates = [
        signature(secret, public, target, timestamp)
        for timestamp in range(11, 52)
    ]
    node.ingest_new(
        workspace, duplicates,
        {fact.fid: [] for fact in duplicates})
    view = _view(node, workspace)

    candidates, _ = _postings(
        view, "author", message, public, limit=64)
    authority = view._reader(indexes.AUTHORITY)
    winner = authority.get(
        indexes.need_key("author", message, public))
    assert len(candidates) == len(duplicates) + 1
    assert winner["fid"] == min(
        candidates, key=lambda row: (row.rank, row.fid)).fid
    assert authority.pages_read <= view.trees[indexes.AUTHORITY]["depth"]
    candidate_page = view.postings(
        "author", message, public, limit=64)
    assert candidate_page.pages_read \
        <= 2 * view.trees[indexes.FACT]["depth"] + len(candidates) + 1
    assert candidate_page.pages_read > authority.pages_read


def test_transitive_liveness_postings_follow_same_rank_provider_rewire(
        tmp_path):
    """A grandchild's direct edges stay fixed while an ancestor winner moves."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    cmds.bind_device(node, workspace, "primary")

    device_secrets = []
    for label in ("sibling-a", "sibling-b"):
        secret, public = keypair()
        node.keychain.add_identity(secret)
        cmds.grant_device(node, workspace, founder, public, label)
        device_secrets.append((secret, public))

    target_secret, target = keypair()
    node.keychain.add_identity(target_secret)
    proposed = [
        (
            secret,
            public,
            device_invite(
                workspace, public, founder, target,
                f"target-{ordinal}", 100 + ordinal),
        )
        for ordinal, (secret, public) in enumerate(device_secrets)
    ]
    high = max(proposed, key=lambda row: row[2].fid)
    low = min(proposed, key=lambda row: row[2].fid)
    high_claim = inject_device_claim(
        node, workspace, high[0], high[1], founder, target,
        high[2].body["label"], high[2].ts)
    assert offer_src(
        node.idx(workspace), "device_key", target) == high_claim.fid

    child_secret, child = keypair()
    node.keychain.add_identity(child_secret)
    child_claim = inject_device_claim(
        node, workspace, target_secret, target, founder, child,
        "child", 200)
    _, grandchild = keypair()
    grandchild_claim = inject_device_claim(
        node, workspace, child_secret, child, founder, grandchild,
        "grandchild", 201)
    before = _view(node, workspace).fact_record(grandchild_claim.fid)

    low_claim = inject_device_claim(
        node, workspace, low[0], low[1], founder, target,
        low[2].body["label"], low[2].ts)
    assert offer_src(
        node.idx(workspace), "device_key", target) == low_claim.fid
    after_view = _view(node, workspace)
    after = after_view.fact_record(grandchild_claim.fid)

    assert before["dependencies"] == after["dependencies"]
    assert before["rank"] == after["rank"]
    assert before["liveness"] != after["liveness"]
    old_sid = indexes.fact_key(high_claim.fid)
    new_sid = indexes.fact_key(low_claim.fid)
    assert old_sid in before["liveness"] and old_sid not in after["liveness"]
    assert new_sid not in before["liveness"] and new_sid in after["liveness"]
    old_rows, _ = _postings(
        after_view, indexes.SCOPE_INDEX, old_sid, "")
    new_rows, _ = _postings(
        after_view, indexes.SCOPE_INDEX, new_sid, "")
    assert grandchild_claim.fid not in {row.fid for row in old_rows}
    assert grandchild_claim.fid in {row.fid for row in new_rows}
    assert child_claim.fid in {row.fid for row in new_rows}
    assert node.store(workspace).get("root") \
        == _canonical_root(node, workspace)


def test_seeded_suppression_histories_keep_incremental_and_full_roots_equal(
        tmp_path):
    for seed in range(3):
        rng = random.Random(seed)
        node = Node(str(tmp_path / f"node-{seed}"))
        workspace = cmds.create(node, f"alice-{seed}", ts=1)
        live = []
        for ordinal in range(8):
            live.append(cmds.post(
                node, workspace, "general",
                f"seed-{seed}-{ordinal}", ts=10 + ordinal))
            if len(live) > 2 and rng.randrange(3) == 0:
                victim = live.pop(rng.randrange(len(live)))
                cmds.remove(
                    node, workspace, victim,
                    ts=100 + ordinal)
            assert node.store(workspace).get("root") \
                == _canonical_root(node, workspace)
