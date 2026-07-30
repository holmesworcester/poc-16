"""The one v7 cut and the current four-map snapshot contract."""
import base64
import json
from pathlib import Path

import pytest

import facts

from core import indexes, legacy_v7, snapshot
from core.candidate_archive import reconstruct
from core.close import encode_pile
from core.crypto import h
from core.fact import canon
from core.kernel import resolve_deps
from core.node import Node
from core.shape import fid_of

from .util import all_fids


V7_FIXTURE = Path(__file__).with_name("fixtures") / "v7_snapshot.json"


def _emit(store):
    def emit(raw):
        oid = h(raw)
        store.put_if_absent("obj/" + oid, raw)
        return oid
    return emit


def _legacy_map(rows, seed, emit):
    """Tiny test-only encoder for the removed canonical v7 Cartesian tree."""
    ordered = sorted(rows)

    def build(items):
        if not items:
            return "", 0, 0
        pivot = min(
            range(len(items)),
            key=lambda at: (
                h(canon([legacy_v7.FORMAT, seed, items[at][0]])),
                items[at][0],
            ),
        )
        key, value = items[pivot]
        left, left_count, left_depth = build(items[:pivot])
        right, right_count, right_depth = build(items[pivot + 1:])
        raw = canon({
            "count": 1 + left_count + right_count,
            "depth": 1 + max(left_depth, right_depth),
            "format": legacy_v7.FORMAT,
            "key": key,
            "left": left,
            "priority": h(canon([legacy_v7.FORMAT, seed, key])),
            "right": right,
            "value": value,
        })
        return emit(raw), 1 + left_count + right_count, \
            1 + max(left_depth, right_depth)

    return build(ordered)[0]


def _outside(members, deps):
    inside = {fact.fid for fact in members}
    seen, stack = set(), list(inside)
    while stack:
        fid = stack.pop()
        if fid in seen:
            continue
        seen.add(fid)
        stack.extend(deps(fid))
    return seen - inside


def test_root_atomically_names_four_uniform_bounded_maps(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.content.message.post(node, workspace, "general", "indexed", ts=10)
    raw = node.store(workspace).get("root")
    body = json.loads(raw)
    committed = snapshot.decode_root(raw)

    assert set(body) == {"anchor", "layout_seed", "maps", "stamp"}
    assert body["stamp"] == snapshot.LAYOUT
    assert set(committed.maps) == set(snapshot.MAP_NAMES)
    assert all(
        set(value) == {"root", "count", "depth"}
        for value in committed.maps.values())
    assert "action_etag" not in body and "manifest" not in body


def test_incremental_and_full_compilation_are_byte_identical(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    for ordinal in range(30):
        facts.content.message.post(
            node, workspace, "general", f"message-{ordinal}",
            ts=10 + ordinal)
    expected = node.store(workspace).get("root")
    node.admission(workspace).publish(reuse=False)
    assert node.store(workspace).get("root") == expected


def test_unknown_stamp_can_republish_only_the_exact_known_envelope(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    honest = node.store(workspace).get("root")
    body = json.loads(honest)

    foreign_stamp = canon({**body, "stamp": "future-layout"})
    node.store(workspace)._replace("root", foreign_stamp)
    node.rebuild(workspace)
    assert node.store(workspace).get("root") == honest

    forged = canon({
        **body,
        "stamp": "future-layout",
        "maps": {
            **body["maps"],
            snapshot.FACT_ORDER: {
                **body["maps"][snapshot.FACT_ORDER],
                "root": "0" * 64,
            },
        },
    })
    node.store(workspace)._replace("root", forged)
    with pytest.raises(ValueError, match="does not match"):
        node.rebuild(workspace)
    assert node.store(workspace).get("root") == forged


def test_real_v7_pile_leaves_cut_over_through_legacy_decoder_only(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    cuts, timestamp = 0, 10
    while cuts < 1:
        fid = facts.content.message.post(
            node, workspace, "general", f"legacy-{timestamp}",
            ts=timestamp)
        cuts += int(fid[:8], 16) % legacy_v7.CUT == 0
        timestamp += 1
    facts.content.message.post(node, workspace, "general", "after-cut", ts=timestamp)

    store = node.store(workspace)
    facts = {
        fid: node.fact_of(workspace, fid)
        for fid in all_fids(node, workspace)
    }
    keys = sorted(fact.key for fact in facts.values())
    cuts = legacy_v7.stable_cut_positions(
        [fid_of(address) for address in keys])
    chunks = [
        keys[start:stop]
        for start, stop in zip([0] + cuts, cuts + [len(keys)])
        if stop > start
    ]
    emit = _emit(store)

    def deps(fid):
        return resolve_deps(facts[fid], node.idx(workspace)) or ()

    entries = []
    for addresses in chunks:
        members = [facts[fid_of(address)] for address in addresses]
        leaf = emit(encode_pile(members, workspace=workspace))
        outside = sorted(facts[fid].key for fid in _outside(members, deps))
        closure = emit(canon({"keys": outside})) if outside else ""
        entries.append((addresses[0], [leaf, closure]))
    old_manifest = _legacy_map(
        entries, legacy_v7.RANGE_SEED, emit)
    empty = {"root": "", "count": 0, "depth": 0}
    old_root = canon({
        "action_etag": h(canon(["legacy-actions", []])),
        "anchor": workspace,
        "layout_seed": snapshot.layout_seed(workspace),
        "manifest": old_manifest,
        "stamp": legacy_v7.LAYOUT,
        "trees": {
            name: dict(empty)
            for name in legacy_v7.TREE_NAMES
        },
    })
    store._replace("root", old_root)

    sibling = next(entry[1][1] for entry in entries if entry[1][1])
    sibling_raw = store.get("obj/" + sibling)
    store._delete("obj/" + sibling)
    with pytest.raises(ValueError, match="object integrity"):
        node.rebuild(workspace)
    store.put_if_absent("obj/" + sibling, sibling_raw)

    node.rebuild(workspace)
    current = store.get("root")
    committed = snapshot.decode_root(current)
    assert committed.anchor == workspace
    rebuilt = reconstruct(
        current, lambda oid: store.get("obj/" + oid))
    assert set(rebuilt.facts) == set(facts)
    assert all(node.candidate_of(workspace, fid) == fact
               for fid, fact in facts.items())


@pytest.mark.parametrize("local_catalog", (False, True))
def test_empty_v7_manifest_cannot_supply_or_replace_the_anchor(
        tmp_path, local_catalog):
    node = Node(str(tmp_path / "node"))
    if local_catalog:
        workspace = facts.auth.workspace.create(node, "alice", ts=1)
    else:
        workspace = "a" * 64
        node.add_workspace(workspace, "empty-v7", peers=[])
    empty = {"root": "", "count": 0, "depth": 0}
    old_root = canon({
        "action_etag": h(canon(["legacy-actions", []])),
        "anchor": workspace,
        "layout_seed": snapshot.layout_seed(workspace),
        "manifest": "",
        "stamp": legacy_v7.LAYOUT,
        "trees": {
            name: dict(empty)
            for name in legacy_v7.TREE_NAMES
        },
    })
    node.store(workspace)._replace("root", old_root)

    with pytest.raises(ValueError, match="store fact set"):
        node.rebuild(workspace)

    assert node.store(workspace).get("root") == old_root


@pytest.mark.parametrize("local_catalog", (False, True))
def test_present_empty_root_is_never_treated_as_rootless(
        tmp_path, local_catalog):
    node = Node(str(tmp_path / "node"))
    if local_catalog:
        workspace = facts.auth.workspace.create(node, "alice", ts=1)
    else:
        workspace = "b" * 64
        node.add_workspace(workspace, "empty-root", peers=[])
    store = node.store(workspace)
    store._replace("root", b"")

    with pytest.raises(ValueError, match="unreadable root does not match"):
        node.rebuild(workspace)

    assert store.get("root") == b""


def test_frozen_production_v7_snapshot_cuts_over_to_candidate_archive(
        tmp_path):
    """The decoder must agree with bytes emitted by the removed v7 code.

    This fixture was generated by production commit 13986b9, rather than by
    the test-only encoder above, so an encoder/decoder bug cannot agree with
    itself and pass.
    """
    fixture = json.loads(V7_FIXTURE.read_bytes())
    assert fixture["source_commit"] \
        == "13986b9ef50c28622ff895927ce4c3d84be644cf"
    workspace = fixture["workspace"]
    node = Node(str(tmp_path / "node"))
    node.add_workspace(workspace, "frozen-v7", peers=[])
    store = node.store(workspace)
    for oid, encoded in fixture["objects"].items():
        raw = base64.b64decode(encoded, validate=True)
        assert h(raw) == oid
        store.put_if_absent("obj/" + oid, raw)
    old_root = base64.b64decode(fixture["root"], validate=True)
    decoded = legacy_v7.decode_root(old_root)
    assert decoded.anchor == workspace
    store._replace("root", old_root)

    node.rebuild(workspace)

    current = store.get("root")
    rebuilt = reconstruct(
        current, lambda oid: store.get("obj/" + oid))
    assert snapshot.decode_root(current).anchor == workspace
    assert sorted(rebuilt.facts) == fixture["fids"]
    assert set(all_fids(node, workspace)) == set(fixture["fids"])
