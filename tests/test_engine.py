"""Acceptance laws for the one sans-I/O tree engine."""
import ast
import json
import pathlib
import random
from dataclasses import replace

import pytest

from core import hoist, layout, shape, treap, tree
from core import cmds
from core.crypto import h
from core.fact import Fact, canon
from facts.content.message import message
from core.kernel import Scratchpad, resolve_deps
from core.node import Node

from .util import author_msg, closed_subset, deliver


class Driver:
    def __init__(self):
        self.objects = {}
        self.reads = []
        self.writes = []

    def emit(self, raw):
        oid = h(raw)
        self.objects.setdefault(oid, raw)
        self.writes.append(oid)
        return oid

    def fetch(self, oid):
        self.reads.append(oid)
        return self.objects[oid]


@pytest.fixture
def engine_world(monkeypatch):
    monkeypatch.setattr(shape, "CUT", 4)
    monkeypatch.setattr(shape, "COLD_CUT", None)
    facts = [Fact("sample", ts, [], {"ordinal": ts}) for ts in range(320)]
    by_fid = {fact.fid: fact for fact in facts}
    keys = sorted(fact.key for fact in facts)
    return keys, by_fid


def build(keys, by_fid, packing, driver):
    return tree.build(
        keys, shape.FACT, packing, by_fid.__getitem__,
        lambda fid: (), driver.emit,
    )


def cold(view, anchor="workspace", globals_=frozenset()):
    return tree.decode_root(
        tree.encode_root(tree.Root(view, anchor, globals_))).view


def leaf_ranges(view, driver):
    return list(tree.leaf_ranges(view, driver.fetch))


def internal_boundary(keys):
    return next(
        key for key in keys[1:-1]
        if shape.boundary(shape.fid_of(key))
    )


# ---- golden gates: the extraction changes nothing ---------------------------

def test_binary_packing_reproduces_treap_bytes(engine_world):
    keys, by_fid = engine_world
    expected, expected_objects = treap.build(
        keys, by_fid.__getitem__, lambda fid: ())
    driver = Driver()

    actual = build(keys, by_fid, tree.BINARY, driver)

    assert actual.oid == expected["hash"]
    assert driver.objects == expected_objects


def test_flat_packing_reproduces_layout_bytes(engine_world):
    keys, by_fid = engine_world
    anchor, globals_ = "workspace", frozenset({("removed", "member")})
    expected, expected_objects = layout.layout(
        keys, by_fid.__getitem__, lambda fid: (),
        anchor, globals_, None,
    )
    driver = Driver()
    view = build(keys, by_fid, tree.FLAT, driver)

    actual = tree.encode_root(tree.Root(view, anchor, globals_))

    assert actual == expected
    assert {"obj/" + oid: raw for oid, raw in driver.objects.items()} \
        == expected_objects


def test_leaf_sets_identical_across_packings(engine_world):
    keys, by_fid = engine_world
    partitions = []
    for packing in (tree.BINARY, tree.FLAT, tree.fat(8)):
        driver = Driver()
        view = build(keys, by_fid, packing, driver)
        partitions.append([
            tuple(tree.range_keys(leaf, lo, hi, shape.FACT, driver.fetch))
            for lo, hi, leaf in leaf_ranges(view, driver)
        ])

    assert partitions[0] == partitions[1] == partitions[2]


def test_fat_root_is_self_describing_and_shallow(engine_world):
    keys, by_fid = engine_world
    driver = Driver()
    root = build(keys, by_fid, tree.fat(8), driver)
    encoded = tree.encode_root(tree.Root(
        root, "workspace", frozenset({("removed", "member")})))

    decoded = tree.decode_root(encoded)
    wire = json.loads(encoded)

    assert decoded.anchor == "workspace"
    assert decoded.globals_ == frozenset({("removed", "member")})
    assert "tree" in wire and "fences" not in wire
    assert all({"f", "o"} <= set(child)
               for child in wire["tree"]["c"])
    assert decoded.view.config == tree.config(tree.fat(8), shape.FACT)
    assert decoded.view.level <= 3
    assert tree.leaf_keys(decoded.view, driver.fetch) == keys

    wire["tree"]["c"][0]["f"] = "forged"
    with pytest.raises(ValueError, match="tree"):
        tree.decode_root(canon(wire))


def test_tree_config_roll_forces_a_new_root_format(tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    before = tree.decode_root(node.store(workspace).get("root")).view

    monkeypatch.setattr(shape, "CUT", shape.CUT * 2)
    cmds.post(node, workspace, "general", "new layout")
    after = tree.decode_root(node.store(workspace).get("root")).view

    assert before.config != after.config
    assert after.config == tree.config(tree.FAT, shape.FACT)


def test_leaf_fetch_checks_object_and_range_summaries(engine_world):
    keys, by_fid = engine_world
    driver = Driver()
    root = cold(build(keys, by_fid, tree.fat(8), driver))
    lo, hi, leaf = leaf_ranges(root, driver)[0]
    raw = driver.objects[leaf.oid]

    driver.objects[leaf.oid] = raw + b" "
    with pytest.raises(ValueError, match="leaf integrity"):
        tree.range_keys(leaf, lo, hi, shape.FACT, driver.fetch)

    driver.objects[leaf.oid] = raw
    with pytest.raises(ValueError, match="leaf summary"):
        tree.range_keys(
            replace(leaf, fp=h(b"forged")), lo, hi,
            shape.FACT, driver.fetch,
        )


def test_fold_and_merge_reject_stale_tree_config(engine_world, monkeypatch):
    keys, by_fid = engine_world
    driver = Driver()
    old = cold(build(keys, by_fid, tree.fat(8), driver))

    monkeypatch.setattr(shape, "CUT", 8)
    with pytest.raises(ValueError, match="tree config"):
        tree.fold(
            old, (), shape.FACT, tree.fat(8), by_fid.__getitem__,
            lambda fid: (), driver.fetch, driver.emit,
        )
    with pytest.raises(ValueError, match="tree config"):
        tree.merge(
            old, old, shape.FACT, tree.fat(8),
            driver.fetch, driver.emit,
        )


# ---- fold laws ---------------------------------------------------------------

@pytest.mark.parametrize("packing", [tree.BINARY, tree.FLAT, tree.fat(8)])
def test_fold_empty_is_identity(engine_world, packing):
    keys, by_fid = engine_world
    driver = Driver()
    view = cold(build(keys, by_fid, packing, driver))
    driver.reads.clear()
    driver.writes.clear()

    assert tree.fold(
        view, (), shape.FACT, packing, by_fid.__getitem__,
        lambda fid: (), driver.fetch, driver.emit,
    ) is view
    assert driver.reads == driver.writes == []


@pytest.mark.parametrize(
    "packing", [tree.BINARY, tree.FLAT, tree.fat(2), tree.fat(8)])
def test_fold_any_batching_equals_build(engine_world, packing):
    keys, by_fid = engine_world
    shuffled = keys[:]
    random.Random(16).shuffle(shuffled)
    batches = (shuffled[:80], shuffled[80:190], shuffled[190:])
    driver = Driver()
    view = build(batches[0], by_fid, packing, driver)

    for batch in batches[1:]:
        view = tree.fold(
            cold(view), batch, shape.FACT, packing, by_fid.__getitem__,
            lambda fid: (), driver.fetch, driver.emit,
        )
    expected = build(keys, by_fid, packing, driver)

    actual_root = tree.encode_root(tree.Root(view, "workspace", frozenset()))
    expected_root = tree.encode_root(tree.Root(
        expected, "workspace", frozenset()))
    assert actual_root == expected_root


def test_flat_fold_promotes_a_boundary_terminated_tail(engine_world):
    keys, by_fid = engine_world
    split = next(
        index for index in range(1, len(keys))
        if shape.boundary(shape.fid_of(keys[index]))
        and not shape.boundary(shape.fid_of(keys[index - 1]))
    )
    driver = Driver()
    before = build(keys[:split], by_fid, tree.FLAT, driver)

    actual = tree.fold(
        before, [keys[split]], shape.FACT, tree.FLAT,
        by_fid.__getitem__, lambda fid: (), driver.fetch, driver.emit,
    )
    expected = build(keys[:split + 1], by_fid, tree.FLAT, driver)

    assert tree.encode_root(tree.Root(actual, "workspace", frozenset())) \
        == tree.encode_root(tree.Root(
            expected, "workspace", frozenset()))


def test_binary_fold_promotes_the_former_tail_boundary(monkeypatch):
    monkeypatch.setattr(shape, "CUT", 4)
    facts = [
        Fact("sample", ts, [], {"c": 4, "i": ts})
        for ts in range(90)
    ]
    by_fid = {fact.fid: fact for fact in facts}
    keys = sorted(fact.key for fact in facts)
    base = [
        keys[index]
        for index in (1, 11, 13, 15, 23, 42, 45, 49,
                      52, 58, 61, 66, 73, 85)
    ]
    added = keys[86]
    driver = Driver()
    before = build(base, by_fid, tree.BINARY, driver)

    actual = tree.fold(
        before, [added], shape.FACT, tree.BINARY,
        by_fid.__getitem__, lambda fid: (),
        driver.fetch, driver.emit,
    )
    expected = build(base + [added], by_fid, tree.BINARY, driver)

    assert shape.boundary(shape.fid_of(before.sep))
    assert not shape.boundary(shape.fid_of(added))
    assert actual.oid == expected.oid


def test_diff_partitions_symmetric_difference(engine_world):
    keys, by_fid = engine_world
    rng = random.Random(17)
    left = set(rng.sample(keys, 230))
    right = set(rng.sample(keys, 240))
    driver = Driver()
    mine = cold(build(left, by_fid, tree.fat(8), driver))
    theirs = cold(build(right, by_fid, tree.fat(8), driver))
    symmetric = set()

    for lo, hi, my_keys, their_leaf in tree.diff(
            mine, theirs, shape.FACT, driver.fetch, driver.fetch):
        their_keys = tree.range_keys(
            their_leaf, lo, hi, shape.FACT, driver.fetch)
        symmetric.update(set(my_keys) ^ set(their_keys))

    assert symmetric == left ^ right


def test_diff_aligns_across_a_promoted_leaf_boundary(engine_world):
    keys, by_fid = engine_world
    promoted = internal_boundary(keys)
    driver = Driver()
    packing = tree.fat(8)
    mine = cold(build(
        [key for key in keys if key != promoted],
        by_fid, packing, driver,
    ))
    theirs = cold(build(keys, by_fid, packing, driver))
    leaf_count = len(leaf_ranges(theirs, driver))
    driver.reads.clear()
    symmetric = set()

    for lo, hi, my_keys, their_leaf in tree.diff(
            mine, theirs, shape.FACT, driver.fetch, driver.fetch):
        their_keys = tree.range_keys(
            their_leaf, lo, hi, shape.FACT, driver.fetch)
        symmetric.update(set(my_keys) ^ set(their_keys))

    assert symmetric == {promoted}
    assert len(set(driver.reads)) <= mine.level + theirs.level + 2
    assert len(set(driver.reads)) < leaf_count


def test_merge_one_delta_reads_and_writes_only_spines(engine_world):
    keys, by_fid = engine_world
    promoted = internal_boundary(keys)
    driver = Driver()
    packing = tree.fat(8)
    mine = cold(build(
        [key for key in keys if key != promoted],
        by_fid, packing, driver,
    ))
    theirs = cold(build(keys, by_fid, packing, driver))
    leaf_count = len(leaf_ranges(theirs, driver))
    driver.reads.clear()
    driver.writes.clear()

    merged = tree.merge(
        mine, theirs, shape.FACT, packing,
        driver.fetch, driver.emit,
    )

    assert (merged.fp, merged.oid, merged.n) == \
        (theirs.fp, theirs.oid, theirs.n)
    assert len(set(driver.reads)) <= mine.level + theirs.level + 2
    assert len(set(driver.reads)) < leaf_count
    assert len(set(driver.writes)) <= 2 * (mine.level + 1)


def test_merge_height_change_still_reads_only_spines(monkeypatch):
    """A rare high-tier boundary may wrap the root, but not scan its siblings."""
    monkeypatch.setattr(shape, "CUT", 2)
    monkeypatch.setattr(shape, "COLD_CUT", None)
    facts = [
        Fact("sample", ts, [], {"n": ts})
        for ts in range(30_000)
    ]
    by_fid = {fact.fid: fact for fact in facts}
    keys = sorted(fact.key for fact in facts)
    driver = Driver()
    packing = tree.FAT
    mine = cold(build(
        keys[:29_800] + keys[29_801:], by_fid, packing, driver))
    theirs = cold(build(keys, by_fid, packing, driver))
    driver.reads.clear()
    driver.writes.clear()

    merged = tree.merge(
        mine, theirs, shape.FACT, packing,
        driver.fetch, driver.emit,
    )

    spines = mine.level + theirs.level
    assert mine.level != theirs.level
    assert (merged.fp, merged.oid) == (theirs.fp, theirs.oid)
    assert len(set(driver.reads)) <= 2 * spines
    assert len(set(driver.writes)) <= 2 * spines


@pytest.mark.parametrize("packing", [tree.BINARY, tree.FLAT, tree.fat(8)])
def test_merge_is_root_of_union(engine_world, packing):
    keys, by_fid = engine_world
    rng = random.Random(18)
    left = set(rng.sample(keys, 250))
    right = set(rng.sample(keys, 255))
    driver = Driver()
    a = build(left, by_fid, packing, driver)
    b = build(right, by_fid, packing, driver)
    expected = build(left | right, by_fid, packing, driver)
    driver.reads.clear()

    merged = tree.merge(
        a, b, shape.FACT, packing, driver.fetch, driver.emit)

    assert (merged.fp, merged.oid, merged.n) == \
        (expected.fp, expected.oid, expected.n)
    assert len(set(driver.reads)) < len(keys)


@pytest.mark.parametrize("missing", [
    Fact("unknown", 321, [["ref", "missing", "0" * 64]], {}),
    message("unauthorized", "general", "missing closure", 321),
])
def test_merge_rejects_a_leaf_without_resolvable_closure(
        engine_world, missing):
    keys, by_fid = engine_world
    broken = {**by_fid, missing.fid: missing}
    driver = Driver()
    a = cold(build(keys[:1], broken, tree.fat(8), driver))
    b = cold(build([missing.key], broken, tree.fat(8), driver))
    driver.writes.clear()

    with pytest.raises(ValueError, match="merge closure"):
        tree.merge(
            a, b, shape.FACT, tree.fat(8),
            driver.fetch, driver.emit,
        )

    assert driver.writes == []


def test_merge_discards_staged_objects_when_fold_fails(
        engine_world, monkeypatch):
    keys, by_fid = engine_world
    driver = Driver()
    a = build(keys[:40], by_fid, tree.BINARY, driver)
    b = build(keys[40:80], by_fid, tree.BINARY, driver)
    driver.writes.clear()

    def failing_fold(*args, **kwargs):
        args[7](b"partial object")
        raise ValueError("late failure")

    monkeypatch.setattr(tree, "fold", failing_fold)
    with pytest.raises(ValueError, match="late failure"):
        tree.merge(
            a, b, shape.FACT, tree.BINARY,
            driver.fetch, driver.emit,
        )

    assert driver.writes == []


def test_merge_preserves_real_closed_pile_bytes(tmp_path):
    left = Node(str(tmp_path / "left"))
    workspace = cmds.create(left, "alice")
    right = Node(str(tmp_path / "right"))
    deliver(right, workspace, closed_subset(left, workspace, [workspace]))
    right.turn(workspace)
    a = author_msg(left, workspace, left.sk, left.pk, "left")
    b = author_msg(right, workspace, left.sk, left.pk, "right")
    left_view = tree.decode_root(left.store(workspace).get("root")).view
    right_view = tree.decode_root(right.store(workspace).get("root")).view
    emitted = {}

    def fetch(oid):
        return emitted.get(oid) \
            or left.store(workspace).get("obj/" + oid) \
            or right.store(workspace).get("obj/" + oid)

    def emit(raw):
        oid = h(raw)
        emitted[oid] = raw
        return oid

    merged = tree.merge(
        left_view, right_view, shape.FACT, tree.FAT, fetch, emit)
    deliver(left, workspace, closed_subset(right, workspace, [b.fid]))
    left.turn(workspace)
    expected = tree.decode_root(left.store(workspace).get("root")).view

    assert a.fid != b.fid
    assert (merged.fp, merged.oid) == (expected.fp, expected.oid)


# ---- the read floor ----------------------------------------------------------

def test_read_floor_a_b_p_plus_spine(engine_world):
    keys, by_fid = engine_world
    base, delta = keys[::2], keys[1::32]
    driver = Driver()
    warm = build(base, by_fid, tree.fat(8), driver)
    ranges = leaf_ranges(warm, driver)
    hit = {
        leaf.oid for lo, hi, leaf in ranges
        if any(lo < key <= hi for key in delta)
    }
    all_leaves = {leaf.oid for _, _, leaf in ranges}
    view = cold(warm)
    driver.reads.clear()

    tree.fold(
        view, delta, shape.FACT, tree.fat(8), by_fid.__getitem__,
        lambda fid: (), driver.fetch, driver.emit,
    )

    leaf_reads = set(driver.reads) & all_leaves
    assert hit <= leaf_reads
    assert len(set(driver.reads)) <= len(hit) * (view.level + 1)
    assert leaf_reads < all_leaves


# ---- kernel unification (poc-16-808.3, stage S2) -----------------------------

@pytest.fixture(scope="module")
def hoist_world(tmp_path_factory):
    node = Node(str(tmp_path_factory.mktemp("hoist")))
    workspace = cmds.create(node, "alice", ts=1_000_000)
    for ordinal in range(24):
        cmds.post(
            node, workspace, "general", f"message {ordinal}",
            ts=1_000_001 + ordinal,
        )
    idx = node.idx(workspace)
    fact_of = lambda fid: node.fact_of(workspace, fid)
    deps_of = lambda fid: resolve_deps(fact_of(fid), idx) or ()
    root, objects = hoist.build(node.keys(workspace), fact_of, deps_of)
    return workspace, root, objects, fact_of


def test_verify_judge_ops_equal_valid_set_on_cold_catchup(hoist_world):
    workspace, root, objects, fact_of = hoist_world
    expected = {fid for node in hoist.walk(root) for fid in node["pay"]}

    with Scratchpad(workspace) as pad:
        actual = tree.verify(root, pad, fact_of, objects.get)

    assert actual["ok"]
    assert actual["judged"] == expected
    assert actual["judge_ops"] == len(expected)
    assert actual == hoist.verify_once(root, workspace, fact_of)


def test_scratchpad_carried_across_ranges(hoist_world):
    workspace, root, objects, fact_of = hoist_world
    assert not root["leaf"] and root["pay"]
    expected = {fid for node in hoist.walk(root) for fid in node["pay"]}

    with Scratchpad(workspace) as pad:
        ok, shared = pad.judge(
            [fact_of(fid) for fid in root["pay"]])
        left = tree.verify(root["L"], pad, fact_of, objects.get)
        right = tree.verify(root["R"], pad, fact_of, objects.get)
        pad.pop(shared)

    judged = set(shared) | left["judged"] | right["judged"]
    assert ok and left["ok"] and right["ok"]
    assert judged == expected
    assert len(shared) + left["judge_ops"] + right["judge_ops"] \
        == len(expected)


def test_failed_scratchpad_judge_is_atomic(hoist_world):
    workspace, root, _, fact_of = hoist_world
    signature = next(
        fact_of(fid) for node in hoist.walk(root) for fid in node["pay"]
        if fact_of(fid).t == "signature"
    )
    bad = Fact("unknown", signature.ts, (), {})

    with Scratchpad(workspace) as pad:
        ok, retained = pad.judge([fact_of(workspace)])
        before = pad.db.execute(
            "SELECT fid FROM facts ORDER BY fid").fetchall()
        rejected = pad.judge([signature, bad])
        after = pad.db.execute(
            "SELECT fid FROM facts ORDER BY fid").fetchall()
        pad.pop(retained)

    assert ok
    assert rejected == (False, ())
    assert after == before


def test_single_judge_loop():
    root = pathlib.Path(__file__).resolve().parent.parent / "core"
    modules = {
        name: ast.parse((root / f"{name}.py").read_text())
        for name in ("hoist", "kernel")
    }
    hoist_defs = {
        node.name for node in modules["hoist"].body
        if isinstance(node, ast.FunctionDef)
    }
    kernel_defs = {
        node.name: node for node in modules["kernel"].body
        if isinstance(node, ast.FunctionDef)
    }
    scratchpad = next(
        node for node in modules["kernel"].body
        if isinstance(node, ast.ClassDef) and node.name == "Scratchpad"
    )
    methods = {
        node.name: node for node in scratchpad.body
        if isinstance(node, ast.FunctionDef)
    }

    assert {"_judge", "_insert", "_pop"}.isdisjoint(hoist_defs)
    assert sum(isinstance(node, ast.For)
               for node in ast.walk(kernel_defs["_judge"])) == 1
    for caller in (kernel_defs["kernel"], methods["judge"]):
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_judge"
            for node in ast.walk(caller)
        )
