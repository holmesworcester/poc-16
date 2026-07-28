"""Golden and hostile vectors for the one authenticated tree codec."""
import random

import pytest

from core import btreap
from core.crypto import h


SEED = "ab" * 32


def emitter(objects, fresh=None):
    def emit(raw):
        oid = h(raw)
        if fresh is not None and oid not in objects:
            fresh.add(oid)
        objects.setdefault(oid, raw)
        return oid
    return emit


def rows(count=257):
    return [
        (f"key:{ordinal:05d}", {"n": ordinal, "text": f"value-{ordinal}"})
        for ordinal in range(count)
    ]


def test_forward_reverse_random_and_bulk_builds_are_byte_identical():
    expected_objects, roots = None, set()
    variants = [rows(), list(reversed(rows()))]
    for seed in range(5):
        shuffled = rows()
        random.Random(seed).shuffle(shuffled)
        variants.append(shuffled)
    for variant in variants:
        objects = {}
        built = btreap.build(tuple(variant), SEED, emitter(objects))
        roots.add(built.root)
        if expected_objects is None:
            expected_objects = objects
        else:
            assert objects == expected_objects
    assert len(roots) == 1


def test_exact_reads_are_bounded_and_missing_is_authenticated():
    objects = {}
    built = btreap.build(rows(), SEED, emitter(objects))
    reader = btreap.Reader(
        built.root, SEED, objects.get,
        max_page_depth=built.page_depth)
    for ordinal in (0, 1, 31, 128, 256):
        assert reader.get(f"key:{ordinal:05d}")["n"] == ordinal
        assert reader.pages_read <= built.page_depth
    assert reader.get("key:99999") is None
    assert reader.pages_read <= built.page_depth


def test_incremental_value_update_matches_bulk_and_rewrites_one_path():
    objects = {}
    initial = btreap.build(rows(), SEED, emitter(objects))
    fresh = set()
    changed = [("key:00128", {"n": 128, "text": "changed"})]
    updated = btreap.update(
        initial.root, SEED, changed, objects.get,
        emitter(objects, fresh))

    final_rows = dict(rows())
    final_rows.update(changed)
    bulk_objects = {}
    bulk = btreap.build(tuple(final_rows.items()), SEED, emitter(bulk_objects))
    assert updated.root == bulk.root
    assert {oid: objects[oid] for oid in bulk_objects} == bulk_objects
    assert len(fresh) <= initial.page_depth


def test_missing_or_mutated_page_fails_closed():
    objects = {}
    built = btreap.build(rows(40), SEED, emitter(objects))
    with pytest.raises(ValueError, match="integrity"):
        btreap.Reader(
            built.root, SEED, lambda oid: None).get("key:00001")
    with pytest.raises(ValueError, match="integrity"):
        btreap.Reader(
            built.root, SEED,
            lambda oid: objects[oid] + b" ").get("key:00001")


def test_depth_and_value_budgets_reject_before_publication():
    with pytest.raises(ValueError, match="depth budget"):
        btreap.build(rows(1), SEED, lambda raw: h(raw), max_page_depth=0)
    with pytest.raises(ValueError, match="value too large"):
        btreap.build(
            (("key", "x" * (btreap.MAX_VALUE_BYTES + 1)),),
            SEED, lambda raw: h(raw))
