"""Canonical authenticated discovery and path-copy equivalence for RangeTree."""
import json
import random

import pytest

from core import btreap, manifest, shape
from core.crypto import h
from core.fact import Fact

WORKSPACE = "0" * 64


def _facts(count):
    return [
        Fact(
            "sample", ordinal * 7 + 1, [],
            {"ordinal": ordinal}, WORKSPACE,
        )
        for ordinal in range(count)
    ]


def _corpus():
    facts = _facts(192)
    while sum(shape.boundary(fact.fid) for fact in facts) < 4:
        facts.extend(_facts(len(facts) + 64)[len(facts):])
    return facts


def _emitter(objects, fresh=None):
    def emit(raw):
        oid = h(raw)
        if fresh is not None and oid not in objects:
            fresh.add(oid)
        objects.setdefault(oid, raw)
        return oid
    return emit


def test_randomized_batches_match_clean_full_build_and_touch_bounded_paths():
    """Insertion order/batching cannot affect bytes; one batch stays local."""
    corpus = _corpus()
    canonical = None

    for seed in range(4):
        order = corpus[:]
        rng = random.Random(seed)
        rng.shuffle(order)
        active, objects, root, largest_touch = {}, {}, "", 0
        at = 0
        while at < len(order):
            batch = order[at:at + rng.randint(1, 7)]
            at += len(batch)
            active.update((fact.fid, fact) for fact in batch)
            fresh = set()
            if not root:
                _, root = manifest.build(
                    (fact.key for fact in active.values()), active.get,
                    lambda fid: (), _emitter(objects, fresh))
            else:
                before_depth = json.loads(objects[root])["depth"]
                root = manifest.update(
                    root, manifest.changed_ranges(
                        root, (fact.key for fact in batch), objects.get,
                        WORKSPACE),
                    active.get, lambda fid: (), objects.get,
                    _emitter(objects, fresh))
                assert len(fresh) <= len(batch) * (
                    2 + 4 * (before_depth + 1))
            largest_touch = max(largest_touch, len(fresh))

            _, clean = manifest.build(
                (fact.key for fact in active.values()), active.get,
                lambda fid: (), lambda raw: h(raw))
            assert root == clean

        decoded = manifest.decode(objects[root], objects.get)
        expected, _ = manifest.build(
            (fact.key for fact in corpus),
            {fact.fid: fact for fact in corpus}.get,
            lambda fid: (), lambda raw: h(raw))
        assert decoded == expected
        assert largest_touch < len(corpus)
        canonical = canonical or root
        assert root == canonical


def test_new_key_discovery_reads_one_authenticated_path_not_the_map(
        monkeypatch):
    corpus = _corpus()
    active = {fact.fid: fact for fact in corpus}
    objects = {}
    entries, root = manifest.build(
        (fact.key for fact in corpus), active.get, lambda fid: (),
        _emitter(objects))
    candidate = Fact("sample", 500, [], {"new": True}, WORKSPACE)
    assert candidate.fid not in active
    touched = []

    def fetch(oid):
        touched.append(oid)
        return objects.get(oid)

    monkeypatch.setattr(
        btreap.Reader, "items",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("range discovery enumerated the tree")))
    ranges = manifest.changed_ranges(
        root, (candidate.key,), fetch, WORKSPACE)

    assert any(candidate.key in keys for _, keys in ranges)
    assert sum(len(keys) for _, keys in ranges) < len(corpus)
    assert len(set(touched)) <= json.loads(objects[root])["depth"] + 2
    assert len(entries) > 2
    with pytest.raises(ValueError, match="changed range key"):
        manifest.changed_ranges(root, (None,), objects.get, WORKSPACE)
