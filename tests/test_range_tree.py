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


def test_randomized_add_remove_and_refresh_windows_match_full_build():
    """Every ordinary eligibility delta has one history-independent result."""
    corpus = _corpus()
    active = {fact.fid: fact for fact in corpus[:96]}
    inactive = {fact.fid: fact for fact in corpus[96:]}
    dependencies = {fid: () for fid in active}
    objects = {}
    _, root = manifest.build(
        (fact.key for fact in active.values()),
        active.get,
        lambda fid: dependencies.get(fid, ()),
        _emitter(objects),
    )
    rng = random.Random(90210)

    for _ in range(80):
        additions = rng.sample(
            list(inactive.values()),
            min(len(inactive), rng.randint(0, 4)),
        )
        removable = list(active.values())
        removals = rng.sample(
            removable,
            min(len(removable) - 1, rng.randint(0, 4)),
        )
        removal_ids = {fact.fid for fact in removals}
        refreshable = [
            fact for fact in active.values()
            if fact.fid not in removal_ids
        ]
        rewired = rng.sample(
            refreshable,
            min(len(refreshable), rng.randint(0, 3)),
        )
        rewired = list({
            fact.fid: fact
            for fact in (
                *rewired,
                *(
                    fact for fact in refreshable
                    if set(dependencies.get(fact.fid, ())) & removal_ids
                ),
            )
        }.values())
        impacted = {fact.fid for fact in rewired}
        while True:
            expanded = impacted | {
                fact.fid for fact in refreshable
                if set(dependencies.get(fact.fid, ())) & impacted
            }
            if expanded == impacted:
                break
            impacted = expanded
        refreshed = [
            active[fid] for fid in sorted(impacted)]
        if not additions and not removals and not refreshed:
            continue

        ranges = manifest.changed_ranges(
            root,
            (fact.key for fact in additions),
            objects.get,
            WORKSPACE,
            removed=(fact.key for fact in removals),
            refreshed=(fact.key for fact in refreshed),
        )
        for fact in removals:
            active.pop(fact.fid)
            inactive[fact.fid] = fact
            dependencies.pop(fact.fid, None)
        for fact in additions:
            inactive.pop(fact.fid)
            active[fact.fid] = fact
            dependencies[fact.fid] = ()
        available = sorted(active)
        for fact in rewired:
            choices = [
                fid for fid in available if fid != fact.fid]
            dependencies[fact.fid] = (
                rng.choice(choices),
            ) if choices else ()

        root = manifest.update(
            root,
            ranges,
            active.get,
            lambda fid: dependencies.get(fid, ()),
            objects.get,
            _emitter(objects),
        )
        _, clean = manifest.build(
            (fact.key for fact in active.values()),
            active.get,
            lambda fid: dependencies.get(fid, ()),
            lambda raw: h(raw),
        )
        assert root == clean


def test_boundary_removal_reads_only_two_neighboring_leaves(monkeypatch):
    """Removing a cut joins its old leaf to one successor, never the map."""
    corpus = _corpus()
    active = {fact.fid: fact for fact in corpus}
    objects = {}
    entries, root = manifest.build(
        (fact.key for fact in corpus),
        active.get,
        lambda fid: (),
        _emitter(objects),
    )
    boundary_fact = next(
        fact for fact in corpus
        if shape.boundary(fact.fid)
        and any(entry.sep > fact.key for entry in entries)
    )
    touched = []

    def fetch(oid):
        touched.append(oid)
        return objects.get(oid)

    monkeypatch.setattr(
        btreap.Reader,
        "items",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("range removal enumerated the tree")),
    )
    replacements = manifest.changed_ranges(
        root,
        (),
        fetch,
        WORKSPACE,
        removed=(boundary_fact.key,),
    )

    assert len(replacements) == 1
    assert len(replacements[0].old_seps) == 2
    assert boundary_fact.key not in replacements[0].keys
    depth = json.loads(objects[root])["depth"]
    assert len(set(touched)) <= 2 * depth + 2


def test_transition_shape_rejects_nonresident_and_overlapping_keys():
    facts = _facts(4)
    active = {fact.fid: fact for fact in facts}
    objects = {}
    _, root = manifest.build(
        (fact.key for fact in facts),
        active.get,
        lambda fid: (),
        _emitter(objects),
    )
    absent = Fact("sample", 999, [], {"absent": True}, WORKSPACE)

    with pytest.raises(ValueError, match="not resident"):
        manifest.changed_ranges(
            root, (), objects.get, WORKSPACE,
            removed=(absent.key,))
    with pytest.raises(ValueError, match="overlapping"):
        manifest.changed_ranges(
            root, (facts[0].key,), objects.get, WORKSPACE,
            removed=(facts[0].key,))
