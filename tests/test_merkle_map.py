"""Golden and hostile vectors for the one authenticated tree codec."""
import asyncio
import json
import random

import pytest

from core import merkle_map
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
        built = merkle_map.build(tuple(variant), SEED, emitter(objects))
        roots.add(built.root)
        if expected_objects is None:
            expected_objects = objects
        else:
            assert objects == expected_objects
    assert len(roots) == 1


def test_exact_reads_are_bounded_and_missing_is_authenticated():
    objects = {}
    built = merkle_map.build(rows(), SEED, emitter(objects))
    reader = merkle_map.Reader(
        built.root, SEED, objects.get,
        max_page_depth=built.page_depth)
    for ordinal in (0, 1, 31, 128, 256):
        assert reader.get(f"key:{ordinal:05d}")["n"] == ordinal
        assert reader.pages_read <= built.page_depth
    assert reader.get("key:99999") is None
    assert reader.pages_read <= built.page_depth


@pytest.mark.parametrize("field", ("count", "depth"))
@pytest.mark.parametrize("surface", ("get", "known-items", "same-root-diff"))
def test_reader_rejects_forged_outer_metadata_on_every_root_decode(
        field, surface):
    objects = {}
    built = merkle_map.build(rows(40), SEED, emitter(objects))
    expected = {
        "count": built.count,
        "depth": built.page_depth,
    }
    expected[field] += 1
    fetched = []

    def fetch(oid):
        fetched.append(oid)
        return objects.get(oid)

    def reader():
        return merkle_map.Reader(
            built.root, SEED, fetch,
            max_page_depth=expected["depth"],
            expected_count=expected["count"],
            expected_depth=expected["depth"])

    hostile = reader()
    with pytest.raises(ValueError, match="merkle map root metadata"):
        if surface == "get":
            hostile.get(rows(40)[0][0])
        elif surface == "known-items":
            hostile.items(
                {built.root: objects[built.root]},
                max_pages=max(1, 2 * built.count - 1))
        else:
            hostile.diff_page(reader())
    if surface == "same-root-diff":
        # Equal roots need one authenticated decode, not two store reads.
        assert fetched == [built.root]


@pytest.mark.parametrize("field", ("count", "depth"))
def test_incremental_update_rejects_forged_outer_metadata_before_emit(field):
    objects = {}
    built = merkle_map.build(rows(40), SEED, emitter(objects))
    expected = {
        "count": built.count,
        "depth": built.page_depth,
    }
    expected[field] += 1
    emitted = []

    with pytest.raises(ValueError, match="merkle map root metadata"):
        merkle_map.update(
            built.root, SEED, (), objects.get, emitted.append,
            expected_count=expected["count"],
            expected_depth=expected["depth"])
    assert emitted == []


def test_neighbor_reads_are_bounded_and_match_ordered_map():
    objects = {}
    built = merkle_map.build(rows(), SEED, emitter(objects))
    reader = merkle_map.Reader(
        built.root, SEED, objects.get,
        max_page_depth=built.page_depth)

    assert reader.neighbors("a") == (None, rows()[0])
    assert reader.pages_read <= 3 * built.page_depth
    exact = rows()[128]
    assert reader.neighbors(exact[0]) == (exact, exact)
    assert reader.pages_read <= 3 * built.page_depth
    assert reader.neighbors("key:00128:after") == (rows()[128], rows()[129])
    assert reader.pages_read <= 3 * built.page_depth
    assert reader.neighbors("z") == (rows()[-1], None)
    assert reader.pages_read <= 3 * built.page_depth


def test_range_pages_are_complete_ordered_and_depth_plus_rows_bounded():
    objects = {}
    built = merkle_map.build(rows(), SEED, emitter(objects))
    reader = merkle_map.Reader(
        built.root, SEED, objects.get,
        max_page_depth=built.page_depth)
    wanted = rows()[37:231]
    cursor, found, fetches = None, [], 0
    while True:
        page = reader.range_page(
            "key:00037", "key:00231", after=cursor, limit=17)
        found.extend(page.rows)
        fetches += reader.pages_read
        assert reader.pages_read <= 2 * built.page_depth + 2 * 18
        if page.cursor is None:
            break
        cursor = page.cursor

    assert found == wanted
    assert len(found) == 194
    assert fetches < len(found) * built.page_depth


def test_range_page_fetches_one_lookahead_and_never_crosses_prefix():
    objects = {}
    mixed = [
        ("before", 0),
        *((f"posting:a:{ordinal:04d}", ordinal) for ordinal in range(20)),
        *((f"posting:b:{ordinal:04d}", ordinal) for ordinal in range(20)),
        ("z", 1),
    ]
    built = merkle_map.build(mixed, SEED, emitter(objects))
    reader = merkle_map.Reader(
        built.root, SEED, objects.get,
        max_page_depth=built.page_depth)

    first = reader.range_page(
        "posting:a:", "posting:a:\uffff", limit=7)
    assert [value for _, value in first.rows] == list(range(7))
    assert first.cursor == first.rows[-1][0]
    assert reader.pages_read <= 2 * built.page_depth + 2 * 8

    tail = reader.range_page(
        "posting:a:", "posting:a:\uffff",
        after=first.cursor, limit=20)
    assert [value for _, value in tail.rows] == list(range(7, 20))
    assert tail.cursor is None
    assert all(key.startswith("posting:a:") for key, _ in tail.rows)


def test_range_page_rejects_unbounded_or_ambiguous_requests():
    reader = merkle_map.Reader("", SEED, lambda _oid: None)
    for args in (
            ("same", "same", None, 1),
            ("b", "a", None, 1),
            ("a", "b", "z", 1),
            ("a", "b", None, 0),
            ("a", "b", None, merkle_map.MAX_RANGE_ROWS + 1)):
        start, stop, after, limit = args
        with pytest.raises(ValueError, match="merkle map range"):
            reader.range_page(
                start, stop, after=after, limit=limit)


def test_range_page_seeded_differential_covers_boundaries_and_cursors():
    def expected_page(source, start, stop, after, limit):
        matching = tuple(
            row for row in source
            if start <= row[0] < stop
            and (after is None or row[0] > after)
        )
        selected = matching[:limit]
        return merkle_map.RangePage(
            selected,
            selected[-1][0] if len(matching) > limit else None,
        )

    empty = merkle_map.Reader("", SEED, lambda _oid: None)
    assert empty.range_page("a", "z", limit=3) == merkle_map.RangePage((), None)
    assert empty.pages_read == 0

    for seed in range(12):
        rng = random.Random(seed)
        source = tuple(sorted(
            (f"k:{number:04d}", {"n": number})
            for number in rng.sample(range(100, 700), 83)
        ))
        objects = {}
        built = merkle_map.build(source, SEED, emitter(objects))
        reader = merkle_map.Reader(
            built.root, SEED, objects.get,
            max_page_depth=built.page_depth)

        # Explicit edge cases: a cursor before the first row, one after the
        # last row, and a range containing exactly one full page.
        cases = [
            ("k:0000", "k:0800", "k:0001", 11),
            ("k:0000", "k:0800", "k:0799", 11),
            (source[9][0], source[20][0], None, 11),
        ]
        for _ in range(20):
            lo, hi = sorted(rng.sample(range(0, 801), 2))
            start, stop = f"k:{lo:04d}", f"k:{hi:04d}"
            after = None
            if rng.randrange(2):
                after = f"k:{rng.randrange(lo, hi):04d}:cursor"
            cases.append((start, stop, after, rng.randrange(1, 18)))

        for start, stop, after, limit in cases:
            expected = expected_page(source, start, stop, after, limit)
            assert reader.range_page(
                start, stop, after=after, limit=limit) == expected
            assert reader.pages_read \
                <= 2 * built.page_depth + 2 * (limit + 1)

        # Differentially consume arbitrary intervals through every returned
        # continuation. This exercises cursors that land on actual rows and
        # proves exact-limit pages do not invent a continuation.
        for _ in range(12):
            lo, hi = sorted(rng.sample(range(0, 801), 2))
            start, stop = f"k:{lo:04d}", f"k:{hi:04d}"
            limit = rng.randrange(1, 14)
            expected = tuple(
                row for row in source if start <= row[0] < stop)
            found, cursor = [], None
            while True:
                page = reader.range_page(
                    start, stop, after=cursor, limit=limit)
                found.extend(page.rows)
                assert reader.pages_read \
                    <= 2 * built.page_depth + 2 * (limit + 1)
                if page.cursor is None:
                    break
                assert page.cursor == page.rows[-1][0]
                cursor = page.cursor
            assert tuple(found) == expected


def test_incremental_value_update_matches_bulk_and_rewrites_one_path():
    objects = {}
    initial = merkle_map.build(rows(), SEED, emitter(objects))
    fresh = set()
    changed = [("key:00128", {"n": 128, "text": "changed"})]
    updated = merkle_map.update(
        initial.root, SEED, changed, objects.get,
        emitter(objects, fresh))

    final_rows = dict(rows())
    final_rows.update(changed)
    bulk_objects = {}
    bulk = merkle_map.build(tuple(final_rows.items()), SEED, emitter(bulk_objects))
    assert updated.root == bulk.root
    assert {oid: objects[oid] for oid in bulk_objects} == bulk_objects
    assert len(fresh) <= initial.page_depth


def test_batch_update_establishes_every_final_page_before_returning_root():
    original = rows()
    objects = {}
    initial = merkle_map.build(original, SEED, emitter(objects))
    original_oids = set(objects)
    changed = {
        original[index][0]: None
        for index in range(0, len(original), 11)
    }
    changed.update({
        original[index][0]: {"n": index, "text": "changed"}
        for index in range(3, len(original), 13)
    })
    changed.update({
        f"key:new:{index:03d}": {"new": index}
        for index in range(31)
    })
    changes = sorted(changed.items())
    emitted = []

    def emit(raw):
        oid = h(raw)
        emitted.append(oid)
        objects.setdefault(oid, raw)
        return oid

    updated = merkle_map.update(
        initial.root, SEED, changes, objects.get, emit)
    final = dict(original)
    for key, value in changes:
        if value is None:
            final.pop(key, None)
        else:
            final[key] = value
    bulk = merkle_map.build(
        tuple(final.items()), SEED, lambda raw: h(raw))
    assert updated.root == bulk.root

    reachable = set()

    def visit(oid):
        if not oid or oid in reachable:
            return
        reachable.add(oid)
        page = json.loads(objects[oid])
        if page["kind"] == "branch":
            for child in page["children"]:
                visit(child[1])

    visit(updated.root)
    assert len(emitted) == len(set(emitted)) == updated.pages
    assert reachable - original_oids <= set(emitted)
    assert all(h(objects[oid]) == oid for oid in emitted)


def test_batch_update_releases_superseded_decoded_paths_immediately(
        monkeypatch):
    objects = {}
    initial = merkle_map.build(
        rows(64), SEED, emitter(objects))
    real_decode = merkle_map._decode
    live = peak = calls = 0

    class TrackedPage(dict):
        def __init__(self, value):
            nonlocal live, peak
            super().__init__(value)
            live += 1
            peak = max(peak, live)

        def __del__(self):
            nonlocal live
            live -= 1

    def tracked_decode(*args):
        nonlocal calls
        page, summary = real_decode(*args)
        calls += 1
        return TrackedPage(page), summary

    monkeypatch.setattr(merkle_map, "_decode", tracked_decode)
    changes = tuple(
        (f"key:new:{index:04d}", {"new": index})
        for index in range(128)
    )
    updated = merkle_map.update(
        initial.root,
        SEED,
        changes,
        objects.get,
        emitter(objects),
        expected_count=initial.count,
        expected_depth=initial.page_depth,
    )

    # Superseded versions are reference-released during the batch. Recursive
    # helper cycles are emptied before return, so the next map cannot overlap
    # this map's decoded graph.
    assert live == 0
    assert peak <= updated.pages + 2 * updated.page_depth
    assert calls <= 2 * len(changes) * (
        initial.page_depth + updated.page_depth)


def test_deleting_final_row_releases_decoded_graph(monkeypatch):
    objects = {}
    initial = merkle_map.build(
        (("only", {"value": 1}),), SEED, emitter(objects))
    real_decode = merkle_map._decode
    live = 0

    class TrackedPage(dict):
        def __init__(self, value):
            nonlocal live
            super().__init__(value)
            live += 1

        def __del__(self):
            nonlocal live
            live -= 1

    def tracked_decode(*args):
        page, summary = real_decode(*args)
        return TrackedPage(page), summary

    monkeypatch.setattr(merkle_map, "_decode", tracked_decode)
    emptied = merkle_map.update(
        initial.root, SEED, (("only", None),), objects.get,
        emitter(objects),
        expected_count=initial.count,
        expected_depth=initial.page_depth,
    )

    assert emptied == merkle_map.Built("", 0, 0, 0)
    assert live == 0


def test_failed_publication_releases_decoded_graph_before_error_escapes(
        monkeypatch):
    objects = {}
    initial = merkle_map.build(
        rows(64), SEED, emitter(objects))
    real_decode = merkle_map._decode
    live = 0

    class TrackedPage(dict):
        def __init__(self, value):
            nonlocal live
            super().__init__(value)
            live += 1

        def __del__(self):
            nonlocal live
            live -= 1

    def tracked_decode(*args):
        page, summary = real_decode(*args)
        return TrackedPage(page), summary

    def unavailable(_raw):
        raise OSError("injected immutable-page outage")

    monkeypatch.setattr(merkle_map, "_decode", tracked_decode)
    with pytest.raises(OSError, match="immutable-page outage") as caught:
        merkle_map.update(
            initial.root,
            SEED,
            tuple(
                (f"key:new:{index:04d}", {"new": index})
                for index in range(128)
            ),
            objects.get,
            unavailable,
            expected_count=initial.count,
            expected_depth=initial.page_depth,
        )

    assert caught.value.__traceback__ is not None
    assert live == 0


def test_items_prunes_remote_reads_and_validates_changed_paths():
    objects = {}
    initial = merkle_map.build(rows(), SEED, emitter(objects))
    known = dict(objects)
    updated = merkle_map.update(
        initial.root, SEED,
        [("key:00128", {"n": 128, "text": "changed"})],
        objects.get, emitter(objects))
    reader = merkle_map.Reader(updated.root, SEED, objects.get)

    merged = dict(reader.items(known))
    assert merged["key:00128"]["text"] == "changed"
    assert len(merged) == initial.count
    assert reader.pages_read < initial.count


def test_pruned_subtree_is_still_validated_against_inherited_bounds():
    """A shared hash-valid subtree cannot be grafted under a false byte."""
    objects = {}
    merkle_map.build(rows(80), SEED, emitter(objects))
    known = dict(objects)
    root = next(
        oid for oid, raw in objects.items()
        if json.loads(raw)["kind"] == "branch"
        and len(json.loads(raw)["children"]) >= 2
    )
    page = json.loads(objects[root])
    page["children"][0][1:], page["children"][-1][1:] = (
        page["children"][-1][1:],
        page["children"][0][1:],
    )
    raw = merkle_map.canon(page)
    hostile_root = h(raw)
    objects[hostile_root] = raw

    with pytest.raises(ValueError, match="merkle map page shape"):
        merkle_map.Reader(
            hostile_root, SEED, objects.get).items(known)


def test_sequential_insert_delete_and_bulk_have_one_root():
    wanted = dict(rows(180))
    order = list(wanted)
    random.Random(91).shuffle(order)
    objects = {}
    current = ""
    for key in order:
        current = merkle_map.update(
            current, SEED, [(key, wanted[key])], objects.get,
            emitter(objects)).root
    for key in order[::7]:
        current = merkle_map.update(
            current, SEED, [(key, None)], objects.get,
            emitter(objects)).root
        wanted.pop(key)

    bulk_objects = {}
    bulk = merkle_map.build(
        tuple(wanted.items()), SEED, emitter(bulk_objects))
    assert current == bulk.root
    assert dict(
        merkle_map.Reader(current, SEED, objects.get).items()) == wanted


def test_missing_or_mutated_page_fails_closed():
    objects = {}
    built = merkle_map.build(rows(40), SEED, emitter(objects))
    with pytest.raises(ValueError, match="integrity"):
        merkle_map.Reader(
            built.root, SEED, lambda oid: None).get("key:00001")
    with pytest.raises(ValueError, match="integrity"):
        merkle_map.Reader(
            built.root, SEED,
            lambda oid: objects[oid] + b" ").get("key:00001")


def test_depth_and_value_budgets_reject_before_publication():
    emitted = []
    with pytest.raises(ValueError, match="depth budget"):
        merkle_map.build(
            rows(1), SEED, emitted.append, max_page_depth=0)
    with pytest.raises(ValueError, match="value too large"):
        merkle_map.build(
            (("key", "x" * (merkle_map.MAX_VALUE_BYTES + 1)),),
            SEED, emitted.append)
    with pytest.raises(ValueError, match="key too large"):
        merkle_map.build(
            (("k" * (merkle_map.MAX_KEY_BYTES + 1), 1),),
            SEED, emitted.append)
    with pytest.raises(ValueError, match="null value"):
        merkle_map.build((("key", None),), SEED, emitted.append)
    assert emitted == []


def test_hostile_prefix_chain_has_deterministic_hard_depth_and_leaf_bounds():
    """An author-selected prefix chain replaces the old priority grind.

    This is close to the worst Patricia path: every added key terminates one
    byte later than its predecessor.  It can make the finite key-depth bound
    visible, but cannot overflow a leaf, branch fanout, page, or publication
    depth ceiling.
    """
    source = [
        ("a" * length + "!", {"length": length})
        for length in range(1, merkle_map.MAX_KEY_BYTES)
    ]
    objects = {}
    built = merkle_map.build(source, SEED, emitter(objects))
    pages = [json.loads(raw) for raw in objects.values()]
    leaves = [page for page in pages if page["kind"] == "leaf"]
    branches = [page for page in pages if page["kind"] == "branch"]

    assert 1 < built.page_depth <= merkle_map.MAX_PAGE_DEPTH
    assert all(
        len(page["rows"]) <= merkle_map.LEAF_MAX_ROWS
        and len(objects[h(merkle_map.canon(page))])
        <= merkle_map.LEAF_MAX_BYTES
        for page in leaves
    )
    assert all(
        2 <= len(page["children"]) <= merkle_map.MAX_FANOUT
        and len(objects[h(merkle_map.canon(page))])
        <= merkle_map.MAX_PAGE_BYTES
        for page in branches
    )
    assert all("priority" not in page for page in pages)

    reversed_objects = {}
    reverse = merkle_map.build(
        tuple(reversed(source)), SEED, emitter(reversed_objects))
    assert reverse.root == built.root
    assert reversed_objects == objects


def test_maximum_byte_fanout_is_finite_and_canonical():
    stem = "p" * (merkle_map.MAX_KEY_BYTES - 1)
    wide = "x" * (merkle_map.MAX_VALUE_BYTES - 64)
    source = [
        (stem + chr(byte), {"byte": byte, "wide": wide})
        for byte in range(64, 96)
    ]
    objects = {}
    built = merkle_map.build(source, SEED, emitter(objects))
    root = json.loads(objects[built.root])
    assert root["kind"] == "branch"
    assert len(root["children"]) == merkle_map.MAX_FANOUT == 32
    assert len(objects[built.root]) <= merkle_map.MAX_PAGE_BYTES
    assert dict(
        merkle_map.Reader(
            built.root, SEED, objects.get,
            max_page_depth=built.page_depth,
        ).items()
    ) == dict(source)

    reader = merkle_map.Reader(
        built.root, SEED, objects.get,
        max_page_depth=built.page_depth)
    assert reader.range_page(
        stem + "_", stem + "_\uffff", limit=1
    ) == merkle_map.RangePage(
        ((stem + "_", {"byte": 95, "wide": wide}),), None)
    assert reader.pages_read <= (
        2 * built.page_depth + 2 * (1 + 1))
    assert reader.range_page(
        stem + "]", stem + "^", limit=1
    ) == merkle_map.RangePage(
        ((stem + "]", {"byte": 93, "wide": wide}),), None)
    assert reader.pages_read <= (
        2 * built.page_depth + 2 * (1 + 1))
    assert reader.range_page(
        stem + "_!", stem + "_~", limit=1
    ) == merkle_map.RangePage((), None)
    assert reader.pages_read <= (
        2 * built.page_depth + 2 * (1 + 1))


def test_seeded_insert_delete_restore_matches_bulk_under_hostile_prefixes():
    source = {
        "q" * length + suffix: {"length": length, "suffix": suffix}
        for length in range(1, 90)
        for suffix in ("!", "~")
    }
    wanted, objects, current = {}, {}, ""
    history = list(source)
    random.Random(773).shuffle(history)
    for key in history:
        current = merkle_map.update(
            current, SEED, ((key, source[key]),),
            objects.get, emitter(objects)).root
        wanted[key] = source[key]
    removed = history[::5]
    for key in removed:
        current = merkle_map.update(
            current, SEED, ((key, None),),
            objects.get, emitter(objects)).root
        wanted.pop(key)
    for key in reversed(removed[::2]):
        current = merkle_map.update(
            current, SEED, ((key, source[key]),),
            objects.get, emitter(objects)).root
        wanted[key] = source[key]

    bulk = merkle_map.build(
        tuple(wanted.items()), SEED, lambda raw: h(raw))
    assert current == bulk.root
    assert dict(
        merkle_map.Reader(current, SEED, objects.get).items()
    ) == wanted


def test_one_update_rewrites_only_key_depth_plus_bounded_leaf_neighborhood():
    source = [
        ("z" * length + "!", {"length": length})
        for length in range(1, 180)
    ]
    objects = {}
    initial = merkle_map.build(source, SEED, emitter(objects))
    fresh = set()
    updated = merkle_map.update(
        initial.root,
        SEED,
        ((source[-1][0], {"length": 999}),),
        objects.get,
        emitter(objects, fresh),
    )
    assert updated.pages == len(fresh)
    assert updated.pages <= (
        initial.page_depth + 2 * merkle_map.LEAF_MAX_ROWS)
    expected = dict(source)
    expected[source[-1][0]] = {"length": 999}
    assert updated.root == merkle_map.build(
        tuple(expected.items()), SEED, lambda raw: h(raw)).root


def test_resumable_oid_pruned_diff_is_bounded_and_classifies_rows():
    source = [(f"k:{number:04d}", {"n": number}) for number in range(180)]
    objects = {}
    local_built = merkle_map.build(source, SEED, emitter(objects))
    known = set(objects)
    changes = (
        ("k:0007", {"n": 700}),
        ("k:0091", {"n": 9100}),
        ("k:0179", {"n": 17900}),
    )
    remote_built = merkle_map.update(
        local_built.root, SEED, changes, objects.get, emitter(objects))
    local = merkle_map.Reader(
        local_built.root, SEED, objects.get,
        max_page_depth=local_built.page_depth)
    remote = merkle_map.Reader(
        remote_built.root, SEED, objects.get,
        max_page_depth=remote_built.page_depth)

    cursor, returned, differing = None, [], []
    while True:
        page = remote.diff_page(local, after=cursor, limit=5)
        returned.extend(page.rows)
        differing.extend(page.differing)
        assert remote.pages_read <= (
            2 * remote_built.page_depth + 2 * 6)
        if page.cursor is None:
            break
        assert page.cursor == page.rows[-1][0]
        cursor = page.cursor

    assert dict(differing) == dict(changes)
    assert len(returned) <= (
        len(changes) * merkle_map.LEAF_MAX_ROWS)
    same = merkle_map.Reader(
        remote_built.root, SEED, objects.get,
        max_page_depth=remote_built.page_depth)
    assert remote.diff_page(
        same, limit=5
    ) == merkle_map.DiffPage((), (), None)


def test_awaited_diff_is_sync_identical_and_enforces_aggregate_page_budget():
    source = [(f"k:{number:04d}", {"n": number}) for number in range(180)]
    objects = {}
    local_built = merkle_map.build(source, SEED, emitter(objects))
    changes = (
        ("k:0007", {"n": 700}),
        ("k:0091", {"n": 9100}),
        ("k:0179", {"n": 17900}),
    )
    remote_built = merkle_map.update(
        local_built.root, SEED, changes, objects.get, emitter(objects))

    def sync_readers():
        return (
            merkle_map.Reader(
                remote_built.root, SEED, objects.get,
                max_page_depth=remote_built.page_depth),
            merkle_map.Reader(
                local_built.root, SEED, objects.get,
                max_page_depth=local_built.page_depth),
        )

    remote, local = sync_readers()
    expected = remote.diff_page(local, limit=5)

    def awaited_readers(calls):
        async def fetch(oid):
            calls.append(oid)
            await asyncio.sleep(0)
            return objects.get(oid)

        return (
            merkle_map.Reader(
                remote_built.root, SEED, fetch,
                max_page_depth=remote_built.page_depth),
            merkle_map.Reader(
                local_built.root, SEED, fetch,
                max_page_depth=local_built.page_depth),
        )

    calls = []
    remote, local = awaited_readers(calls)
    actual = asyncio.run(remote.diff_page_awaited(local, limit=5))
    assert actual == expected
    exact = remote.pages_read + local.pages_read
    assert exact == len(calls) > 0

    calls = []
    remote, local = awaited_readers(calls)
    assert asyncio.run(remote.diff_page_awaited(
        local, limit=5, max_pages=exact)) == expected
    assert len(calls) == exact

    calls = []
    remote, local = awaited_readers(calls)
    with pytest.raises(ValueError, match="diff page budget"):
        asyncio.run(remote.diff_page_awaited(
            local, limit=5, max_pages=exact - 1))
    assert len(calls) == exact - 1


def test_stale_physically_held_page_is_not_a_current_reachability_witness():
    objects = {}
    original = merkle_map.build(rows(90), SEED, emitter(objects))
    changed = ("key:00044", {"n": 44, "text": "new current value"})
    current = merkle_map.update(
        original.root, SEED, (changed,), objects.get, emitter(objects))
    # The immutable store still physically contains every object from both
    # roots.  Diff authority nevertheless comes only from ``current.root``.
    historical = merkle_map.Reader(
        original.root, SEED, objects.get,
        max_page_depth=original.page_depth)
    local = merkle_map.Reader(
        current.root, SEED, objects.get,
        max_page_depth=current.page_depth)
    page = historical.diff_page(local, limit=merkle_map.MAX_RANGE_ROWS)
    assert (changed[0], rows(90)[44][1]) in page.differing


def test_missing_label_cannot_hide_a_child_from_nonmembership():
    wide = "v" * (merkle_map.MAX_VALUE_BYTES - 128)
    source = [
        (f"{prefix}:{number:02d}", {"wide": wide, "n": number})
        for prefix in ("a", "c", "e")
        for number in range(11)
    ]
    objects = {}
    built = merkle_map.build(source, SEED, emitter(objects))
    page = json.loads(objects[built.root])
    assert page["kind"] == "branch"
    victim = next(
        child for child in page["children"]
        if merkle_map._decode_bound(child[5]).startswith("c:"))
    victim[0] += 1
    raw = merkle_map.canon(page)
    bad_root = h(raw)
    objects[bad_root] = raw
    with pytest.raises(ValueError, match="merkle map page shape"):
        merkle_map.Reader(
            bad_root, SEED, objects.get,
            max_page_depth=built.page_depth).get("c:05")


def test_child_bound_shorter_than_parent_prefix_fails_as_page_shape():
    source = [
        (f"shared-prefix-{suffix}:{number:02d}", {"n": number})
        for suffix in ("a", "b")
        for number in range(20)
    ]
    objects = {}
    built = merkle_map.build(source, SEED, emitter(objects))
    page = json.loads(objects[built.root])
    assert page["kind"] == "branch"
    assert len(page["prefix"]) > len(merkle_map._tokens("x"))
    page["children"][0][5] = merkle_map._bound_text("x")
    raw = merkle_map.canon(page)
    hostile_root = h(raw)
    objects[hostile_root] = raw

    with pytest.raises(ValueError, match="merkle map page shape"):
        merkle_map.Reader(
            hostile_root, SEED, objects.get,
            max_page_depth=built.page_depth).get(source[0][0])


def test_diff_does_not_prune_same_oid_with_forged_child_descriptor():
    objects = {}
    built = merkle_map.build(rows(80), SEED, emitter(objects))
    page = json.loads(objects[built.root])
    assert page["kind"] == "branch"
    page["children"][0][2] += 1
    page["count"] += 1
    raw = merkle_map.canon(page)
    hostile_root = h(raw)
    objects[hostile_root] = raw

    hostile = merkle_map.Reader(
        hostile_root, SEED, objects.get,
        max_page_depth=built.page_depth)
    current = merkle_map.Reader(
        built.root, SEED, objects.get,
        max_page_depth=built.page_depth)
    with pytest.raises(ValueError, match="merkle map child metadata"):
        hostile.diff_page(current, limit=merkle_map.MAX_RANGE_ROWS)


def test_seeded_neighbor_differential_preserves_ancestor_fallbacks():
    alphabet = "abcxyz013~"
    for seed in range(40):
        rng = random.Random(seed)
        keys = set()
        while len(keys) < 90:
            keys.add("".join(
                rng.choice(alphabet)
                for _ in range(rng.randint(2, 9))))
        source = tuple(
            (key, {"key": key}) for key in sorted(keys))
        objects = {}
        built = merkle_map.build(source, SEED, emitter(objects))
        reader = merkle_map.Reader(
            built.root, SEED, objects.get,
            max_page_depth=built.page_depth)
        ordered = [row[0] for row in source]
        queries = [
            "".join(
                rng.choice(alphabet)
                for _ in range(rng.randint(2, 9)))
            for _ in range(40)
        ]
        if seed == 34:
            queries.append("cb31z~b")
        for query in queries:
            at = __import__("bisect").bisect_left(ordered, query)
            exact = at < len(ordered) and ordered[at] == query
            before = source[at] if exact else source[at - 1] if at else None
            after = source[at] if at < len(source) else None
            assert reader.neighbors(query) == (before, after)
            assert reader.pages_read <= 3 * built.page_depth


def test_disjoint_max_fanout_diff_pages_resume_near_late_labels():
    wide = "y" * (merkle_map.MAX_VALUE_BYTES - 64)
    source = [
        ("p" + chr(byte), {"byte": byte, "wide": wide})
        for byte in range(64, 96)
    ]
    objects = {}
    built = merkle_map.build(source, SEED, emitter(objects))
    reader = merkle_map.Reader(
        built.root, SEED, objects.get,
        max_page_depth=built.page_depth)
    empty = merkle_map.Reader("", SEED, objects.get)
    cursor, found = "p[", []
    for _ in range(4):
        page = reader.diff_page(empty, after=cursor, limit=1)
        found.extend(page.rows)
        assert reader.pages_read <= (
            2 * built.page_depth + 2 * (1 + 1))
        if page.cursor is None:
            break
        cursor = page.cursor
    assert [row[0] for row in found] == ["p\\", "p]", "p^", "p_"]


def test_leaf_byte_limit_splits_before_row_limit_and_collapses_on_delete():
    value = "x" * (merkle_map.MAX_VALUE_BYTES - 64)
    source = [(f"wide:{number:02d}", value) for number in range(6)]
    objects = {}
    built = merkle_map.build(source, SEED, emitter(objects))
    root = json.loads(objects[built.root])
    assert len(source) < merkle_map.LEAF_MAX_ROWS
    assert root["kind"] == "branch"
    leaves = [
        json.loads(raw) for raw in objects.values()
        if json.loads(raw)["kind"] == "leaf"
    ]
    assert all(
        len(merkle_map.canon(page)) <= merkle_map.LEAF_MAX_BYTES
        for page in leaves)

    current = built
    wanted = dict(source)
    for key, _ in source[:-1]:
        current = merkle_map.update(
            current.root, SEED, ((key, None),),
            objects.get, emitter(objects))
        wanted.pop(key)
    final_page = json.loads(objects[current.root])
    assert final_page["kind"] == "leaf"
    assert current.root == merkle_map.build(
        tuple(wanted.items()), SEED, lambda raw: h(raw)).root
