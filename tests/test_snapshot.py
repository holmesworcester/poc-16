"""Composite snapshot and direct FactOrder integration."""
import random

import pytest

from core import merkle_map, snapshot
from core.crypto import h
from core.fact import canon
from core.shape import key_parts

WORKSPACE = h(b"fact-order-workspace")
SEED = snapshot.layout_seed(WORKSPACE)


def row(ordinal):
    fid = h(canon(["fact", ordinal]))
    return key_parts(ordinal, fid), fid


def emitter(objects):
    def emit(raw):
        oid = h(raw)
        objects[oid] = raw
        return oid
    return emit


def test_fact_order_full_and_incremental_histories_are_identical():
    rng = random.Random(0xFAC70)
    wanted = {}
    objects = {}
    descriptor = snapshot.empty_descriptor()
    for _ in range(300):
        ordinal = rng.randrange(600)
        address, oid = row(ordinal)
        value = None if address in wanted and rng.randrange(3) == 0 else oid
        if value is None:
            wanted.pop(address)
        else:
            wanted[address] = value
        if descriptor["root"]:
            descriptor = snapshot.update_fact_order(
                descriptor,
                ((address, value),),
                SEED,
                objects.get,
                emitter(objects),
            )
        elif value is not None:
            descriptor = snapshot.build_fact_order(
                wanted.items(), SEED, emitter(objects))

        clean_objects = {}
        clean = snapshot.build_fact_order(
            wanted.items(), SEED, emitter(clean_objects))
        assert descriptor == clean
        assert snapshot.fact_order_rows(
            descriptor, SEED, objects.get) == tuple(sorted(wanted.items()))


def test_fact_order_is_direct_and_every_page_obeys_map_bounds():
    rows = tuple(row(ordinal) for ordinal in range(257))
    objects = {}
    descriptor = snapshot.build_fact_order(rows, SEED, emitter(objects))
    assert descriptor["count"] == len(rows)
    assert snapshot.fact_order_rows(
        descriptor, SEED, objects.get) == rows

    reader = merkle_map.Reader(
        descriptor["root"], SEED, objects.get,
        max_page_depth=descriptor["depth"])
    assert reader.get(rows[128][0]) == rows[128][1]
    for raw in objects.values():
        assert len(raw) <= merkle_map.MAX_PAGE_BYTES
        value = __import__("json").loads(raw)
        if value["kind"] == "leaf":
            assert len(value["rows"]) <= merkle_map.LEAF_MAX_ROWS
            assert len(raw) <= merkle_map.LEAF_MAX_BYTES
            assert all(
                isinstance(item, list)
                and len(item) == 2
                and item[1] == dict(rows)[item[0]]
                for item in value["rows"])


@pytest.mark.parametrize("field", ("count", "depth"))
def test_fact_order_incremental_wiring_rejects_forged_descriptor(field):
    objects = {}
    descriptor = snapshot.build_fact_order(
        (row(0), row(1)), SEED, emitter(objects))
    forged = dict(descriptor)
    forged[field] += 1
    emitted = []

    with pytest.raises(ValueError, match="merkle map root metadata"):
        snapshot.update_fact_order(
            forged, (), SEED, objects.get, emitted.append)
    assert emitted == []


def test_root_has_four_uniform_descriptors_and_no_cache_identity():
    objects = {}
    order = snapshot.build_fact_order(
        (row(0),), SEED, emitter(objects))
    maps = {
        name: order if name == snapshot.FACT_ORDER
        else snapshot.empty_descriptor()
        for name in snapshot.MAP_NAMES
    }
    raw = snapshot.encode_root(WORKSPACE, maps, seed=SEED)
    decoded = snapshot.decode_root(raw)
    assert set(decoded.maps) == set(snapshot.MAP_NAMES)
    assert decoded.maps[snapshot.FACT_ORDER] == order
    assert set(__import__("json").loads(raw)) == {
        "anchor", "layout_seed", "maps", "stamp"}


@pytest.mark.parametrize(
    "bad",
    (
        ("not-a-fact-key", "0" * 64),
        (key_parts(1, "0" * 64), "not-an-oid"),
        (key_parts(1, "0" * 64), None),
    ),
)
def test_fact_order_rejects_noncanonical_rows_before_emit(bad):
    emitted = []
    with pytest.raises(ValueError, match="FactOrder row"):
        snapshot.build_fact_order((bad,), SEED, emitted.append)
    assert emitted == []
