"""Composite snapshot and the direct eligible-fact order map.

One mutable ``root`` value atomically names four immutable bounded Merkle
maps:

``fact_order``
    Eligible ``fact.key -> fact object oid`` rows.  This is an ordering and
    transfer projection only; admission authority lives in Fact records and
    their historical proof DAGs.

``fact``, ``supp``, ``authority``
    The exact candidate, suppression, and selected-authority indexes described
    by :mod:`core.indexes`.

Every map uses the same history-independent codec and descriptor shape.  There
is no range directory, grouped pile leaf, closure sibling, action cache stamp,
or second mutable root.
"""
from typing import NamedTuple

from . import merkle_map
from .crypto import h
from .fact import canon
from .limits import MAX_ROOT_BYTES, decode_json
from .shape import is_key, valid_fid

LAYOUT = "composite-merkle-map-v8-admission-proof-archive"
FACT_ORDER = "fact_order"
TREE_NAMES = ("fact", "supp", "authority")
MAP_NAMES = (FACT_ORDER, *TREE_NAMES)


class Root(NamedTuple):
    """One fully checked snapshot named by the mutable ``root`` key."""

    anchor: str
    layout_seed: str
    maps: dict


def layout_seed(anchor):
    """Bind every map page to this workspace and format family."""
    if not valid_fid(anchor):
        raise ValueError("snapshot anchor")
    return h(canon(["composite-layout-seed-v1", anchor]))


def empty_descriptor():
    return {"root": "", "count": 0, "depth": 0}


def descriptor(built):
    """Normalize one map build result into the root's wire descriptor."""
    return {
        "root": built.root,
        "count": built.count,
        "depth": built.page_depth,
    }


def _descriptor_ok(value):
    return isinstance(value, dict) \
        and set(value) == {"root", "count", "depth"} \
        and isinstance(value["root"], str) \
        and (not value["root"] or valid_fid(value["root"])) \
        and type(value["count"]) is int and value["count"] >= 0 \
        and type(value["depth"]) is int \
        and 0 <= value["depth"] <= merkle_map.MAX_PAGE_DEPTH \
        and bool(value["root"]) == bool(value["count"]) \
        and bool(value["root"]) == bool(value["depth"])


def _maps_ok(maps):
    return isinstance(maps, dict) and set(maps) == set(MAP_NAMES) \
        and all(_descriptor_ok(value) for value in maps.values())


def encode_root(anchor, maps=None, *, seed=None):
    """Encode the exact four-map snapshot advanced by one root CAS."""
    seed = layout_seed(anchor) if seed is None else seed
    if seed != layout_seed(anchor):
        raise ValueError("snapshot layout seed")
    maps = maps or {name: empty_descriptor() for name in MAP_NAMES}
    if not _maps_ok(maps):
        raise ValueError("snapshot maps")
    return canon({
        "anchor": anchor,
        "layout_seed": seed,
        "maps": maps,
        "stamp": LAYOUT,
    })


def decode_root(raw):
    """Strictly decode the current root format; old layouts are not accepted."""
    value = decode_json(raw, MAX_ROOT_BYTES, "root")
    if not isinstance(value, dict) or set(value) != {
            "anchor", "layout_seed", "maps", "stamp"} \
            or value.get("stamp") != LAYOUT \
            or not valid_fid(value.get("anchor")) \
            or value.get("layout_seed") != layout_seed(value["anchor"]) \
            or not _maps_ok(value.get("maps")):
        raise ValueError("root shape")
    return Root(
        value["anchor"],
        value["layout_seed"],
        {
            name: dict(value["maps"][name])
            for name in MAP_NAMES
        },
    )


def _fact_order_row(row):
    if not isinstance(row, (tuple, list)) or len(row) != 2 \
            or not is_key(row[0]) or not valid_fid(row[1]):
        raise ValueError("FactOrder row")
    return row[0], row[1]


def build_fact_order(rows, seed, emit):
    """Build the canonical direct ``fact.key -> fact oid`` projection."""
    checked = tuple(_fact_order_row(row) for row in rows)
    return descriptor(merkle_map.build(checked, seed, emit))


def update_fact_order(descriptor_value, changes, seed, fetch, emit):
    """Path-copy an exact eligible activation/deactivation batch."""
    if not _descriptor_ok(descriptor_value):
        raise ValueError("FactOrder descriptor")
    checked = []
    for row in changes:
        if not isinstance(row, tuple) or len(row) != 2 \
                or not is_key(row[0]) \
                or row[1] is not None and not valid_fid(row[1]):
            raise ValueError("FactOrder change")
        checked.append(row)
    built = merkle_map.update(
        descriptor_value["root"], seed, tuple(checked), fetch, emit)
    return descriptor(built)


def fact_order_rows(descriptor_value, seed, fetch):
    """Maintenance-only full traversal with exact descriptor verification."""
    if not _descriptor_ok(descriptor_value):
        raise ValueError("FactOrder descriptor")
    count = descriptor_value["count"]
    if not descriptor_value["root"]:
        if descriptor_value != empty_descriptor():
            raise ValueError("FactOrder descriptor")
        return ()
    reader = merkle_map.Reader(
        descriptor_value["root"], seed, fetch,
        max_page_depth=descriptor_value["depth"])
    rows = reader.items(max_pages=max(1, 2 * count - 1))
    checked = tuple(_fact_order_row(row) for row in rows)
    if len(checked) != count:
        raise ValueError("FactOrder descriptor count")
    return checked

