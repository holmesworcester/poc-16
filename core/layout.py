"""Byte-compatible reader/builder for pre-fat flat manifests."""
from dataclasses import replace

from . import tree
from .crypto import h
from .shape import FACT, cut_positions


def layout(keys, fact_of, deps_of, anchor, globals_, memo=None):
    """Return legacy manifest bytes and newly materialized leaf objects."""
    objects = {}

    def emit(raw):
        oid = h(raw)
        objects["obj/" + oid] = raw
        return oid

    legacy = replace(FACT, cuts=cut_positions)
    view = tree.build(
        keys, legacy, tree.FLAT, fact_of, deps_of, emit, memo)
    manifest = tree.encode_root(
        tree.Root(view, anchor, frozenset(globals_)))
    return manifest, objects
