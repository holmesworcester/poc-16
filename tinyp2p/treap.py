"""Compatibility façade for the engine's binary packing.

The prototype's public dict shape stays available to benches; construction and
folding live only in :mod:`tinyp2p.tree`.
"""
from . import tree
from .crypto import h
from .shape import FACT


def _dict(view):
    if view.level == 0:
        return {
            "leaf": True, "ks": list(view.keys),
            "n": view.n, "hash": view.oid,
        }
    left, right = view.children
    return {
        "leaf": False, "sep": left.sep, "n": view.n, "hash": view.oid,
        "L": _dict(left), "R": _dict(right),
    }


def _view(node):
    if node["leaf"]:
        keys = tuple(node["ks"])
        return tree.View(
            FACT.fingerprint(keys), node["hash"],
            keys[-1] if keys else "", node["n"], (), keys,
        )
    left, right = _view(node["L"]), _view(node["R"])
    level = max(left.level, right.level) + 1
    return tree.View(
        tree._fp("binary", level, (left, right)), node["hash"],
        right.sep, node["n"], (left, right),
        level=level, kind="binary",
    )


def build(keys, fact_of, deps_of):
    objects = {}

    def emit(raw):
        oid = h(raw)
        objects[oid] = raw
        return oid

    return _dict(tree.build(
        keys, FACT, tree.BINARY, fact_of, deps_of, emit)), objects


def update(node, delta, fact_of, deps_of, objects):
    def emit(raw):
        oid = h(raw)
        objects[oid] = raw
        return oid

    view = tree.fold(
        _view(node), delta, FACT, tree.BINARY, fact_of, deps_of,
        objects.get, emit,
    )
    return _dict(view)


def _leaf_keys(node):
    if node["leaf"]:
        return list(node["ks"])
    return _leaf_keys(node["L"]) + _leaf_keys(node["R"])


def live_hashes(node):
    if node["leaf"]:
        return {node["hash"]} if node["n"] else set()
    return live_hashes(node["L"]) | live_hashes(node["R"])
