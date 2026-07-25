"""Pure tree-shape parameters and their single-definition contract."""
import ast
from pathlib import Path

from core import shape
from core.crypto import h
from core.fact import Fact

ROOT = Path(__file__).parents[1]


def fid(prefix):
    return f"{prefix:08x}" + "0" * 56


def test_fact_key_round_trips_through_fact_shape():
    fact = Fact("sample", 7, [], {})
    expected = f"{fact.ts:015d}:{fact.fid}"

    assert fact.key == shape.key(fact) == shape.FACT.key(fact) == expected
    assert shape.fid_of(expected) == fact.fid
    assert shape.fid_of(f"chan:x|0|{expected}") == fact.fid


def test_hash_derived_boundary_priority_and_fingerprint():
    item = fid(16)
    keys = ["a", "b"]

    assert shape.boundary(item, 8)
    assert not shape.boundary(fid(17), 8)
    assert shape.priority(item) == int(item, 16)
    assert shape.fingerprint(keys) == h(b"a|b")


def test_cut_tiers_preserve_cold_pages_and_fine_guard(monkeypatch):
    fids = [fid(number) for number in range(1, 11)]
    monkeypatch.setattr(shape, "CUT", 2)
    monkeypatch.setattr(shape, "COLD_CUT", 4)
    monkeypatch.setattr(shape, "GUARD", 2)

    assert shape.cut_positions(fids) == [4, 8, 10]
    monkeypatch.setattr(shape, "COLD_CUT", None)
    assert shape.cut_positions(fids) == [2, 4, 6, 8, 10]


def test_shape_is_the_single_definition_site():
    forbidden = {
        "core/layout.py": {"boundary", "_cut_positions", "fingerprint"},
        "core/treap.py": {"_fid", "priority"},
        "core/hoist.py": {"_fid", "priority"},
    }
    for relative, names in forbidden.items():
        tree = ast.parse((ROOT / relative).read_text())
        definitions = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert definitions.isdisjoint(names)
