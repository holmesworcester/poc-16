"""Pure key-discipline parameters: format, boundary, fingerprint."""
from core import shape
from core.crypto import h
from core.fact import Fact


def fid(prefix):
    return f"{prefix:08x}" + "0" * 56


def test_fact_key_round_trips_through_fact_shape():
    fact = Fact("sample", 7, [], {})
    expected = f"{fact.ts:015d}:{fact.fid}"

    assert fact.key == shape.key(fact) == expected
    assert shape.key_parts(fact.ts, fact.fid) == expected
    assert shape.fid_of(expected) == fact.fid


def test_hash_derived_boundary_and_fingerprint(monkeypatch):
    monkeypatch.setattr(shape, "CUT", 8)
    keys = ["a", "b"]

    assert shape.boundary(fid(16))
    assert not shape.boundary(fid(17))
    assert shape.fingerprint(keys) == h(b"a|b")


def test_stable_cuts_are_monotone(monkeypatch):
    """Adding keys never removes a boundary — the settle's licence to
    rebuild only the touched leaf and shard."""
    monkeypatch.setattr(shape, "CUT", 2)
    fids = [fid(number) for number in range(1, 11)]

    assert shape.stable_cut_positions(fids) == [2, 4, 6, 8, 10]
    for stop in range(len(fids)):
        prefix = shape.stable_cut_positions(fids[:stop])
        assert prefix == [
            cut for cut in shape.stable_cut_positions(fids) if cut <= stop]
