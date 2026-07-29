"""Pure key-discipline parameters: format and stable boundary."""
import pytest

from core import shape
from core.fact import Fact


def fid(prefix):
    return f"{prefix:08x}" + "0" * 56


def test_fact_key_round_trips_through_fact_shape():
    fact = Fact("sample", 7, [], {})
    expected = f"{fact.ts:015d}:{fact.fid}"

    assert fact.key == shape.key(fact) == expected
    assert shape.key_parts(fact.ts, fact.fid) == expected
    assert shape.fid_of(expected) == fact.fid


def test_fact_address_door_is_exact_and_bounded():
    low = shape.key_parts(shape.FACT_TS_MIN, "0" * 64)
    high = shape.key_parts(shape.FACT_TS_MAX, "f" * 64)

    assert len(low.encode()) == len(high.encode()) == shape.FACT_KEY_BYTES == 80
    assert shape.parse_key(low) == (shape.FACT_TS_MIN, "0" * 64)
    assert shape.parse_key(high) == (shape.FACT_TS_MAX, "f" * 64)

    bad_parts = (
        (True, "0" * 64),
        (-1, "0" * 64),
        (shape.FACT_TS_MAX + 1, "0" * 64),
        (0, "0" * 63),
        (0, "0" * 65),
        (0, "A" * 64),
        (0, "g" * 64),
    )
    for ts, content_id in bad_parts:
        with pytest.raises(ValueError, match="fact address"):
            shape.key_parts(ts, content_id)

    bad_wire = (
        "-00000000000001:" + "0" * 64,
        "+00000000000000:" + "0" * 64,
        "0000000000000000:" + "0" * 64,
        " 00000000000000:" + "0" * 64,
        "000000000000000: " + "0" * 64,
        "000000000000000:" + "A" * 64,
        "000000000000000:" + "0" * 63,
        "000000000000000::" + "0" * 64,
        "٠٠٠٠٠٠٠٠٠٠٠٠٠٠٠:" + "0" * 64,
    )
    for value in bad_wire:
        assert not shape.is_key(value)
        with pytest.raises(ValueError, match="fact address"):
            shape.parse_key(value)


@pytest.mark.parametrize(
    "timestamp",
    (True, False, -1, shape.FACT_TS_MAX + 1),
)
def test_fact_constructor_rejects_noncanonical_timestamp(timestamp):
    with pytest.raises(ValueError, match="fact timestamp"):
        Fact("sample", timestamp, [], {})


def test_hash_derived_boundary(monkeypatch):
    monkeypatch.setattr(shape, "CUT", 8)

    assert shape.boundary(fid(16))
    assert not shape.boundary(fid(17))


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
