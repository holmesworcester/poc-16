"""The old treap is a finite read-only cutover decoder, never a writer."""
import json

import pytest

from core import legacy_v7
from core.crypto import h
from core.fact import canon

SEED = "ab" * 32


def _page(key, value, left="", right="", count=1, depth=1):
    raw = canon({
        "count": count,
        "depth": depth,
        "format": legacy_v7.FORMAT,
        "key": key,
        "left": left,
        "priority": legacy_v7._priority(SEED, key),
        "right": right,
        "value": value,
    })
    return h(raw), raw


def test_v7_decoder_recovers_a_finite_ordered_fixture():
    left_oid, left = _page("a", 1)
    right_oid, right = _page("z", 3)
    candidates = []
    for key in ("b", "m", "y"):
        oid, raw = _page(
            key, 2, left_oid, right_oid, count=3, depth=2)
        priority = json.loads(raw)["priority"]
        if priority <= min(
                json.loads(left)["priority"],
                json.loads(right)["priority"]):
            candidates.append((oid, raw))
    if not candidates:
        # Deterministically find a valid old Cartesian-tree parent.
        for number in range(10_000):
            oid, raw = _page(
                f"m:{number:04d}", 2,
                left_oid, right_oid, count=3, depth=2)
            priority = json.loads(raw)["priority"]
            if priority <= min(
                    json.loads(left)["priority"],
                    json.loads(right)["priority"]):
                candidates.append((oid, raw))
                break
    root_oid, root = candidates[0]
    objects = {left_oid: left, right_oid: right, root_oid: root}
    expected_key = json.loads(root)["key"]
    assert legacy_v7.Reader(
        root_oid, SEED, objects.get, max_pages=3
    ).items() == (("a", 1), (expected_key, 2), ("z", 3))


def test_v7_decoder_has_no_write_api_and_enforces_page_budget():
    assert not hasattr(legacy_v7, "build")
    assert not hasattr(legacy_v7, "update")
    oid, raw = _page("only", 1)
    assert legacy_v7.Reader(
        oid, SEED, {oid: raw}.get, max_pages=1
    ).items() == (("only", 1),)
    with pytest.raises(ValueError, match="legacy v7 read budget"):
        legacy_v7.Reader(
            oid, SEED, {oid: raw}.get, max_pages=0)
