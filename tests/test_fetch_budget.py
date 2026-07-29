"""Authorization object-read budget contracts."""
import pytest

from core.fetch_budget import BudgetedFetch, FetchBudgetExceeded


def test_budgeted_fetch_memoizes_bytes_and_misses():
    calls = []

    def fetch(oid):
        calls.append(oid)
        return b"abc" if oid == "hit" else None

    bounded = BudgetedFetch(fetch, max_fetches=2, max_bytes=3)
    assert bounded("hit") == b"abc"
    assert bounded("hit") == b"abc"
    assert bounded("miss") is None
    assert bounded("miss") is None
    assert calls == ["hit", "miss"]
    assert (bounded.fetches, bounded.bytes) == (2, 3)


def test_budgeted_fetch_checks_before_unbounded_work_or_cache_insert():
    fetches = BudgetedFetch(
        lambda oid: b"x", max_fetches=0, max_bytes=10)
    with pytest.raises(FetchBudgetExceeded, match="unique"):
        fetches("new")

    byte_bound = BudgetedFetch(
        lambda oid: b"large", max_fetches=1, max_bytes=4)
    with pytest.raises(FetchBudgetExceeded, match="byte"):
        byte_bound("new")
    assert byte_bound.cache == {}
