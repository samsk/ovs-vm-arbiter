"""Tests for src.ttl_cache."""
from src.ttl_cache import TTLCache
from src.test import _test_assert


def test_ttl_cache() -> None:
    """TTLCache: get, invalidate."""
    hit = [0]

    def fetch() -> int:
        hit[0] += 1
        return hit[0]

    c = TTLCache(ttl=10.0, fetch_fn=fetch, default=0)
    _test_assert(c.get() == 1, "first get")
    _test_assert(c.get() == 1, "cached")
    c.invalidate()
    _test_assert(c.get() == 2, "after invalidate")


def test_ttl_cache_force_refresh() -> None:
    """TTLCache: force_refresh bypasses TTL."""
    hit = [0]

    def fetch() -> int:
        hit[0] += 1
        return hit[0]

    c = TTLCache(ttl=999.0, fetch_fn=fetch, default=0)
    _test_assert(c.get() == 1, "first get")
    _test_assert(c.get(force_refresh=True) == 2, "force_refresh")
    _test_assert(c.get() == 2, "still cached")


def test_ttl_cache_fetch_exception_keeps_previous() -> None:
    """TTLCache: on fetch exception, return previous cache."""
    c = TTLCache(ttl=0.0, fetch_fn=lambda: 1, default=-1)
    _test_assert(c.get() == 1, "first fetch ok")
    c._cache_ts = 0
    c._fetch_fn = lambda: (_ for _ in ()).throw(ValueError("oops"))
    _test_assert(c.get() == 1, "exception: return previous")
