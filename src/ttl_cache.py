# Generic TTL cache
import time
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class TTLCache(Generic[T]):
    """Generic TTL-based cache for expensive operations."""

    def __init__(self, ttl: float, fetch_fn: Callable[[], T], default: T) -> None:
        self._ttl = ttl
        self._fetch_fn = fetch_fn
        self._default = default
        self._cache: T = default
        self._cache_ts: float = 0

    def get(self, force_refresh: bool = False) -> T:
        """Return cached value or refresh if TTL expired."""
        now = time.time()
        if force_refresh or (now - self._cache_ts) >= self._ttl:
            try:
                self._cache = self._fetch_fn()
                self._cache_ts = now
            except Exception:
                pass
        return self._cache

    def invalidate(self) -> None:
        """Force next get() to refresh."""
        self._cache_ts = 0
