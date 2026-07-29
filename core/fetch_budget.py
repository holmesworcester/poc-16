"""Request-local immutable-read memoization and resource accounting."""


class FetchBudgetExceeded(ValueError):
    """An authorization decision exceeded its configured read budget."""


class BudgetedFetch:
    """Memoize object reads and bound unique requests plus returned bytes."""

    def __init__(self, fetch, *, max_fetches, max_bytes):
        if max_fetches < 0 or max_bytes < 0:
            raise ValueError("fetch budget")
        self.fetch = fetch
        self.max_fetches = max_fetches
        self.max_bytes = max_bytes
        self.cache = {}
        self.fetches = 0
        self.bytes = 0

    def __call__(self, oid):
        if oid in self.cache:
            return self.cache[oid]
        if self.fetches >= self.max_fetches:
            raise FetchBudgetExceeded("unique object-fetch budget")
        self.fetches += 1
        raw = self.fetch(oid)
        if raw is not None:
            if not isinstance(raw, bytes):
                raise TypeError("object fetch returned non-bytes")
            if self.bytes + len(raw) > self.max_bytes:
                raise FetchBudgetExceeded("object-fetch byte budget")
            self.bytes += len(raw)
        self.cache[oid] = raw
        return raw
