"""Provider-neutral F10 history recorded around real adapter calls.

The wrappers do not implement storage semantics. They forward every operation
to an S3/R2 ObjectStore, then normalize only acknowledged results for the
shared obligation checker. Applied-but-lost provider responses therefore enter
the history only when the running Applier performs an exact readback.
"""
import threading

from core.object_store import ABSENT, CREATED, Applied, Versioned

from .shared_bucket import Commit, Event, InjectedCrash


class ProviderHistory:
    """One replayable logical history shared by independent adapter handles."""

    _rules = ()

    def __init__(self, provider, seed, native_history):
        self.provider = provider
        self.seed = seed
        self.native_history = native_history
        self.initial = {}
        self.history = []
        self.commits = []
        self._data = {}
        self._token_values = {}
        self._crashes = set()
        self._lock = threading.Lock()

    def sync_store(self, store, actor):
        return _SyncObservedStore(self, store, actor)

    def async_store(self, store, actor):
        return _AsyncObservedStore(self, store, actor)

    def crash_after(self, actor, operation, key):
        self._crashes.add((actor, operation, key))

    def record(
            self, actor, operation, key, *,
            value=None, expected=None, result=None):
        with self._lock:
            before = self._data.get(key)
            if operation in {"get", "read_versioned"}:
                current = result.value \
                    if isinstance(result, Versioned) else result
                if current is ABSENT or current is None:
                    self._data.pop(key, None)
                else:
                    self._data[key] = current
            elif operation == "put":
                self._data[key] = value
            elif operation == "put_if_absent" and result is CREATED:
                self._data[key] = value
            elif operation == "cas" and isinstance(result, Applied):
                self._data[key] = value
            elif operation == "delete":
                result = key in self._data
                self._data.pop(key, None)
            after = self._data.get(key)
            event = Event(
                len(self.history) + 1, actor, operation, key,
                value, expected, before, result, after)
            self.history.append(event)
            if key == "root" and (
                    operation == "cas" and isinstance(result, Applied)
                    or operation == "read_versioned"
                    and isinstance(result, Versioned)):
                root = value if operation == "cas" else result.value
                token = result.token
                incumbent = self._token_values.setdefault(
                    token.value, root)
                if incumbent != root:
                    raise AssertionError(
                        "provider token aliases different root bytes")
                self.commits.append(Commit(
                    event.seq, root,
                    tuple(sorted(
                        (name[4:], raw)
                        for name, raw in self._data.items()
                        if name.startswith("obj/")))))
        if (actor, operation, key) in self._crashes:
            self._crashes.remove((actor, operation, key))
            raise InjectedCrash(
                f"{self.provider} seed={self.seed:#x} worker crashed after "
                f"{operation}({key})")
        return result

    def assert_valid_history(self):
        assert [event.seq for event in self.history] == list(
            range(1, len(self.history) + 1)), self.diagnostic()
        for token, raw in self._token_values.items():
            assert token and isinstance(raw, bytes), self.diagnostic()
        return True

    @property
    def token_values(self):
        return dict(self._token_values)

    def diagnostic(self):
        events = "\n".join(
            f"  {event.seq}. {event.actor}.{event.op}({event.key})"
            f" -> {event.result!r}"
            for event in self.history
        ) or "  <none>"
        native = "\n".join(
            f"  {event!r}" for event in self.native_history
        ) or "  <none>"
        return (
            f"provider F10 history provider={self.provider} "
            f"seed={self.seed:#x}\n"
            f"normalized:\n{events}\nnative:\n{native}")

class _ObservedStore:
    def __init__(self, history, store, actor):
        self.history, self.store, self.actor = history, store, actor

    def _record(self, operation, key, **values):
        return self.history.record(
            self.actor, operation, key, **values)


class _SyncObservedStore(_ObservedStore):
    def get_bounded(self, key, maximum):
        return self._record(
            "get", key, result=self.store.get_bounded(key, maximum))

    def read_versioned(self, key):
        return self._record(
            "read_versioned", key, result=self.store.read_versioned(key))

    def put(self, key, value):
        return self._record(
            "put", key, value=value, result=self.store.put(key, value))

    def put_if_absent(self, key, value):
        return self._record(
            "put_if_absent", key, value=value,
            result=self.store.put_if_absent(key, value))

    def cas(self, key, expected, value):
        return self._record(
            "cas", key, value=value, expected=expected,
            result=self.store.cas(key, expected, value))

    def list_page(self, prefix, cursor, limit):
        return self._record(
            "list_page", prefix, expected=(cursor, limit),
            result=self.store.list_page(prefix, cursor, limit))

    def delete(self, key):
        self.store.delete(key)
        return self._record("delete", key)


class _AsyncObservedStore(_ObservedStore):
    async def get_bounded(self, key, maximum):
        return self._record(
            "get", key,
            result=await self.store.get_bounded(key, maximum))

    async def read_versioned(self, key):
        return self._record(
            "read_versioned", key,
            result=await self.store.read_versioned(key))

    async def put(self, key, value):
        return self._record(
            "put", key, value=value,
            result=await self.store.put(key, value))

    async def put_if_absent(self, key, value):
        return self._record(
            "put_if_absent", key, value=value,
            result=await self.store.put_if_absent(key, value))

    async def cas(self, key, expected, value):
        return self._record(
            "cas", key, value=value, expected=expected,
            result=await self.store.cas(key, expected, value))

    async def list_page(self, prefix, cursor, limit):
        return self._record(
            "list_page", prefix, expected=(cursor, limit),
            result=await self.store.list_page(prefix, cursor, limit))

    async def delete(self, key):
        await self.store.delete(key)
        return self._record("delete", key)
