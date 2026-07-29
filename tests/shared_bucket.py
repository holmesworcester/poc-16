"""Deterministic shared ObjectStore scheduler for concurrency tests.

Every operation has one atomic linearization point guarded by the bucket lock.
Tests may pause or crash an actor immediately before or after that point,
without sleeps.  The resulting history is replayable against the same small
object-map/root-CAS state machine used by the abstract model.
"""
from dataclasses import dataclass, field
import threading

from core.crypto import h


class InjectedCrash(RuntimeError):
    pass


@dataclass
class Gate:
    actor: str
    op: str
    key: str
    when: str
    nth: int
    error: Exception | None = None
    entered: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)
    seen: int = 0

    def wait(self):
        if not self.entered.wait(timeout=5):
            raise AssertionError(
                f"operation did not reach {self.actor}.{self.op}.{self.when}")


@dataclass(frozen=True)
class Event:
    seq: int
    actor: str
    op: str
    key: str
    value: bytes | None
    expected: str | None
    before: str | None
    result: object
    after: str | None


@dataclass(frozen=True)
class Commit:
    seq: int
    root: bytes
    objects: tuple


def _etag(value):
    return h(value) if value is not None else None


class ScriptedBucket:
    def __init__(self, initial=None):
        self.initial = dict(initial or {})
        self._data = dict(self.initial)
        self._lock = threading.Lock()
        self._rules_lock = threading.Lock()
        self._rules = []
        self.history = []
        self.commits = []

    def handle(self, actor):
        return BucketHandle(self, actor)

    def pause(self, actor, op, key, *, when="before", nth=1):
        if when not in {"before", "after"} or nth < 1:
            raise ValueError("gate")
        gate = Gate(actor, op, key, when, nth)
        with self._rules_lock:
            self._rules.append(gate)
        return gate

    def crash(self, actor, op, key, *, when="before", nth=1):
        gate = self.pause(actor, op, key, when=when, nth=nth)
        gate.error = InjectedCrash(
            f"{actor} crashed {when} {op}({key})")
        gate.release.set()
        return gate

    def _gate(self, actor, op, key, when):
        triggered = []
        with self._rules_lock:
            for rule in self._rules:
                if (rule.actor, rule.op, rule.key, rule.when) != (
                        actor, op, key, when):
                    continue
                rule.seen += 1
                if rule.seen == rule.nth:
                    triggered.append(rule)
        for rule in triggered:
            rule.entered.set()
            if not rule.release.wait(timeout=5):
                raise AssertionError(
                    f"gate not released: {actor}.{op}.{when}")
            if rule.error is not None:
                raise rule.error

    def _record(
            self, actor, op, key, value, expected, before, result, after):
        event = Event(
            len(self.history) + 1, actor, op, key, value, expected,
            before, result, after)
        self.history.append(event)
        return event

    def _get(self, actor, key):
        self._gate(actor, "get", key, "before")
        with self._lock:
            before = _etag(self._data.get(key))
            result = self._data.get(key)
            self._record(
                actor, "get", key, None, None, before, result, before)
        self._gate(actor, "get", key, "after")
        return result

    def _put(self, actor, key, value):
        if key == "root" or key.startswith("obj/"):
            raise ValueError("authoritative keys require conditional writes")
        self._gate(actor, "put", key, "before")
        with self._lock:
            before = _etag(self._data.get(key))
            self._data[key] = value
            after = h(value)
            self._record(
                actor, "put", key, value, None, before, after, after)
        self._gate(actor, "put", key, "after")
        return after

    def _put_if_absent(self, actor, key, value):
        if not key.startswith("obj/") or key[4:] != h(value):
            raise ValueError("immutable object address")
        self._gate(actor, "put_if_absent", key, "before")
        with self._lock:
            before = _etag(self._data.get(key))
            existing = self._data.get(key)
            if existing is not None and existing != value:
                raise ValueError("immutable object conflict")
            created = existing is None
            if created:
                self._data[key] = value
            after = _etag(self._data.get(key))
            self._record(
                actor, "put_if_absent", key, value, None,
                before, created, after)
        self._gate(actor, "put_if_absent", key, "after")
        return created

    def _cas(self, actor, key, expected, value):
        if key != "root":
            raise ValueError("only root is mutable by CAS")
        self._gate(actor, "cas", key, "before")
        with self._lock:
            before = _etag(self._data.get(key))
            if before == expected:
                self._data[key] = value
                result = h(value)
            else:
                result = None
            after = _etag(self._data.get(key))
            event = self._record(
                actor, "cas", key, value, expected,
                before, result, after)
            if result is not None:
                objects = tuple(sorted(
                    (name[4:], raw)
                    for name, raw in self._data.items()
                    if name.startswith("obj/")))
                self.commits.append(Commit(event.seq, value, objects))
        self._gate(actor, "cas", key, "after")
        return result

    def _list(self, actor, prefix):
        self._gate(actor, "list", prefix, "before")
        with self._lock:
            result = tuple(sorted(
                key for key in self._data if key.startswith(prefix)))
            self._record(
                actor, "list", prefix, None, None,
                None, result, None)
        self._gate(actor, "list", prefix, "after")
        return list(result)

    def _delete(self, actor, key):
        if key == "root" or key.startswith("obj/"):
            raise ValueError("authoritative keys are not deletable")
        self._gate(actor, "delete", key, "before")
        with self._lock:
            before = _etag(self._data.get(key))
            existed = self._data.pop(key, None) is not None
            self._record(
                actor, "delete", key, None, None,
                before, existed, None)
        self._gate(actor, "delete", key, "after")

    def assert_valid_history(self):
        """Replay every completed operation and compare the terminal map."""
        data = dict(self.initial)
        for seq, event in enumerate(self.history, 1):
            assert event.seq == seq
            before = _etag(data.get(event.key)) \
                if event.op != "list" else None
            assert event.before == before
            if event.op == "get":
                assert event.result == data.get(event.key)
            elif event.op == "put":
                data[event.key] = event.value
                assert event.result == h(event.value)
            elif event.op == "put_if_absent":
                created = event.key not in data
                assert event.result is created
                if created:
                    data[event.key] = event.value
                else:
                    assert data[event.key] == event.value
            elif event.op == "cas":
                if before == event.expected:
                    data[event.key] = event.value
                    assert event.result == h(event.value)
                else:
                    assert event.result is None
            elif event.op == "list":
                assert event.result == tuple(sorted(
                    key for key in data if key.startswith(event.key)))
            elif event.op == "delete":
                assert event.result is (event.key in data)
                data.pop(event.key, None)
            else:
                raise AssertionError(f"unknown history operation {event.op}")
            after = _etag(data.get(event.key)) \
                if event.op != "list" else None
            assert event.after == after
        assert data == self._data
        return True


class BucketHandle:
    def __init__(self, bucket, actor):
        self.bucket = bucket
        self.actor = actor

    def get(self, key):
        return self.bucket._get(self.actor, key)

    def has(self, key):
        return self.get(key) is not None

    def etag(self, key):
        return _etag(self.get(key))

    def put(self, key, value):
        return self.bucket._put(self.actor, key, value)

    def put_if_absent(self, key, value):
        return self.bucket._put_if_absent(self.actor, key, value)

    def cas(self, key, expected, value):
        return self.bucket._cas(self.actor, key, expected, value)

    def list(self, prefix):
        return self.bucket._list(self.actor, prefix)

    def delete(self, key):
        return self.bucket._delete(self.actor, key)
