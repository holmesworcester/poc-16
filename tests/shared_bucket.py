"""Deterministic shared ObjectStore scheduler for concurrency tests.

Every operation has one atomic linearization point guarded by the bucket lock.
Tests may pause or crash an actor immediately before or after that point,
without sleeps.  The resulting history is replayable against the same small
object-map/root-CAS state machine used by the abstract model.
"""
from dataclasses import dataclass, field
import random
import threading

from core.crypto import h
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    STALE,
    ListPage as ObjectListPage,
    Versioned,
    VersionToken,
    authoritative_key,
    mutable_key,
    validate_create,
    validate_key,
)
from core.limits import PAGE_BATCH, PayloadTooLarge


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
    expected: object
    before: object
    result: object
    after: object


@dataclass(frozen=True)
class Commit:
    seq: int
    root: bytes
    objects: tuple


@dataclass(frozen=True)
class _ListRequest:
    cursor: str | None
    after_key: str | None
    limit: int


@dataclass(frozen=True)
class _HistoryListPage:
    keys: tuple[str, ...]
    cursor: str | None
    truncated: bool


class ScriptedBucket:
    """Strong in-memory ObjectStore with deterministic concurrency gates.

    Tokens are seeded opaque capabilities.  The default schedule deliberately
    reuses a token when bytes return through value ABA, without deriving that
    token from the bytes or requiring globally unique generations.
    """

    def __init__(self, initial=None, *, seed=0xC0F016):
        if type(seed) is not int:
            raise TypeError("integer seed required")
        self.seed = seed
        self._random = random.Random(seed)
        self._value_tokens = {}
        self._token_values = {}
        self.initial = dict(initial or {})
        self._data = dict(self.initial)
        self._tokens = {
            key: self._issue_token(key, value)
            for key, value in sorted(self.initial.items())
        }
        self.initial_tokens = dict(self._tokens)
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

    def _issue_token(self, key, value):
        token = self._value_tokens.get(value)
        if token is None:
            while True:
                token = VersionToken(
                    f"opaque:{self._random.getrandbits(128):032x}")
                incumbent = self._token_values.get(token.value)
                if incumbent is None or incumbent == value:
                    break
            self._value_tokens[value] = token
            self._token_values[token.value] = value
        return token

    def _current_token(self, key):
        return self._tokens.get(key, ABSENT)

    @staticmethod
    def _cas_matches(key, expected, current):
        return current == expected

    def _after_cas_applied(self, key, expected, value, result):
        pass

    def _get(self, actor, key):
        validate_key(key)
        self._gate(actor, "get", key, "before")
        with self._lock:
            before = self._current_token(key)
            result = self._data.get(key)
            self._record(
                actor, "get", key, None, None, before, result, before)
        self._gate(actor, "get", key, "after")
        return result

    def _read_versioned(self, actor, key):
        validate_key(key)
        self._gate(actor, "read_versioned", key, "before")
        with self._lock:
            before = self._current_token(key)
            value = self._data.get(key)
            result = ABSENT if value is None else Versioned(value, before)
            self._record(
                actor, "read_versioned", key, None, None,
                before, result, before)
        self._gate(actor, "read_versioned", key, "after")
        return result

    def _has(self, actor, key):
        validate_key(key)
        self._gate(actor, "has", key, "before")
        with self._lock:
            before = self._current_token(key)
            result = key in self._data
            self._record(
                actor, "has", key, None, None,
                before, result, before)
        self._gate(actor, "has", key, "after")
        return result

    def _put(self, actor, key, value):
        key = validate_key(key)
        if not isinstance(value, bytes):
            raise TypeError("object value must be bytes")
        if authoritative_key(key):
            raise ValueError("authoritative keys require conditional writes")
        self._gate(actor, "put", key, "before")
        with self._lock:
            before = self._current_token(key)
            self._data[key] = value
            after = self._issue_token(key, value)
            self._tokens[key] = after
            self._record(
                actor, "put", key, value, None, before, after, after)
        self._gate(actor, "put", key, "after")

    def _put_if_absent(self, actor, key, value):
        key = validate_create(key, value)
        self._gate(actor, "put_if_absent", key, "before")
        with self._lock:
            before = self._current_token(key)
            existing = self._data.get(key)
            created = existing is None
            if created:
                self._data[key] = value
                self._tokens[key] = self._issue_token(key, value)
            after = self._current_token(key)
            result = CREATED if created else EXISTS
            self._record(
                actor, "put_if_absent", key, value, None,
                before, result, after)
        self._gate(actor, "put_if_absent", key, "after")
        return result

    def _cas(self, actor, key, expected, value):
        key = validate_key(key)
        if not isinstance(value, bytes):
            raise TypeError("object value must be bytes")
        if not mutable_key(key):
            raise ValueError("key is not a CAS register")
        if expected is not ABSENT and not isinstance(expected, VersionToken):
            raise TypeError("version token")
        self._gate(actor, "cas", key, "before")
        with self._lock:
            before = self._current_token(key)
            if self._cas_matches(key, expected, before):
                self._data[key] = value
                self._tokens[key] = self._issue_token(key, value)
                result = Applied(self._tokens[key])
                self._after_cas_applied(
                    key, expected, value, result)
            else:
                result = STALE
            after = self._current_token(key)
            event = self._record(
                actor, "cas", key, value, expected,
                before, result, after)
            if isinstance(result, Applied) and key == "authority":
                objects = tuple(sorted(
                    (name[4:], raw)
                    for name, raw in self._data.items()
                    if name.startswith("obj/")))
                self.commits.append(Commit(event.seq, value, objects))
        self._gate(actor, "cas", key, "after")
        return result

    def _list(self, actor, prefix):
        if not isinstance(prefix, str):
            raise ValueError("bad list prefix")
        logical = prefix[:-1] if prefix.endswith("/") else prefix
        if logical:
            validate_key(logical)
        self._gate(actor, "list", prefix, "before")
        with self._lock:
            result = tuple(sorted(
                key for key in self._data if key.startswith(prefix)))
            self._record(
                actor, "list", prefix, None, None,
                None, result, None)
        self._gate(actor, "list", prefix, "after")
        return list(result)

    def _list_page(self, actor, prefix, cursor, limit):
        """Return one genuinely bounded page for applier contract tests."""
        if not isinstance(prefix, str):
            raise ValueError("bad list prefix")
        logical = prefix[:-1] if prefix.endswith("/") else prefix
        if logical:
            validate_key(logical)
        if cursor is not None:
            validate_key(cursor)
        if type(limit) is not int or not 0 < limit <= PAGE_BATCH:
            raise ValueError("list page limit")
        self._gate(actor, "list_page", prefix, "before")
        with self._lock:
            eligible = tuple(sorted(
                key for key in self._data
                if key.startswith(prefix)
                and (cursor is None or key > cursor)
            ))
            keys = eligible[:limit]
            truncated = len(eligible) > limit
            next_cursor = keys[-1] if truncated else None
            request = _ListRequest(cursor, cursor, limit)
            page = _HistoryListPage(keys, next_cursor, truncated)
            self._record(
                actor, "list_page", prefix, None, request,
                eligible, page, eligible)
        self._gate(actor, "list_page", prefix, "after")
        return ObjectListPage(keys, next_cursor)

    def _delete(self, actor, key):
        key = validate_key(key)
        if authoritative_key(key):
            raise ValueError("authoritative keys are not deletable")
        self._gate(actor, "delete", key, "before")
        with self._lock:
            before = self._current_token(key)
            existed = self._data.pop(key, None) is not None
            self._tokens.pop(key, None)
            self._record(
                actor, "delete", key, None, None,
                before, existed, ABSENT)
        self._gate(actor, "delete", key, "after")

    def assert_valid_history(self):
        """Replay every completed operation and compare the terminal map."""
        data = dict(self.initial)
        tokens = dict(self.initial_tokens)
        token_values = {}
        cursors = {}

        def current(key):
            return tokens.get(key, ABSENT)

        def observe(key, token, value):
            if token is ABSENT:
                assert value is None
                return
            identity = (key, token.value)
            incumbent = token_values.setdefault(identity, value)
            assert incumbent == value

        for key, value in data.items():
            observe(key, tokens[key], value)
        for seq, event in enumerate(self.history, 1):
            assert event.seq == seq
            if event.op == "list":
                before = None
            elif event.op == "list_page":
                request = event.expected
                assert request.cursor is None \
                    or cursors[request.cursor] == request.after_key
                before = tuple(sorted(
                    key for key in data
                    if key.startswith(event.key)
                    and (
                        request.after_key is None
                        or key > request.after_key)
                ))
            else:
                before = current(event.key)
            assert event.before == before
            if event.op == "get":
                assert event.result == data.get(event.key)
                observe(event.key, before, event.result)
            elif event.op == "read_versioned":
                expected = ABSENT if event.key not in data else Versioned(
                    data[event.key], before)
                assert event.result == expected
                if isinstance(expected, Versioned):
                    observe(event.key, expected.token, expected.value)
            elif event.op == "has":
                assert event.result is (event.key in data)
                observe(event.key, before, data.get(event.key))
            elif event.op == "put":
                data[event.key] = event.value
                tokens[event.key] = event.after
                assert event.result == event.after
                observe(event.key, event.after, event.value)
            elif event.op == "put_if_absent":
                created = event.key not in data
                assert event.result is (
                    CREATED if created else EXISTS)
                if created:
                    data[event.key] = event.value
                    tokens[event.key] = event.after
                observe(event.key, event.after, data[event.key])
            elif event.op == "cas":
                if before == event.expected:
                    data[event.key] = event.value
                    tokens[event.key] = event.after
                    assert event.result == Applied(event.after)
                    observe(event.key, event.after, event.value)
                else:
                    assert event.result is STALE
            elif event.op == "list":
                assert event.result == tuple(sorted(
                    key for key in data if key.startswith(event.key)))
            elif event.op == "list_page":
                page = event.result
                assert page.keys == before[:event.expected.limit]
                assert page.truncated is (
                    len(before) > event.expected.limit)
                if page.truncated:
                    assert page.keys
                    assert isinstance(page.cursor, str) and page.cursor
                    incumbent = cursors.setdefault(
                        page.cursor, page.keys[-1])
                    assert incumbent == page.keys[-1]
                else:
                    assert page.cursor is None
            elif event.op == "delete":
                assert not authoritative_key(event.key)
                assert event.result is (event.key in data)
                data.pop(event.key, None)
                tokens.pop(event.key, None)
            else:
                raise AssertionError(f"unknown history operation {event.op}")
            after = before if event.op == "list_page" else (
                current(event.key)
                if event.op != "list" else None)
            assert event.after == after
        assert data == self._data
        assert tokens == self._tokens
        return True


class BucketHandle:
    def __init__(self, bucket, actor):
        self.bucket = bucket
        self.actor = actor

    def get(self, key):
        return self.bucket._get(self.actor, key)

    def get_bounded(self, key, maximum):
        if type(maximum) is not int or maximum < 1:
            raise ValueError("bounded read limit")
        value = self.bucket._get(self.actor, key)
        if value is not None and len(value) > maximum:
            raise PayloadTooLarge("bucket read exceeds byte limit")
        return value

    def read_versioned(self, key):
        return self.bucket._read_versioned(self.actor, key)

    def has(self, key):
        return self.bucket._has(self.actor, key)

    def put(self, key, value):
        return self.bucket._put(self.actor, key, value)

    def put_if_absent(self, key, value):
        return self.bucket._put_if_absent(self.actor, key, value)

    def cas(self, key, expected, value):
        return self.bucket._cas(self.actor, key, expected, value)

    def list(self, prefix):
        return self.bucket._list(self.actor, prefix)

    def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        return self.bucket._list_page(
            self.actor, prefix, cursor, limit)

    def delete(self, key):
        return self.bucket._delete(self.actor, key)
