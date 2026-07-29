"""Seeded fault schedules over the deterministic shared-bucket history.

``AdversarialBucket`` keeps the direct-provider contract strong by default:
each key is linearizable, acknowledged mutations are immediately visible,
and opaque comparison tokens are read atomically with their bytes.  Explicit
``Nonconforming`` switches exist only as mutation tests for the laws.

Faults are attached to the before/after gates from ``ScriptedBucket``.  A
before fault has no linearized history event.  An after fault has exactly one
event even though the actor did not receive its result.  The distinction makes
not-applied and applied-but-response-lost schedules replayable without
pretending either is a failed precondition.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum

from core.object_store import (
    ABSENT,
    CREATED,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    StoreError,
    Versioned,
    VersionToken,
    validate_key,
)

from .shared_bucket import InjectedCrash, ScriptedBucket

_NO_NEGATIVE_READ = object()


class Fault(Enum):
    """ObjectStore-level failures with unambiguous mutation semantics."""

    REJECTED = "rejected"
    THROTTLED = "throttled"
    RETRYABLE_SERVICE = "retryable-service"
    TRANSPORT = "transport"
    RESPONSE_LOST = "response-lost"
    CRASH = "crash"


@dataclass(frozen=True)
class FaultRule:
    seed: int
    actor: str
    op: str
    key: str
    when: str
    nth: int
    fault: Fault


@dataclass(frozen=True)
class Nonconforming:
    """Opt-in violations used to prove that conformance checks are live."""

    acknowledged_create_invisible: bool = False
    stale_successful_reads: bool = False
    reused_cas_precondition: bool = False
    token_alias: bool = False
    destructive_objects: bool = False
    repeated_list_cursor: bool = False


@dataclass(frozen=True)
class ListRequest:
    cursor: str | None
    after_key: str | None
    limit: int


@dataclass(frozen=True)
class ListPage:
    keys: tuple[str, ...]
    cursor: str | None
    truncated: bool


def _fault_error(rule):
    label = (
        f"seed={rule.seed:#x} {rule.fault.value} {rule.when} "
        f"{rule.actor}.{rule.op}({rule.key})")
    if rule.fault is Fault.REJECTED:
        return StoreError(label)
    if rule.fault in {Fault.THROTTLED, Fault.RETRYABLE_SERVICE}:
        return RetryableStoreError(label)
    if rule.fault is Fault.TRANSPORT and rule.op in {
            "get", "read_versioned", "list", "list_page", "has"}:
        return RetryableStoreError(label)
    if rule.fault in {Fault.TRANSPORT, Fault.RESPONSE_LOST}:
        return OutcomeUnknown(label)
    if rule.fault is Fault.CRASH:
        return InjectedCrash(label)
    raise AssertionError(rule.fault)


class AdversarialBucket(ScriptedBucket):
    """Strong seeded ObjectStore plus typed failures and paginated LIST."""

    def __init__(
            self, initial=None, *, seed=0xAD5EED,
            list_page_size=1000, max_list_pages=10_000,
            short_page_sizes=(), reuse_aba_tokens=True,
            nonconforming=Nonconforming()):
        if type(list_page_size) is not int or list_page_size < 1:
            raise ValueError("list page size")
        if type(max_list_pages) is not int or max_list_pages < 1:
            raise ValueError("list page budget")
        short_page_sizes = tuple(short_page_sizes)
        if any(type(size) is not int or size < 1
               or size > list_page_size for size in short_page_sizes):
            raise ValueError("short list page size")
        if not isinstance(nonconforming, Nonconforming):
            raise TypeError("Nonconforming required")
        self.list_page_size = list_page_size
        self.max_list_pages = max_list_pages
        self.short_page_sizes = short_page_sizes
        self.reuse_aba_tokens = bool(reuse_aba_tokens)
        self.nonconforming = nonconforming
        self.fault_script = []
        self._fault_gates = []
        self._accepted_cas_preconditions = set()
        self._hidden_keys = set()
        self._stale_pairs = {}
        self._cursor_positions = {}
        self._cursor_values = set()
        self._page_ordinal = 0
        super().__init__(initial, seed=seed)

    def _issue_token(self, key, value):
        if self.nonconforming.token_alias:
            return VersionToken("nonconforming:aliased-token")
        if self.reuse_aba_tokens:
            return super()._issue_token(key, value)
        while True:
            token = VersionToken(
                f"opaque:{self._random.getrandbits(128):032x}")
            incumbent = self._token_values.get(token.value)
            if incumbent is None or incumbent == value:
                self._token_values[token.value] = value
                return token

    def fail(
            self, actor, op, key, fault, *, when="before", nth=1):
        """Install one deterministic typed failure and return its gate.

        Definitive rejection classes are valid only before mutation.
        ``RESPONSE_LOST`` is valid only after mutation.  ``TRANSPORT`` may be
        placed on either side: from the caller's perspective both outcomes are
        unknown, while the history says whether a mutation linearized.
        """
        if not isinstance(fault, Fault):
            raise TypeError("Fault required")
        mutation = op in {"put", "put_if_absent", "cas", "delete"}
        if fault in {
                Fault.REJECTED, Fault.THROTTLED,
                Fault.RETRYABLE_SERVICE} and when != "before":
            raise ValueError("definitive rejection must precede mutation")
        if fault is Fault.RESPONSE_LOST and (
                when != "after" or not mutation):
            raise ValueError(
                "response loss must follow a mutation")
        rule = FaultRule(self.seed, actor, op, key, when, nth, fault)
        gate = self.pause(actor, op, key, when=when, nth=nth)
        gate.error = _fault_error(rule)
        gate.release.set()
        self.fault_script.append(rule)
        self._fault_gates.append(gate)
        return gate

    def diagnostic(self):
        rules = "\n".join(
            f"  {index + 1}. {rule} seen={gate.seen}"
            for index, (rule, gate) in enumerate(zip(
                self.fault_script, self._fault_gates))
        ) or "  <none>"
        events = "\n".join(
            f"  {event.seq}. {event.actor}.{event.op}({event.key})"
            f" -> {event.result!r}"
            for event in self.history
        ) or "  <none>"
        return (
            f"adversarial bucket seed={self.seed:#x}\n"
            f"fault script:\n{rules}\nlinearized history:\n{events}"
        )

    @contextmanager
    def capture(self):
        """Attach the replay seed, fault script, and history to a failure."""
        try:
            yield self
        except BaseException as error:
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note(self.diagnostic())
            raise

    def _cas_matches(self, key, expected, current):
        return current == expected or (
            self.nonconforming.reused_cas_precondition
            and (key, expected) in self._accepted_cas_preconditions)

    def _after_cas_applied(self, key, expected, value, result):
        self._accepted_cas_preconditions.add((key, expected))

    def _put_if_absent(self, actor, key, value):
        result = super()._put_if_absent(actor, key, value)
        if self.nonconforming.acknowledged_create_invisible \
                and result is CREATED:
            self._hidden_keys.add(key)
        return result

    def _cas(self, actor, key, expected, value):
        with self._lock:
            previous = (
                self._data.get(key), self._current_token(key))
        result = super()._cas(actor, key, expected, value)
        if self.nonconforming.stale_successful_reads \
                and isinstance(result, Applied):
            self._stale_pairs[key] = previous
        return result

    def _negative_read(self, actor, op, key):
        hidden = key in self._hidden_keys
        stale = self._stale_pairs.get(key)
        if not hidden and stale is None:
            return _NO_NEGATIVE_READ
        self._gate(actor, op, key, "before")
        with self._lock:
            before = self._current_token(key)
            if hidden:
                value, token = None, ABSENT
            else:
                value, token = stale
            if op == "get":
                result = value
            elif op == "has":
                result = value is not None
            else:
                result = ABSENT \
                    if value is None else Versioned(value, token)
            self._record(
                actor, op, key, None, None, before, result, before)
        self._gate(actor, op, key, "after")
        return result

    def _get(self, actor, key):
        negative = self._negative_read(actor, "get", key)
        return super()._get(actor, key) \
            if negative is _NO_NEGATIVE_READ else negative

    def _read_versioned(self, actor, key):
        negative = self._negative_read(actor, "read_versioned", key)
        return (
            super()._read_versioned(actor, key)
            if negative is _NO_NEGATIVE_READ else negative)

    def _has(self, actor, key):
        negative = self._negative_read(actor, "has", key)
        return super()._has(actor, key) \
            if negative is _NO_NEGATIVE_READ else negative

    def refresh_authoritative_reads(self, key=None):
        """Release explicit stale/invisible negative-control reads."""
        if key is None:
            self._hidden_keys.clear()
            self._stale_pairs.clear()
        else:
            self._hidden_keys.discard(key)
            self._stale_pairs.pop(key, None)

    def _list_width(self):
        if not self.short_page_sizes:
            return self.list_page_size
        width = self.short_page_sizes[
            self._page_ordinal % len(self.short_page_sizes)]
        self._page_ordinal += 1
        return width

    def _new_cursor(self, after_key):
        if self.nonconforming.repeated_list_cursor:
            cursor = "nonconforming:repeated-cursor"
        else:
            while True:
                cursor = (
                    f"cursor:{self._random.getrandbits(128):032x}")
                if cursor not in self._cursor_values:
                    break
        incumbent = self._cursor_positions.setdefault(cursor, after_key)
        if incumbent != after_key:
            return cursor
        self._cursor_values.add(cursor)
        return cursor

    def _list(self, actor, prefix):
        if not isinstance(prefix, str):
            raise ValueError("bad list prefix")
        logical = prefix[:-1] if prefix.endswith("/") else prefix
        if logical:
            validate_key(logical)
        self._gate(actor, "list", prefix, "before")
        cursor = None
        out = []
        for _ in range(self.max_list_pages):
            self._gate(actor, "list_page", prefix, "before")
            with self._lock:
                if cursor is None:
                    after_key = None
                else:
                    try:
                        after_key = self._cursor_positions[cursor]
                    except KeyError as error:
                        raise StoreError("unknown LIST cursor") from error
                width = self._list_width()
                eligible = tuple(sorted(
                    key for key in self._data
                    if key.startswith(prefix)
                    and (after_key is None or key > after_key)
                ))
                keys = eligible[:width]
                truncated = len(eligible) > width
                next_cursor = self._new_cursor(keys[-1]) \
                    if truncated else None
                request = ListRequest(cursor, after_key, width)
                page = ListPage(keys, next_cursor, truncated)
                self._record(
                    actor, "list_page", prefix, None, request,
                    eligible, page, eligible)
            self._gate(actor, "list_page", prefix, "after")
            out.extend(page.keys)
            if not page.truncated:
                result = sorted(out)
                self._gate(actor, "list", prefix, "after")
                return result
            if not page.cursor or page.cursor == cursor:
                raise StoreError("LIST returned a repeated cursor")
            cursor = page.cursor
        raise StoreError("LIST exceeded page budget")

    def _delete(self, actor, key):
        if not (
                self.nonconforming.destructive_objects
                and key.startswith("obj/")):
            return super()._delete(actor, key)
        self._gate(actor, "delete", key, "before")
        with self._lock:
            before = self._current_token(key)
            existed = self._data.pop(key, None) is not None
            self._tokens.pop(key, None)
            self._record(
                actor, "delete", key, None, None,
                before, existed, ABSENT)
        self._gate(actor, "delete", key, "after")


class LaggedReader:
    """Explicit non-authoritative cache/replica negative control.

    This wrapper intentionally freezes the first successful direct read.  It
    exposes no mutation methods, so it cannot accidentally be passed as the
    authoritative direct S3/R2 ObjectStore.
    """

    def __init__(self, direct):
        self.direct = direct
        self._values = {}
        self._versions = {}

    def get(self, key):
        if key not in self._values:
            self._values[key] = self.direct.get(key)
        return self._values[key]

    def read_versioned(self, key):
        if key not in self._versions:
            self._versions[key] = self.direct.read_versioned(key)
        return self._versions[key]

    def has(self, key):
        return self.get(key) is not None

    def refresh(self, key=None):
        if key is None:
            self._values.clear()
            self._versions.clear()
        else:
            self._values.pop(key, None)
            self._versions.pop(key, None)


class AsyncLaggedReader:
    """Awaited form of ``LaggedReader`` for replica-read negative controls."""

    def __init__(self, direct):
        self.direct = direct
        self._values = {}
        self._versions = {}

    async def get(self, key):
        if key not in self._values:
            self._values[key] = await self.direct.get(key)
        return self._values[key]

    async def read_versioned(self, key):
        if key not in self._versions:
            self._versions[key] = await self.direct.read_versioned(key)
        return self._versions[key]

    async def has(self, key):
        return await self.get(key) is not None

    def refresh(self, key=None):
        if key is None:
            self._values.clear()
            self._versions.clear()
        else:
            self._values.pop(key, None)
            self._versions.pop(key, None)
