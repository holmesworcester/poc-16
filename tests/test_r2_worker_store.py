"""Native Cloudflare R2 binding adapter contracts."""
import asyncio
from dataclasses import dataclass

import pytest

from adapters.r2 import R2BindingStore
from core.crypto import h
from core.limits import PayloadTooLarge
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    StoreError,
    retire_exact_async,
)
from core.repository_applier import RepositoryApplier


class R2Object:
    def __init__(self, key, value, etag):
        self.key, self.value, self.etag = key, value, etag
        self.size = len(value)
        self.array_calls = 0

    async def arrayBuffer(self):
        self.array_calls += 1
        return self.value


@dataclass
class Page:
    objects: list
    truncated: bool
    cursor: str | None = None


class Bucket:
    def __init__(self):
        self.data = {}
        self.etags = {}
        self.generation = 0
        self.calls = []
        self.fail = None
        self.page_size = 1000

    def _token(self):
        self.generation += 1
        return f"opaque-r2-{self.generation}"

    async def get(self, key):
        self.calls.append(("get", key))
        if key not in self.data:
            return None
        return R2Object(key, self.data[key], self.etags[key])

    async def head(self, key):
        self.calls.append(("head", key))
        return None if key not in self.data else R2Object(
            key, b"", self.etags[key])

    async def put(self, key, value, **options):
        self.calls.append(("put", key, value, options))
        if self.fail is not None:
            raise self.fail
        condition = options.get("onlyIf")
        if isinstance(condition, dict) \
                and condition.get("If-None-Match") == "*" \
                and key in self.data:
            return None
        if isinstance(condition, dict) and "etagMatches" in condition \
                and self.etags.get(key) != condition["etagMatches"]:
            return None
        self.data[key] = bytes(value)
        self.etags[key] = self._token()
        return R2Object(key, b"", self.etags[key])

    async def list(self, prefix, limit, cursor=None):
        self.calls.append(("list", prefix, limit, cursor))
        keys = sorted(key for key in self.data if key.startswith(prefix))
        start = int(cursor or 0)
        stop = min(len(keys), start + self.page_size, start + limit)
        objects = [
            R2Object(key, b"", self.etags[key])
            for key in keys[start:stop]
        ]
        return Page(
            objects, stop < len(keys),
            str(stop) if stop < len(keys) else None)

    async def delete(self, key):
        self.calls.append(("delete", key))
        self.data.pop(key, None)
        self.etags.pop(key, None)


def run(awaitable):
    return asyncio.run(awaitable)


def test_native_r2_preserves_opaque_tokens_and_conditional_outcomes():
    bucket, store = Bucket(), R2BindingStore(Bucket())
    bucket = store.bucket

    assert run(store.read_versioned("root")) is ABSENT
    created = run(store.cas("root", ABSENT, b"root-1"))
    assert isinstance(created, Applied)
    assert created.token.value == "opaque-r2-1"
    pair = run(store.read_versioned("root"))
    assert pair.value == b"root-1"
    assert pair.token == created.token
    assert pair.token.value != h(pair.value)

    assert run(store.cas("root", ABSENT, b"loser")) is STALE
    replaced = run(store.cas("root", pair.token, b"root-2"))
    assert isinstance(replaced, Applied)
    assert run(store.get("root")) == b"root-2"


def test_native_r2_immutable_create_collision_is_verified():
    bucket, store = Bucket(), R2BindingStore(Bucket(), "workspaces/w")
    bucket = store.bucket
    raw, oid = b"same", h(b"same")

    applier = RepositoryApplier("0" * 64, store)
    assert run(applier.admit_object(oid, raw)) is CREATED
    assert run(applier.admit_object(oid, raw)) is EXISTS
    bucket.data[f"workspaces/w/obj/{oid}"] = b"corrupt"
    with pytest.raises(ValueError, match="conflict"):
        run(applier.admit_object(oid, raw))


def test_native_r2_list_uses_truncation_and_opaque_cursors():
    bucket, store = Bucket(), R2BindingStore(Bucket(), "tenant")
    bucket = store.bucket
    bucket.page_size = 2
    for ordinal in range(5):
        key = f"tenant/pile/member/{ordinal}"
        bucket.data[key] = str(ordinal).encode()
        bucket.etags[key] = bucket._token()
    bucket.data["other/pile/member/no"] = b"x"
    bucket.etags["other/pile/member/no"] = bucket._token()

    assert run(store.list("pile/")) == [
        f"pile/member/{ordinal}" for ordinal in range(5)
    ]
    assert [
        call[3] for call in bucket.calls if call[0] == "list"
    ] == [None, "2", "4"]


def test_native_r2_list_stops_at_one_over_the_provider_page_bound():
    class Counted:
        def __init__(self, values):
            self.values = values
            self.pulls = 0

        def __iter__(self):
            for value in self.values:
                self.pulls += 1
                yield value

    objects = Counted([
        R2Object("tenant/pile/member/a", b"", "a"),
        R2Object("tenant/pile/member/a", b"", "a"),
        R2Object("tenant/pile/member/a", b"", "a"),
        R2Object("tenant/pile/member/never-read", b"", "b"),
    ])

    class Overlong(Bucket):
        async def list(self, prefix, limit, cursor=None):
            return Page(objects, False)

    with pytest.raises(StoreError, match="requested page limit"):
        run(R2BindingStore(Overlong(), "tenant").list_page(
            "pile/", None, 2))
    assert objects.pulls == 3


@pytest.mark.parametrize("key, message", [
    ("tenant/other/key", "out-of-prefix"),
    ("tenant/pile/../key", "invalid logical key"),
    ("tenant/pile/" + "x" * 1025, "invalid logical key"),
    (object(), "non-string"),
])
def test_native_r2_list_rejects_malformed_provider_keys(key, message):
    class Malformed(Bucket):
        async def list(self, prefix, limit, cursor=None):
            return Page([R2Object(key, b"", "etag")], False)

    with pytest.raises(StoreError, match=message):
        run(R2BindingStore(Malformed(), "tenant").list_page(
            "pile/", None, 2))


@pytest.mark.parametrize("next_cursor", [None, 7, object(), "same"])
def test_native_r2_list_rejects_missing_malformed_or_repeated_cursor(
        next_cursor):
    class BadCursor(Bucket):
        async def list(self, prefix, limit, cursor=None):
            return Page([], True, next_cursor)

    cursor = "same" if next_cursor == "same" else None
    with pytest.raises(StoreError, match="cursor"):
        run(R2BindingStore(BadCursor()).list_page(
            "pile/", cursor, 2))


def test_native_r2_list_rejects_unbounded_unique_cursors():
    class Endless(Bucket):
        async def list(self, prefix, limit, cursor=None):
            self.calls.append(("list", prefix, limit, cursor))
            ordinal = int(cursor or 0)
            return Page([], True, str(ordinal + 1))

    bucket = Endless()
    store = R2BindingStore(bucket, max_list_pages=3)

    with pytest.raises(StoreError, match="page budget"):
        run(store.list("pile/"))
    assert len([
        call for call in bucket.calls if call[0] == "list"
    ]) == 3


@pytest.mark.parametrize(
    "etag", (None, "", 'W/"weak"', 7, False, object()))
def test_native_r2_rejects_unusable_root_etag(etag):
    bucket = Bucket()
    bucket.data["root"] = b"root"
    bucket.etags["root"] = etag
    store = R2BindingStore(bucket)

    with pytest.raises(StoreError, match="no usable strong ETag"):
        run(store.read_versioned("root"))

    class ResultWithoutToken(Bucket):
        async def put(self, key, value, **options):
            return R2Object(key, b"", etag)

    with pytest.raises(StoreError, match="no usable strong ETag"):
        run(R2BindingStore(ResultWithoutToken()).cas(
            "root", ABSENT, b"candidate"))


def test_native_r2_never_maps_throttle_or_transport_to_stale():
    class Error(Exception):
        def __init__(self, status=None):
            self.status = status

    bucket, store = Bucket(), R2BindingStore(Bucket())
    bucket = store.bucket
    bucket.fail = Error(429)
    with pytest.raises(RetryableStoreError):
        run(store.cas("root", ABSENT, b"x"))

    bucket.fail = Error(503)
    with pytest.raises(OutcomeUnknown):
        run(store.cas("root", ABSENT, b"x"))


def test_native_r2_guards_authoritative_mutations_and_prefixes():
    store = R2BindingStore(Bucket(), "tenant")
    with pytest.raises(ValueError, match="conditional"):
        run(store.put("root", b"x"))
    with pytest.raises(ValueError, match="not deletable"):
        run(store.delete("obj/" + "0" * 64))
    with pytest.raises(ValueError, match="key"):
        R2BindingStore(Bucket(), "../escape")
    with pytest.raises(ValueError, match="page budget"):
        R2BindingStore(Bucket(), max_list_pages=0)


def test_native_r2_exact_retirement_handles_absence_success_and_change():
    bucket = Bucket()
    store = R2BindingStore(bucket, "tenant")
    key, physical, raw = (
        "ingress/v1/pile/member/fid",
        "tenant/ingress/v1/pile/member/fid",
        b"closed pile",
    )

    assert run(retire_exact_async(store, key, raw)) is False
    bucket.data[physical] = raw
    bucket.etags[physical] = bucket._token()
    assert run(retire_exact_async(store, key, raw)) is True
    assert physical not in bucket.data

    bucket.data[physical] = b"replacement"
    bucket.etags[physical] = bucket._token()
    with pytest.raises(OSError, match="source changed"):
        run(retire_exact_async(store, key, raw))
    assert not any(
        call == ("delete", physical) for call in bucket.calls[-2:])


def test_native_r2_exact_retirement_reconciles_lost_delete_response():
    class AppliedWithoutResponse(Bucket):
        async def delete(self, key):
            self.calls.append(("delete", key))
            self.data.pop(key, None)
            self.etags.pop(key, None)
            raise ConnectionError("response lost after apply")

    bucket = AppliedWithoutResponse()
    store = R2BindingStore(bucket, "tenant")
    key = "ingress/v1/pile/member/fid"
    physical = "tenant/" + key
    raw = b"durable intent"
    bucket.data[physical] = raw
    bucket.etags[physical] = bucket._token()

    assert run(retire_exact_async(store, key, raw)) is True
    assert physical not in bucket.data


def test_native_r2_exact_retirement_keeps_retryable_or_changed_source():
    class FailedOrChanged(Bucket):
        def __init__(self, replacement=None):
            super().__init__()
            self.replacement = replacement

        async def delete(self, key):
            self.calls.append(("delete", key))
            if self.replacement is not None:
                self.data[key] = self.replacement
                self.etags[key] = self._token()
            raise ConnectionError("delete response unknown")

    key = "ingress/v1/pile/member/fid"
    physical = "tenant/" + key
    raw = b"durable intent"

    retained = FailedOrChanged()
    retained.data[physical] = raw
    retained.etags[physical] = retained._token()
    with pytest.raises(OutcomeUnknown, match="outcome unknown"):
        run(retire_exact_async(
            R2BindingStore(retained, "tenant"), key, raw))
    assert retained.data[physical] == raw

    changed = FailedOrChanged(b"replacement")
    changed.data[physical] = raw
    changed.etags[physical] = changed._token()
    with pytest.raises(OSError, match="source changed"):
        run(retire_exact_async(
            R2BindingStore(changed, "tenant"), key, raw))
    assert changed.data[physical] == b"replacement"


def test_native_r2_exact_retirement_refuses_noop_and_authoritative_keys():
    class NoopDelete(Bucket):
        async def delete(self, key):
            self.calls.append(("delete", key))

    key, raw = "ingress/v1/pile/member/fid", b"durable intent"
    bucket = NoopDelete()
    bucket.data[key] = raw
    bucket.etags[key] = bucket._token()
    store = R2BindingStore(bucket)

    with pytest.raises(OSError, match="did not remove"):
        run(retire_exact_async(store, key, raw))
    for authoritative in ("root", "obj/" + h(raw)):
        bucket.data[authoritative] = raw
        bucket.etags[authoritative] = bucket._token()
        with pytest.raises(ValueError, match="not deletable"):
            run(retire_exact_async(store, authoritative, raw))


def test_native_r2_exact_retirement_never_converts_read_failure_to_success():
    class InitialReadFails(Bucket):
        async def get(self, key):
            self.calls.append(("get", key))
            raise ConnectionError("read unavailable")

    with pytest.raises(StoreError, match="read failed"):
        run(retire_exact_async(
            R2BindingStore(InitialReadFails()),
            "ingress/v1/pile/member/fid",
            b"intent",
        ))

    class ReconcileReadFails(Bucket):
        def __init__(self):
            super().__init__()
            self.reads = 0

        async def get(self, key):
            self.reads += 1
            if self.reads > 1:
                raise ConnectionError("reconciliation read unavailable")
            return await super().get(key)

        async def delete(self, key):
            self.calls.append(("delete", key))
            raise ConnectionError("delete response unknown")

    key, raw = "ingress/v1/pile/member/fid", b"intent"
    bucket = ReconcileReadFails()
    bucket.data[key] = raw
    bucket.etags[key] = bucket._token()
    with pytest.raises(OutcomeUnknown, match="outcome unknown"):
        run(retire_exact_async(
            R2BindingStore(bucket), key, raw))
    assert bucket.data[key] == raw


def test_native_r2_bounded_read_rejects_known_oversize_before_allocation():
    class One:
        def __init__(self, obj):
            self.obj = obj

        async def get(self, _key):
            return self.obj

    exact = R2Object("obj/exact", b"abcd", "exact")
    assert run(R2BindingStore(One(exact)).get_bounded(
        "obj/" + "0" * 64, 4)) == b"abcd"
    assert exact.array_calls == 1

    over = R2Object("obj/over", b"abcde", "over")
    with pytest.raises(PayloadTooLarge, match="byte limit"):
        run(R2BindingStore(One(over)).get_bounded(
            "obj/" + "1" * 64, 4))
    assert over.array_calls == 0


def test_native_r2_missing_size_fails_before_allocation():
    class One:
        async def get(self, _key):
            return obj

    obj = R2Object("obj/legacy", b"abcde", "legacy")
    del obj.size

    with pytest.raises(StoreError, match="no size"):
        run(R2BindingStore(One()).get_bounded(
            "obj/" + "0" * 64, 4))
    assert obj.array_calls == 0


@pytest.mark.parametrize(
    ("size", "value", "message", "array_calls"),
    [
        ("4", b"abcd", "invalid size", 0),
        (4.0, b"abcd", "invalid size", 0),
        (True, b"a", "invalid size", 0),
        (object(), b"abcd", "invalid size", 0),
        (-1, b"", "invalid size", 0),
        (4, b"abc", "size mismatch", 1),
        (3, b"abcd", "size mismatch", 1),
    ])
def test_native_r2_rejects_malformed_or_inconsistent_size(
        size, value, message, array_calls):
    obj = R2Object("obj/bad", value, "etag")
    obj.size = size

    class One:
        async def get(self, _key):
            return obj

    with pytest.raises(StoreError, match=message):
        run(R2BindingStore(One()).get_bounded(
            "obj/" + "0" * 64, 4))
    assert obj.array_calls == array_calls
