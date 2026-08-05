"""Native Cloudflare R2 binding adapter contracts."""
import asyncio
from dataclasses import dataclass

import pytest

from adapters.r2 import R2BindingStore
from core.crypto import h
from core.limits import (
    DIRECT_STREAM_CHUNK_BYTES,
    MAX_DIRECT_OBJECT_BYTES,
    MAX_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    PayloadTooLarge,
)
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    StoreError,
    UNCHANGED,
    async_store,
    ensure_object_async,
)


class R2Object:
    def __init__(self, key, value, etag):
        self.key, self.value, self.etag = key, value, etag
        self.size = len(value)
        self.array_calls = 0
        self.body = Stream((value,))

    async def arrayBuffer(self):
        self.array_calls += 1
        return self.value


class StreamResult:
    def __init__(self, done, value=None):
        self.done, self.value = done, value


class Reader:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.released = False

    async def read(self):
        try:
            return StreamResult(False, next(self.chunks))
        except StopIteration:
            return StreamResult(True)

    def releaseLock(self):
        self.released = True


class Stream:
    def __init__(self, chunks):
        self.reader = Reader(chunks)

    def getReader(self):
        return self.reader


class VirtualObject:
    def __init__(self, size, *, delivered=None):
        self.size = size
        remaining = size if delivered is None else delivered

        def chunks():
            chunk = b"x" * DIRECT_STREAM_CHUNK_BYTES
            while remaining_chunks[0]:
                take = min(remaining_chunks[0], len(chunk))
                remaining_chunks[0] -= take
                yield chunk[:take]

        remaining_chunks = [remaining]
        self.body = Stream(chunks())
        self.array_calls = 0

    async def arrayBuffer(self):  # pragma: no cover - direct copy must stream
        self.array_calls += 1
        raise AssertionError("direct R2 pile read buffered ArrayBuffer")


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

    async def get(self, key, options=None):
        self.calls.append(("get", key))
        if key not in self.data:
            return None
        condition = options.get("onlyIf") \
            if isinstance(options, dict) else None
        if isinstance(condition, dict) and condition.get(
                "etagDoesNotMatch") == self.etags[key]:
            result = R2Object(key, self.data[key], self.etags[key])
            result.body = None
            return result
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

    assert run(store.read_versioned("removal")) is ABSENT
    created = run(store.cas("removal", ABSENT, b"removal-1"))
    assert isinstance(created, Applied)
    assert created.token.value == "opaque-r2-1"
    pair = run(store.read_versioned("removal"))
    assert pair.value == b"removal-1"
    assert pair.token == created.token
    assert pair.token.value != h(pair.value)
    assert run(store.read_versioned_if_changed(
        "removal", pair.token)) is UNCHANGED

    assert run(store.cas("removal", ABSENT, b"loser")) is STALE
    replaced = run(store.cas("removal", pair.token, b"removal-2"))
    assert isinstance(replaced, Applied)
    changed = run(store.read_versioned_if_changed(
        "removal", pair.token))
    assert changed.value == b"removal-2"
    assert changed.token == replaced.token
    assert run(store.get("removal")) == b"removal-2"


def test_native_r2_layout_reads_use_the_semantic_object_limit():
    bucket, store = Bucket(), R2BindingStore(Bucket())
    bucket = store.bucket
    key = "layouts/" + "/".join(
        ("0" * 64, "1" * 64, "0000000000000001"))
    value = b"l" * (MAX_ROOT_BYTES + 1)
    physical = key
    bucket.data[physical] = value
    bucket.etags[physical] = bucket._token()

    assert run(store.get(key)) == value
    assert run(store.read_versioned(key)).value == value


def test_native_r2_immutable_create_collision_is_verified():
    bucket, store = Bucket(), R2BindingStore(Bucket(), "workspaces/w")
    bucket = store.bucket
    raw, oid = b"same", h(b"same")

    awaited = async_store(store)
    assert run(ensure_object_async(awaited, oid, raw)) is CREATED
    assert run(ensure_object_async(awaited, oid, raw)) is EXISTS
    bucket.data[f"workspaces/w/obj/{oid}"] = b"corrupt"
    with pytest.raises(ValueError, match="conflict"):
        run(ensure_object_async(awaited, oid, raw))


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
def test_native_r2_rejects_unusable_removal_etag(etag):
    bucket = Bucket()
    bucket.data["removal"] = b"removal"
    bucket.etags["removal"] = etag
    store = R2BindingStore(bucket)

    with pytest.raises(StoreError, match="no usable strong ETag"):
        run(store.read_versioned("removal"))

    class ResultWithoutToken(Bucket):
        async def put(self, key, value, **options):
            return R2Object(key, b"", etag)

    with pytest.raises(StoreError, match="no usable strong ETag"):
        run(R2BindingStore(ResultWithoutToken()).cas(
            "removal", ABSENT, b"candidate"))


def test_native_r2_never_maps_throttle_or_transport_to_stale():
    class Error(Exception):
        def __init__(self, status=None):
            self.status = status

    bucket, store = Bucket(), R2BindingStore(Bucket())
    bucket = store.bucket
    bucket.fail = Error(429)
    with pytest.raises(RetryableStoreError):
        run(store.cas("removal", ABSENT, b"x"))

    bucket.fail = Error(503)
    with pytest.raises(OutcomeUnknown):
        run(store.cas("removal", ABSENT, b"x"))


def test_native_r2_guards_authoritative_mutations_and_prefixes():
    store = R2BindingStore(Bucket(), "tenant")
    with pytest.raises(ValueError, match="conditional"):
        run(store.put("removal", b"x"))
    with pytest.raises(ValueError, match="not deletable"):
        run(store.delete("obj/" + "0" * 64))
    with pytest.raises(ValueError, match="key"):
        R2BindingStore(Bucket(), "../escape")
    with pytest.raises(ValueError, match="page budget"):
        R2BindingStore(Bucket(), max_list_pages=0)


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


def test_native_r2_direct_pile_copy_streams_the_exact_protocol_maximum():
    obj = VirtualObject(MAX_DIRECT_OBJECT_BYTES)

    class One:
        async def get(self, _key):
            return obj

    chunks = []
    total = run(R2BindingStore(One()).copy_pile_object(
        h(b"virtual maximum pile"), MAX_DIRECT_OBJECT_BYTES,
        lambda chunk: chunks.append(len(chunk))))

    assert total == MAX_DIRECT_OBJECT_BYTES == sum(chunks)
    assert max(chunks) == DIRECT_STREAM_CHUNK_BYTES
    assert obj.array_calls == 0
    assert obj.body.reader.released


def test_native_r2_direct_pile_copy_rejects_one_over_and_short_stream():
    oversized = VirtualObject(MAX_OBJECT_BYTES + 1)
    short = VirtualObject(4, delivered=3)
    responses = iter((oversized, short, None))

    class Sequence:
        async def get(self, _key):
            return next(responses)

    store = R2BindingStore(Sequence())
    with pytest.raises(PayloadTooLarge, match="byte limit"):
        run(store.copy_pile_object(
            h(b"oversized pile"), MAX_OBJECT_BYTES, lambda _chunk: None))
    with pytest.raises(StoreError, match="size mismatch"):
        run(store.copy_pile_object(
            h(b"short pile"), MAX_OBJECT_BYTES, lambda _chunk: None))
    assert short.body.reader.released
    assert run(store.copy_pile_object(
        h(b"missing pile"), MAX_OBJECT_BYTES, lambda _chunk: None)) is None


def test_native_r2_missing_size_fails_before_allocation():
    class One:
        async def get(self, _key):
            return obj

    obj = R2Object("obj/opaque", b"abcde", "opaque")
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
