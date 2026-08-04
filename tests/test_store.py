"""Object-store concurrency contracts."""
import asyncio
import base64
import fcntl
import io
import json
import os
import threading
import urllib.error
from concurrent.futures import ThreadPoolExecutor, TimeoutError

import pytest

from core import http
from core.crypto import h
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    STALE,
    Versioned,
    VersionToken,
    async_store,
    ensure_object_async,
    verified_object,
)
from core.limits import (
    MAX_OBJECT_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    MAX_STORE_READ_BYTES,
    PayloadTooLarge,
)
from core.store import FsStore, RemoteStore
from full_peer import walk
from full_peer.walk import Peer as WalkPeer

WORKSPACE = "0" * 64


def establish(store, oid, raw):
    return asyncio.run(ensure_object_async(async_store(store), oid, raw))


def test_fs_puts_use_distinct_atomic_temp_files(tmp_path, monkeypatch):
    store = FsStore(str(tmp_path))
    replace = os.replace
    callers = threading.Barrier(2)
    sources = []

    def rendezvous(source, target):
        sources.append(source)
        callers.wait(timeout=5)
        replace(source, target)

    monkeypatch.setattr("core.store.os.replace", rendezvous)
    values = (b"first", b"second")
    with ThreadPoolExecutor(max_workers=2) as pool:
        writes = [
            pool.submit(store.put, "pile/member/same", value)
            for value in values
        ]
        for write in writes:
            write.result()

    assert len(set(sources)) == 2
    assert store.get("pile/member/same") in values
    assert not tuple(tmp_path.rglob("*.tmp"))


def test_fs_put_if_absent_is_one_atomic_immutable_create(tmp_path):
    stores = [FsStore(str(tmp_path)) for _ in range(8)]
    raw = b"one immutable value"
    key = "obj/" + h(raw)
    start = threading.Barrier(len(stores))

    def create(store):
        start.wait(timeout=5)
        return store.put_if_absent(key, raw)

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        results = list(pool.map(create, stores))

    assert results.count(CREATED) == 1
    assert results.count(EXISTS) == len(stores) - 1
    assert stores[0].get(key) == raw
    assert not tuple(tmp_path.rglob("*.tmp"))

    stores[0]._replace(key, b"corrupt")
    with pytest.raises(ValueError, match="conflict"):
        establish(stores[1], h(raw), raw)
    with pytest.raises(ValueError, match="address"):
        stores[1].put_if_absent("obj/" + "0" * 64, raw)


@pytest.mark.parametrize("key", ("root", "root/old", ".root.lock"))
def test_removed_root_namespace_stays_reserved(tmp_path, key):
    store = FsStore(str(tmp_path))

    with pytest.raises(ValueError, match="reserved key"):
        store.put(key, b"obsolete")
    with pytest.raises(ValueError, match="reserved key"):
        store.put_if_absent(key, b"obsolete")
    with pytest.raises(ValueError, match="reserved key"):
        store.get(key)
    with pytest.raises(ValueError, match="reserved key"):
        store.delete(key)


def test_fs_get_bounded_never_accepts_a_whole_oversized_value(
        tmp_path, monkeypatch):
    store = FsStore(str(tmp_path))
    store.put("pile/member/value", b"12345")
    store.cas("authority", ABSENT, b"authority")

    assert store.get_bounded("pile/member/value", 5) == b"12345"
    assert store.get_bounded("pile/member/missing", 5) is None
    with pytest.raises(PayloadTooLarge, match="read exceeds"):
        store.get_bounded("pile/member/value", 4)
    for invalid in (0, -1, True, MAX_STORE_READ_BYTES + 1):
        with pytest.raises(ValueError, match="read byte limit"):
            store.get_bounded("pile/member/value", invalid)

    monkeypatch.setattr(
        store,
        "get",
        lambda _key: pytest.fail("bounded read called whole-object get"),
    )
    assert store.get_bounded("pile/member/value", 5) == b"12345"
    assert store.read_versioned("authority").value == b"authority"


def test_immutable_create_reconciles_ambiguity_and_verifies_collision():
    raw, other = b"wanted", b"wrong"
    oid = h(raw)

    class Store:
        def __init__(self, outcomes, incumbent=None):
            self.outcomes = list(outcomes)
            self.value = incumbent
            self.calls = 0
            self.read_limits = []

        def put_if_absent(self, key, value):
            self.calls += 1
            outcome = self.outcomes.pop(0)
            if outcome == "applied-unknown":
                self.value = value
                raise OutcomeUnknown("response lost")
            if outcome == "unknown":
                raise OutcomeUnknown("request state unknown")
            if outcome is CREATED:
                self.value = value
            return outcome

        def get(self, key):
            return self.value

        def get_bounded(self, key, maximum):
            self.read_limits.append(maximum)
            value = self.get(key)
            if value is not None and len(value) > maximum:
                raise PayloadTooLarge("test value exceeds byte limit")
            return value

    applied = Store(["applied-unknown"])
    assert establish(applied, oid, raw) is EXISTS
    assert applied.calls == 1
    assert applied.read_limits == [len(raw)]

    retried = Store(["unknown", CREATED])
    assert establish(retried, oid, raw) is CREATED
    assert retried.calls == 2
    assert retried.read_limits == [len(raw)]

    with pytest.raises(ValueError, match="conflict"):
        establish(Store([EXISTS], other), oid, raw)

    absent = Store(["unknown", "unknown"])
    with pytest.raises(OutcomeUnknown):
        establish(absent, oid, raw)
    assert absent.calls == 2


def test_verified_repository_object_enforces_the_hosted_reader_ceiling():
    exact = b"x" * MAX_REPOSITORY_OBJECT_BYTES
    assert verified_object(h(exact), lambda _oid: exact) == exact

    oversized = exact + b"x"
    with pytest.raises(ValueError, match="integrity"):
        verified_object(h(oversized), lambda _oid: oversized)


def test_fs_cas_lock_is_shared_by_independent_handles(tmp_path):
    first, second = FsStore(str(tmp_path)), FsStore(str(tmp_path))
    result = first.cas("authority", ABSENT, b"base")
    assert result == Applied(VersionToken(h(b"base")))
    base = first.read_versioned("authority").token

    # Holding the bucket's stable lock prevents another handle from even
    # comparing the cell. This distinguishes a shared CAS from two per-object
    # Python locks without relying on a lucky thread race.
    with open(first._cas_lock, "a+b") as held, \
            ThreadPoolExecutor(max_workers=1) as pool:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(ValueError, match="reserved"):
            first.delete(".cas.lock")
        attempt = pool.submit(
            second.cas, "authority", base, b"after-lock")
        with pytest.raises(TimeoutError):
            attempt.result(timeout=0.1)
        fcntl.flock(held, fcntl.LOCK_UN)
        assert isinstance(attempt.result(timeout=5), Applied)

    expected = first.read_versioned("authority").token
    start = threading.Barrier(2)

    def advance(store, value):
        start.wait(timeout=5)
        return store.cas("authority", expected, value)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result()
            for future in (
                pool.submit(advance, first, b"alice"),
                pool.submit(advance, second, b"bob"),
            )
        ]
    assert sum(isinstance(result, Applied) for result in results) == 1
    assert sum(result is STALE for result in results) == 1
    assert first.get("authority") in {b"alice", b"bob"}
    assert ".cas.lock" not in first.list("")
    for key in (
            ".cas.lock", ".cas.lock/child", "./.cas.lock",
            "authority/child", "/outside", "../outside"):
        with pytest.raises(ValueError, match="key"):
            first.put(key, b"clobber")
    with pytest.raises(ValueError, match="CAS register"):
        first.cas("obj/" + h(b"x"), ABSENT, b"x")
    with pytest.raises(ValueError, match="conditional"):
        first.put("authority", b"clobber")
    with pytest.raises(ValueError, match="compare-and-swap"):
        first.put_if_absent("authority", b"clobber")
    with pytest.raises(ValueError, match="conditional"):
        first.put("obj/" + h(b"x"), b"x")
    with pytest.raises(ValueError, match="not deletable"):
        first.delete("authority")
    with pytest.raises(ValueError, match="not deletable"):
        first.delete("obj/" + h(b"x"))


def test_remote_store_adapts_current_object_and_writer_head_reads():
    page, slot = b"page", b"slot"
    calls = []
    device = "1" * 64

    class Peer:
        def obj(self, oid, *, response_limit):
            calls.append((oid, response_limit))
            return page if oid == h(page) else None

        def head(self, candidate):
            calls.append(("head", candidate))
            return slot, VersionToken("opaque-slot")

    store = RemoteStore(Peer())

    assert asyncio.run(store.get_bounded(
        "obj/" + h(page), len(page))) == page
    assert asyncio.run(store.read_versioned(
        f"heads/{WORKSPACE}/{device}")) == Versioned(
            slot, VersionToken("opaque-slot"))
    assert calls == [
        (h(page), len(page)),
        ("head", device),
    ]
    with pytest.raises(TypeError, match="writer-head-only"):
        asyncio.run(store.read_versioned("obj/" + h(page)))
    with pytest.raises(TypeError, match="writer-head-only"):
        asyncio.run(store.read_many_versioned(("obj/" + h(page),)))


def test_remote_store_object_existence_maps_http_missing_to_false():
    body = b"present"

    class Peer:
        @staticmethod
        def obj(oid, *, response_limit):
            if oid == h(body):
                return body
            raise urllib.error.HTTPError(
                "https://peer/obj", 404, "missing", {}, io.BytesIO())

    store = RemoteStore(Peer())
    assert asyncio.run(store.has("obj/" + h(body)))
    assert not asyncio.run(store.has("obj/" + h(b"missing")))
    with pytest.raises(TypeError, match="object-only"):
        asyncio.run(store.has("authority"))


def test_remote_store_batches_object_gets_in_bounded_order():
    keys = [f"obj/{ordinal:064x}" for ordinal in range(513)]

    class Peer:
        def __init__(self):
            self.calls = []

        def objs(self, oids):
            self.calls.append(tuple(oids))
            return tuple(oid.encode() for oid in oids)

    peer = Peer()
    assert asyncio.run(RemoteStore(peer).get_many(keys)) == tuple(
        key[4:].encode() for key in keys)
    assert list(map(len, peer.calls)) == [256, 256, 1]
    with pytest.raises(TypeError, match="object-only"):
        asyncio.run(RemoteStore(peer).get_many((
            f"heads/{WORKSPACE}/{'1' * 64}",
        )))


def test_peer_decodes_one_ordered_page_batch():
    peer = object.__new__(WalkPeer)
    expected = (b"first", None, b"third")
    calls = []

    def http(method, path, data, **kwargs):
        calls.append((method, path, json.loads(data)))
        raw = json.dumps([
            base64.b64encode(value).decode()
            if value is not None else None
            for value in expected
        ]).encode()
        return 200, raw, {}

    peer._http = http
    oids = ("a" * 64, "b" * 64, "c" * 64)

    assert peer.objs(oids) == expected
    assert calls == [("POST", "/obj", list(oids))]


def test_peer_adaptively_splits_413_batches_without_losing_order_or_misses():
    peer = object.__new__(WalkPeer)
    oids = tuple(f"{ordinal:064x}" for ordinal in range(5))
    held = {
        oids[0]: b"zero",
        oids[2]: b"two",
        oids[4]: b"four",
    }
    calls = []

    def http(method, path, data, **kwargs):
        requested = tuple(json.loads(data))
        calls.append(requested)
        if len(requested) > 2:
            raise urllib.error.HTTPError(
                "https://peer/obj", 413, "too large", {}, io.BytesIO())
        return 200, json.dumps([
            base64.b64encode(held[oid]).decode() if oid in held else None
            for oid in requested
        ]).encode(), {}

    peer._http = http

    assert peer.objs(oids) == (
        b"zero", None, b"two", None, b"four")
    assert list(map(len, calls)) == [5, 2, 3, 1, 2]


def test_peer_falls_back_to_single_get_when_one_object_cannot_fit_a_batch():
    peer = object.__new__(WalkPeer)
    raw = b"x" * (walk.MAX_PAGE_BATCH_BYTES + 1)
    oid = h(raw)
    calls = []

    def http(method, path, *_args, **_kwargs):
        calls.append((method, path, _kwargs.get("response_limit")))
        if method == "POST":
            raise urllib.error.HTTPError(
                "https://peer/obj", 413, "too large", {}, io.BytesIO())
        assert (method, path) == ("GET", f"/obj/{oid}")
        return 200, raw, {}

    peer._http = http

    assert peer.objs((oid,)) == (raw,)
    assert calls == [
        ("POST", "/obj", walk.MAX_PAGE_BATCH_BYTES),
        ("GET", f"/obj/{oid}", walk.MAX_OBJECT_BYTES),
    ]


def test_peer_never_buffers_a_large_object_when_direct_open_is_unsupported():
    peer = object.__new__(WalkPeer)
    raw = b"ordinary buffered object"
    oid = h(raw)
    calls = []

    def http(method, path, *_args, **kwargs):
        calls.append((method, path, kwargs.get("response_limit")))
        if method == "POST":
            raise urllib.error.HTTPError(
                "https://peer/obj/open", 405, "unsupported", {}, io.BytesIO())
        return 200, raw, {}

    peer._http = http
    with pytest.raises(urllib.error.HTTPError) as rejected:
        peer.obj(oid, response_limit=MAX_OBJECT_BYTES + 1)
    assert rejected.value.code == 405
    assert calls == [("POST", "/obj/open", walk.MAX_SCOPED_REQUEST_BYTES)]

    # Ordinary semantic objects have their own bounded route. This is a hard
    # protocol split, not a probe followed by a legacy large-body fallback.
    assert peer.obj(oid, response_limit=MAX_OBJECT_BYTES) == raw
    assert calls[-1] == ("GET", f"/obj/{oid}", MAX_OBJECT_BYTES)


def test_peer_caps_an_untrusted_response_while_streaming(monkeypatch):
    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, count):
            assert count == 9
            return b"x" * count

    monkeypatch.setattr(
        walk._DIRECT_OPENER, "open",
        lambda *_args, **_kwargs: Response())
    peer = object.__new__(WalkPeer)
    peer.url, peer.ws = "https://peer", "workspace"
    peer._token = peer._sync_profile = None

    with pytest.raises(ValueError, match="response too large"):
        peer._http(
            "GET", "/public", auth=False, response_limit=8)


def test_remote_bounded_read_drives_the_peer_stream_limit(monkeypatch):
    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def read(count):
            assert count == 9
            return b"x" * count

    monkeypatch.setattr(
        walk._DIRECT_OPENER, "open",
        lambda *_args, **_kwargs: Response())
    peer = object.__new__(WalkPeer)
    peer.url, peer.ws = "https://peer", "workspace"
    peer._token = "already-minted"
    peer._sync_profile = None

    with pytest.raises(ValueError, match="response too large"):
        asyncio.run(RemoteStore(peer).get_bounded("obj/" + "a" * 64, 8))


def test_peer_reads_writer_head_etag_case_insensitively():
    peer = object.__new__(WalkPeer)
    peer.ws = WORKSPACE
    peer._observed_heads = {}
    peer._http = lambda *_args, **_kwargs: (
        200, b"slot", {"etag": "opaque"})

    assert peer.head("1" * 64) == (
        b"slot", VersionToken("opaque"))


def test_page_batch_route_is_authenticated_ordered_and_preserves_misses():
    first, third = b"first", b"third"
    first_oid, missing_oid, third_oid = h(first), "b" * 64, h(third)
    objects = {first_oid: first, third_oid: third}

    class Store:
        def get_bounded(self, key, maximum):
            value = objects.get(key[4:])
            if value is not None and len(value) > maximum:
                raise PayloadTooLarge("fake object")
            return value

    secret = b"b" * 32
    gate = http.HttpGate(
        http.AsyncFromSyncReader(Store()),
        "workspace",
        secret,
        lambda: 100,
    )
    query = {"ws": "workspace"}
    body = json.dumps(
        [first_oid, missing_oid, third_oid]).encode()
    assert asyncio.run(gate.handle(
        "POST", "/obj", query, {}, body)).status == 401
    token = http.make_token(
        secret, "member", "workspace", issued_at=0, ttl_ms=1_000)
    headers = {"Authorization": "Bearer " + token}
    assert asyncio.run(gate.handle(
        "POST", "/obj", query, headers,
        json.dumps([first_oid] * 257).encode(),
    )).status == 413

    response = asyncio.run(gate.handle(
        "POST", "/obj", query, headers, body))
    assert response.status == 200
    assert json.loads(response.body) == [
        base64.b64encode(first).decode(), None,
        base64.b64encode(third).decode(),
    ]


def test_page_batch_route_stops_before_256_valid_objects_exceed_bytes(
        monkeypatch):
    objects = {
        h(f"object-{ordinal}".encode()): f"object-{ordinal}".encode()
        for ordinal in range(256)
    }

    class Store:
        def __init__(self):
            self.reads = 0

        def get_bounded(self, key, maximum):
            self.reads += 1
            value = objects.get(key[4:])
            if value is not None and len(value) > maximum:
                raise PayloadTooLarge("fake object")
            return value

    store = Store()

    secret = b"b" * 32
    gate = http.HttpGate(
        http.AsyncFromSyncReader(store),
        "workspace",
        secret,
        lambda: 100,
        max_batch_bytes=64,
    )
    token = http.make_token(
        secret, "member", "workspace", issued_at=0, ttl_ms=1_000)
    response = asyncio.run(gate.handle(
        "POST",
        "/obj",
        {"ws": "workspace"},
        {"Authorization": "Bearer " + token},
        json.dumps(list(objects)).encode(),
    ))

    assert response.status == 413
    assert store.reads < len(objects)
