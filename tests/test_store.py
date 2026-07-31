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
    VersionToken,
    verified_object,
)
from core.repository_applier import RepositoryApplier
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
    return asyncio.run(
        RepositoryApplier(WORKSPACE, store).admit_object(oid, raw))


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


def test_fs_get_bounded_never_accepts_a_whole_oversized_value(
        tmp_path, monkeypatch):
    store = FsStore(str(tmp_path))
    store.put("pile/member/value", b"12345")
    store.cas("root", ABSENT, b"root")

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
    assert store.read_versioned("root").value == b"root"


def test_applier_reconciles_ambiguous_create_and_verifies_collision():
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


def test_fs_root_cas_lock_is_shared_by_independent_handles(tmp_path):
    first, second = FsStore(str(tmp_path)), FsStore(str(tmp_path))
    result = first.cas("root", ABSENT, b"base")
    assert result == Applied(VersionToken(h(b"base")))
    base = first.read_versioned("root").token

    # Holding the bucket's stable lock prevents another handle from even
    # comparing the root. This distinguishes a shared CAS from two per-object
    # Python locks without relying on a lucky thread race.
    with open(first._root_lock, "a+b") as held, \
            ThreadPoolExecutor(max_workers=1) as pool:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(ValueError, match="reserved"):
            first.delete(".root.lock")
        attempt = pool.submit(
            second.cas, "root", base, b"after-lock")
        with pytest.raises(TimeoutError):
            attempt.result(timeout=0.1)
        fcntl.flock(held, fcntl.LOCK_UN)
        assert isinstance(attempt.result(timeout=5), Applied)

    expected = first.read_versioned("root").token
    start = threading.Barrier(2)

    def advance(store, value):
        start.wait(timeout=5)
        return store.cas("root", expected, value)

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
    assert first.get("root") in {b"alice", b"bob"}
    assert ".root.lock" not in first.list("")
    for key in (
            ".root.lock", ".root.lock/child", "./.root.lock",
            "root/child", "/outside", "../outside"):
        with pytest.raises(ValueError, match="key"):
            first.put(key, b"clobber")
    with pytest.raises(ValueError, match="only root"):
        first.cas("obj/" + h(b"x"), ABSENT, b"x")
    with pytest.raises(ValueError, match="conditional"):
        first.put("root", b"clobber")
    with pytest.raises(ValueError, match="compare-and-swap"):
        first.put_if_absent("root", b"clobber")
    with pytest.raises(ValueError, match="conditional"):
        first.put("obj/" + h(b"x"), b"x")
    with pytest.raises(ValueError, match="not deletable"):
        first.delete("root")
    with pytest.raises(ValueError, match="not deletable"):
        first.delete("obj/" + h(b"x"))


def test_remote_store_adapts_peer_gets_without_exposing_list():
    root, page = b"root", b"page"
    calls = []

    class Peer:
        def root(self, *, response_limit):
            calls.append(("root", response_limit))
            return root, h(root)

        def obj(self, oid, *, response_limit):
            calls.append((oid, response_limit))
            return page if oid == h(page) else None

    store = RemoteStore(Peer())

    assert store.get("root") == root
    assert store.get("obj/" + h(page)) == page
    assert store.get_bounded("root", len(root)) == root
    assert store.get_bounded("obj/" + h(page), len(page)) == page
    assert store.has("obj/" + h(page))
    assert calls == [
        ("root", MAX_ROOT_BYTES),
        (h(page), MAX_OBJECT_BYTES),
        ("root", len(root)),
        (h(page), len(page)),
        (h(page), MAX_OBJECT_BYTES),
    ]
    assert not hasattr(store, "read_versioned")
    with pytest.raises(TypeError, match="LIST"):
        store.list_page("obj/", None, 1)


def test_remote_store_batches_object_gets_in_bounded_order():
    keys = [f"obj/{ordinal:064x}" for ordinal in range(513)]

    class Peer:
        def __init__(self):
            self.calls = []

        def objs(self, oids):
            self.calls.append(tuple(oids))
            return tuple(oid.encode() for oid in oids)

    peer = Peer()
    assert RemoteStore(peer).get_many(keys) == tuple(
        key[4:].encode() for key in keys)
    assert list(map(len, peer.calls)) == [256, 256, 1]


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
    assert calls == [("POST", "/page", list(oids))]


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
                "https://peer/page", 413, "too large", {}, io.BytesIO())
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
                "https://peer/page", 413, "too large", {}, io.BytesIO())
        assert (method, path) == ("GET", f"/page/{oid}")
        return 200, raw, {}

    peer._http = http

    assert peer.objs((oid,)) == (raw,)
    assert calls == [
        ("POST", "/page", walk.MAX_PAGE_BATCH_BYTES),
        ("GET", f"/page/{oid}", walk.MAX_OBJECT_BYTES),
    ]


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
        walk.urllib.request, "urlopen",
        lambda *_args, **_kwargs: Response())
    peer = object.__new__(WalkPeer)
    peer.url, peer.ws, peer.cache = "https://peer", "workspace", {}

    with pytest.raises(ValueError, match="response too large"):
        peer._http(
            "GET", "/public", auth=False, response_limit=8)


@pytest.mark.parametrize("key", ("root", "obj/" + "a" * 64))
def test_remote_bounded_read_drives_the_peer_stream_limit(
        monkeypatch, key):
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
        walk.urllib.request, "urlopen",
        lambda *_args, **_kwargs: Response())
    peer = object.__new__(WalkPeer)
    peer.url, peer.ws = "https://peer", "workspace"
    peer.cache = {"token": "already-minted"}

    with pytest.raises(ValueError, match="response too large"):
        RemoteStore(peer).get_bounded(key, 8)


def test_peer_reads_snapshot_etag_case_insensitively():
    peer = object.__new__(WalkPeer)
    peer._http = lambda *_args, **_kwargs: (
        200, b"root", {"etag": "opaque"})

    assert peer.root(
        response_limit=MAX_ROOT_BYTES) == (b"root", "opaque")


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
        "POST", "/page", query, {}, body)).status == 401
    token = http.make_token(
        secret, "member", "workspace", issued_at=0, ttl_ms=1_000)
    headers = {"Authorization": "Bearer " + token}
    assert asyncio.run(gate.handle(
        "POST", "/page", query, headers,
        json.dumps([first_oid] * 257).encode(),
    )).status == 413

    response = asyncio.run(gate.handle(
        "POST", "/page", query, headers, body))
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
        "/page",
        {"ws": "workspace"},
        {"Authorization": "Bearer " + token},
        json.dumps(list(objects)).encode(),
    ))

    assert response.status == 413
    assert store.reads < len(objects)
