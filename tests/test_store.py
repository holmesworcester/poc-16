"""Object-store concurrency contracts."""
import base64
import fcntl
import io
import json
import os
import threading
import urllib.error
from concurrent.futures import ThreadPoolExecutor, TimeoutError

import pytest

from core import daemon
from core import walk
from core.crypto import h
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    STALE,
    VersionToken,
    ensure_object,
)
from core.store import FsStore, RemoteStore
from core.walk import Peer as WalkPeer


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
        ensure_object(stores[1], h(raw), raw)
    with pytest.raises(ValueError, match="address"):
        stores[1].put_if_absent("obj/" + "0" * 64, raw)


def test_ensure_object_reconciles_ambiguous_create_and_verifies_collision():
    raw, other = b"wanted", b"wrong"
    oid = h(raw)

    class Store:
        def __init__(self, outcomes, incumbent=None):
            self.outcomes = list(outcomes)
            self.value = incumbent
            self.calls = 0

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

    applied = Store(["applied-unknown"])
    assert ensure_object(applied, oid, raw) is EXISTS
    assert applied.calls == 1

    retried = Store(["unknown", CREATED])
    assert ensure_object(retried, oid, raw) is CREATED
    assert retried.calls == 2

    with pytest.raises(ValueError, match="conflict"):
        ensure_object(Store([EXISTS], other), oid, raw)

    absent = Store(["unknown", "unknown"])
    with pytest.raises(OutcomeUnknown):
        ensure_object(absent, oid, raw)
    assert absent.calls == 2


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

    class Peer:
        def root(self):
            return root, h(root)

        def obj(self, oid):
            return page if oid == h(page) else None

    store = RemoteStore(Peer())

    assert store.get("root") == root
    assert store.get("obj/" + h(page)) == page
    assert store.has("obj/" + h(page))
    assert not hasattr(store, "read_versioned")
    with pytest.raises(TypeError, match="LIST"):
        store.list("obj/")


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


def test_peer_reports_a_single_object_that_cannot_fit_a_batch():
    peer = object.__new__(WalkPeer)

    def http(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "https://peer/page", 413, "too large", {}, io.BytesIO())

    peer._http = http

    with pytest.raises(ValueError, match="single object"):
        peer.objs(("a" * 64,))


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


def test_page_batch_route_is_authenticated_ordered_and_preserves_misses():
    first, third = b"first", b"third"
    first_oid, missing_oid, third_oid = h(first), "b" * 64, h(third)
    objects = {first_oid: first, third_oid: third}

    class Store:
        def get(self, key):
            return objects.get(key[4:])

    class Node:
        def store(self, ws):
            return Store()

    handler = object.__new__(daemon.Handler)
    handler.node = Node()
    handler._q = lambda: (["page"], {"ws": "workspace"})
    handler._known = lambda ws: True
    handler._member = lambda ws: "member"
    handler._body = lambda *_: json.dumps(
        [first_oid, missing_oid, third_oid]).encode()
    handler._json = lambda code, body, **kwargs: (code, body)
    handler._send = lambda code: code

    handler._member = lambda ws: None
    assert handler.do_POST() == 401
    handler._member = lambda ws: "member"
    handler._body = lambda *_: json.dumps([first_oid] * 257).encode()
    assert handler.do_POST() == 413
    handler._body = lambda *_: json.dumps(
        [first_oid, missing_oid, third_oid]).encode()

    assert handler.do_POST() == (200, [
        base64.b64encode(first).decode(), None,
        base64.b64encode(third).decode(),
    ])


def test_page_batch_route_stops_before_256_valid_objects_exceed_bytes(
        monkeypatch):
    objects = {
        h(f"object-{ordinal}".encode()): f"object-{ordinal}".encode()
        for ordinal in range(256)
    }

    class Store:
        def __init__(self):
            self.reads = 0

        def get(self, key):
            self.reads += 1
            return objects.get(key[4:])

    store = Store()

    class Node:
        def store(self, ws):
            return store

    handler = object.__new__(daemon.Handler)
    handler.node = Node()
    handler._q = lambda: (["page"], {"ws": "workspace"})
    handler._known = lambda ws: True
    handler._member = lambda ws: "member"
    handler._body = lambda *_: json.dumps(list(objects)).encode()
    handler._json = lambda code, body, **kwargs: (code, body)
    handler._send = lambda code, *args, **kwargs: code
    monkeypatch.setattr(daemon, "MAX_PAGE_BATCH_BYTES", 64)

    assert handler.do_POST() == 413
    assert store.reads < len(objects)
