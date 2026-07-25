"""Object-store concurrency contracts."""
import base64
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from core import daemon
from core.crypto import h
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
    assert store.etag("root") == h(root)
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

    def http(method, path, data):
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


def test_page_batch_route_is_authenticated_ordered_and_preserves_misses():
    first, third = b"first", b"third"
    objects = {"a" * 64: first, "c" * 64: third}

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
    handler._body = lambda: json.dumps(
        ["a" * 64, "b" * 64, "c" * 64]).encode()
    handler._json = lambda code, body: (code, body)
    handler._send = lambda code: code

    handler._member = lambda ws: None
    assert handler.do_POST() == 401
    handler._member = lambda ws: "member"
    handler._body = lambda: json.dumps(["a" * 64] * 257).encode()
    assert handler.do_POST() == 400
    handler._body = lambda: json.dumps(
        ["a" * 64, "b" * 64, "c" * 64]).encode()

    assert handler.do_POST() == (200, [
        base64.b64encode(first).decode(), None,
        base64.b64encode(third).decode(),
    ])
