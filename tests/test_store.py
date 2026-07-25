"""Object-store concurrency contracts."""
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.crypto import h
from core.store import FsStore, RemoteStore


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
