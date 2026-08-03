"""Real-socket tests for FullPeer's ordinary streaming pack data plane."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import asyncio
import http.client
import io
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import facts
import pytest

from core import peer_capability
from core.crypto import h
from core.grants import make_token
from core.limits import MAX_DIRECT_OBJECT_BYTES, MAX_OBJECT_BYTES
from core.pack_access import (
    MAX_PACK_BYTES,
    InvalidPackAccess,
    ObjectOpen,
    PackOpen,
    ScopedRequest,
    copy_object_get,
    copy_pack_get,
    decode_scoped_request,
    encode_object_open,
    encode_pack_open,
    encode_scoped_request,
    object_key,
    pack_key,
)
from core.object_store import EXISTS
from core.store import RemoteStore
from core.writer_repository import ensure_pile_async
from full_peer.node import FullPeer
from full_peer.pack_http import (
    STREAM_CHUNK_BYTES,
    FullPeerPackService,
    handler_for,
)
from full_peer.walk import Peer


NOW = 1_800_000_000_000
SECRET = b"full-peer-pack-test-secret-00001"


class Clock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


@contextmanager
def serving(tmp_path, *, ttl_ms=10_000, read_opener=open):
    peer = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(peer, "alice", ts=1)
    clock = Clock()
    packs = FullPeerPackService(
        peer, SECRET, clock=clock, ttl_ms=ttl_ms,
        read_opener=read_opener)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        handler_for(peer, SECRET, pack_service=packs),
    )
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield (
            f"http://{host}:{port}", peer, workspace, clock, packs)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


def request(url, method, path, *, body=None, headers=None, timeout=5):
    parsed = urlsplit(url)
    connection = http.client.HTTPConnection(
        parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(), dict(response.headers)
    finally:
        connection.close()


def bearer(peer, workspace, clock, capability=peer_capability.FULL):
    return {"Authorization": "Bearer " + make_token(
        SECRET,
        peer.member_for(workspace),
        workspace,
        capability=capability,
        issued_at=clock(),
        ttl_ms=60_000,
    )}


def open_pack(url, peer, workspace, clock, opened, *, capability=None):
    status, raw, _headers = request(
        url,
        "POST",
        f"/pack/open?ws={workspace}",
        body=encode_pack_open(opened),
        headers=bearer(
            peer, workspace, clock,
            peer_capability.FULL if capability is None else capability),
    )
    assert status == 200
    return decode_scoped_request(raw)


def open_object(url, peer, workspace, clock, opened):
    status, raw, _headers = request(
        url,
        "POST",
        f"/obj/open?ws={workspace}",
        body=encode_object_open(opened),
        headers=bearer(
            peer, workspace, clock,
            peer_capability.READ_ONLY
            if opened.method == "GET" else peer_capability.FULL),
    )
    assert status == 200
    return decode_scoped_request(raw)


def perform(scoped, *, body=None, headers=None):
    parsed = urlsplit(scoped.url)
    supplied = dict(scoped.headers)
    supplied.update(headers or {})
    return request(
        f"{parsed.scheme}://{parsed.netloc}",
        scoped.method,
        parsed.path + ("?" + parsed.query if parsed.query else ""),
        body=body,
        headers=supplied,
    )


def copy_get(scoped, opened):
    """Use the common receiver while the real socket remains streaming."""
    parsed = urlsplit(scoped.url)
    connection = http.client.HTTPConnection(
        parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request(
            "GET",
            parsed.path + ("?" + parsed.query if parsed.query else ""),
            headers=dict(scoped.headers),
        )
        response = connection.getresponse()
        sink = io.BytesIO()

        def chunks():
            while True:
                chunk = response.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    return
                yield chunk

        copy_pack_get(
            opened, response.status, dict(response.headers),
            chunks(), sink.write)
        return response.status, sink.getvalue(), dict(response.headers)
    finally:
        connection.close()


def copy_object(scoped, opened):
    """Use the common object verifier over the FullPeer streaming route."""
    parsed = urlsplit(scoped.url)
    connection = http.client.HTTPConnection(
        parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request(
            "GET",
            parsed.path + ("?" + parsed.query if parsed.query else ""),
            headers=dict(scoped.headers),
        )
        response = connection.getresponse()
        sink = io.BytesIO()

        def chunks():
            while True:
                chunk = response.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    return
                yield chunk

        copy_object_get(
            opened, response.status, dict(response.headers),
            chunks(), sink.write)
        return response.status, sink.getvalue(), dict(response.headers)
    finally:
        connection.close()


def pack_path(peer, workspace, oid):
    return os.path.join(peer.store(workspace).root, pack_key(oid))


def object_path(peer, workspace, oid):
    return os.path.join(peer.store(workspace).root, object_key(oid))


def temp_paths(peer, workspace):
    directory = os.path.dirname(pack_path(peer, workspace, "0" * 64))
    return tuple(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.endswith(".tmp")
    ) if os.path.isdir(directory) else ()


def object_temp_paths(peer, workspace):
    directory = os.path.dirname(
        object_path(peer, workspace, "0" * 64))
    return tuple(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.endswith(".tmp")
    ) if os.path.isdir(directory) else ()


def test_real_http_streams_whole_put_get_and_exact_206_range(tmp_path):
    body = (b"complete signed pile bytes\0" * 10_000) \
        + b"final boundary"
    oid = h(body)
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        put = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, len(body)))
        assert perform(put, body=io.BytesIO(body))[0] == 201
        assert open(pack_path(peer, workspace, oid), "rb").read() == body

        whole_open = PackOpen("GET", oid, len(body))
        whole = open_pack(
            url, peer, workspace, clock,
            whole_open,
            capability=peer_capability.READ_ONLY)
        status, recovered, headers = copy_get(whole, whole_open)
        assert status == 200
        assert recovered == body
        assert headers["Content-Length"] == str(len(body))
        assert headers["Accept-Ranges"] == "bytes"

        offset, length = STREAM_CHUNK_BYTES - 7, STREAM_CHUNK_BYTES + 19
        ranged_open = PackOpen("GET", oid, len(body), offset, length)
        ranged = open_pack(
            url, peer, workspace, clock,
            ranged_open,
            capability=peer_capability.READ_ONLY)
        status, recovered, headers = copy_get(ranged, ranged_open)
        assert status == 206
        assert recovered == body[offset:offset + length]
        assert headers["Content-Range"] == (
            f"bytes {offset}-{offset + length - 1}/{len(body)}")


def test_real_http_streams_tree_selected_object_outside_gate_buffer(tmp_path):
    body = b"one independently closed pile\0" * 20_000
    oid = h(body)
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        store = peer.store(workspace)
        assert store.put_if_absent(object_key(oid), body).value == "created"
        original = store.get_bounded

        def guarded(key, maximum):
            if key == object_key(oid):
                raise AssertionError("large object entered buffered gate read")
            return original(key, maximum)

        store.get_bounded = guarded
        opened = ObjectOpen("GET", oid, len(body))
        scoped = open_object(url, peer, workspace, clock, opened)
        status, recovered, headers = copy_object(scoped, opened)

        assert status == 200
        assert recovered == body
        assert headers["Content-Length"] == str(len(body))
        assert urlsplit(scoped.url).path == "/" + object_key(oid)
        assert scoped.method == "GET" and scoped.headers == ()


def test_real_http_direct_object_put_is_create_only_and_hash_checked(tmp_path):
    body = b"one directly established closed pile\0" * 20_000
    oid = h(body)
    corrupt_oid = h(b"different logical object")
    collision_body = b"correct occupied object" * 20_000
    collision_oid = h(collision_body)
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        opened = ObjectOpen("PUT", oid, len(body))
        first = open_object(url, peer, workspace, clock, opened)
        second = open_object(url, peer, workspace, clock, opened)

        assert perform(first, body=io.BytesIO(body))[0] == 201
        assert perform(second, body=io.BytesIO(body))[0] == 204
        with open(object_path(peer, workspace, oid), "rb") as source:
            assert source.read() == body

        wrong_hash = open_object(
            url, peer, workspace, clock,
            ObjectOpen("PUT", corrupt_oid, len(body)))
        assert perform(wrong_hash, body=io.BytesIO(body))[0] == 400
        assert not os.path.exists(object_path(
            peer, workspace, corrupt_oid))

        corrupt_path = object_path(peer, workspace, collision_oid)
        os.makedirs(os.path.dirname(corrupt_path), exist_ok=True)
        with open(corrupt_path, "wb") as target:
            target.write(b"x" * len(collision_body))
        collision = open_object(
            url, peer, workspace, clock,
            ObjectOpen("PUT", collision_oid, len(collision_body)))
        assert perform(
            collision, body=io.BytesIO(collision_body))[0] == 409
        with open(corrupt_path, "rb") as source:
            assert source.read() == b"x" * len(collision_body)
        assert object_temp_paths(peer, workspace) == ()

        # The former buffered mutation is gone, including for small bodies.
        assert request(
            url,
            "PUT",
            f"/{object_key(h(b'old route'))}?ws={workspace}",
            body=b"old route",
            headers=bearer(peer, workspace, clock),
        )[0] == 404


def test_object_ticket_cannot_widen_key_method_size_or_lifetime(tmp_path):
    body = b"bounded direct object"
    oid = h(body)
    with serving(tmp_path, ttl_ms=50) \
            as (url, peer, workspace, clock, _packs):
        peer.store(workspace).put_if_absent(object_key(oid), body)
        opened = ObjectOpen("GET", oid, len(body))
        scoped = open_object(url, peer, workspace, clock, opened)
        parsed = urlsplit(scoped.url)
        path = parsed.path + "?" + parsed.query
        base = f"{parsed.scheme}://{parsed.netloc}"

        assert request(base, "PUT", path, body=b"")[0] == 403
        assert request(
            base, "GET", path.replace(oid, h(b"wrong")))[0] == 403
        assert request(
            base, "GET", path, headers={"Range": "bytes=0-1"})[0] == 403

        smaller = open_object(
            url, peer, workspace, clock,
            ObjectOpen("GET", oid, len(body) - 1))
        assert perform(smaller)[0] == 413

        clock.value += 50
        assert perform(scoped)[0] == 403


def test_object_put_ticket_requires_push_exact_length_and_fresh_scope(tmp_path):
    body = b"exact object PUT ticket"
    oid = h(body)
    with serving(tmp_path, ttl_ms=50) \
            as (url, peer, workspace, clock, _packs):
        opened = ObjectOpen("PUT", oid, len(body))
        status, _, _ = request(
            url,
            "POST",
            f"/obj/open?ws={workspace}",
            body=encode_object_open(opened),
            headers=bearer(
                peer, workspace, clock, peer_capability.READ_ONLY),
        )
        assert status == 401

        scoped = open_object(url, peer, workspace, clock, opened)
        assert perform(
            scoped,
            body=body,
            headers={"content-length": str(len(body) - 1)},
        )[0] == 403
        parsed = urlsplit(scoped.url)
        widened = parsed.path.replace(oid, h(b"another object")) \
            + "?" + parsed.query
        assert request(
            f"{parsed.scheme}://{parsed.netloc}",
            "PUT",
            widened,
            body=body,
            headers=dict(scoped.headers),
        )[0] == 403
        clock.value += 50
        assert perform(scoped, body=body)[0] == 403
        assert not os.path.exists(object_path(peer, workspace, oid))


def test_opening_the_95_mib_ceiling_allocates_only_control_metadata(tmp_path):
    oid = h(b"not allocated")
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        scoped = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, MAX_PACK_BYTES))

        assert dict(scoped.headers)["content-length"] \
            == str(MAX_PACK_BYTES)
        assert len(scoped.url) < 512
        assert not os.path.exists(pack_path(peer, workspace, oid))
        assert temp_paths(peer, workspace) == ()

        direct = open_object(
            url, peer, workspace, clock,
            ObjectOpen("PUT", oid, MAX_DIRECT_OBJECT_BYTES))
        assert direct.method == "PUT"
        assert dict(direct.headers) == {
            "content-length": str(MAX_DIRECT_OBJECT_BYTES),
            "if-none-match": "*",
        }
        assert len(direct.url) < 512
        assert not os.path.exists(object_path(peer, workspace, oid))


def test_wrong_hash_length_and_corrupt_collision_never_establish(tmp_path):
    body = b"good pack" * 20_000
    oid = h(body)
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        wrong_hash = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", h(b"other"), len(body)))
        assert perform(wrong_hash, body=body)[0] == 400
        assert not os.path.exists(
            pack_path(peer, workspace, h(b"other")))

        correct = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, len(body)))
        assert perform(
            correct,
            body=body,
            headers={"content-length": str(len(body) - 1)},
        )[0] == 403
        assert not os.path.exists(pack_path(peer, workspace, oid))

        path = pack_path(peer, workspace, oid)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as target:
            target.write(b"x" * len(body))
        assert perform(correct, body=body)[0] == 409
        with open(path, "rb") as source:
            assert source.read() == b"x" * len(body)
        assert temp_paths(peer, workspace) == ()


def test_existing_valid_pack_is_an_idempotent_collision(tmp_path):
    body, oid = b"idempotent pack" * 10_000, None
    oid = h(body)
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        first = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, len(body)))
        second = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, len(body)))
        assert perform(first, body=body)[0] == 201
        assert perform(second, body=body)[0] == 204
        assert temp_paths(peer, workspace) == ()


def test_ticket_expiry_and_method_key_range_widening_fail_closed(tmp_path):
    body = b"ticket scope" * 20_000
    oid = h(body)
    with serving(tmp_path, ttl_ms=50) \
            as (url, peer, workspace, clock, _packs):
        put = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, len(body)))
        assert perform(put, body=body)[0] == 201

        opened = PackOpen("GET", oid, len(body), 10, 100)
        scoped = open_pack(
            url, peer, workspace, clock, opened,
            capability=peer_capability.READ_ONLY)
        parsed = urlsplit(scoped.url)
        path = parsed.path + "?" + parsed.query
        base = f"{parsed.scheme}://{parsed.netloc}"
        assert request(base, "PUT", path, body=b"", headers={})[0] == 403
        assert request(
            base, "GET", path.replace(oid, h(b"wrong key")),
            headers=dict(scoped.headers))[0] == 403
        assert request(base, "GET", path, headers={})[0] == 403
        assert request(
            base, "GET", path,
            headers={"Range": "bytes=10-110"})[0] == 403

        clock.value += 50
        assert perform(scoped)[0] == 403


def test_concurrent_identical_and_different_puts_never_clobber(tmp_path):
    same = b"same" * 50_000
    different = (b"left" * 40_000, b"right" * 40_000)
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        same_scopes = tuple(
            open_pack(
                url, peer, workspace, clock,
                PackOpen("PUT", h(same), len(same)))
            for _ in range(2)
        )
        barrier = threading.Barrier(2)

        def upload_same(scoped):
            barrier.wait()
            return perform(scoped, body=same)[0]

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = tuple(pool.map(upload_same, same_scopes))
        assert sorted(statuses) == [201, 204]

        scopes = tuple(
            open_pack(
                url, peer, workspace, clock,
                PackOpen("PUT", h(body), len(body)))
            for body in different
        )
        barrier = threading.Barrier(2)

        def upload_different(pair):
            scoped, body = pair
            barrier.wait()
            return perform(scoped, body=body)[0]

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = tuple(pool.map(
                upload_different, zip(scopes, different)))
        assert statuses == (201, 201)
        for body in (same, *different):
            with open(pack_path(peer, workspace, h(body)), "rb") as source:
                assert source.read() == body
        assert temp_paths(peer, workspace) == ()


def test_interrupted_put_removes_same_directory_temporary_file(tmp_path):
    size = 4 * STREAM_CHUNK_BYTES
    oid = h(b"body that will never be sent")
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        scoped = open_pack(
            url, peer, workspace, clock, PackOpen("PUT", oid, size))
        parsed = urlsplit(scoped.url)
        sock = socket.create_connection(
            (parsed.hostname, parsed.port), timeout=5)
        request_head = (
            f"PUT {parsed.path}?{parsed.query} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"Content-Length: {size}\r\n"
            "If-None-Match: *\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(request_head + b"partial")
        sock.shutdown(socket.SHUT_WR)
        while sock.recv(4096):
            pass
        sock.close()

        assert temp_paths(peer, workspace) == ()
        assert not os.path.exists(pack_path(peer, workspace, oid))


def test_interrupted_object_put_removes_same_directory_temporary_file(
        tmp_path):
    size = 4 * STREAM_CHUNK_BYTES
    oid = h(b"object body that will never be sent")
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        scoped = open_object(
            url, peer, workspace, clock,
            ObjectOpen("PUT", oid, size))
        parsed = urlsplit(scoped.url)
        sock = socket.create_connection(
            (parsed.hostname, parsed.port), timeout=5)
        request_head = (
            f"PUT {parsed.path}?{parsed.query} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"Content-Length: {size}\r\n"
            "If-None-Match: *\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(request_head + b"partial")
        sock.shutdown(socket.SHUT_WR)
        while sock.recv(4096):
            pass
        sock.close()

        assert object_temp_paths(peer, workspace) == ()
        assert not os.path.exists(object_path(peer, workspace, oid))


def test_lost_object_put_ack_reconciles_through_exact_direct_get(tmp_path):
    body = b"x" * (MAX_OBJECT_BYTES + 1)
    oid = h(body)
    with serving(tmp_path) as (url, peer, workspace, clock, service):
        clock.value = time.time_ns() // 1_000_000
        finish = service._finish
        lost = True

        def lose_first_created(handler, status, *, length=0, headers=()):
            nonlocal lost
            if lost and status == 201:
                lost = False
                handler.close_connection = True
                handler.connection.shutdown(socket.SHUT_RDWR)
                handler.connection.close()
                return None
            return finish(
                handler, status, length=length, headers=headers)

        service._finish = lose_first_created
        client = Peer(peer, workspace, url)
        client.cache.update({
            "sync_profile": peer_capability.FULL,
            "token": make_token(
                SECRET,
                peer.member_for(workspace),
                workspace,
                capability=peer_capability.FULL,
                issued_at=clock(),
                ttl_ms=60_000,
            ),
        })
        remote = RemoteStore(client)
        result = asyncio.run(ensure_pile_async(remote, oid, body))

        assert result is EXISTS
        assert not lost
        with open(object_path(peer, workspace, oid), "rb") as source:
            assert source.read() == body


def test_direct_object_put_never_follows_provider_redirect():
    paths = []

    class Redirect(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_PUT(self):
            paths.append(self.path)
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(307)
            self.send_header("Content-Length", "0")
            self.send_header("Location", "/redirected")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = b"must not be redirected"
        oid = h(body)
        host, port = server.server_address[:2]
        expires = int(time.time() * 1000) + 10_000
        scoped = ScopedRequest(
            "PUT",
            f"http://{host}:{port}/{object_key(oid)}?ticket=exact",
            (
                ("content-length", str(len(body))),
                ("if-none-match", "*"),
            ),
            expires,
        )
        peer = object.__new__(Peer)
        peer._http = lambda *_args, **_kwargs: (
            200, encode_scoped_request(scoped), {})

        with pytest.raises(ValueError, match="HTTP 307"):
            peer.put_obj(oid, body)
        assert paths == [f"/{object_key(oid)}?ticket=exact"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_independent_service_never_collects_another_upload_temp(tmp_path):
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        directory = os.path.dirname(
            pack_path(peer, workspace, "0" * 64))
        os.makedirs(directory, exist_ok=True)
        foreign = os.path.join(directory, ".pack-upload-other.tmp")
        with open(foreign, "wb") as target:
            target.write(b"active in another process")

        independent = FullPeerPackService(peer, SECRET, clock=clock)
        independent.issue(
            workspace,
            peer.member_for(workspace),
            PackOpen("GET", h(b"future pack"), 1),
            clock(),
            url,
        )

        with open(foreign, "rb") as source:
            assert source.read() == b"active in another process"


def test_stream_reader_never_uses_an_unbounded_or_oversized_read(tmp_path):
    calls = []

    class BoundedReader:
        def __init__(self, source):
            self.source = source

        def read(self, size=-1):
            assert 0 < size <= STREAM_CHUNK_BYTES
            calls.append(size)
            return self.source.read(size)

        def seek(self, offset):
            return self.source.seek(offset)

        def close(self):
            return self.source.close()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def bounded_open(path, mode):
        return BoundedReader(open(path, mode))

    body = b"bounded reader" * 30_000
    oid = h(body)
    with serving(tmp_path, read_opener=bounded_open) \
            as (url, peer, workspace, clock, _packs):
        put = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, len(body)))
        assert perform(put, body=body)[0] == 201
        opened = PackOpen("GET", oid, len(body))
        get = open_pack(
            url, peer, workspace, clock,
            opened,
            capability=peer_capability.READ_ONLY)
        assert copy_get(get, opened)[1] == body
    assert calls
    assert max(calls) == STREAM_CHUNK_BYTES


def test_same_size_disk_corruption_is_detected_by_the_receiving_hash(tmp_path):
    body = b"immutable source" * 20_000
    oid = h(body)
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        put = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, len(body)))
        assert perform(put, body=body)[0] == 201
        path = pack_path(peer, workspace, oid)
        with open(path, "r+b") as target:
            target.seek(len(body) // 2)
            target.write(b"!")

        opened = PackOpen("GET", oid, len(body))
        get = open_pack(
            url, peer, workspace, clock,
            opened,
            capability=peer_capability.READ_ONLY)
        with pytest.raises(InvalidPackAccess, match="integrity"):
            copy_get(get, opened)


def test_pack_bodies_never_use_bounded_object_store_reads(tmp_path):
    body = b"separate data plane" * 20_000
    oid = h(body)
    with serving(tmp_path) as (url, peer, workspace, clock, _packs):
        store = peer.store(workspace)
        original = store.get_bounded

        def guarded(key, maximum):
            assert not key.startswith("pack/")
            return original(key, maximum)

        store.get_bounded = guarded
        put = open_pack(
            url, peer, workspace, clock,
            PackOpen("PUT", oid, len(body)))
        assert perform(put, body=body)[0] == 201
        opened = PackOpen("GET", oid, len(body))
        get = open_pack(
            url, peer, workspace, clock,
            opened,
            capability=peer_capability.READ_ONLY)
        assert copy_get(get, opened)[1] == body
