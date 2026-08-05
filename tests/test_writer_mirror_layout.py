"""Layout-guided RepositoryMirror fetches remain signed-tree subordinate."""
import asyncio
from contextlib import contextmanager
import threading
from http.server import ThreadingHTTPServer

import pytest

from core import peer_capability
from core.close import (
    encode_signed_pile,
    make_signed_pile,
    signed_pile_oid,
)
from core.crypto import h, keypair
from core.fact import canon
from core.grants import make_token
from core.limits import (
    MAX_FACT_BYTES,
    MAX_SEMANTIC_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
)
from core.object_store import ABSENT, Applied, Versioned
from core.pack_access import PackOpen, copy_pack_get
from core.store import FsStore, RemoteStore
from core.writer_fetch import fetch_layout_piles
from core.writer_head import (
    HeadSlot,
    WriterBinding,
    decode_slot_at,
    encode_head,
    encode_slot,
    head_oid,
    head_slot_key,
    make_head,
)
from core.writer_layout import (
    MAX_LAYOUT_PAGE_BYTES,
    WINDOW_PILES,
    LayoutPage,
    build_pack,
    encode_layout_page,
    layout_page_key,
    window_start,
)
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
from tests.util import mechanical_head_authorizer
from core.writer_tree import EMPTY_TREE, append_piles, leaf_key
from facts.auth.device import device as device_fact
from facts.auth.head_request import head_request
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message as message_fact
from full_peer.pack_http import handler_for as pack_handler_for
from full_peer.walk import Peer


SECRET = b"writer-mirror-layout-http-secret"


def run(awaitable):
    return asyncio.run(awaitable)


def authority_proof(
        secret, public, root, device_signature, device, proposed_head,
        base_head=None):
    request = head_request(
        root.fid, public, public, base_head,
        proposed_head, 1_000, h(b"mechanical removal path"), 100)
    request_signature = signature_fact(
        secret, public, request, 100)
    return encode_signed_pile(make_signed_pile(
        secret,
        root.fid,
        public,
        (root, device_signature, device, request_signature, request),
    ))


async def published(store, count=3, *, large=False):
    secret, public = keypair()
    root = workspace_fact(secret, public, "workspace", 1)
    device = device_fact(root.fid, public, "device", 2)
    device_signature = signature_fact(secret, public, device, 2)
    binding = WriterBinding(
        root.fid, public, public, h(b"writer-layout-store"))
    closures = [(root, device_signature, device)]
    for ordinal in range(1, count):
        text = f"message {ordinal}"
        if large and ordinal == count - 1:
            probe = message_fact(
                root.fid, public, "general", "", 10 + ordinal)
            text = "x" * (
                MAX_FACT_BYTES - len(canon(probe.to_json())))
        message = message_fact(
            root.fid, public, "general", text, 10 + ordinal)
        signed = signature_fact(
            secret, public, message, 10 + ordinal)
        closures.append((
            root, device_signature, device, signed, message))
    writer = WriterLog(
        root.fid, public, public, binding.store,
        secret, store)
    update = await writer.prepare(tuple(closures))
    await writer.establish(update)
    result = await OpaqueHeadGate(
        store,
        mechanical_head_authorizer(
            root.fid, h(b"removal root")),
    ).advance(
        authority_proof(
            secret, public, root, device_signature,
            device, update.head_oid),
        update.head_oid,
        10,
    )
    assert result.status == "applied"
    raws = tuple(encode_signed_pile(pile) for pile in update.piles)
    return secret, public, root, device_signature, device, binding, update, raws


def resolver(binding):
    def resolve(workspace, device, _removal_root, _candidate):
        return binding if (
            workspace, device) == (
                binding.workspace, binding.device) else None
    return resolve


def publish_page(store, workspace, device, placements):
    start = window_start(placements[0].first)
    raw = encode_layout_page(LayoutPage(
        workspace, device, start, tuple(placements)))
    result = store.cas(
        layout_page_key(workspace, device, start), ABSENT, raw)
    assert isinstance(result, Applied)


class LayoutSource:
    """Awaited fake provider with a physically separate pack data plane."""

    def __init__(self, backing, pack_bodies):
        self.backing = backing
        self.pack_bodies = dict(pack_bodies)
        self.layout_reads = []
        self.pack_reads = []
        self.loose_batches = []
        self.page_overrides = {}
        self.pack_overrides = {}
        self.range_overrides = {}

    async def get_bounded(self, key, maximum):
        assert not key.startswith("pack/")
        return self.backing.get_bounded(key, maximum)

    async def read_versioned(self, key):
        return self.backing.read_versioned(key)

    async def put_if_absent(self, key, value):
        return self.backing.put_if_absent(key, value)

    async def cas(self, key, token, value):
        return self.backing.cas(key, token, value)

    async def list_page(self, prefix, cursor=None, limit=256):
        return self.backing.list_page(prefix, cursor, limit)

    async def get_many(self, keys):
        return tuple(self.backing.get_bounded(key, 4 * 1024 * 1024)
                     for key in keys)

    async def fetch_writer_piles(self, workspace, device, rows):
        async def read_layout(key, maximum):
            self.layout_reads.append(key)
            if key in self.page_overrides:
                return self.page_overrides[key]
            return self.backing.get_bounded(key, maximum)

        async def copy_pack(opened, write):
            self.pack_reads.append(opened)
            body = self.pack_overrides.get(
                opened.oid, self.pack_bodies.get(opened.oid))
            if body is None:
                raise FileNotFoundError(opened.oid)
            if opened.offset is None:
                status = 200
                selected = body
                headers = {"Content-Length": str(len(selected))}
            else:
                status = 206
                selected = body[
                    opened.offset:opened.offset + opened.length]
                selected = self.range_overrides.get(
                    (opened.oid, opened.offset, opened.length), selected)
                headers = {
                    "Content-Length": str(len(selected)),
                    "Content-Range": (
                        f"bytes {opened.offset}-"
                        f"{opened.offset + opened.length - 1}/"
                        f"{opened.pack_bytes}"
                    ),
                }
            middle = max(1, len(selected) // 2)
            chunks = tuple(filter(None, (
                selected[:middle], selected[middle:])))
            return copy_pack_get(
                opened, status, headers, chunks, write)

        async def read_loose(oids, maximum):
            self.loose_batches.append(tuple(oids))
            out = []
            for oid in oids:
                value = bytearray()
                copied = self.backing.copy_pile_object(
                    oid, maximum, value.extend)
                out.append(None if copied is None else bytes(value))
            return tuple(out)

        return await fetch_layout_piles(
            workspace,
            device,
            rows,
            read_layout=read_layout,
            copy_pack=copy_pack,
            read_loose=read_loose,
        )


async def sync_receiver(tmp_path, name, fixture, source, consumer=True):
    _secret, public, root, _sig, _device, binding, _update, _raws = fixture
    store = FsStore(str(tmp_path / name))
    sink = FactConsumer(root.fid) if consumer else None
    result = await RepositoryMirror(
        root.fid,
        store,
        resolver(binding),
        sink,
        observe_controls=not consumer,
    ).sync_from(source)
    return store, sink, result


def test_cold_mirror_uses_one_whole_pack_and_matches_opaque_peer(tmp_path):
    async def scenario():
        backing = FsStore(str(tmp_path / "source"))
        fixture = await published(backing, 3)
        _secret, public, root, _sig, _device, _binding, update, raws = fixture
        placement, body = build_pack(root.fid, public, 1, raws)
        publish_page(backing, root.fid, public, (placement,))
        source = LayoutSource(backing, {placement.pack_oid: body})

        consuming_store, consumer, consuming = await sync_receiver(
            tmp_path, "consuming", fixture, source)
        assert consuming.errors == ()
        assert consuming.changed == 1 and consuming.piles == len(raws)
        assert source.pack_reads == [
            PackOpen("GET", placement.pack_oid, placement.pack_bytes)]
        assert source.loose_batches == []

        source.pack_reads.clear()
        opaque_store, _none, opaque = await sync_receiver(
            tmp_path, "opaque", fixture, source, consumer=False)
        assert opaque.errors == ()
        assert opaque.changed == 1 and opaque.piles == len(raws)
        assert source.pack_reads == [
            PackOpen("GET", placement.pack_oid, placement.pack_bytes)]
        assert source.loose_batches == []
        assert consumer.fact_ids()

        pile_keys = tuple("obj/" + signed_pile_oid(raw) for raw in raws)
        key = head_slot_key(root.fid, public)
        for object_key in (*pile_keys, "obj/" + update.head_oid):
            assert consuming_store.get(object_key) \
                == opaque_store.get(object_key)
        assert decode_slot_at(
            key, consuming_store.get(key)).head == decode_slot_at(
                key, opaque_store.get(key)).head

    run(scenario())


def test_warm_sparse_difference_uses_one_exact_pile_range(tmp_path):
    async def scenario():
        backing = FsStore(str(tmp_path / "source"))
        first = await published(backing, 1)
        receiver, consumer, initial = await sync_receiver(
            tmp_path, "receiver", first, backing)
        assert initial.errors == ()

        secret, public, root, device_signature, device, binding, old, raws = first
        writer = WriterLog(
            root.fid, public, public, binding.store, secret, backing)
        message = message_fact(
            root.fid, public, "general", "later", 50)
        signed = signature_fact(secret, public, message, 50)
        update = await writer.prepare(((
            root, device_signature, device, signed, message),))
        await writer.establish(update)
        proof = authority_proof(
            secret, public, root, device_signature, device,
            update.head_oid, update.base_head)
        advanced = await OpaqueHeadGate(
            backing,
            mechanical_head_authorizer(
                root.fid, h(b"removal root")),
        ).advance(proof, update.head_oid, 10)
        assert advanced.status == "applied"
        all_raws = raws + tuple(
            encode_signed_pile(pile) for pile in update.piles)
        placement, body = build_pack(root.fid, public, 1, all_raws)
        publish_page(backing, root.fid, public, (placement,))
        source = LayoutSource(backing, {placement.pack_oid: body})

        result = await RepositoryMirror(
            root.fid, receiver, resolver(binding), consumer).sync_from(source)
        assert result.errors == ()
        assert result.changed == result.piles == 1
        offset, length = placement.byte_range(2)
        assert source.pack_reads == [PackOpen(
            "GET", placement.pack_oid, placement.pack_bytes,
            offset, length)]
        assert source.loose_batches == []

    run(scenario())


def test_mixed_pack_and_hole_batches_only_the_loose_hole(tmp_path):
    async def scenario():
        backing = FsStore(str(tmp_path / "source"))
        fixture = await published(backing, 3)
        _secret, public, root, _sig, _device, _binding, _update, raws = fixture
        placement, body = build_pack(root.fid, public, 1, raws[:2])
        publish_page(backing, root.fid, public, (placement,))
        source = LayoutSource(backing, {placement.pack_oid: body})

        _store, _consumer, result = await sync_receiver(
            tmp_path, "receiver", fixture, source)
        assert result.errors == ()
        assert source.pack_reads == [
            PackOpen("GET", placement.pack_oid, placement.pack_bytes)]
        assert source.loose_batches == [(signed_pile_oid(raws[2]),)]

    run(scenario())


@pytest.mark.parametrize("failure", (
    "missing-page", "bad-page", "stale-page", "bad-pack",
))
def test_missing_or_corrupt_layout_hint_falls_back_loose(tmp_path, failure):
    async def scenario():
        backing = FsStore(str(tmp_path / failure / "source"))
        fixture = await published(backing, 2)
        _secret, public, root, _sig, _device, _binding, _update, raws = fixture
        placement, body = build_pack(root.fid, public, 1, raws)
        packs = {placement.pack_oid: body}
        key = layout_page_key(root.fid, public, 1)
        if failure != "missing-page":
            published_placement = placement
            if failure == "stale-page":
                published_placement, stale = build_pack(
                    root.fid, public, 1, tuple(reversed(raws)))
                packs[published_placement.pack_oid] = stale
            publish_page(
                backing, root.fid, public, (published_placement,))
        source = LayoutSource(backing, packs)
        if failure == "bad-page":
            source.page_overrides[key] = b"not a layout page"
        if failure == "bad-pack":
            source.pack_overrides[placement.pack_oid] = body[:-1] + b"!"

        _store, _consumer, result = await sync_receiver(
            tmp_path / failure, "receiver", fixture, source)
        assert result.errors == ()
        assert source.loose_batches == [tuple(map(signed_pile_oid, raws))]
        if failure in {"bad-pack", "stale-page"}:
            expected = published_placement
            assert source.pack_reads == [PackOpen(
                "GET", expected.pack_oid, expected.pack_bytes)]
        else:
            assert source.pack_reads == []

    run(scenario())


def test_wrong_sparse_slice_is_rejected_then_recovered_by_exact_oid(tmp_path):
    async def scenario():
        backing = FsStore(str(tmp_path / "source"))
        fixture = await published(backing, 2)
        _secret, public, root, _sig, _device, _binding, _update, raws = fixture
        placement, body = build_pack(root.fid, public, 1, raws)
        publish_page(backing, root.fid, public, (placement,))
        source = LayoutSource(backing, {placement.pack_oid: body})
        offset, length = placement.byte_range(2)
        source.range_overrides[(
            placement.pack_oid, offset, length)] = b"x" * length

        # Selecting only row two makes this a range request without needing a
        # synthetic writer-tree fork. The bad slice cannot satisfy its OID and
        # therefore falls through to the normal object.
        got = await source.fetch_writer_piles(
            root.fid, public,
            ((leaf_key(2), signed_pile_oid(raws[1])),))
        assert got == (raws[1],)
        assert source.pack_reads == [PackOpen(
            "GET", placement.pack_oid, placement.pack_bytes,
            offset, length)]
        assert source.loose_batches == [(signed_pile_oid(raws[1]),)]

    run(scenario())


def test_layout_fetch_never_coalesces_across_fixed_windows(tmp_path):
    async def scenario():
        backing = FsStore(str(tmp_path / "source"))
        fixture = await published(backing, 2)
        _secret, public, root, _sig, _device, _binding, _update, raws = fixture
        placements, bodies = [], {}
        for sequence, raw in (
                (WINDOW_PILES, raws[0]),
                (WINDOW_PILES + 1, raws[1])):
            placement, body = build_pack(
                root.fid, public, sequence, (raw,))
            publish_page(backing, root.fid, public, (placement,))
            placements.append(placement)
            bodies[placement.pack_oid] = body
        source = LayoutSource(backing, bodies)

        got = await source.fetch_writer_piles(
            root.fid,
            public,
            tuple(
                (leaf_key(sequence), signed_pile_oid(raw))
                for sequence, raw in (
                    (WINDOW_PILES, raws[0]),
                    (WINDOW_PILES + 1, raws[1]))
            ),
        )
        assert got == raws
        assert source.layout_reads == [
            layout_page_key(root.fid, public, 1),
            layout_page_key(root.fid, public, WINDOW_PILES + 1),
        ]
        assert source.pack_reads == [
            PackOpen("GET", item.pack_oid, item.pack_bytes)
            for item in placements
        ]

    run(scenario())


def test_repository_mirror_rechecks_capability_oid_and_commits_nothing(
        tmp_path):
    class SubstitutingSource(LayoutSource):
        async def fetch_writer_piles(self, _workspace, _device, _rows):
            return tuple(reversed(raws))

    async def scenario():
        nonlocal raws
        backing = FsStore(str(tmp_path / "source"))
        fixture = await published(backing, 2)
        _secret, public, root, _sig, _device, _binding, update, raws = fixture
        source = SubstitutingSource(backing, {})
        receiver, consumer, result = await sync_receiver(
            tmp_path, "receiver", fixture, source)

        assert result.changed == result.piles == result.facts == 0
        assert result.errors and result.errors[0][1] \
            == "repository object integrity"
        assert consumer.fact_ids() == ()
        assert receiver.get(head_slot_key(root.fid, public)) is None
        assert all(receiver.get("obj/" + signed_pile_oid(raw)) is None
                   for raw in raws)
        # Immutable head/tree metadata may be cached, but no semantic pile or
        # mutable slot crossed the complete-suffix commit boundary.
        assert receiver.get("obj/" + update.head_oid) is not None

    raws = ()
    run(scenario())


def test_packed_bad_later_pile_cannot_leak_earlier_valid_pile(tmp_path):
    async def scenario():
        secret, public = keypair()
        root = workspace_fact(secret, public, "workspace", 1)
        device = device_fact(root.fid, public, "device", 2)
        device_signature = signature_fact(secret, public, device, 2)
        binding = WriterBinding(
            root.fid, public, public, h(b"bad-suffix-store"))
        source_store = FsStore(str(tmp_path / "source"))
        receiver = FsStore(str(tmp_path / "receiver"))
        good = make_signed_pile(
            secret, root.fid, public,
            (root, device_signature, device))
        dangling = message_fact(
            root.fid, public, "general", "missing authority", 9)
        bad = make_signed_pile(
            secret, root.fid, public, (dangling,))
        raws = tuple(map(encode_signed_pile, (good, bad)))
        objects = {signed_pile_oid(raw): raw for raw in raws}

        def emit(raw):
            oid = h(raw)
            objects[oid] = raw
            return oid

        tree = append_piles(
            EMPTY_TREE, root.fid, public,
            tuple(map(signed_pile_oid, raws)), objects.get, emit)
        head = make_head(
            secret, root.fid, public, public,
            tree.count, tree, binding.store)
        raw_head = encode_head(head)
        oid_head = head_oid(raw_head)
        objects[oid_head] = raw_head
        for oid, raw in objects.items():
            source_store.put_if_absent("obj/" + oid, raw)
        key = head_slot_key(root.fid, public)
        source_store.cas(key, ABSENT, encode_slot(HeadSlot(
            root.fid, public, oid_head, h(b"removal root"))))
        placement, body = build_pack(root.fid, public, 1, raws)
        publish_page(source_store, root.fid, public, (placement,))
        source = LayoutSource(
            source_store, {placement.pack_oid: body})
        consumer = FactConsumer(root.fid)

        result = await RepositoryMirror(
            root.fid, receiver, resolver(binding), consumer,
        ).sync_from(source)
        assert result.changed == result.piles == result.facts == 0
        assert result.errors and "closed pile rejected" in result.errors[0][1]
        assert source.pack_reads == [PackOpen(
            "GET", placement.pack_oid, placement.pack_bytes)]
        assert consumer.fact_ids() == ()
        assert receiver.get(key) is None
        assert all(receiver.get("obj/" + signed_pile_oid(raw)) is None
                   for raw in raws)

    run(scenario())


class _ReadPeer:
    def __init__(self, workspace, store):
        self.workspace = workspace
        self._store = store
        self.lock = threading.RLock()

    def has_workspace(self, workspace):
        return workspace == self.workspace

    def store(self, workspace):
        if not self.has_workspace(workspace):
            raise KeyError(workspace)
        return self._store

class _DialNode:
    def __init__(self, token):
        self.token = token


def _preminted_peer(node, workspace, url):
    peer = Peer(node, workspace, url)
    peer._token = node.token
    peer._sync_profile = peer_capability.FULL
    return peer


@contextmanager
def serving(peer):
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), pack_handler_for(peer, SECRET))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


def test_real_http_remote_store_streams_pack_not_gate_response(tmp_path):
    async def prepare():
        backing = FsStore(str(tmp_path / "source"))
        fixture = await published(backing, 3)
        _secret, public, root, _sig, _device, binding, _update, raws = fixture
        placement, body = build_pack(root.fid, public, 1, raws)
        backing.put_if_absent("pack/" + placement.pack_oid, body)
        publish_page(backing, root.fid, public, (placement,))
        return backing, fixture, placement, body

    backing, fixture, placement, _body = run(prepare())
    _secret, public, root, _sig, _device, binding, _update, raws = fixture
    member = h(b"layout-reader")
    token = make_token(
        SECRET, member, root.fid,
        capability=peer_capability.FULL,
        issued_at=1, ttl_ms=(1 << 52))
    bounded_get = backing.get_bounded

    def semantic_get(key, maximum):
        assert not key.startswith("pack/")
        return bounded_get(key, maximum)

    backing.get_bounded = semantic_get
    with serving(_ReadPeer(root.fid, backing)) as url:
        peer = _preminted_peer(_DialNode(token), root.fid, url)
        layout_requests, pack_requests, loose_batches = [], [], []
        original_layout = peer.layout
        original_copy, original_objs = peer.copy_pack, peer.objs

        def counted_layout(key, *, response_limit):
            layout_requests.append((key, response_limit))
            return original_layout(key, response_limit=response_limit)

        def counted_copy(opened, write):
            pack_requests.append(opened)
            return original_copy(opened, write)

        def counted_objs(oids):
            loose_batches.append(tuple(oids))
            return original_objs(oids)

        peer.layout = counted_layout
        peer.copy_pack = counted_copy
        peer.objs = counted_objs
        consumer = FactConsumer(root.fid)
        result = run(RepositoryMirror(
            root.fid,
            FsStore(str(tmp_path / "receiver")),
            resolver(binding),
            consumer,
        ).sync_from(RemoteStore(peer)))

    assert result.errors == ()
    assert result.changed == 1 and result.piles == len(raws)
    assert layout_requests == [(
        layout_page_key(root.fid, public, 1),
        MAX_LAYOUT_PAGE_BYTES,
    )]
    assert pack_requests == [
        PackOpen("GET", placement.pack_oid, placement.pack_bytes)]
    assert loose_batches == []
    assert consumer.fact_ids()


def test_real_http_loose_piles_use_the_same_direct_object_stream(tmp_path):
    async def prepare():
        backing = FsStore(str(tmp_path / "source"))
        fixture = await published(backing, 2, large=True)
        return backing, fixture

    backing, fixture = run(prepare())
    _secret, public, root, _sig, _device, binding, _update, raws = fixture
    assert any(len(raw) > MAX_REPOSITORY_OBJECT_BYTES for raw in raws)
    token = make_token(
        SECRET,
        h(b"loose-layout-reader"),
        root.fid,
        capability=peer_capability.READ_ONLY,
        issued_at=1,
        ttl_ms=(1 << 52),
    )
    with serving(_ReadPeer(root.fid, backing)) as url:
        peer = _preminted_peer(_DialNode(token), root.fid, url)
        limits = []
        original = peer.copy_obj

        def counted(oid, *, response_limit, write):
            limits.append(response_limit)
            return original(
                oid, response_limit=response_limit, write=write)

        peer.copy_obj = counted
        consumer = FactConsumer(root.fid)
        result = run(RepositoryMirror(
            root.fid,
            FsStore(str(tmp_path / "receiver")),
            resolver(binding),
            consumer,
        ).sync_from(RemoteStore(peer)))

    assert result.errors == ()
    assert result.changed == 1 and result.piles == len(raws)
    assert limits.count(MAX_SEMANTIC_PILE_BYTES) == len(raws)
    assert consumer.fact_ids()
