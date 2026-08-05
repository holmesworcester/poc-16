"""Request-count ratchets for realistic opaque-cloud writer scenarios."""
import asyncio

from bench.writer_cloud_cost import CountingStore
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.store import FsStore
from core.writer_head import WriterBinding
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
from tests.util import mechanical_head_authorizer
from core.writer_tree import reachable_staged_pages
from facts.auth.device import device as device_fact
from facts.auth.head_request import head_request
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message as message_fact


def run(awaitable):
    return asyncio.run(awaitable)


def fixture():
    secret, public = keypair()
    root = workspace_fact(secret, public, "alice", 1)
    device = device_fact(root.fid, public, "laptop", 2)
    device_signature = signature_fact(secret, public, device, 2)
    return secret, public, root, device_signature, device


def proof(values, proposed_head, base_head=None):
    secret, public, root, device_signature, device = values
    request = head_request(
        root.fid, public, public, base_head,
        proposed_head, 1_000_000, h(b"mechanical removal path"), 3)
    request_signature = signature_fact(secret, public, request, 3)
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, public,
        (root, device_signature, device, request_signature, request),
    ))


def test_one_pile_publish_cold_sync_and_noop_have_small_exact_costs(tmp_path):
    async def scenario():
        values = fixture()
        secret, public, root, device_signature, device = values
        store_binding = h(b"store")
        removal_root = h(b"removal root")
        author = FsStore(str(tmp_path / "author"))
        cloud_raw = FsStore(str(tmp_path / "cloud"))
        cloud = CountingStore(cloud_raw)
        receiver = FsStore(str(tmp_path / "receiver"))
        writer = WriterLog(
            root.fid, public, public, store_binding, secret, author)
        update = await writer.prepare(((
            root, device_signature, device),))
        await writer.establish(update)
        authorize = mechanical_head_authorizer(
            root.fid, removal_root)
        await OpaqueHeadGate(author, authorize).advance(
            proof(values, update.head_oid), update.head_oid, 10)

        await writer.establish(update, cloud)
        await OpaqueHeadGate(cloud, authorize).advance(
            proof(values, update.head_oid), update.head_oid, 10)
        published = cloud.snapshot()
        assert published.object_puts == len(update.objects) == 3
        assert published.slot_gets == published.slot_cas == 1
        assert published.object_gets == 1  # head existence, no body bytes
        assert published.lists == 0
        assert published.requests == 6

        cloud.clear()
        consumer = FactConsumer(root.fid)
        mirror = RepositoryMirror(
            root.fid,
            receiver,
            lambda workspace, device_key, _root, _candidate: WriterBinding(
                workspace, device_key, public, store_binding),
            consumer,
        )
        result = await mirror.sync_from(cloud)
        cold = cloud.snapshot()
        assert result.changed == result.piles == 1
        assert cold.lists == cold.slot_gets == 1
        assert cold.object_gets == 3  # head + one tree page + one pile
        assert cold.requests == 5

        cloud.clear()
        result = await mirror.sync_from(cloud)
        noop = cloud.snapshot()
        assert result.changed == result.piles == result.facts == 0
        assert noop.lists == noop.slot_gets == 1
        assert noop.object_gets == 0
        assert noop.requests == 2

    run(scenario())


def test_hundred_piles_use_one_head_cas_and_only_final_tree_pages(tmp_path):
    async def scenario():
        values = fixture()
        secret, public, root, _device_signature, _device = values
        local = FsStore(str(tmp_path / "author"))
        cloud = CountingStore(FsStore(str(tmp_path / "cloud")))
        writer = WriterLog(
            root.fid, public, public, h(b"store"), secret, local)
        closures = tuple(
            (root, signature_fact(secret, public, root, 10 + ordinal))
            for ordinal in range(100)
        )
        update = await writer.prepare(closures)
        await writer.establish(update, cloud)

        removal_root = h(b"removal root")
        authorize = mechanical_head_authorizer(
            root.fid, removal_root)
        await OpaqueHeadGate(cloud, authorize).advance(
            proof(values, update.head_oid), update.head_oid, 10)
        cost = cloud.snapshot()
        tree_pages = len(update.objects) - 100 - 1
        objects = dict(update.objects)
        pile_oids = {
            h(encode_signed_pile(pile)) for pile in update.piles
        }
        reachable = reachable_staged_pages(
            update.head.tree, root.fid, public, objects)

        assert update.head.sequence == 100
        assert set(objects) == pile_oids | reachable | {update.head_oid}
        assert cost.object_puts == 100 + tree_pages + 1
        assert cost.slot_gets == cost.slot_cas == 1
        assert cost.object_gets == 1  # head existence, no body bytes
        assert cost.requests == 100 + tree_pages + 4
        # A batch emits only the pages reachable from its final root. It does
        # not upload one intermediate path-copy tree per pile.
        assert tree_pages < 2 * len(closures)

    run(scenario())


def test_warm_one_pile_publish_and_mirror_cost_do_not_scale_with_history(
        tmp_path):
    async def scenario():
        values = fixture()
        secret, public, root, device_signature, device = values
        binding = h(b"store")
        removal_root = h(b"removal root")
        author = FsStore(str(tmp_path / "author"))
        cloud = CountingStore(FsStore(str(tmp_path / "cloud")))
        receiver = FsStore(str(tmp_path / "receiver"))
        authorize = mechanical_head_authorizer(
            root.fid, removal_root)
        log = WriterLog(
            root.fid, public, public, binding, secret, author)

        initial = await log.prepare(((
            root, device_signature, device),))
        await log.establish(initial, author)
        assert (await OpaqueHeadGate(
            author, authorize).advance(
                proof(values, initial.head_oid),
                initial.head_oid, 10)).status == "applied"
        await log.establish(initial, cloud)
        assert (await OpaqueHeadGate(
            cloud, authorize).advance(
                proof(values, initial.head_oid),
                initial.head_oid, 10)).status == "applied"

        consumer = FactConsumer(root.fid)
        mirror = RepositoryMirror(
            root.fid,
            receiver,
            lambda workspace, device_key, _root, _candidate: WriterBinding(
                workspace, device_key, public, binding),
            consumer,
        )
        await mirror.sync_from(cloud)

        item = message_fact(
            root.fid, public, "general", "warm", 10)
        item_signature = signature_fact(secret, public, item, 10)
        update = await log.prepare((
            (root, device_signature, device, item_signature, item),))
        await log.establish(update, author)
        assert (await OpaqueHeadGate(
            author, authorize).advance(
                proof(values, update.head_oid, update.base_head),
                update.head_oid, 10)).status == "applied"

        cloud.clear()
        await log.establish(update, cloud)
        assert (await OpaqueHeadGate(
            cloud, authorize).advance(
                proof(values, update.head_oid, update.base_head),
                update.head_oid, 10)).status == "applied"
        publish = cloud.snapshot()
        assert len(update.objects) == 3  # pile + final tree page + head
        assert publish.object_puts == 3
        assert publish.slot_gets == publish.slot_cas == 1
        assert publish.object_gets == 1  # head existence, no body bytes
        assert publish.lists == 0
        assert publish.requests == 6

        cloud.clear()
        result = await mirror.sync_from(cloud)
        warm = cloud.snapshot()
        assert result.changed == result.piles == 1
        assert warm.lists == warm.slot_gets == 1
        assert warm.object_gets == 3  # new head + changed page + new pile
        assert warm.requests == 5

    run(scenario())
