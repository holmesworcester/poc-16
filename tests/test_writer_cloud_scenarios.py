"""Rate-independent cloud costs for multi-device writer directories."""
import asyncio
from collections import Counter
from dataclasses import dataclass

import pytest

from adapters.r2 import R2BindingStore
from adapters.s3 import S3Config, S3Store
from bench.writer_cloud_cost import CostVector, CountingStore
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.store import FsStore
from core.writer_head import WriterBinding, encode_slot
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
from tests.util import mechanical_head_authorizer
from facts.auth.device import device as device_fact
from facts.auth.device_invite import device_invite
from facts.auth.head_request import head_request
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message as message_fact
from tests.provider_fakes import FakeR2Bucket, FakeS3Bucket


PAGE_SIZE = 10
PREFIX = "tenant"
REMOVAL_ROOT = h(b"current removal root")
TRUSTED_NOW = 8_500_000

# Canonical-byte ratchets for this fixed realistic fixture. These are storage
# and transfer volumes, not a price sheet; provider rates remain external.
SCALE_BYTES = {
    1: {
        "publication": 4_070,
        "cold": 4_070,
        "noop": 349,
        "changed_publication_read": 349,
        "changed_publication_write": 4_163,
        "one_changed": 4_163,
    },
    10: {
        "publication": 51_189,
        "cold": 51_189,
        "noop": 3_490,
        "changed_publication_read": 349,
        "changed_publication_write": 5_330,
        "one_changed": 8_471,
    },
    100: {
        "publication": 522_613,
        "cold": 522_613,
        "noop": 34_900,
        "changed_publication_read": 349,
        "changed_publication_write": 5_332,
        "one_changed": 39_883,
    },
}

RACE_BYTES = {
    "candidate_upload": 7_625,
    "contention_read": 698,
    "contention_write": 698,
    "rebase_read": 3_223,
    "rebase_write": 4_254,
    "cold": 10_006,
}


@dataclass(frozen=True)
class DeviceSpec:
    secret: object
    public: str
    owner: str
    binding: WriterBinding
    authority: tuple
    initial: tuple


@dataclass
class DeviceRuntime:
    spec: DeviceSpec
    local: FsStore
    writer: WriterLog
    current: object


@dataclass
class CloudRun:
    kind: str
    bucket: object
    cloud: CountingStore
    root: object
    authorize: object
    devices: tuple[DeviceRuntime, ...]
    bindings: dict
    slot_bytes: dict
    publication: CostVector


@dataclass(frozen=True)
class ScaleOutcome:
    publication: CostVector
    cold: CostVector
    noop: CostVector
    changed_publication: CostVector
    one_changed: CostVector
    fact_ids: tuple
    slots: tuple


@dataclass(frozen=True)
class RaceOutcome:
    candidate_upload: CostVector
    contention: CostVector
    rebase: CostVector
    cold: CostVector
    fact_ids: tuple
    slot: bytes


def provider(kind):
    if kind == "s3":
        bucket = FakeS3Bucket(page_size=PAGE_SIZE)
        return bucket, S3Store(
            S3Config(
                bucket="writer-cloud-scenarios",
                prefix=PREFIX,
                list_page_size=PAGE_SIZE,
                read_total_max_attempts=1,
            ),
            client=bucket.client("cloud"),
        )
    if kind == "r2":
        bucket = FakeR2Bucket(page_size=PAGE_SIZE)
        return bucket, R2BindingStore(bucket, PREFIX)
    raise AssertionError(kind)


def provider_counts(kind, bucket, start):
    history = bucket.history[start:]
    operations = (
        (entry[1] for entry in history)
        if kind == "s3"
        else (entry[0] for entry in history)
    )
    return Counter(operations)


def fixture(count):
    founder_secret, founder = keypair()
    root = workspace_fact(founder_secret, founder, "workspace", 1)
    primary = device_fact(root.fid, founder, "device-000", 2)
    primary_signature = signature_fact(
        founder_secret, founder, primary, 2)
    primary_authority = (root, primary_signature, primary)
    devices = []
    for ordinal in range(count):
        if ordinal == 0:
            secret, public = founder_secret, founder
            authority = primary_authority
        else:
            secret, public = keypair()
            grant = device_invite(
                root.fid,
                founder,
                public,
                f"device-{ordinal:03d}",
                ordinal + 2,
            )
            grant_signature = signature_fact(
                founder_secret, founder, grant, ordinal + 2)
            authority = (*primary_authority, grant_signature, grant)
        item = message_fact(
            root.fid,
            public,
            "general",
            f"initial from device {ordinal}",
            1_000 + ordinal,
            owner=founder,
        )
        item_signature = signature_fact(secret, public, item, item.ts)
        binding = WriterBinding(
            root.fid,
            public,
            founder,
            h(f"writer-store-{ordinal}".encode()),
        )
        devices.append(DeviceSpec(
            secret,
            public,
            founder,
            binding,
            authority,
            (*authority, item_signature, item),
        ))
    return root, tuple(devices)


def proof(root, spec, proposed_head, base_head):
    request = head_request(
        root.fid,
        spec.public,
        spec.owner,
        base_head,
        proposed_head,
        9_000_000,
        b"mechanical removal path",
        8_000_000,
    )
    request_signature = signature_fact(
        spec.secret, spec.public, request, request.ts)
    return encode_signed_pile(make_signed_pile(
        spec.secret,
        root.fid,
        spec.public,
        (*spec.authority, request_signature, request),
    ))


def added_message(root, spec, text, timestamp):
    item = message_fact(
        root.fid,
        spec.public,
        "general",
        text,
        timestamp,
        owner=spec.owner,
    )
    signed = signature_fact(
        spec.secret, spec.public, item, timestamp)
    return (*spec.authority, signed, item), item, signed


async def publish(kind, tmp_path, root, specs, label):
    bucket, raw_store = provider(kind)
    cloud = CountingStore(raw_store)
    authorize = mechanical_head_authorizer(
        root.fid, REMOVAL_ROOT)
    runtimes = []
    bindings = {spec.public: spec.binding for spec in specs}
    slot_bytes = {}
    immutable_bytes = 0
    for ordinal, spec in enumerate(specs):
        local = FsStore(str(
            tmp_path / f"{kind}-{label}-writer-{ordinal}"))
        writer = WriterLog(
            root.fid,
            spec.public,
            spec.owner,
            spec.binding.store,
            spec.secret,
            local,
        )
        prepared = await writer.prepare((spec.initial,))
        assert len(prepared.objects) == 3
        request = proof(root, spec, prepared.head_oid, None)
        await writer.establish(prepared)
        local_result = await OpaqueHeadGate(
            local, authorize).advance(
                request, prepared.head_oid, TRUSTED_NOW)
        assert local_result.status == "applied"
        await writer.establish(prepared, cloud)
        cloud_result = await OpaqueHeadGate(
            cloud, authorize).advance(
                request, prepared.head_oid, TRUSTED_NOW)
        assert cloud_result.status == "applied"
        slot_bytes[spec.public] = encode_slot(cloud_result.slot)
        immutable_bytes += sum(
            len(raw) for _oid, raw in prepared.objects)
        runtimes.append(DeviceRuntime(
            spec, local, writer, prepared))

    expected = CostVector(
        slot_gets=len(specs),
        object_gets=len(specs),
        object_puts=3 * len(specs),
        slot_cas=len(specs),
        write_bytes=immutable_bytes + sum(map(len, slot_bytes.values())),
    )
    assert cloud.snapshot() == expected
    return CloudRun(
        kind,
        bucket,
        cloud,
        root,
        authorize,
        tuple(runtimes),
        bindings,
        slot_bytes,
        expected,
    )


def mirror_for(run, receiver, consumer):
    def binding_for(workspace, device, removal_root, _candidate):
        assert workspace == run.root.fid
        assert removal_root == REMOVAL_ROOT
        return run.bindings.get(device)

    return RepositoryMirror(
        run.root.fid, receiver, binding_for, consumer)


async def scale_scenario(kind, tmp_path, root, specs):
    count = len(specs)
    pages = (count + PAGE_SIZE - 1) // PAGE_SIZE
    run = await publish(kind, tmp_path, root, specs, f"scale-{count}")
    receiver = FsStore(str(
        tmp_path / f"{kind}-scale-{count}-receiver"))
    consumer = FactConsumer(root.fid)
    mirror = mirror_for(run, receiver, consumer)
    initial_object_bytes = sum(
        len(raw)
        for runtime in run.devices
        for _oid, raw in runtime.current.objects
    )
    initial_slot_bytes = sum(map(len, run.slot_bytes.values()))

    run.cloud.clear()
    history = len(run.bucket.history)
    cold_result = await mirror.sync_from(
        run.cloud, page_limit=PAGE_SIZE)
    cold = run.cloud.snapshot()
    assert cold_result.listed == cold_result.changed == count
    assert cold_result.piles == count
    assert cold_result.facts == 4 * count + 1
    assert cold_result.errors == ()
    assert cold == CostVector(
        lists=pages,
        slot_gets=count,
        object_gets=3 * count,
        read_bytes=initial_slot_bytes + initial_object_bytes,
    )
    assert provider_counts(kind, run.bucket, history) == {
        "get": 4 * count,
        "list": pages,
    }

    run.cloud.clear()
    history = len(run.bucket.history)
    noop_result = await mirror.sync_from(
        run.cloud, page_limit=PAGE_SIZE)
    noop = run.cloud.snapshot()
    assert noop_result.changed == noop_result.piles == noop_result.facts == 0
    assert noop_result.errors == ()
    assert noop == CostVector(
        lists=pages,
        slot_gets=count,
        read_bytes=initial_slot_bytes,
    )
    assert provider_counts(kind, run.bucket, history) == {
        "get": count,
        "list": pages,
    }

    changed = run.devices[-1]
    closure, item, signed = added_message(
        root, changed.spec, "one changed writer", 20_000)
    update = await changed.writer.prepare((closure,))
    assert update.base_head == changed.current.head_oid
    assert len(update.objects) == 3
    request = proof(
        root, changed.spec, update.head_oid, update.base_head)
    await changed.writer.establish(update)
    local_result = await OpaqueHeadGate(
        changed.local, run.authorize).advance(
            request, update.head_oid, TRUSTED_NOW)
    assert local_result.status == "applied"

    old_slot_bytes = run.slot_bytes[changed.spec.public]
    changed_immutable_bytes = sum(
        len(raw) for _oid, raw in update.objects)
    run.cloud.clear()
    history = len(run.bucket.history)
    await changed.writer.establish(update, run.cloud)
    cloud_result = await OpaqueHeadGate(
        run.cloud, run.authorize).advance(
            request, update.head_oid, TRUSTED_NOW)
    assert cloud_result.status == "applied"
    new_slot_bytes = encode_slot(cloud_result.slot)
    run.slot_bytes[changed.spec.public] = new_slot_bytes
    changed_publication = run.cloud.snapshot()
    assert changed_publication == CostVector(
        slot_gets=1,
        object_gets=1,
        object_puts=3,
        slot_cas=1,
        read_bytes=len(old_slot_bytes),
        write_bytes=changed_immutable_bytes + len(new_slot_bytes),
    )
    assert provider_counts(kind, run.bucket, history) == {
        "get": 1,
        "head": 1,
        "put": 4,
    }

    run.cloud.clear()
    history = len(run.bucket.history)
    changed_result = await mirror.sync_from(
        run.cloud, page_limit=PAGE_SIZE)
    one_changed = run.cloud.snapshot()
    assert changed_result.listed == count
    assert changed_result.changed == changed_result.piles == 1
    assert changed_result.facts == 2
    assert changed_result.errors == ()
    assert item.fid in consumer.fact_ids()
    assert signed.fid in consumer.fact_ids()
    assert one_changed == CostVector(
        lists=pages,
        slot_gets=count,
        object_gets=3,
        read_bytes=sum(map(len, run.slot_bytes.values()))
        + changed_immutable_bytes,
    )
    assert provider_counts(kind, run.bucket, history) == {
        "get": count + 3,
        "list": pages,
    }

    return ScaleOutcome(
        run.publication,
        cold,
        noop,
        changed_publication,
        one_changed,
        consumer.fact_ids(),
        tuple(sorted(run.slot_bytes.items())),
    )


class ReadBarrierStore:
    """Hold two exact slot reads so both contenders reach provider CAS."""

    def __init__(self, store, key):
        self.store = store
        self.key = key
        self.arrivals = 0
        self.ready = asyncio.Event()

    async def get_bounded(self, key, maximum):
        return await self.store.get_bounded(key, maximum)

    async def has(self, key):
        return await self.store.has(key)

    async def read_versioned(self, key):
        value = await self.store.read_versioned(key)
        if key == self.key:
            self.arrivals += 1
            if self.arrivals == 2:
                self.ready.set()
            await self.ready.wait()
        return value

    async def put_if_absent(self, key, value):
        return await self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        return await self.store.cas(key, token, value)

    async def list_page(self, prefix, cursor=None, limit=256):
        return await self.store.list_page(prefix, cursor, limit)


async def race_scenario(kind, tmp_path, root, specs):
    run = await publish(kind, tmp_path, root, specs, "race")
    runtime = run.devices[0]
    spec = runtime.spec
    initial = runtime.current
    first = added_message(root, spec, "concurrent first", 30_000)
    second = added_message(root, spec, "concurrent second", 30_001)
    candidates = await asyncio.gather(*(
        runtime.writer.prepare((candidate[0],))
        for candidate in (first, second)
    ))
    assert all(candidate.base_head == initial.head_oid
               for candidate in candidates)
    assert all(len(candidate.objects) == 3 for candidate in candidates)
    requests = tuple(
        proof(root, spec, candidate.head_oid, candidate.base_head)
        for candidate in candidates)

    for candidate in candidates:
        await runtime.writer.establish(candidate)
    run.cloud.clear()
    for candidate in candidates:
        await runtime.writer.establish(candidate, run.cloud)
    candidate_upload = run.cloud.snapshot()
    candidate_bytes = sum(
        len(raw)
        for candidate in candidates
        for _oid, raw in candidate.objects
    )
    assert candidate_upload == CostVector(
        object_puts=6,
        write_bytes=candidate_bytes,
    )

    initial_slot = run.slot_bytes[spec.public]
    slot_key = f"heads/{root.fid}/{spec.public}"
    barrier_store = ReadBarrierStore(run.cloud, slot_key)
    run.cloud.clear()
    outcomes = await asyncio.gather(*(
        OpaqueHeadGate(
            barrier_store, run.authorize).advance(
                request, candidate.head_oid, TRUSTED_NOW)
        for request, candidate in zip(requests, candidates)
    ))
    statuses = [outcome.status for outcome in outcomes]
    assert statuses.count("applied") == statuses.count("retryable") == 1
    assert barrier_store.arrivals == 2
    contention = run.cloud.snapshot()
    candidate_slots = tuple(encode_slot(outcome.slot) for outcome in outcomes)
    assert contention == CostVector(
        slot_gets=2,
        object_gets=2,
        slot_cas=2,
        read_bytes=2 * len(initial_slot),
        write_bytes=sum(map(len, candidate_slots)),
    )
    assert contention.read_bytes == 2 * len(initial_slot)

    winner = statuses.index("applied")
    loser = 1 - winner
    winner_result = await OpaqueHeadGate(
        runtime.local, run.authorize).advance(
            requests[winner], candidates[winner].head_oid, TRUSTED_NOW)
    assert winner_result.status == "applied"
    run.slot_bytes[spec.public] = encode_slot(outcomes[winner].slot)
    runtime.current = candidates[winner]

    rebased = await runtime.writer.prepare((
        (first, second)[loser][0],))
    assert rebased.base_head == candidates[winner].head_oid
    assert rebased.head.sequence == 3
    assert len(rebased.objects) == 3
    rebased_request = proof(
        root, spec, rebased.head_oid, rebased.base_head)
    await runtime.writer.establish(rebased)
    local_rebase = await OpaqueHeadGate(
        runtime.local, run.authorize).advance(
            rebased_request, rebased.head_oid, TRUSTED_NOW)
    assert local_rebase.status == "applied"

    old_slot = run.slot_bytes[spec.public]
    loser_pile_bytes = len(encode_signed_pile(rebased.piles[0]))
    rebased_object_bytes = sum(
        len(raw) for _oid, raw in rebased.objects)
    run.cloud.clear()
    await runtime.writer.establish(rebased, run.cloud)
    cloud_rebase = await OpaqueHeadGate(
        run.cloud, run.authorize).advance(
            rebased_request, rebased.head_oid, TRUSTED_NOW)
    assert cloud_rebase.status == "applied"
    final_slot = encode_slot(cloud_rebase.slot)
    rebase = run.cloud.snapshot()
    assert rebase == CostVector(
        slot_gets=1,
        object_gets=2,
        object_puts=3,
        slot_cas=1,
        read_bytes=len(old_slot) + loser_pile_bytes,
        write_bytes=rebased_object_bytes + len(final_slot),
    )

    receiver = FsStore(str(tmp_path / f"{kind}-race-receiver"))
    consumer = FactConsumer(root.fid)
    mirror = mirror_for(run, receiver, consumer)
    run.slot_bytes[spec.public] = final_slot
    run.cloud.clear()
    result = await mirror.sync_from(run.cloud, page_limit=PAGE_SIZE)
    cold = run.cloud.snapshot()
    mirrored_objects = tuple(
        (key, receiver.get(key)) for key in receiver.list("obj/"))
    assert result.listed == result.changed == 1
    assert result.piles == 3
    assert result.facts == 9
    assert result.errors == ()
    assert all(value.fid in consumer.fact_ids()
               for value in (first[1], first[2], second[1], second[2]))
    assert cold == CostVector(
        lists=1,
        slot_gets=1,
        object_gets=len(mirrored_objects),
        read_bytes=len(final_slot)
        + sum(len(raw) for _key, raw in mirrored_objects),
    )
    return RaceOutcome(
        candidate_upload,
        contention,
        rebase,
        cold,
        consumer.fact_ids(),
        final_slot,
    )


@pytest.mark.parametrize("count", (1, 10, 100))
def test_directory_costs_scale_with_writers_and_only_one_changed_tree(
        tmp_path, count):
    async def scenario():
        root, specs = fixture(count)
        s3 = await scale_scenario("s3", tmp_path, root, specs)
        r2 = await scale_scenario("r2", tmp_path, root, specs)
        assert s3 == r2
        assert {
            "publication": s3.publication.write_bytes,
            "cold": s3.cold.read_bytes,
            "noop": s3.noop.read_bytes,
            "changed_publication_read":
                s3.changed_publication.read_bytes,
            "changed_publication_write":
                s3.changed_publication.write_bytes,
            "one_changed": s3.one_changed.read_bytes,
        } == SCALE_BYTES[count]

    asyncio.run(scenario())


def test_same_writer_contention_retries_and_rebases_without_lost_piles(
        tmp_path):
    async def scenario():
        root, specs = fixture(1)
        s3 = await race_scenario("s3", tmp_path, root, specs)
        r2 = await race_scenario("r2", tmp_path, root, specs)
        assert s3 == r2
        assert {
            "candidate_upload": s3.candidate_upload.write_bytes,
            "contention_read": s3.contention.read_bytes,
            "contention_write": s3.contention.write_bytes,
            "rebase_read": s3.rebase.read_bytes,
            "rebase_write": s3.rebase.write_bytes,
            "cold": s3.cold.read_bytes,
        } == RACE_BYTES

    asyncio.run(scenario())
