"""One writer-log black box over the native S3 and R2 adapters."""
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
from core.writer_head import (
    WriterBinding,
    decode_slot_at,
    encode_slot,
    head_slot_key,
)
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
from tests.util import mechanical_head_authorizer
from facts.auth.device import device as device_fact
from facts.auth.head_request import head_request
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message as message_fact
from tests.provider_fakes import FakeR2Bucket, FakeS3Bucket


PREFIX = "tenant"


@dataclass(frozen=True)
class EndState:
    facts: tuple
    slot: bytes
    objects: tuple


def authority_proof(
        secret, public, root, device_signature, device, proposed_head):
    request = head_request(
        root.fid, public, public, None, proposed_head, 1_000,
        h(b"mechanical removal path"), 4)
    request_signature = signature_fact(secret, public, request, 4)
    return encode_signed_pile(make_signed_pile(
        secret,
        root.fid,
        public,
        (root, device_signature, device, request_signature, request),
    ))


def provider(kind):
    if kind == "s3":
        bucket = FakeS3Bucket(page_size=2)
        store = S3Store(
            S3Config(
                bucket="writer-provider-blackbox",
                prefix=PREFIX,
                read_total_max_attempts=1,
            ),
            client=bucket.client("cloud"),
        )
        return bucket, store
    if kind == "r2":
        bucket = FakeR2Bucket(page_size=2)
        return bucket, R2BindingStore(bucket, PREFIX)
    raise AssertionError(kind)


def physical_operations(kind, bucket, start):
    """Normalize only physical operations that both shared fakes expose."""
    history = bucket.history[start:]
    if kind == "s3":
        operations = ((entry[1], entry[2]) for entry in history)
    else:
        operations = ((entry[0], entry[1]) for entry in history)
    normalized = []
    namespace = PREFIX + "/"
    for operation, physical_key in operations:
        assert physical_key.startswith(namespace)
        normalized.append((operation, physical_key[len(namespace):]))
    return tuple(normalized)


async def exercise(kind, tmp_path, values):
    secret, public, root, device_signature, device = values
    bucket, raw_store = provider(kind)
    cloud = CountingStore(raw_store)
    store_binding = h(b"provider writer binding")
    removal_root = h(b"current removal root")
    slot_key = head_slot_key(root.fid, public)

    message = message_fact(
        root.fid, public, "general", "provider black box", 3)
    message_signature = signature_fact(secret, public, message, 3)
    closures = (
        (root, device_signature, device),
        (root, message_signature, message),
    )
    writer = WriterLog(
        root.fid,
        public,
        public,
        store_binding,
        secret,
        cloud,
    )
    prepared = await writer.prepare(closures)
    proof = authority_proof(
        secret, public, root, device_signature, device,
        prepared.head_oid)
    cloud.clear()
    physical_start = len(bucket.history)
    with pytest.raises(ValueError, match="head object is missing"):
        await OpaqueHeadGate(
            cloud,
            mechanical_head_authorizer(
                root.fid, removal_root)).advance(
                proof, prepared.head_oid, 10)
    assert cloud.snapshot() == CostVector(object_gets=1)
    assert f"{PREFIX}/{slot_key}" not in bucket.data
    assert physical_operations(kind, bucket, physical_start) == (
        ("head", "obj/" + prepared.head_oid),
    )

    cloud.clear()
    physical_start = len(bucket.history)
    await writer.establish(prepared)
    immutable_bytes = sum(len(raw) for _oid, raw in prepared.objects)
    assert cloud.snapshot() == CostVector(
        object_puts=len(prepared.objects),
        write_bytes=immutable_bytes,
    )
    establish_operations = physical_operations(
        kind, bucket, physical_start)
    assert Counter(operation for operation, _key in establish_operations) \
        == {"put": len(prepared.objects)}
    assert all(key.startswith("obj/")
               for _operation, key in establish_operations)

    proof = authority_proof(
        secret, public, root, device_signature, device,
        prepared.head_oid)
    cloud.clear()
    physical_start = len(bucket.history)
    advanced = await OpaqueHeadGate(
        cloud,
        mechanical_head_authorizer(
            root.fid, removal_root)).advance(
                proof, prepared.head_oid, 10)
    slot_raw = encode_slot(advanced.slot)
    assert advanced.status == "applied"
    assert cloud.snapshot() == CostVector(
        object_gets=1,
        slot_gets=1,
        slot_cas=1,
        write_bytes=len(slot_raw),
    )
    gate_operations = physical_operations(kind, bucket, physical_start)
    assert [(operation, key) for operation, key in gate_operations
            if key.startswith("obj/")] == [
        ("head", "obj/" + prepared.head_oid),
    ]
    assert [key for operation, key in gate_operations
            if operation == "put"] == [slot_key]

    receiver = FsStore(str(tmp_path / f"{kind}-receiver"))
    consumer = FactConsumer(root.fid)

    def binding_for(
            workspace, candidate_device, candidate_removal, _candidate):
        assert candidate_removal == removal_root
        if (workspace, candidate_device) != (root.fid, public):
            return None
        return WriterBinding(
            root.fid, public, public, store_binding)

    mirror = RepositoryMirror(
        root.fid, receiver, binding_for, consumer)
    cloud.clear()
    physical_start = len(bucket.history)
    result = await mirror.sync_from(cloud)
    assert result.listed == result.changed == 1
    assert result.piles == 2
    assert result.facts == 5
    assert result.errors == ()
    mirrored_objects = tuple(
        (key, receiver.get(key)) for key in receiver.list("obj/"))
    mirrored_bytes = sum(len(raw) for _key, raw in mirrored_objects)
    # Two signed piles, their final content/control pages, and one signed
    # head: every established immutable is reachable, with no intermediate
    # path-copy page uploaded to either provider.
    expected_objects = tuple(sorted(
        ("obj/" + oid, raw) for oid, raw in prepared.objects))
    assert mirrored_objects == expected_objects
    assert len(prepared.objects) == len(mirrored_objects) == 5
    assert immutable_bytes == mirrored_bytes
    assert cloud.snapshot() == CostVector(
        lists=1,
        slot_gets=1,
        object_gets=len(prepared.objects),
        read_bytes=len(slot_raw) + immutable_bytes,
    )
    mirror_operations = physical_operations(kind, bucket, physical_start)
    assert Counter(operation for operation, _key in mirror_operations) == {
        "get": len(prepared.objects) + 1,
        "list": 1,
    }

    cloud.clear()
    physical_start = len(bucket.history)
    again = await mirror.sync_from(cloud)
    assert again.changed == again.piles == again.facts == 0
    assert again.errors == ()
    assert cloud.snapshot() == CostVector(
        lists=1,
        slot_gets=1,
        read_bytes=len(slot_raw),
    )
    assert Counter(
        operation for operation, _key in physical_operations(
            kind, bucket, physical_start)
    ) == {"get": 1, "list": 1}

    facts = tuple(
        (fid, consumer.fact_bytes(fid)) for fid in consumer.fact_ids())
    assert decode_slot_at(
        slot_key, receiver.get(slot_key)).head == decode_slot_at(
            slot_key, slot_raw).head
    return EndState(facts, slot_raw, mirrored_objects)


def test_s3_and_native_r2_have_the_same_opaque_cloud_end_state(tmp_path):
    async def scenario():
        secret, public = keypair()
        root = workspace_fact(secret, public, "workspace", 1)
        device = device_fact(root.fid, public, "laptop", 2)
        device_signature = signature_fact(secret, public, device, 2)
        message = message_fact(
            root.fid, public, "general", "provider black box", 3)
        message_signature = signature_fact(secret, public, message, 3)
        values = secret, public, root, device_signature, device

        s3 = await exercise("s3", tmp_path, values)
        r2 = await exercise("r2", tmp_path, values)

        assert s3 == r2
        assert {fid for fid, _raw in s3.facts} == {
            root.fid,
            device_signature.fid,
            device.fid,
            message_signature.fid,
            message.fid,
        }

    asyncio.run(scenario())
