"""Per-device slot CAS and directory behavior across provider adapters."""
import asyncio
from concurrent.futures import ThreadPoolExecutor

from adapters.r2.worker import R2BindingStore
from adapters.s3 import S3Config, S3Store
from core.crypto import h
from core.object_store import ABSENT, STALE, Applied
from core.store import FsStore
from core.writer_head import (
    HeadSlot,
    encode_slot,
    head_slot_key,
    head_slot_prefix,
)
from tests.provider_fakes import FakeR2Bucket, FakeS3Bucket


WORKSPACE = h(b"workspace")
ALICE = h(b"alice-device")
BOB = h(b"bob-device")
REMOVAL_ROOT = h(b"removal root")


def slot(device, label):
    return encode_slot(HeadSlot(
        WORKSPACE, device, h(label.encode()), REMOVAL_ROOT))


def exercise_sync(store):
    alice_key = head_slot_key(WORKSPACE, ALICE)
    bob_key = head_slot_key(WORKSPACE, BOB)
    with ThreadPoolExecutor(max_workers=2) as pool:
        alice, bob = (
            future.result()
            for future in (
                pool.submit(store.cas, alice_key, ABSENT, slot(ALICE, "a1")),
                pool.submit(store.cas, bob_key, ABSENT, slot(BOB, "b1")),
            )
        )
    assert isinstance(alice, Applied)
    assert isinstance(bob, Applied)
    assert store.list_page(
        head_slot_prefix(WORKSPACE), limit=10).keys == (
            alice_key, bob_key)

    opened = store.read_versioned(alice_key)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            future.result()
            for future in (
                pool.submit(
                    store.cas, alice_key, opened.token,
                    slot(ALICE, "a2")),
                pool.submit(
                    store.cas, alice_key, opened.token,
                    slot(ALICE, "a3")),
            )
        ]
    assert sum(isinstance(result, Applied) for result in outcomes) == 1
    assert sum(result is STALE for result in outcomes) == 1


def test_filesystem_and_s3_support_independent_writer_slots(tmp_path):
    exercise_sync(FsStore(str(tmp_path / "fs")))
    bucket = FakeS3Bucket(page_size=10)
    exercise_sync(S3Store(
        S3Config(bucket="writer-slots-test"),
        client=bucket.client("writer"),
    ))


def test_native_r2_supports_independent_writer_slots():
    async def scenario():
        store = R2BindingStore(FakeR2Bucket(page_size=10))
        alice_key = head_slot_key(WORKSPACE, ALICE)
        bob_key = head_slot_key(WORKSPACE, BOB)
        alice, bob = await asyncio.gather(
            store.cas(alice_key, ABSENT, slot(ALICE, "a1")),
            store.cas(bob_key, ABSENT, slot(BOB, "b1")),
        )
        assert isinstance(alice, Applied)
        assert isinstance(bob, Applied)
        page = await store.list_page(
            head_slot_prefix(WORKSPACE), limit=10)
        assert page.keys == (alice_key, bob_key)

        opened = await store.read_versioned(alice_key)
        outcomes = await asyncio.gather(
            store.cas(alice_key, opened.token, slot(ALICE, "a2")),
            store.cas(alice_key, opened.token, slot(ALICE, "a3")),
        )
        assert sum(isinstance(result, Applied) for result in outcomes) == 1
        assert sum(result is STALE for result in outcomes) == 1

    asyncio.run(scenario())
