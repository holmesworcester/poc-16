"""Seeded ObjectStore fault schedules and their negative controls."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import sys

import pytest

from adapters.r2 import R2BindingStore
from core.crypto import h
from core.object_store import (
    ABSENT,
    CREATED,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    StoreError,
)
from tests.adversarial_bucket import (
    AdversarialBucket,
    AsyncLaggedReader,
    Fault,
    LaggedReader,
    Nonconforming,
)
from tests.provider_conformance import ConformanceRun, exercise_sync_store
from tests.provider_fakes import FakeR2Bucket

pytestmark = pytest.mark.unit

PROCESS_TIMEOUT_SECONDS = 10


def _run_python(script, *arguments, timeout=PROCESS_TIMEOUT_SECONDS):
    return subprocess.run(
        [sys.executable, "-c", script, *map(str, arguments)],
        cwd=str(Path(__file__).parents[1]),
        check=False,
        timeout=timeout,
    )


def _aba_schedule(seed):
    bucket = AdversarialBucket({"authority": b"A"}, seed=seed)
    store = bucket.handle("writer")
    first = store.read_versioned("authority")
    to_b = store.cas("authority", first.token, b"B")
    to_a = store.cas("authority", to_b.token, b"A")
    final = store.read_versioned("authority")
    assert bucket.assert_valid_history()
    return bucket, first, to_b, to_a, final


def test_seed_replays_opaque_value_aba_without_content_hash_tokens():
    first = _aba_schedule(0xABAD1DEA)
    replay = _aba_schedule(0xABAD1DEA)
    other = _aba_schedule(0xABAD1DEB)

    _, opened, to_b, to_a, final = first
    assert opened.token == to_a.token == final.token
    assert opened.token != to_b.token
    assert opened.token.value != h(opened.value)
    assert [
        (event.op, event.before, event.result, event.after)
        for event in first[0].history
    ] == [
        (event.op, event.before, event.result, event.after)
        for event in replay[0].history
    ]
    assert opened.token != other[1].token


def test_versioned_read_keeps_one_atomic_pair_while_authority_advances():
    bucket = AdversarialBucket({"authority": b"old"}, seed=7)
    reader = bucket.handle("reader")
    writer = bucket.handle("writer")
    old = writer.read_versioned("authority")
    paused = bucket.pause(
        "reader", "read_versioned", "authority", when="after")

    with ThreadPoolExecutor(max_workers=1) as pool:
        reading = pool.submit(reader.read_versioned, "authority")
        paused.wait()
        advanced = writer.cas("authority", old.token, b"new")
        assert isinstance(advanced, Applied)
        paused.release.set()
        paired = reading.result(timeout=5)

    assert paired == old
    assert writer.read_versioned("authority").value == b"new"
    assert bucket.assert_valid_history()


@pytest.mark.parametrize(
    ("fault", "expected"),
    [
        (Fault.REJECTED, StoreError),
        (Fault.THROTTLED, RetryableStoreError),
        (Fault.RETRYABLE_SERVICE, RetryableStoreError),
        (Fault.TRANSPORT, OutcomeUnknown),
    ],
)
def test_prelinearization_failures_have_typed_results_and_no_mutation(
        fault, expected):
    bucket = AdversarialBucket({"authority": b"base"}, seed=11)
    store = bucket.handle("writer")
    token = bucket._tokens["authority"]
    bucket.fail("writer", "cas", "authority", fault, when="before")

    with pytest.raises(expected) as caught:
        store.cas("authority", token, b"candidate")

    assert type(caught.value) is expected
    assert bucket._data["authority"] == b"base"
    assert bucket.history == []
    assert bucket.assert_valid_history()


@pytest.mark.parametrize("operation", ["read_versioned", "has"])
def test_read_transport_failure_is_retryable_not_a_mutation_outcome(
        operation):
    bucket = AdversarialBucket({"authority": b"base"}, seed=12)
    store = bucket.handle("reader")
    bucket.fail(
        "reader", operation, "authority",
        Fault.TRANSPORT, when="before")

    with pytest.raises(RetryableStoreError) as caught:
        getattr(store, operation)("authority")

    assert type(caught.value) is RetryableStoreError
    assert bucket.history == []
    assert bucket.assert_valid_history()


@pytest.mark.parametrize("fault", [Fault.RESPONSE_LOST, Fault.TRANSPORT])
@pytest.mark.parametrize("operation", ["create", "cas"])
def test_applied_response_loss_is_unknown_but_present_in_history(
        fault, operation):
    initial = {"authority": b"base"} if operation == "cas" else {}
    bucket = AdversarialBucket(initial, seed=13)
    store = bucket.handle("writer")
    if operation == "create":
        op, key, value = "put_if_absent", "probe/item", b"created"
        invoke = lambda: store.put_if_absent(key, value)
    else:
        op, key, value = "cas", "authority", b"candidate"
        token = bucket._tokens["authority"]
        invoke = lambda: store.cas(key, token, value)
    bucket.fail("writer", op, key, fault, when="after")

    with pytest.raises(OutcomeUnknown):
        invoke()

    assert bucket._data[key] == value
    assert [event.op for event in bucket.history] == [op]
    assert bucket.assert_valid_history()


def test_unknown_before_then_unknown_after_replays_both_create_outcomes():
    bucket = AdversarialBucket(seed=0x5150)
    store = bucket.handle("writer")
    key, value = "probe/ambiguous", b"same"
    bucket.fail(
        "writer", "put_if_absent", key,
        Fault.TRANSPORT, when="before")
    bucket.fail(
        "writer", "put_if_absent", key,
        Fault.RESPONSE_LOST, when="after")

    with pytest.raises(OutcomeUnknown):
        store.put_if_absent(key, value)
    assert key not in bucket._data

    with pytest.raises(OutcomeUnknown):
        store.put_if_absent(key, value)
    assert bucket._data[key] == value
    assert store.put_if_absent(key, value).value == "exists"
    assert [event.result.value for event in bucket.history] == [
        "created", "exists"]
    assert "seed=0x5150" in bucket.diagnostic()
    assert bucket.assert_valid_history()


def test_pending_cas_becomes_definitively_stale_after_another_writer_wins():
    bucket = AdversarialBucket({"authority": b"base"}, seed=17)
    alice, bob = bucket.handle("alice"), bucket.handle("bob")
    base = alice.read_versioned("authority")
    paused = bucket.pause("alice", "cas", "authority", when="before")

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(
            alice.cas, "authority", base.token, b"alice")
        paused.wait()
        winner = pool.submit(
            bob.cas, "authority", base.token, b"bob")
        assert isinstance(winner.result(timeout=5), Applied)
        paused.release.set()
        assert pending.result(timeout=5) is STALE

    assert bucket._data["authority"] == b"bob"
    assert bucket.assert_valid_history()


def test_short_list_pages_pick_up_a_concurrent_addition_after_the_cursor():
    bucket = AdversarialBucket(
        seed=19, list_page_size=3, short_page_sizes=(1, 2))
    writer, lister = bucket.handle("writer"), bucket.handle("lister")
    for ordinal in (0, 2, 3):
        key = f"probe/list/{ordinal:04d}"
        assert writer.put_if_absent(key, key.encode()) is CREATED
    paused = bucket.pause(
        "lister", "list_page", "probe/list/", when="after")

    with ThreadPoolExecutor(max_workers=1) as pool:
        listing = pool.submit(lister.list, "probe/list/")
        paused.wait()
        inserted = "probe/list/0001"
        assert writer.put_if_absent(
            inserted, inserted.encode()) is CREATED
        paused.release.set()
        result = listing.result(timeout=5)

    assert result == [
        f"probe/list/{ordinal:04d}" for ordinal in range(4)]
    pages = [
        event.result for event in bucket.history
        if event.op == "list_page"]
    assert [len(page.keys) for page in pages] == [1, 2, 1]
    assert all(
        page.cursor is None or not page.cursor.endswith(page.keys[-1])
        for page in pages)
    assert bucket.assert_valid_history()


def test_list_drains_more_than_513_seeded_short_pages():
    bucket = AdversarialBucket(
        seed=23, list_page_size=1, max_list_pages=600)
    writer = bucket.handle("writer")
    expected = [
        f"probe/many/{ordinal:04d}" for ordinal in range(514)]
    for key in expected:
        assert writer.put_if_absent(key, key.encode()) is CREATED

    assert bucket.handle("lister").list("probe/many/") == expected
    assert len([
        event for event in bucket.history
        if event.op == "list_page"]) == 514
    assert bucket.assert_valid_history()


def test_list_page_budget_is_a_bounded_failure():
    bucket = AdversarialBucket(
        seed=29, list_page_size=1, max_list_pages=2)
    writer = bucket.handle("writer")
    for ordinal in range(3):
        key = f"probe/bounded/{ordinal}"
        writer.put_if_absent(key, key.encode())

    with pytest.raises(StoreError, match="page budget"):
        bucket.handle("lister").list("probe/bounded/")

    assert len([
        event for event in bucket.history
        if event.op == "list_page"]) == 2
    assert bucket.assert_valid_history()


@pytest.mark.parametrize(
    ("op", "key"),
    [
        ("get", "authority"),
        ("read_versioned", "authority"),
        ("has", "authority"),
        ("put", "invite/item"),
        ("put_if_absent", "probe/item"),
        ("cas", "authority"),
        ("list_page", "pile/"),
        ("delete", "pile/member/item"),
    ],
)
@pytest.mark.parametrize("when", ["before", "after"])
def test_actor_crash_is_available_on_both_sides_of_every_linearization(
        op, key, when):
    initial = {
        "authority": b"base",
        "pile/member/item": b"ingress",
    }
    bucket = AdversarialBucket(initial, seed=31)
    store = bucket.handle("worker")
    bucket.fail("worker", op, key, Fault.CRASH, when=when)

    def invoke():
        if op == "get":
            return store.get(key)
        if op == "read_versioned":
            return store.read_versioned(key)
        if op == "has":
            return store.has(key)
        if op == "put":
            return store.put(key, b"invite")
        if op == "put_if_absent":
            return store.put_if_absent(key, b"conditional")
        if op == "cas":
            return store.cas(
                key, bucket.initial_tokens["authority"], b"candidate")
        if op == "list_page":
            return store.list(key)
        if op == "delete":
            return store.delete(key)
        raise AssertionError(op)

    with pytest.raises(RuntimeError, match="crash"):
        invoke()

    assert len(bucket.history) == (0 if when == "before" else 1)
    if op == "put":
        assert ("invite/item" in bucket._data) is (when == "after")
    elif op == "put_if_absent":
        assert ("probe/item" in bucket._data) is (when == "after")
    elif op == "cas":
        assert bucket._data["authority"] == (
            b"candidate" if when == "after" else b"base")
    elif op == "delete":
        assert ("pile/member/item" in bucket._data) is (when == "before")
    assert bucket.assert_valid_history()


def test_acknowledged_creation_invisibility_is_a_failing_control():
    bucket = AdversarialBucket(nonconforming=Nonconforming(
        acknowledged_create_invisible=True))
    store = bucket.handle("writer")

    assert store.put_if_absent("probe/invisible", b"value") is CREATED
    assert store.get("probe/invisible") is None
    assert not store.has("probe/invisible")
    with pytest.raises(AssertionError):
        bucket.assert_valid_history()


def test_stale_successful_direct_read_is_a_failing_control():
    bucket = AdversarialBucket(
        {"authority": b"old"},
        nonconforming=Nonconforming(stale_successful_reads=True))
    store = bucket.handle("writer")
    old = store.read_versioned("authority")
    assert isinstance(store.cas("authority", old.token, b"new"), Applied)

    assert store.read_versioned("authority") == old
    with pytest.raises(AssertionError):
        bucket.assert_valid_history()


def test_two_replacements_of_one_precondition_are_a_failing_control():
    bucket = AdversarialBucket(
        {"authority": b"base"},
        nonconforming=Nonconforming(reused_cas_precondition=True))
    store = bucket.handle("writer")
    base = store.read_versioned("authority")

    assert isinstance(store.cas("authority", base.token, b"one"), Applied)
    assert isinstance(store.cas("authority", base.token, b"two"), Applied)
    with pytest.raises(AssertionError):
        bucket.assert_valid_history()


def test_token_alias_across_distinct_bytes_is_a_failing_control():
    bucket = AdversarialBucket(
        nonconforming=Nonconforming(token_alias=True))
    store = bucket.handle("writer")
    first = store.cas("authority", ABSENT, b"one")
    assert isinstance(first, Applied)
    assert isinstance(store.cas(
        "authority", first.token, b"two"), Applied)

    with pytest.raises(AssertionError) as caught:
        with bucket.capture():
            bucket.assert_valid_history()
    assert any(
        "adversarial bucket seed=" in note
        and "linearized history:" in note
        for note in caught.value.__notes__)


def test_content_addressed_destruction_is_a_failing_control():
    bucket = AdversarialBucket(
        nonconforming=Nonconforming(destructive_objects=True))
    store = bucket.handle("writer")
    raw = b"immutable"
    key = "obj/" + h(raw)
    assert store.put_if_absent(key, raw) is CREATED
    store.delete(key)
    assert store.get(key) is None

    with pytest.raises(AssertionError):
        bucket.assert_valid_history()


def test_repeated_opaque_list_cursor_is_a_bounded_failing_control():
    bucket = AdversarialBucket(
        list_page_size=1,
        nonconforming=Nonconforming(repeated_list_cursor=True))
    writer = bucket.handle("writer")
    for ordinal in range(3):
        key = f"probe/repeated/{ordinal}"
        writer.put_if_absent(key, key.encode())

    with pytest.raises(StoreError, match="repeated cursor"):
        bucket.handle("lister").list("probe/repeated/")
    with pytest.raises(AssertionError):
        bucket.assert_valid_history()


def test_cached_reader_is_explicitly_stale_while_direct_store_stays_strong():
    bucket = AdversarialBucket({"authority": b"old"}, seed=37)
    direct = bucket.handle("direct")
    cached = LaggedReader(direct)
    opened = cached.read_versioned("authority")
    advanced = direct.cas("authority", opened.token, b"new")
    assert isinstance(advanced, Applied)

    assert cached.read_versioned("authority") == opened
    assert direct.read_versioned("authority").value == b"new"
    cached.refresh("authority")
    assert cached.read_versioned("authority").value == b"new"
    assert bucket.assert_valid_history()


def test_async_replica_reader_is_separate_from_strong_r2_binding():
    async def scenario():
        bucket = FakeR2Bucket()
        direct = R2BindingStore(bucket)
        created = await direct.cas("authority", ABSENT, b"old")
        replica = AsyncLaggedReader(direct)
        opened = await replica.read_versioned("authority")
        advanced = await direct.cas("authority", created.token, b"new")
        assert isinstance(advanced, Applied)
        assert await replica.read_versioned("authority") == opened
        assert (await direct.read_versioned("authority")).value == b"new"
        replica.refresh()
        assert (await replica.read_versioned("authority")).value == b"new"

    asyncio.run(scenario())


def test_shared_conformance_catches_a_hidden_retry_after_apply():
    bucket = AdversarialBucket(seed=41)
    actor = 0

    class HiddenRetry:
        def __init__(self, direct):
            self.direct = direct

        def __getattr__(self, name):
            return getattr(self.direct, name)

        def cas(self, key, token, value):
            result = self.direct.cas(key, token, value)
            if isinstance(result, Applied):
                return self.direct.cas(key, token, value)
            return result

    def store():
        nonlocal actor
        actor += 1
        return HiddenRetry(bucket.handle(f"sdk-{actor}"))

    with pytest.raises(AssertionError) as caught:
        exercise_sync_store(
            store, ConformanceRun("hidden-retry", seed=41))

    assert "provider=hidden-retry" in str(caught.value)
    assert bucket._data["authority"].startswith(b"authority-a:")


@pytest.mark.parametrize("operation", ["object-link", "authority-replace"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_real_process_exit_brackets_fs_linearization(
        tmp_path, operation, when):
    store_dir = tmp_path / f"{operation}-{when}"
    script = r"""
import os
import sys
from core.crypto import h
from core.object_store import ABSENT
from core.store import FsStore

directory, operation, when = sys.argv[1:]
store = FsStore(directory)
if operation == "object-link":
    value = b"immutable subprocess value"
    if when == "before":
        os._exit(71)
    store.put_if_absent("obj/" + h(value), value)
else:
    if store.read_versioned("authority") is ABSENT:
        store.cas("authority", ABSENT, b"base")
    current = store.read_versioned("authority")
    if when == "before":
        os._exit(71)
    store.cas("authority", current.token, b"replacement")
os._exit(72)
"""
    completed = _run_python(script, store_dir, operation, when)
    assert completed.returncode == (71 if when == "before" else 72)

    from core.store import FsStore
    store = FsStore(str(store_dir))
    if operation == "object-link":
        raw = b"immutable subprocess value"
        assert store.get("obj/" + h(raw)) == (
            raw if when == "after" else None)
    else:
        assert store.get("authority") == (
            b"replacement" if when == "after" else b"base")


def test_real_process_probe_terminates_a_hung_child():
    with pytest.raises(subprocess.TimeoutExpired):
        _run_python(
            "import time; time.sleep(60)",
            timeout=0.1,
        )
