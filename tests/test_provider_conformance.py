"""Deterministic provider contract and adapter fault probes."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from itertools import count
from pathlib import Path
import threading

import pytest

from adapters.r2 import R2BindingStore, R2S3Config, R2S3Store
from adapters.s3 import S3Config, S3Store
from core.crypto import h
from core.object_store import (
    ABSENT,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    StoreError,
    VersionToken,
)
from core.store import FsStore
from core.writer_layout import (
    LayoutPage,
    PackPlacement,
    decode_layout_page_at,
    encode_layout_page,
    layout_page_key,
    publish_placements,
)
from tests.provider_conformance import (
    ConformanceRun,
    exercise_async_store,
    exercise_sync_store,
)
from tests.provider_fakes import (
    AtomicBody,
    BrokenBody,
    FakeR2Bucket,
    FakeS3Bucket,
    OneShotAsyncBarrier,
    ProviderError,
)
from tests.shared_bucket import ScriptedBucket
from tests.test_provider_live import (
    _cleanup_generated_store,
    _generated_prefix,
    _require_endpoint,
)

pytestmark = pytest.mark.unit


class _FirstCasBarrier:
    """Make distinct sync adapter handles replace one layout base."""

    def __init__(self, store, barrier):
        self.store = store
        self.barrier = barrier
        self.first = True

    def __getattr__(self, name):
        return getattr(self.store, name)

    def cas(self, key, token, value):
        if self.first:
            self.first = False
            self.barrier.wait()
        return self.store.cas(key, token, value)


def _s3_config(**changes):
    values = {
        "bucket": "conformance-bucket",
        "prefix": "poc16-conformance/run-fixed",
        "list_page_size": 2,
    }
    values.update(changes)
    return S3Config(**values)


def _r2_config(**changes):
    values = {
        "account_id": "a" * 32,
        "bucket": "conformance-bucket",
        "prefix": "poc16-conformance/run-fixed",
        "list_page_size": 2,
    }
    values.update(changes)
    return R2S3Config(**values)


def test_fs_store_runs_the_shared_contract(tmp_path):
    exercise_sync_store(
        lambda: FsStore(str(tmp_path)),
        ConformanceRun("fs", seed=0xF5))


def test_scripted_bucket_runs_the_shared_contract_with_atomic_opaque_pairs():
    bucket = ScriptedBucket(seed=0x5C71)
    actors = count()

    result = exercise_sync_store(
        lambda: bucket.handle(f"handle-{next(actors)}"),
        ConformanceRun("scripted-bucket", seed=0x5C71))

    assert result["removal"].token.value.startswith("opaque:")
    assert result["removal"].token.value != h(
        result["removal"].value)
    assert bucket.assert_valid_history()


def test_s3_adapter_runs_the_shared_contract_with_opaque_aba_tokens():
    bucket = FakeS3Bucket(page_size=2)

    def store():
        return S3Store(
            _s3_config(), client=bucket.client("independent-s3-handle"))

    result = exercise_sync_store(
        store, ConformanceRun("fake-s3", seed=0x53))
    assert result["removal"].token.value.startswith('"opaque-value-')
    assert len([
        event for event in bucket.history if event[1] == "list"
    ]) >= 4


def test_r2_host_adapter_runs_the_same_shared_contract():
    bucket = FakeS3Bucket(page_size=2)

    def store():
        return R2S3Store(
            _r2_config(), client=bucket.client("independent-r2-host"))

    result = exercise_sync_store(
        store, ConformanceRun("fake-r2-s3", seed=0x5232))
    assert result["removal"].token.value.startswith('"opaque-value-')


def test_native_r2_binding_runs_the_awaited_shared_contract():
    bucket = FakeR2Bucket(page_size=2)
    bucket.conditional_barrier = OneShotAsyncBarrier(2)
    result = asyncio.run(exercise_async_store(
        lambda: R2BindingStore(
            bucket, "poc16-conformance/run-fixed"),
        ConformanceRun("fake-r2-binding", seed=0xB1D1)))

    assert result["removal"].token.value.startswith("opaque-r2-value-")
    assert len([
        event for event in bucket.history if event[0] == "list"
    ]) >= 4
    assert bucket.conditional_barrier.arrivals == 2
    assert bucket.conditional_barrier.released


@pytest.mark.parametrize("provider", ("fs", "s3", "r2-s3"))
def test_distinct_layout_publishers_merge_on_every_sync_provider_contract(
        tmp_path, provider):
    if provider == "fs":
        backing = FsStore(str(tmp_path / "layout-provider"))
        stores = (backing, backing)
    else:
        bucket = FakeS3Bucket()
        adapter = S3Store if provider == "s3" else R2S3Store
        config = _s3_config() if provider == "s3" else _r2_config()
        stores = tuple(adapter(
            config, client=bucket.client(f"{provider}-{index}"))
            for index in range(2))
        backing = stores[0]
    barrier = threading.Barrier(2)
    stores = tuple(_FirstCasBarrier(store, barrier) for store in stores)
    workspace, device = h(b"layout workspace"), h(b"layout writer")
    placements = (
        PackPlacement(1, h(b"first shared pack"), 1, (1,)),
        PackPlacement(3, h(b"second shared pack"), 1, (1,)),
    )

    def publish(item):
        store, placement = item
        return asyncio.run(publish_placements(
            store, workspace, device, 1, (placement,)))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(publish, zip(stores, placements)))

    key = layout_page_key(workspace, device, 1)
    final = decode_layout_page_at(key, backing.get(key))
    assert final == LayoutPage(workspace, device, 1, placements)
    assert final in results


def test_distinct_layout_publishers_merge_on_native_r2_contract():
    async def scenario():
        bucket = FakeR2Bucket()
        stores = tuple(R2BindingStore(
            bucket, "poc16-conformance/run-fixed") for _index in range(2))
        workspace, device = h(b"layout workspace"), h(b"layout writer")
        placements = (
            PackPlacement(1, h(b"first shared pack"), 1, (1,)),
            PackPlacement(3, h(b"second shared pack"), 1, (1,)),
        )
        key = layout_page_key(workspace, device, 1)
        seeded = await stores[0].cas(
            key,
            ABSENT,
            encode_layout_page(LayoutPage(workspace, device, 1, ())),
        )
        assert isinstance(seeded, Applied)
        bucket.conditional_barrier = OneShotAsyncBarrier(2)
        results = await asyncio.gather(*(
            publish_placements(
                store, workspace, device, 1, (placement,))
            for store, placement in zip(stores, placements)
        ))
        final = decode_layout_page_at(key, await stores[0].get(key))
        assert final == LayoutPage(workspace, device, 1, placements)
        assert final in results
        assert bucket.conditional_barrier.arrivals == 2
        assert bucket.conditional_barrier.released

    asyncio.run(scenario())


def test_atomic_s3_response_keeps_body_and_token_from_one_version():
    bucket = FakeS3Bucket()
    store = S3Store(_s3_config(), client=bucket.client("reader"))
    first = store.cas("removal", ABSENT, b"version-a")
    assert isinstance(first, Applied)
    physical = "poc16-conformance/run-fixed/removal"

    def body(value):
        def advance_after_response():
            with bucket.lock:
                bucket.data[physical] = b"version-b"
                bucket.tokens[physical] = bucket._etag(b"version-b")
        return AtomicBody(value, advance_after_response)

    bucket.body_factory = body
    paired = store.read_versioned("removal")

    assert paired.value == b"version-a"
    assert paired.token == first.token
    bucket.body_factory = None
    assert store.read_versioned("removal").value == b"version-b"


def test_s3_applied_response_loss_is_unknown_and_recoverable_by_direct_read():
    bucket = FakeS3Bucket()
    store = S3Store(_s3_config(), client=bucket.client("applier"))
    first = store.cas("removal", ABSENT, b"base")
    bucket.drop_after_apply = 1

    with pytest.raises(OutcomeUnknown, match="ConnectionError"):
        store.cas("removal", first.token, b"candidate")

    recovered = store.read_versioned("removal")
    assert recovered.value == b"candidate"
    assert recovered.token.value != first.token.value


def test_s3_list_drains_cursor_pages_when_a_key_arrives_between_pages():
    bucket = FakeS3Bucket(page_size=2)
    store = S3Store(_s3_config(), client=bucket.client("lister"))
    for key in ("probe/list/0000", "probe/list/0001",
                "probe/list/0003", "probe/list/0004"):
        store.put_if_absent(key, key.encode())
    physical = (
        "poc16-conformance/run-fixed/probe/list/0002")
    bucket.insert_after_page = (physical, b"inserted")

    assert store.list("probe/list/") == [
        f"probe/list/{ordinal:04d}" for ordinal in range(5)]


def test_no_list_bucket_403_and_broken_body_never_become_absence():
    bucket = FakeS3Bucket()
    bucket.deny_missing_get = True
    store = S3Store(_s3_config(), client=bucket.client("restricted-reader"))
    with pytest.raises(StoreError) as denied:
        store.read_versioned("removal")
    assert type(denied.value) is StoreError

    physical = "poc16-conformance/run-fixed/removal"
    bucket.data[physical] = b"removal"
    bucket.tokens[physical] = '"quoted-non-content-etag"'
    broken = BrokenBody()
    bucket.body_factory = lambda value: broken
    with pytest.raises(RetryableStoreError, match="ConnectionError"):
        store.read_versioned("removal")
    assert broken.closed


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [
        (409, "ConditionalRequestConflict", RetryableStoreError),
        (429, "TooManyRequests", RetryableStoreError),
        (500, "InternalError", OutcomeUnknown),
    ])
def test_provider_fault_classes_do_not_collapse_to_stale(
        status, code, expected):
    class FailingClient:
        def put_object(self, **request):
            raise ProviderError(status, code)

    store = S3Store(_s3_config(), client=FailingClient())
    with pytest.raises(expected) as caught:
        store.cas("removal", VersionToken('"old"'), b"new")
    assert type(caught.value) is expected


def test_token_alias_across_different_bytes_is_a_failing_negative_control():
    run = ConformanceRun("nonconforming-alias", seed=7)
    token = VersionToken('"same-provider-token"')
    run.observe(token, b"first")

    with pytest.raises(AssertionError) as caught:
        run.observe(token, b"different")

    assert "provider=nonconforming-alias" in str(caught.value)
    assert "seed=0x7" in str(caught.value)


def test_provider_sdk_import_guard_covers_the_shared_harness():
    source = Path(__file__).with_name("provider_conformance.py").read_text()
    assert "boto3" not in source
    assert "botocore" not in source


def test_live_cleanup_namespace_is_generated_and_narrow():
    prefix = _generated_prefix()
    assert prefix.startswith("poc16-conformance/run-")
    assert len(prefix) == len("poc16-conformance/run-") + 32

    class Unsafe:
        config = type("Config", (), {"prefix": "production/workspace"})()

    with pytest.raises(ValueError, match="refusing cleanup"):
        _cleanup_generated_store(Unsafe())


def test_live_cleanup_removes_only_generated_current_keys_and_versions():
    prefix = "poc16-conformance/run-" + "a" * 32

    class Client:
        def __init__(self):
            self.deleted = []

        def delete_object(self, **request):
            self.deleted.append(request)

        @staticmethod
        def list_object_versions(**request):
            assert request["Prefix"] == prefix + "/"
            return {
                "Versions": [{
                    "Key": prefix + "/removal",
                    "VersionId": "removal-v1",
                }],
                "DeleteMarkers": [{
                    "Key": prefix + "/obj/dead",
                    "VersionId": "marker-v2",
                }],
                "IsTruncated": False,
            }

    class SafeStore:
        config = type(
            "Config", (), {
                "prefix": prefix,
                "bucket": "dedicated-test-bucket",
            })()

        def __init__(self):
            self._mutation_client = self._read_client = Client()
            self.list_calls = 0

        def list(self, logical):
            self.list_calls += 1
            return ["removal", "obj/dead"] \
                if self.list_calls == 1 else []

        def _read_args(self, key):
            return {
                "Bucket": self.config.bucket,
                "Key": prefix + "/" + key,
            }

        @staticmethod
        def _owner_args():
            return {}

    store = SafeStore()
    _cleanup_generated_store(store, delete_versions=True)

    assert store._mutation_client.deleted == [
        {
            "Bucket": "dedicated-test-bucket",
            "Key": prefix + "/removal",
        },
        {
            "Bucket": "dedicated-test-bucket",
            "Key": prefix + "/obj/dead",
        },
        {
            "Bucket": "dedicated-test-bucket",
            "Key": prefix + "/removal",
            "VersionId": "removal-v1",
        },
        {
            "Bucket": "dedicated-test-bucket",
            "Key": prefix + "/obj/dead",
            "VersionId": "marker-v2",
        },
    ]


def test_live_provider_evidence_rejects_emulator_and_cache_endpoints():
    def store(endpoint, *, r2_endpoint=None):
        meta = type("Meta", (), {"endpoint_url": endpoint})()
        value = type(
            "Store", (), {
                "_read_client": type("Client", (), {"meta": meta})(),
            })()
        if r2_endpoint is not None:
            value.r2_config = type(
                "Config", (), {"endpoint_url": r2_endpoint})()
        return value

    for endpoint in (
            "https://s3.amazonaws.com",
            "https://s3.us-west-2.amazonaws.com",
            "https://s3.dualstack.us-west-2.amazonaws.com",
            "https://s3-fips.us-gov-west-1.amazonaws.com",
            "https://s3.cn-north-1.amazonaws.com.cn"):
        _require_endpoint(store(endpoint), "s3")
    _require_endpoint(
        store(
            "https://a.r2.cloudflarestorage.com",
            r2_endpoint="https://a.r2.cloudflarestorage.com"),
        "r2")
    with pytest.raises(pytest.fail.Exception, match="direct provider API"):
        _require_endpoint(store("http://127.0.0.1:4566"), "s3")
    with pytest.raises(pytest.fail.Exception, match="direct provider API"):
        _require_endpoint(
            store("https://id.execute-api.us-east-1.amazonaws.com"),
            "s3")
    with pytest.raises(pytest.fail.Exception, match="direct provider API"):
        _require_endpoint(
            store(
                "https://s3-emulator-123.us-west-2.elb.amazonaws.com"),
            "s3")
    with pytest.raises(pytest.fail.Exception, match="direct provider API"):
        _require_endpoint(
            store(
                "https://cached.example.test",
                r2_endpoint="https://a.r2.cloudflarestorage.com"),
            "r2")
