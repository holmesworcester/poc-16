"""Amazon S3 adapter requests, races, and failure classification."""
import asyncio
import base64
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from adapters.s3 import S3Config, S3Store
from core.crypto import h
from core.limits import (
    DIRECT_STREAM_CHUNK_BYTES,
    MAX_DIRECT_OBJECT_BYTES,
    MAX_OBJECT_BYTES,
    PayloadTooLarge,
)
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    StoreError,
    Versioned,
    VersionToken,
    async_store,
    ensure_object_async,
)


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = "0" * 64


def establish(store, oid, raw):
    return asyncio.run(ensure_object_async(async_store(store), oid, raw))


class ServiceError(Exception):
    def __init__(self, status, code=None):
        super().__init__(code or str(status))
        self.response = {
            "ResponseMetadata": {"HTTPStatusCode": status},
            "Error": {"Code": code or str(status)},
        }


class Body(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.reads = 0
        self.closes = 0

    def read(self, *args):
        self.reads += 1
        return super().read(*args)

    def close(self):
        self.closes += 1
        super().close()


class ScriptedClient:
    def __init__(self, **outcomes):
        self.outcomes = {
            operation: list(values)
            for operation, values in outcomes.items()
        }
        self.calls = []

    def _call(self, operation, args):
        self.calls.append((operation, args))
        values = self.outcomes.get(operation)
        if not values:
            raise AssertionError(f"unexpected {operation}")
        outcome = values.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            return outcome(args)
        return outcome

    def get_object(self, **args):
        return self._call("get_object", args)

    def head_object(self, **args):
        return self._call("head_object", args)

    def put_object(self, **args):
        return self._call("put_object", args)

    def list_objects_v2(self, **args):
        return self._call("list_objects_v2", args)

    def delete_object(self, **args):
        return self._call("delete_object", args)


def checksum(value):
    return base64.b64encode(hashlib.sha256(value).digest()).decode("ascii")


def config(**changes):
    values = {
        "bucket": "test-bucket",
        "prefix": "tenant/workspace",
        "expected_bucket_owner": "123456789012",
    }
    values.update(changes)
    return S3Config(**values)


@pytest.mark.parametrize(
    "changes",
    [
        {"bucket": "an_arn_is_not_a_general_bucket"},
        {"bucket": "directory--x-s3"},
        {"bucket": "192.168.1.1"},
        {"prefix": "../workspace"},
        {"prefix": "workspace/"},
        {"server_side_encryption": "AES256",
         "sse_kms_key_id": "kms-key"},
        {"server_side_encryption": "AES256",
         "bucket_key_enabled": True},
        {"list_page_size": 1001},
        {"read_total_max_attempts": 0},
        {"max_body_read_calls": 0},
        {"max_body_read_calls": 65_537},
        {"connect_timeout": float("nan")},
        {"connect_timeout": float("inf")},
        {"read_timeout": float("-inf")},
    ])
def test_config_rejects_ambiguous_or_unsupported_provider_settings(changes):
    with pytest.raises((TypeError, ValueError)):
        config(**changes)


def test_read_versioned_and_cas_preserve_the_same_response_opaque_etags():
    old, new = b"old root", b"new root"
    body = Body(old)
    client = ScriptedClient(
        get_object=[{"Body": body, "ETag": '"opaque:old-7"'}],
        put_object=[{"ETag": '"opaque:new-11"'}])
    store = S3Store(config(
        server_side_encryption="aws:kms",
        sse_kms_key_id="arn:aws:kms:us-west-2:123456789012:key/test",
        bucket_key_enabled=True), client=client)

    versioned = store.read_versioned("root")
    assert versioned == Versioned(
        old, VersionToken('"opaque:old-7"'))
    assert body.reads == 2
    assert body.closes == 1
    assert client.calls[0] == ("get_object", {
        "Bucket": "test-bucket",
        "Key": "tenant/workspace/root",
        "ExpectedBucketOwner": "123456789012",
    })

    assert store.cas("root", versioned.token, new) == Applied(
        VersionToken('"opaque:new-11"'))
    assert client.calls[1] == ("put_object", {
        "Bucket": "test-bucket",
        "Key": "tenant/workspace/root",
        "ExpectedBucketOwner": "123456789012",
        "Body": new,
        "ChecksumAlgorithm": "SHA256",
        "ChecksumSHA256": checksum(new),
        "ServerSideEncryption": "aws:kms",
        "SSEKMSKeyId":
            "arn:aws:kms:us-west-2:123456789012:key/test",
        "BucketKeyEnabled": True,
        "IfMatch": '"opaque:old-7"',
    })


def test_absent_read_and_first_root_cas_use_if_none_match():
    raw = b"first root"
    client = ScriptedClient(
        get_object=[ServiceError(404, "NoSuchKey")],
        put_object=[{"ETag": '"first"'}])
    store = S3Store(config(), client=client)

    assert store.read_versioned("root") is ABSENT
    assert store.cas("root", ABSENT, raw) == Applied(
        VersionToken('"first"'))
    assert client.calls[-1] == ("put_object", {
        "Bucket": "test-bucket",
        "Key": "tenant/workspace/root",
        "ExpectedBucketOwner": "123456789012",
        "Body": raw,
        "ChecksumAlgorithm": "SHA256",
        "ChecksumSHA256": checksum(raw),
        "IfNoneMatch": "*",
    })


def test_conditional_object_create_sends_address_checksum_and_header():
    raw = b"immutable bytes"
    key = "obj/" + h(raw)
    client = ScriptedClient(put_object=[{}])
    store = S3Store(config(), client=client)

    assert store.put_if_absent(key, raw) is CREATED
    assert client.calls == [("put_object", {
        "Bucket": "test-bucket",
        "Key": "tenant/workspace/" + key,
        "ExpectedBucketOwner": "123456789012",
        "Body": raw,
        "ChecksumAlgorithm": "SHA256",
        "ChecksumSHA256": checksum(raw),
        "IfNoneMatch": "*",
    })]


def test_immutable_create_verifies_collision_and_unknown_outcome():
    raw = b"immutable bytes"
    oid = h(raw)

    same_body = Body(raw)
    collision_client = ScriptedClient(
        put_object=[ServiceError(412, "PreconditionFailed")],
        get_object=[{"Body": same_body, "ETag": '"incumbent"'}])
    assert establish(
        S3Store(config(), client=collision_client), oid, raw) is EXISTS
    assert [call[0] for call in collision_client.calls] == [
        "put_object", "get_object"]

    unknown_body = Body(raw)
    unknown_client = ScriptedClient(
        put_object=[ServiceError(500, "InternalError")],
        get_object=[{"Body": unknown_body, "ETag": '"applied"'}])
    assert establish(
        S3Store(config(), client=unknown_client), oid, raw) is EXISTS
    assert [call[0] for call in unknown_client.calls] == [
        "put_object", "get_object"]

    wrong_client = ScriptedClient(
        put_object=[ServiceError(412, "PreconditionFailed")],
        get_object=[{"Body": Body(b"wrong"), "ETag": '"wrong"'}])
    with pytest.raises(ValueError, match="immutable object conflict"):
        establish(S3Store(config(), client=wrong_client), oid, raw)


def test_immutable_create_retries_once_after_unknown_and_absent_read():
    raw = b"immutable bytes"
    oid = h(raw)
    client = ScriptedClient(
        put_object=[
            ConnectionError("response lost"),
            {},
        ],
        get_object=[ServiceError(404, "NoSuchKey")])

    assert establish(
        S3Store(config(), client=client), oid, raw) is CREATED
    assert [call[0] for call in client.calls] == [
        "put_object", "get_object", "put_object"]


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ServiceError(403, "AccessDenied"), StoreError),
        (ServiceError(404, "NoSuchBucket"), StoreError),
        (ServiceError(409, "Conflict"), RetryableStoreError),
        (ServiceError(429, "TooManyRequests"), RetryableStoreError),
        (ServiceError(500, "InternalError"), RetryableStoreError),
        (ConnectionError("network down"), RetryableStoreError),
    ])
def test_get_failure_classification_never_turns_403_into_absence(
        error, expected):
    store = S3Store(
        config(), client=ScriptedClient(get_object=[error]))

    with pytest.raises(expected) as caught:
        store.get("root")
    assert type(caught.value) is expected


def test_get_and_head_only_treat_key_level_404_as_absent():
    client = ScriptedClient(
        get_object=[ServiceError(404, "NoSuchKey")],
        head_object=[
            ServiceError(404, "NotFound"),
            ServiceError(403, "AccessDenied"),
        ])
    store = S3Store(config(), client=client)

    assert store.get("invite/missing") is None
    assert not store.has("invite/missing")
    with pytest.raises(StoreError) as caught:
        store.has("invite/forbidden")
    assert type(caught.value) is StoreError


def test_opt_in_exact_list_probe_disambiguates_missing_from_denied_403():
    physical = "tenant/workspace/invite/missing"
    client = ScriptedClient(
        get_object=[
            ServiceError(403, "AccessDenied"),
            ServiceError(403, "AccessDenied"),
            ServiceError(403, "AccessDenied"),
        ],
        list_objects_v2=[
            {"Contents": [], "IsTruncated": False},
            {
                "Contents": [{"Key": physical}],
                "IsTruncated": False,
            },
            ServiceError(403, "AccessDenied"),
        ])
    store = S3Store(
        config(probe_access_denied_missing=True), client=client)

    assert store.get("invite/missing") is None
    with pytest.raises(StoreError, match="AccessDenied"):
        store.get("invite/missing")
    with pytest.raises(StoreError, match="AccessDenied"):
        store.get("invite/missing")
    list_calls = [
        request for operation, request in client.calls
        if operation == "list_objects_v2"
    ]
    assert list_calls == [{
        "Bucket": "test-bucket",
        "Prefix": physical,
        "MaxKeys": 1,
        "ExpectedBucketOwner": "123456789012",
    }] * 3


def test_streaming_body_transport_failure_is_retryable_and_still_closes():
    class BrokenBody:
        def __init__(self):
            self.closed = False

        @staticmethod
        def read(_amount):
            raise ConnectionError("body truncated")

        def close(self):
            self.closed = True
            raise ConnectionError("cleanup also failed")

    body = BrokenBody()
    store = S3Store(config(), client=ScriptedClient(get_object=[{
        "Body": body,
        "ETag": '"response-token"',
    }]))

    with pytest.raises(RetryableStoreError, match="ConnectionError"):
        store.read_versioned("root")
    assert body.closed


def test_bounded_get_checks_length_and_never_uses_an_unbounded_read():
    class GuardedBody(Body):
        def __init__(self, value):
            super().__init__(value)
            self.amounts = []

        def read(self, amount=None):
            if amount is None:
                raise AssertionError("unbounded provider read")
            self.amounts.append(amount)
            return super().read(amount)

    exact = GuardedBody(b"abcd")
    oversized = GuardedBody(b"abcde")
    declared_oversized = GuardedBody(b"must not be read")
    store = S3Store(config(), client=ScriptedClient(get_object=[
        {"Body": exact, "ContentLength": 4},
        {"Body": oversized},
        {"Body": declared_oversized, "ContentLength": 5},
    ]))

    assert store.get_bounded("obj/" + "0" * 64, 4) == b"abcd"
    assert exact.amounts == [5, 1]
    assert exact.closes == 1
    with pytest.raises(PayloadTooLarge, match="byte limit"):
        store.get_bounded("obj/" + "1" * 64, 4)
    assert oversized.amounts == [5]
    assert oversized.closes == 1
    with pytest.raises(PayloadTooLarge, match="byte limit"):
        store.get_bounded("obj/" + "2" * 64, 4)
    assert declared_oversized.amounts == []
    assert declared_oversized.closes == 1


def test_direct_pile_copy_streams_the_exact_protocol_maximum():
    class VirtualBody:
        def __init__(self, size):
            self.remaining = size
            self.amounts = []
            self.closed = False

        def read(self, amount):
            self.amounts.append(amount)
            if not self.remaining:
                return b""
            take = min(amount, self.remaining)
            self.remaining -= take
            return b"x" * take

        def close(self):
            self.closed = True

    body = VirtualBody(MAX_DIRECT_OBJECT_BYTES)
    store = S3Store(config(), client=ScriptedClient(get_object=[{
        "Body": body,
        "ContentLength": MAX_DIRECT_OBJECT_BYTES,
    }]))
    copied = []
    total = store.copy_pile_object(
        h(b"virtual maximum pile"), MAX_DIRECT_OBJECT_BYTES,
        lambda chunk: copied.append(len(chunk)))

    assert total == MAX_DIRECT_OBJECT_BYTES == sum(copied)
    assert max(copied) == DIRECT_STREAM_CHUNK_BYTES
    assert body.amounts[-1] == 1
    assert body.closed


def test_direct_pile_copy_rejects_one_over_before_read_and_short_body():
    oversized = Body(b"must not be read")
    short = Body(b"abc")
    store = S3Store(config(), client=ScriptedClient(get_object=[
        {"Body": oversized, "ContentLength": MAX_OBJECT_BYTES + 1},
        {"Body": short, "ContentLength": 4},
        ServiceError(404, "NoSuchKey"),
    ]))

    with pytest.raises(PayloadTooLarge, match="byte limit"):
        store.copy_pile_object(
            h(b"oversized pile"), MAX_OBJECT_BYTES, lambda _chunk: None)
    assert oversized.reads == 0
    assert oversized.closes == 1
    with pytest.raises(StoreError, match="ContentLength mismatch"):
        store.copy_pile_object(
            h(b"short pile"), MAX_OBJECT_BYTES, lambda _chunk: None)
    assert short.closes == 1
    assert store.copy_pile_object(
        h(b"missing pile"), MAX_OBJECT_BYTES, lambda _chunk: None) is None


@pytest.mark.parametrize(
    ("declared", "value", "message"),
    [
        ("4", b"abcd", "invalid ContentLength"),
        (-1, b"", "invalid ContentLength"),
        (4, b"abc", "ContentLength mismatch"),
        (3, b"abcd", "ContentLength mismatch"),
    ])
def test_bounded_get_rejects_malformed_or_inconsistent_content_length(
        declared, value, message):
    body = Body(value)
    store = S3Store(config(), client=ScriptedClient(get_object=[{
        "Body": body,
        "ContentLength": declared,
    }]))

    with pytest.raises(StoreError, match=message):
        store.get_bounded("obj/" + "0" * 64, 4)
    assert body.closes == 1


def test_bounded_get_accepts_legal_short_reads_and_detects_true_edges():
    class Chunked:
        def __init__(self, value):
            self.value = value
            self.offset = 0
            self.amounts = []
            self.closed = False

        def read(self, amount):
            self.amounts.append(amount)
            if self.offset == len(self.value):
                return b""
            chunk = self.value[self.offset:self.offset + 1]
            self.offset += 1
            return chunk

        def close(self):
            self.closed = True

    exact = Chunked(b"abcd")
    truncated = Chunked(b"abc")
    over = Chunked(b"abcde")
    store = S3Store(config(), client=ScriptedClient(get_object=[
        {"Body": exact, "ContentLength": 4},
        {"Body": truncated, "ContentLength": 4},
        {"Body": over},
    ]))

    assert store.get_bounded("obj/" + "0" * 64, 4) == b"abcd"
    assert exact.amounts == [5, 4, 3, 2, 1]
    assert exact.closed
    with pytest.raises(StoreError, match="ContentLength mismatch"):
        store.get_bounded("obj/" + "1" * 64, 4)
    assert truncated.closed
    with pytest.raises(PayloadTooLarge, match="byte limit"):
        store.get_bounded("obj/" + "2" * 64, 4)
    assert over.closed


def test_bounded_get_caps_realistic_one_byte_fragment_calls():
    class Fragmented:
        def __init__(self, size):
            self.value = b"x" * size
            self.offset = 0
            self.reads = 0
            self.closed = False

        def read(self, amount):
            assert amount > 0
            self.reads += 1
            if self.offset == len(self.value):
                return b""
            chunk = self.value[self.offset:self.offset + 1]
            self.offset += 1
            return chunk

        def close(self):
            self.closed = True

    size = 64 * 1024
    read_budget = 4096
    body = Fragmented(size)
    store = S3Store(config(
        max_body_read_calls=read_budget), client=ScriptedClient(get_object=[{
        "Body": body,
        "ContentLength": size,
    }]))

    with pytest.raises(StoreError, match="fragment budget"):
        store.get_bounded("obj/" + "0" * 64, size)
    assert body.reads == read_budget
    assert body.offset == read_budget
    assert body.closed


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ServiceError(403, "AccessDenied"), StoreError),
        (ServiceError(404, "NoSuchBucket"), StoreError),
        (ServiceError(409, "ConditionalRequestConflict"),
         RetryableStoreError),
        (ServiceError(429, "TooManyRequests"), RetryableStoreError),
        (ServiceError(500, "InternalError"), OutcomeUnknown),
        (ConnectionError("response lost"), OutcomeUnknown),
    ])
def test_conditional_create_failure_classification(error, expected):
    raw = b"immutable"
    store = S3Store(
        config(), client=ScriptedClient(put_object=[error]))

    with pytest.raises(expected) as caught:
        store.put_if_absent("obj/" + h(raw), raw)
    assert type(caught.value) is expected


def test_precondition_results_are_definitive_only_in_their_context():
    token = VersionToken('"old"')
    create = S3Store(config(), client=ScriptedClient(
        put_object=[ServiceError(412, "PreconditionFailed")]))
    assert create.put_if_absent("obj/" + h(b"x"), b"x") is EXISTS

    stale = S3Store(config(), client=ScriptedClient(put_object=[
        ServiceError(412, "PreconditionFailed"),
        ServiceError(404, "NoSuchKey"),
    ]))
    assert stale.cas("root", token, b"new") is STALE
    assert stale.cas("root", token, b"newer") is STALE

    absent = S3Store(config(), client=ScriptedClient(
        put_object=[ServiceError(404, "NoSuchKey")]))
    with pytest.raises(StoreError) as caught:
        absent.cas("root", ABSENT, b"first")
    assert type(caught.value) is StoreError

    missing_bucket = S3Store(config(), client=ScriptedClient(
        put_object=[ServiceError(404, "NoSuchBucket")]))
    with pytest.raises(StoreError) as caught:
        missing_bucket.cas("root", token, b"new")
    assert type(caught.value) is StoreError


def test_successful_cas_without_etag_is_an_unknown_applied_mutation():
    store = S3Store(
        config(), client=ScriptedClient(put_object=[{}]))

    with pytest.raises(OutcomeUnknown, match="without a usable strong ETag"):
        store.cas("root", ABSENT, b"root")


def test_weak_etags_are_never_accepted_as_root_cas_tokens():
    read = S3Store(config(), client=ScriptedClient(get_object=[{
        "Body": Body(b"root"),
        "ETag": 'W/"weak-read"',
    }]))
    with pytest.raises(StoreError, match="no usable strong ETag"):
        read.read_versioned("root")

    mutation = S3Store(config(), client=ScriptedClient(put_object=[{
        "ETag": 'W/"weak-write"',
    }]))
    with pytest.raises(OutcomeUnknown, match="without a usable strong ETag"):
        mutation.cas("root", ABSENT, b"candidate")


def test_non_authoritative_put_and_delete_use_direct_scoped_requests():
    raw = b"pile"
    client = ScriptedClient(
        put_object=[{}],
        delete_object=[{}])
    store = S3Store(config(), client=client)

    assert store.put("pile/member/key", raw) is None
    assert store.delete("pile/member/key") is None
    assert client.calls == [
        ("put_object", {
            "Bucket": "test-bucket",
            "Key": "tenant/workspace/pile/member/key",
            "ExpectedBucketOwner": "123456789012",
            "Body": raw,
            "ChecksumAlgorithm": "SHA256",
            "ChecksumSHA256": checksum(raw),
        }),
        ("delete_object", {
            "Bucket": "test-bucket",
            "Key": "tenant/workspace/pile/member/key",
            "ExpectedBucketOwner": "123456789012",
        }),
    ]


@pytest.mark.parametrize("operation", ["put", "delete"])
def test_ambiguous_unconditional_mutations_raise_outcome_unknown(operation):
    client = ScriptedClient(**{
        "put_object" if operation == "put" else "delete_object":
            [ServiceError(503, "SlowDown")]})
    store = S3Store(config(), client=client)

    with pytest.raises(OutcomeUnknown):
        if operation == "put":
            store.put("pile/member/key", b"value")
        else:
            store.delete("pile/member/key")


def test_authoritative_guards_fail_before_any_sdk_request():
    client = ScriptedClient()
    store = S3Store(config(), client=client)
    raw = b"value"

    for key in ("root", "root/child", "obj", "obj/" + h(raw)):
        with pytest.raises(ValueError):
            store.put(key, raw)
        with pytest.raises(ValueError):
            store.delete(key)
    with pytest.raises(ValueError, match="compare-and-swap"):
        store.put_if_absent("root", raw)
    with pytest.raises(ValueError, match="address"):
        store.put_if_absent("obj/" + "0" * 64, raw)
    with pytest.raises(ValueError, match="CAS register"):
        store.cas("obj/" + h(raw), ABSENT, raw)
    with pytest.raises(TypeError, match="version token"):
        store.cas("root", "not-a-token", raw)
    for key in ("/outside", "../outside", "pile//key", "Root"):
        with pytest.raises(ValueError):
            store.put(key, raw)
    assert client.calls == []


def test_list_objects_v2_reads_every_page_with_bounded_exact_requests():
    client = ScriptedClient(list_objects_v2=[
        {
            "Contents": [
                {"Key": "tenant/workspace/pile/member/b"},
                {"Key": "tenant/workspace/pile/member/a"},
            ],
            "IsTruncated": True,
            "NextContinuationToken": "opaque-page-token",
        },
        {
            "Contents": [
                {"Key": "tenant/workspace/pile/member/c"},
                {"Key": "tenant/workspace/pile/member/b"},
            ],
            "IsTruncated": False,
        },
    ])
    store = S3Store(
        config(list_page_size=37, max_list_pages=2), client=client)

    assert store.list("pile/member/") == [
        "pile/member/a", "pile/member/b", "pile/member/c"]
    assert client.calls == [
        ("list_objects_v2", {
            "Bucket": "test-bucket",
            "Prefix": "tenant/workspace/pile/member/",
            "MaxKeys": 37,
            "ExpectedBucketOwner": "123456789012",
        }),
        ("list_objects_v2", {
            "Bucket": "test-bucket",
            "Prefix": "tenant/workspace/pile/member/",
            "MaxKeys": 37,
            "ExpectedBucketOwner": "123456789012",
            "ContinuationToken": "opaque-page-token",
        }),
    ]


def test_list_page_caps_a_larger_caller_budget_to_the_store_page_size():
    client = ScriptedClient(list_objects_v2=[{
        "Contents": [],
        "IsTruncated": False,
    }])
    store = S3Store(config(list_page_size=2), client=client)

    page = store.list_page("pile/", None, 256)

    assert page.keys == ()
    assert page.cursor is None
    assert client.calls == [("list_objects_v2", {
        "Bucket": "test-bucket",
        "Prefix": "tenant/workspace/pile/",
        "MaxKeys": 2,
        "ExpectedBucketOwner": "123456789012",
    })]


@pytest.mark.parametrize("duplicate", [False, True])
def test_list_page_rejects_provider_response_over_effective_limit(
        duplicate):
    keys = [
        "tenant/workspace/pile/member/a",
        "tenant/workspace/pile/member/b",
        "tenant/workspace/pile/member/c",
    ]
    if duplicate:
        keys = [keys[0]] * 3
    store = S3Store(config(), client=ScriptedClient(list_objects_v2=[{
        "Contents": [{"Key": key} for key in keys],
        "IsTruncated": False,
    }]))

    with pytest.raises(StoreError, match="requested page limit"):
        store.list_page("pile/", None, 2)


@pytest.mark.parametrize("second_page", [False, True])
def test_list_rejects_nonadvancing_or_over_bound_pagination(second_page):
    pages = [{
        "Contents": [],
        "IsTruncated": True,
        "NextContinuationToken": "same",
    }]
    if second_page:
        pages.append({
            "Contents": [],
            "IsTruncated": True,
            "NextContinuationToken": "same",
        })
    store = S3Store(
        config(max_list_pages=2 if second_page else 1),
        client=ScriptedClient(list_objects_v2=pages))

    message = "token did not advance" if second_page else "page bound"
    with pytest.raises(StoreError, match=message):
        store.list("")


def test_list_rejects_provider_keys_outside_the_workspace_namespace():
    store = S3Store(config(), client=ScriptedClient(list_objects_v2=[{
        "Contents": [{"Key": "other/workspace/pile/member/key"}],
        "IsTruncated": False,
    }]))

    with pytest.raises(StoreError, match="out-of-prefix"):
        store.list("pile/")


class ConditionalBucket:
    def __init__(self, parties):
        self.values = {}
        self.lock = threading.Lock()
        self.start = threading.Barrier(parties)
        self.generation = 0

    def put(self, **args):
        self.start.wait(timeout=5)
        with self.lock:
            key = args["Key"]
            if args.get("IfNoneMatch") == "*" and key in self.values:
                raise ServiceError(412, "PreconditionFailed")
            if "IfMatch" in args and (
                    key not in self.values
                    or self.values[key][1] != args["IfMatch"]):
                raise ServiceError(412, "PreconditionFailed")
            self.generation += 1
            etag = f'"opaque-generation-{self.generation}"'
            self.values[key] = (args["Body"], etag)
            return {"ETag": etag}


class RaceClient:
    def __init__(self, bucket):
        self.bucket = bucket

    def put_object(self, **args):
        return self.bucket.put(**args)


def test_independent_adapter_handles_admit_one_absent_root_winner():
    bucket = ConditionalBucket(2)
    stores = [
        S3Store(config(), client=RaceClient(bucket)),
        S3Store(config(), client=RaceClient(bucket)),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            result.result(timeout=5)
            for result in (
                pool.submit(stores[0].cas, "root", ABSENT, b"alice"),
                pool.submit(stores[1].cas, "root", ABSENT, b"bob"),
            )
        ]

    assert sum(isinstance(result, Applied) for result in results) == 1
    assert results.count(STALE) == 1
    assert bucket.values["tenant/workspace/root"][0] in {
        b"alice", b"bob"}


def test_sdk_construction_separates_read_retries_from_one_attempt_mutations(
        monkeypatch, tmp_path):
    configs = []
    clients = []

    class FakeConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            configs.append(self)

    class FakeBoto3:
        @staticmethod
        def client(service, **kwargs):
            client = object()
            clients.append((service, kwargs, client))
            return client

    class FakeSession:
        @staticmethod
        def get_service_model(service):
            assert service == "s3"
            operation = type("Operation", (), {
                "input_shape": type("Shape", (), {
                    "members": {
                        "ChecksumSHA256": object(),
                        "IfMatch": object(),
                        "IfNoneMatch": object(),
                    },
                })(),
            })()
            return type("Service", (), {
                "operation_model": staticmethod(
                    lambda name: operation if name == "PutObject" else None),
            })()

    def module(name):
        if name == "boto3":
            return FakeBoto3
        if name == "botocore.config":
            return type("Module", (), {"Config": FakeConfig})
        if name == "botocore.session":
            return type("Module", (), {
                "get_session": staticmethod(FakeSession)})
        raise AssertionError(name)

    monkeypatch.setattr(
        "adapters.s3.store.importlib.import_module", module)
    hostile_config = tmp_path / "aws-config"
    hostile_config.write_text(
        "[default]\nservices=hostile\n"
        "[services hostile]\ns3 =\n"
        "  endpoint_url = https://shared-profile.invalid\n")
    monkeypatch.setenv(
        "AWS_ENDPOINT_URL_S3", "https://environment.invalid")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(hostile_config))
    store = S3Store(config(
        region_name="us-west-2",
        endpoint_url="https://s3.us-west-2.amazonaws.com",
        addressing_style="virtual",
        read_total_max_attempts=7))

    assert configs[0].kwargs == {
        "ignore_configured_endpoint_urls": True}
    runtime_configs = configs[1:]
    assert [item.kwargs["retries"] for item in runtime_configs] == [
        {"mode": "standard", "total_max_attempts": 7},
        {"mode": "standard", "total_max_attempts": 1},
    ]
    assert all(item.kwargs["s3"] == {"addressing_style": "virtual"}
               for item in runtime_configs)
    assert all(
        item.kwargs["ignore_configured_endpoint_urls"] is True
        for item in runtime_configs)
    assert clients[0][:2] == ("s3", {
        "config": runtime_configs[0],
        "region_name": "us-west-2",
        "endpoint_url": "https://s3.us-west-2.amazonaws.com",
    })
    assert clients[1][:2] == ("s3", {
        "config": runtime_configs[1],
        "region_name": "us-west-2",
        "endpoint_url": "https://s3.us-west-2.amazonaws.com",
    })
    assert store._read_client is clients[0][2]
    assert store._mutation_client is clients[1][2]


def test_sdk_store_startup_rejects_an_old_model_before_client_creation(
        monkeypatch):
    client_calls = []

    class Config:
        def __init__(self, **_options):
            pass

    class Session:
        @staticmethod
        def get_service_model(_service):
            operation = type("Operation", (), {
                "input_shape": type("Shape", (), {
                    "members": {
                        "ChecksumSHA256": object(),
                        "IfNoneMatch": object(),
                    },
                })(),
            })()
            return type("Service", (), {
                "operation_model": staticmethod(lambda _name: operation),
            })()

    class Boto3:
        @staticmethod
        def client(*args, **kwargs):
            client_calls.append((args, kwargs))
            return object()

    modules = {
        "boto3": Boto3,
        "botocore.config": type("Module", (), {"Config": Config}),
        "botocore.session": type("Module", (), {
            "get_session": staticmethod(Session),
        }),
    }
    monkeypatch.setattr(
        "adapters.s3.store.importlib.import_module",
        lambda name: modules[name])

    with pytest.raises(RuntimeError, match="lacks IfMatch"):
        S3Store(config())
    assert client_calls == []


def test_injected_sdk_clients_do_not_run_the_installed_capability_probe(
        monkeypatch):
    monkeypatch.setattr(
        "adapters.s3.store.importlib.import_module",
        lambda _name: (_ for _ in ()).throw(
            AssertionError("injected clients imported the installed SDK")))

    client = ScriptedClient()
    assert S3Store(config(), client=client)._read_client is client


def test_injected_botocore_client_must_disable_hidden_mutation_retries():
    class Client:
        def __init__(self, retries):
            sdk_config = type("Config", (), {"retries": retries})()
            self.meta = type("Meta", (), {"config": sdk_config})()

    with pytest.raises(ValueError, match="exactly one total attempt"):
        S3Store(config(), client=Client({
            "mode": "standard", "total_max_attempts": 3}))

    one_attempt = Client({
        "mode": "standard", "total_max_attempts": 1})
    assert S3Store(config(), client=one_attempt)._mutation_client \
        is one_attempt

    no_retries_after_initial = Client({
        "mode": "standard", "max_attempts": 0})
    assert S3Store(
        config(), client=no_retries_after_initial)._mutation_client \
        is no_retries_after_initial


def test_import_and_injected_construction_do_not_require_provider_sdks():
    script = r"""
import builtins
real_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split(".", 1)[0] in {"boto3", "botocore"}:
        raise AssertionError("provider SDK imported")
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded
from adapters.s3 import S3Config, S3Store
S3Store(S3Config(bucket="test-bucket"), client=object())
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT,
        capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
