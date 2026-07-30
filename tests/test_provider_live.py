"""Opt-in evidence against real direct provider APIs.

Commands:

    POC16_LIVE_S3=1 POC16_S3_BUCKET=... \
      python3 -m pytest -q -m live_s3 tests/test_provider_live.py

    POC16_LIVE_R2=1 POC16_R2_ACCOUNT_ID=... POC16_R2_BUCKET=... \
      POC16_R2_ACCESS_KEY_ID=... POC16_R2_SECRET_ACCESS_KEY=... \
      python3 -m pytest -q -m live_r2 tests/test_provider_live.py

    POC16_LIVE_R2_UPLOAD=1 POC16_R2_ACCOUNT_ID=... \
      POC16_R2_BUCKET=... POC16_R2_ACCESS_KEY_ID=... \
      POC16_R2_SECRET_ACCESS_KEY=... \
      python3 -m pytest -q -m live_r2 \
        tests/test_provider_live.py::test_live_r2_presigned_staging_put

These tests reject endpoint overrides.  Emulator runs can exercise SDK wiring
elsewhere but are not provider evidence.
"""
import os
import hashlib
import re
import secrets
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

import pytest

from adapters.r2 import R2S3Config, R2S3Store
from adapters.s3 import S3Config, S3Store
from core.object_store import Applied, OutcomeUnknown
from core.staged_intent import parse_staging_key, staging_key
from deploy.cloudflare_upload.boundary import Deployment
from deploy.cloudflare_upload.signer import R2UploadSigner
from deploy.upload_broker import AuthorizedPut
from tests.provider_conformance import (
    ConformanceRun,
    exercise_sync_store,
)


_RUN_PREFIX_RE = re.compile(
    r"^poc16-conformance/run-[0-9a-f]{32}$")
_S3_ENDPOINT_RE = re.compile(
    r"^s3(?:-fips)?(?:\.dualstack)?"
    r"(?:\.[a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$")
_MAX_CLEANUP_KEYS = 128


def _generated_prefix():
    prefix = "poc16-conformance/run-" + secrets.token_hex(16)
    if not _RUN_PREFIX_RE.fullmatch(prefix):
        raise AssertionError("unsafe generated conformance prefix")
    return prefix


def _required_opt_in(flag, variables):
    if os.environ.get(flag) != "1":
        pytest.skip(f"set {flag}=1 for direct-provider evidence")
    missing = [name for name in variables if not os.environ.get(name)]
    if missing:
        pytest.skip("missing live-provider configuration: " + ", ".join(
            missing))
    if os.environ.get("AWS_ENDPOINT_URL") \
            or os.environ.get("AWS_ENDPOINT_URL_S3"):
        pytest.fail(
            "endpoint overrides are wiring tests, not live S3/R2 evidence")


def _cleanup_generated_store(store, *, delete_versions=False):
    """Delete only the validated unique run namespace, with a hard bound."""
    prefix = store.config.prefix
    if not _RUN_PREFIX_RE.fullmatch(prefix):
        raise ValueError("refusing cleanup outside generated test prefix")
    keys = store.list("")
    if len(keys) > _MAX_CLEANUP_KEYS:
        raise RuntimeError("refusing unbounded live-provider cleanup")
    for key in keys:
        request = store._read_args(key)
        physical = request["Key"]
        if not physical.startswith(prefix + "/"):
            raise ValueError("refusing out-of-prefix cleanup")
        store._mutation_client.delete_object(**request)
    if delete_versions:
        request = {
            "Bucket": store.config.bucket,
            "Prefix": prefix + "/",
            "MaxKeys": _MAX_CLEANUP_KEYS + 1,
            **store._owner_args(),
        }
        response = store._read_client.list_object_versions(**request)
        versions = [
            item
            for collection in ("Versions", "DeleteMarkers")
            for item in response.get(collection, ())
        ]
        if response.get("IsTruncated") \
                or len(versions) > _MAX_CLEANUP_KEYS:
            raise RuntimeError(
                "refusing unbounded live-provider version cleanup")
        for item in versions:
            physical = item.get("Key")
            version = item.get("VersionId")
            if not isinstance(physical, str) \
                    or not physical.startswith(prefix + "/") \
                    or not isinstance(version, str) or not version:
                raise ValueError("refusing unsafe version cleanup")
            store._mutation_client.delete_object(
                Bucket=store.config.bucket,
                Key=physical,
                VersionId=version,
                **store._owner_args(),
            )
    if store.list(""):
        raise RuntimeError("live-provider cleanup was incomplete")


def _require_endpoint(store, provider):
    """Reject SDK/config redirection to an emulator or presentation cache."""
    meta = getattr(store._read_client, "meta", None)
    endpoint = getattr(meta, "endpoint_url", None)
    parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
    host = parsed.hostname if parsed is not None else None
    if provider == "s3":
        direct = (
            parsed is not None
            and parsed.scheme == "https"
            and isinstance(host, str)
            and _S3_ENDPOINT_RE.fullmatch(host) is not None
        )
    elif provider == "r2":
        direct = endpoint == store.r2_config.endpoint_url
    else:
        raise ValueError("unknown provider")
    if not direct:
        pytest.fail(
            f"{provider} live evidence requires its direct provider API; "
            f"got {endpoint!r}")


def _prove_recovery_after_discarded_response(store, run, pace):
    """Simulate the client losing an acknowledged conditional response."""
    pace()
    before = store.read_versioned("root")
    candidate = run.value("discarded-response-candidate")
    applied = store.cas("root", before.token, candidate)
    if not isinstance(applied, Applied):
        raise AssertionError(run.diagnostic())
    try:
        raise OutcomeUnknown("test discarded the applied response")
    except OutcomeUnknown:
        recovered = store.read_versioned("root")
    assert recovered.value == candidate, run.diagnostic()
    assert recovered.token == applied.token, run.diagnostic()
    run.record("discard applied response/read recovery", recovered)


@pytest.fixture
def live_s3_store():
    _required_opt_in("POC16_LIVE_S3", ("POC16_S3_BUCKET",))
    # Explicitly skip an opted-in environment that has no credential source.
    try:
        import boto3
    except ImportError:
        pytest.skip("boto3 is required for live S3 evidence")
    if boto3.Session().get_credentials() is None:
        pytest.skip("AWS credentials are absent")

    prefix = _generated_prefix()
    print(f"live S3 conformance prefix: {prefix}", flush=True)
    config = S3Config(
        bucket=os.environ["POC16_S3_BUCKET"],
        prefix=prefix,
        region_name=os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION"),
        expected_bucket_owner=os.environ.get(
            "POC16_S3_EXPECTED_BUCKET_OWNER"),
        list_page_size=2,
        max_list_pages=64,
    )
    stores = []

    def make():
        store = S3Store(config)
        stores.append(store)
        return store

    probe = make()
    _require_endpoint(probe, "s3")
    if probe.list(""):
        pytest.fail("generated S3 conformance prefix was not empty")
    try:
        yield make
    finally:
        _cleanup_generated_store(stores[0], delete_versions=True)


@pytest.fixture
def live_r2_store():
    required = (
        "POC16_R2_ACCOUNT_ID",
        "POC16_R2_BUCKET",
        "POC16_R2_ACCESS_KEY_ID",
        "POC16_R2_SECRET_ACCESS_KEY",
    )
    _required_opt_in("POC16_LIVE_R2", required)
    try:
        import boto3  # noqa: F401
    except ImportError:
        pytest.skip("boto3 is required for live R2 evidence")

    prefix = _generated_prefix()
    print(f"live R2 conformance prefix: {prefix}", flush=True)
    config = R2S3Config(
        account_id=os.environ["POC16_R2_ACCOUNT_ID"],
        bucket=os.environ["POC16_R2_BUCKET"],
        prefix=prefix,
        list_page_size=2,
        max_list_pages=64,
    )
    stores = []

    def make():
        store = R2S3Store(
            config,
            access_key_id=os.environ["POC16_R2_ACCESS_KEY_ID"],
            secret_access_key=os.environ[
                "POC16_R2_SECRET_ACCESS_KEY"],
        )
        stores.append(store)
        return store

    probe = make()
    _require_endpoint(probe, "r2")
    if probe.list(""):
        pytest.fail("generated R2 conformance prefix was not empty")
    try:
        yield make
    finally:
        _cleanup_generated_store(stores[0])


@pytest.mark.live
@pytest.mark.live_s3
def test_live_s3_direct_api_conformance(live_s3_store):
    run = ConformanceRun("live-amazon-s3")
    exercise_sync_store(live_s3_store, run)
    _prove_recovery_after_discarded_response(
        live_s3_store(), run, lambda: None)


@pytest.mark.live
@pytest.mark.live_r2
def test_live_r2_direct_api_conformance(live_r2_store):
    run = ConformanceRun("live-cloudflare-r2")

    def pace():
        # R2 documents a one-write-per-second rate for one key.  Pacing
        # sequential probes avoids mistaking that liveness limit for CAS
        # semantics; the concurrent same-token step remains concurrent.
        time.sleep(1.05)

    exercise_sync_store(live_r2_store, run, pace=pace)
    _prove_recovery_after_discarded_response(
        live_r2_store(), run, pace)


def _live_put(capability, body, *, url=None, headers=None):
    request = Request(
        capability.url if url is None else url,
        data=body,
        method="PUT",
        headers=dict(capability.headers)
        if headers is None else dict(headers),
    )
    try:
        with urlopen(request, timeout=30) as response:
            response.read()
            return response.status
    except HTTPError as error:
        error.close()
        return error.code


@pytest.mark.live
@pytest.mark.live_r2
def test_live_r2_presigned_staging_put():
    required = (
        "POC16_R2_ACCOUNT_ID",
        "POC16_R2_BUCKET",
        "POC16_R2_ACCESS_KEY_ID",
        "POC16_R2_SECRET_ACCESS_KEY",
    )
    _required_opt_in("POC16_LIVE_R2_UPLOAD", required)
    try:
        import boto3  # noqa: F401
    except ImportError:
        pytest.skip("boto3 is required for the privileged R2 observer")

    account = os.environ["POC16_R2_ACCOUNT_ID"]
    bucket = os.environ["POC16_R2_BUCKET"]
    access = os.environ["POC16_R2_ACCESS_KEY_ID"]
    secret = os.environ["POC16_R2_SECRET_ACCESS_KEY"]
    workspace = secrets.token_hex(32)
    member = secrets.token_hex(8)
    session = secrets.token_hex(16)
    body = b"poc16 live direct R2 staging upload"
    digest = hashlib.sha256(body).hexdigest()
    other_digest = hashlib.sha256(body + b"!").hexdigest()
    canonical = "poc16-live-unused-canonical"
    if bucket == canonical:
        canonical += "-other"
    candidate = Deployment(
        account_id=account,
        workspace=workspace,
        canonical_bucket=canonical,
        ingress_bucket=bucket,
        owner="live-provider-conformance",
        broker_name="poc16-live-upload-broker",
        publisher_name="poc16-live-upload-publisher",
        read_permission_group_id="c" * 32,
        write_permission_group_id="d" * 32,
        presign_ttl_seconds=30,
    )
    key = staging_key(
        workspace, member, session, "obj", digest)
    other_key = staging_key(
        workspace, member, session, "obj", other_digest)
    observer = R2S3Store(
        R2S3Config(account_id=account, bucket=bucket),
        access_key_id=access,
        secret_access_key=secret,
    )
    _require_endpoint(observer, "r2")
    capability = R2UploadSigner(
        candidate, access, secret).sign(AuthorizedPut(
            workspace,
            member,
            session,
            "obj",
            digest,
            len(body),
            "application/octet-stream",
            key,
            time.time_ns() // 1_000_000 + 30_000,
        ))
    parsed = urlsplit(capability.url)
    wrong_url = urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path.removesuffix(digest) + other_digest,
        parsed.query,
        parsed.fragment,
    ))
    cleanup = (key, other_key)
    print(f"live R2 presigned staging key: {key}", flush=True)
    try:
        wrong_headers = {
            **dict(capability.headers),
            "content-type": "text/plain",
        }
        assert _live_put(
            capability, body, headers=wrong_headers) == 403
        assert _live_put(capability, body, url=wrong_url) == 403
        assert observer.get(key) is None
        assert observer.get(other_key) is None

        assert _live_put(capability, body) in {200, 201}
        assert observer.get(key) == body
        assert _live_put(capability, body) == 412
        assert observer.get(key) == body
        assert observer.get(other_key) is None
    finally:
        for staged in cleanup:
            address = parse_staging_key(staged)
            if address.workspace != workspace:
                raise ValueError("refusing unsafe live R2 cleanup")
            observer._mutation_client.delete_object(
                Bucket=bucket, Key=staged)
