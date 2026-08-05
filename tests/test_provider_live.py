"""Opt-in evidence against real direct provider APIs.

Commands:

    POC16_LIVE_S3=1 POC16_S3_BUCKET=... \
      python3 -m pytest -q -m live_s3 tests/test_provider_live.py

    POC16_LIVE_R2=1 POC16_R2_ACCOUNT_ID=... POC16_R2_BUCKET=... \
      POC16_R2_ACCESS_KEY_ID=... POC16_R2_SECRET_ACCESS_KEY=... \
      python3 -m pytest -q -m live_r2 tests/test_provider_live.py

Scenario 8-11 lookup-gate contention is included in the live R2 selection and
prints exact operation counts plus projected request cost.

These tests reject endpoint overrides.  Emulator runs can exercise SDK wiring
elsewhere but are not provider evidence.
"""
import asyncio
import json
import os
import re
import secrets
import time
from dataclasses import replace
from urllib.parse import urlsplit

import pytest

from adapters.r2 import R2S3Config, R2S3Store
from bench.removal_contention import run_removal_scenarios
from adapters.s3 import S3Config, S3Store
from core.object_store import Applied, OutcomeUnknown
from infrastructure.authority import (
    CapabilityReconciler,
    InstalledCapability,
    ServiceGrant,
)
from peerlog.cloud import MULTIPART_EDGE, CloudCache, CloudQueue
from peerlog.cloud_s3 import S3Cloud
from peerlog.fact import Fact
from peerlog.ingest import PeerState
from peerlog.log import WriterLog
from tests.provider_conformance import (
    ConformanceRun,
    exercise_sync_store,
)


_RUN_PREFIX_RE = re.compile(
    r"^poc16-conformance/run-[0-9a-f]{32}$")
_S3_ENDPOINT_RE = re.compile(
    r"^s3(?:-fips)?(?:\.dualstack)?"
    r"(?:\.[a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$")
_MAX_CLEANUP_KEYS = 4096


class _LiveObjectCapabilities:
    """Disposable provider objects exercising the reconciler control plane."""

    def __init__(self, store):
        self.store = store

    @staticmethod
    def _key(binding):
        return "service-capability/" + binding

    @staticmethod
    def _body(binding, fingerprint):
        return json.dumps(
            {"binding": binding, "fingerprint": fingerprint},
            sort_keys=True, separators=(",", ":"),
        ).encode("ascii")

    def inventory(self):
        rows = []
        for key in self.store.list("service-capability"):
            raw = self.store.get_bounded(key, 256)
            value = json.loads(raw)
            rows.append(InstalledCapability(
                value["binding"], value["fingerprint"], key))
        return tuple(rows)

    def ensure(self, grant):
        key = self._key(grant.binding)
        body = self._body(grant.binding, grant.fingerprint)
        self.store.put_if_absent(key, body)
        if self.store.get_bounded(key, 256) != body:
            raise RuntimeError("provider capability collision")
        return InstalledCapability(
            grant.binding, grant.fingerprint, key)

    def revoke(self, installed):
        key = self._key(installed.binding)
        expected = self._body(
            installed.binding, installed.fingerprint)
        if self.store.get_bounded(key, 256) != expected:
            raise RuntimeError("provider capability changed before revoke")
        self.store.delete(key)


def _exercise_live_capability_reconciliation(store, provider):
    grant = ServiceGrant(
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "3" * 64,
        "4" * 64,
        provider,
        "live-conformance-prefix",
    )
    reconciler = CapabilityReconciler(_LiveObjectCapabilities(store))
    first = asyncio.run(reconciler.reconcile((grant,)))
    assert len(first.ensured) == 1
    assert asyncio.run(reconciler.reconcile((grant,))).ensured == ()
    handle = first.ensured[0].handle
    assert store.get_bounded(handle, 256) is not None
    removed = asyncio.run(reconciler.reconcile(()))
    assert removed.revoked == first.ensured
    assert store.get_bounded(handle, 256) is None


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
    before = store.read_versioned("removal")
    candidate = run.value("discarded-response-candidate")
    applied = store.cas("removal", before.token, candidate)
    if not isinstance(applied, Applied):
        raise AssertionError(run.diagnostic())
    try:
        raise OutcomeUnknown("test discarded the applied response")
    except OutcomeUnknown:
        recovered = store.read_versioned("removal")
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
        max_list_pages=_MAX_CLEANUP_KEYS,
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
    _exercise_live_capability_reconciliation(live_s3_store(), "aws")


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
    _exercise_live_capability_reconciliation(
        live_r2_store(), "cloudflare")
    _prove_recovery_after_discarded_response(
        live_r2_store(), run, pace)


@pytest.mark.live
@pytest.mark.live_r2
def test_live_r2_peerlog_rounds_and_five_mib_part_copy(live_r2_store):
    """Phase-2 evidence; skipped unless direct R2 credentials are explicit."""
    provider = S3Cloud(live_r2_store())
    workspace = secrets.token_bytes(32)
    cloud = CloudQueue(provider, workspace)
    log = WriterLog.owned()
    log.append(Fact("msg", 1, (), b"first"))
    cloud.publish(log)
    cloud.repair_directory()
    state, cache = PeerState(), CloudCache()
    assert cloud.sync(state, cache).rounds == 2
    assert cloud.sync(state, cache).rounds == 1

    # Respect R2's documented same-key write pacing for the derived directory.
    time.sleep(1.05)
    log.append(Fact("msg", 2, (), b"delta"))
    cloud.publish(log, 1, 2)
    cloud.repair_directory()
    assert cloud.sync(state, cache).rounds == 2

    edge = b"r" * MULTIPART_EDGE
    provider.create("part-copy/source", edge)
    upload = provider.begin_multipart("part-copy/destination")
    provider.copy_part(upload, "part-copy/source", MULTIPART_EDGE)
    provider.upload_part(upload, b"tail")
    assert provider.get("part-copy/destination")[0] is None
    provider.complete_multipart(upload)
    assert provider.get("part-copy/destination")[0] == edge + b"tail"


@pytest.mark.live
@pytest.mark.live_r2
def test_live_r2_lookup_gate_removal_scenarios_8_to_11(live_r2_store):
    """Run the bead's removal scenarios through separate direct R2 stores."""
    print(
        "lookup-gate scenarios 8-11 projected ceiling: "
        "<10,000 Class A + <10,000 Class B requests, <$0.05",
        flush=True,
    )

    def factory(label):
        seed = live_r2_store()
        config = replace(
            seed.r2_config,
            prefix=seed.r2_config.prefix + "/" + label,
        )
        return R2S3Store(
            config,
            read_client=seed._read_client,
            mutation_client=seed._mutation_client,
        )

    reports = run_removal_scenarios(
        factory,
        pace=lambda: time.sleep(1.05),
        members=100,
    )
    print(json.dumps(reports, indent=2), flush=True)
    assert all(report["projected_r2_usd"] < 0.05 for report in reports)
