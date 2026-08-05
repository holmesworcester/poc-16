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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from urllib.parse import urlsplit

import pytest
from nacl import signing

from adapters.r2 import R2S3Config, R2S3Store
from bench.cloud_contention import provider_request_report
from bench.removal_contention import run_removal_scenarios
from adapters.s3 import S3Config, S3Store
from core.object_store import Applied, OutcomeUnknown
from infrastructure.authority import (
    CapabilityReconciler,
    InstalledCapability,
    ServiceGrant,
)
from peerlog.cloud import (
    MULTIPART_EDGE,
    CloudCache,
    CloudMicroFork,
    CloudQueue,
)
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


class _PausedSlotCasCloud(S3Cloud):
    """Pause a real provider client immediately before one writer-slot CAS."""

    def __init__(self, store, *, entered=None, release=None, barrier=None):
        super().__init__(store)
        self.entered = entered
        self.release = release
        self.barrier = barrier
        self.pause_next_slot = True

    def cas(self, key, token, value):
        if self.pause_next_slot and "/slots/" in key:
            self.pause_next_slot = False
            if self.entered is not None:
                self.entered.set()
            if self.release is not None and not self.release.wait(120):
                raise TimeoutError("live slot CAS release")
            if self.barrier is not None:
                self.barrier.wait(120)
        return super().cas(key, token, value)


class _CrashBeforeSlotCasCloud(S3Cloud):
    """Lose one process after immutable creation but before its real CAS."""

    def __init__(self, store):
        super().__init__(store)
        self.crash_next_slot = True

    def cas(self, key, token, value):
        if self.crash_next_slot and "/slots/" in key:
            self.crash_next_slot = False
            raise OSError("injected crash before live R2 slot CAS")
        return super().cas(key, token, value)


class _RangeCountingCloud(S3Cloud):
    def __init__(self, store):
        super().__init__(store)
        self.range_gets = 0

    def get(self, key, *, if_none_match=None, suffix=None):
        if suffix is not None:
            self.range_gets += 1
        return super().get(
            key, if_none_match=if_none_match, suffix=suffix)


@pytest.mark.live
@pytest.mark.live_r2
def test_live_r2_queue_clobber_scenarios_3_4_5_7(live_r2_store):
    """Force the remaining queue races through independent real R2 clients."""
    providers = []

    def provider(kind=S3Cloud, **kwargs):
        result = kind(live_r2_store(), **kwargs)
        providers.append(result)
        return result

    # Scenario 3: publish advances the slot while an already-materialized fold
    # is paused at its real conditional write. The fold must lose as stale,
    # and a fresh fold must preserve both publications.
    workspace = secrets.token_bytes(32)
    log = WriterLog.owned()
    log.append(Fact("msg", 1, (), b"fold base"))
    CloudQueue(provider(), workspace).publish(log)
    entered, release = threading.Event(), threading.Event()
    folding = CloudQueue(provider(
        _PausedSlotCasCloud, entered=entered, release=release), workspace)
    fold_errors = []

    def stale_fold():
        try:
            folding.fold_idle(log.writer, announce=False)
        except Exception as error:  # noqa: BLE001 - asserted below
            fold_errors.append(error)

    thread = threading.Thread(target=stale_fold, name="live-r2-stale-fold")
    thread.start()
    assert entered.wait(120)
    log.append(Fact("msg", 2, (), b"publish wins"))
    CloudQueue(provider(), workspace).publish(log, 1, 2)
    release.set()
    thread.join(120)
    assert not thread.is_alive()
    assert len(fold_errors) == 1
    assert str(fold_errors[0]) == "stale cloud fold"
    audit = CloudQueue(provider(), workspace)
    assert audit.fold_idle(log.writer, announce=False).hi == 2
    audit.repair_directory()
    folded_state = PeerState()
    assert audit.sync(folded_state).facts == 2
    assert folded_state.logs[log.writer].coverage() == ((0, 2),)

    # Scenario 4: crash after immutable micro creation. An exact retry can be
    # chosen by readmission; a divergent restart returns typed fork evidence.
    workspace = secrets.token_bytes(32)
    secret = signing.SigningKey.generate()
    orphan = WriterLog.owned(secret)
    divergent = WriterLog.owned(signing.SigningKey(secret.encode()))
    orphan.append(Fact("msg", 3, (), b"orphan branch"))
    divergent.append(Fact("msg", 3, (), b"divergent branch"))
    crashing = CloudQueue(provider(_CrashBeforeSlotCasCloud), workspace)
    with pytest.raises(OSError, match="before live R2 slot CAS"):
        crashing.publish(orphan)
    recovery = CloudQueue(provider(), workspace)
    with pytest.raises(CloudMicroFork) as found:
        recovery.publish(divergent)
    assert found.value.evidence.incumbent_hash \
        != found.value.evidence.proposed_hash
    receipt = recovery.readmit_orphan(orphan.writer, 0, 1)
    assert recovery.readmit_orphan(orphan.writer, 0, 1) == receipt
    recovery.repair_directory()
    orphan_state = PeerState()
    assert recovery.sync(orphan_state).facts == 1
    assert orphan_state.logs[orphan.writer].fact(0) == orphan.fact(0)

    # Scenario 5: both folds finish multipart assembly of the same canonical
    # bytes before racing the slot. Exactly one slot CAS wins; both completed
    # objects are harmless because the destination key and bytes are equal.
    workspace = secrets.token_bytes(32)
    large = WriterLog.owned()
    for seq in range(2):
        large.append(Fact("msg", 10 + seq, (), b"m" * 2_000_000))
        CloudQueue(provider(), workspace).publish(large, seq, seq + 1)
    seed = CloudQueue(provider(), workspace)
    initial = seed.fold_idle(large.writer, announce=False)
    assert initial.segments[-1].size >= MULTIPART_EDGE
    large.append(Fact("msg", 12, (), b"bounded tail" * 100))
    CloudQueue(provider(), workspace).publish(large, 2, 3)
    barrier = threading.Barrier(2)
    racers = tuple(CloudQueue(provider(
        _PausedSlotCasCloud, barrier=barrier), workspace) for _ in range(2))
    fold_results, concurrent_errors = [], []

    def concurrent_fold(queue):
        try:
            fold_results.append(queue.fold_idle(
                large.writer, announce=False))
        except Exception as error:  # noqa: BLE001 - asserted below
            concurrent_errors.append(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        tuple(pool.map(concurrent_fold, racers))
    assert len(fold_results) == 1
    assert len(concurrent_errors) == 1
    assert str(concurrent_errors[0]) == "stale cloud fold"
    assert sum(item.metrics.multipart_completes for item in providers) == 2
    multipart_state = PeerState()
    multipart_audit = CloudQueue(provider(), workspace)
    multipart_audit.repair_directory()
    assert multipart_audit.sync(multipart_state).facts == 3
    assert multipart_state.logs[large.writer].coverage() == ((0, 3),)

    # Scenario 7: conditional directory reads and footer range GETs overlap
    # publication, repair, and folding. Every observed body remains whole and
    # the final state reaches the complete writer prefix.
    workspace = secrets.token_bytes(32)
    churn_log = WriterLog.owned()
    writer = CloudQueue(provider(), workspace)
    reader_provider = provider(_RangeCountingCloud)
    reader = CloudQueue(reader_provider, workspace)
    done = threading.Event()
    churn_errors = []

    def churn():
        try:
            for seq in range(8):
                churn_log.append(Fact(
                    "msg", 100 + seq, (), f"churn-{seq}".encode("ascii")))
                writer.publish(churn_log, seq, seq + 1)
                if seq in {3, 7}:
                    writer.fold_idle(churn_log.writer, announce=False)
                writer.repair_directory()
        except Exception as error:  # noqa: BLE001 - asserted below
            churn_errors.append(error)
        finally:
            done.set()

    churn_thread = threading.Thread(target=churn, name="live-r2-read-churn")
    churn_thread.start()
    churn_state, churn_cache = PeerState(), CloudCache()
    not_modified = changed = 0
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        report = reader.sync(
            churn_state, churn_cache, ts_window=(0, 10_000))
        if report.rounds == 1:
            not_modified += 1
        else:
            changed += 1
        if done.is_set() and churn_state.logs.get(churn_log.writer) \
                is not None and churn_state.logs[
                    churn_log.writer].coverage() == ((0, 8),):
            break
        time.sleep(0.05)
    churn_thread.join(180)
    assert not churn_thread.is_alive()
    assert not churn_errors
    assert churn_state.logs[churn_log.writer].coverage() == ((0, 8),)
    assert changed > 0 and not_modified > 0
    assert reader_provider.range_gets > 0

    cost = provider_request_report(providers)
    report = {
        "scenarios": (3, 4, 5, 7),
        "stale_fold_rejected": True,
        "orphan_readmitted": True,
        "multipart_completes": 2,
        "read_churn_changes": changed,
        "read_churn_not_modified": not_modified,
        "footer_range_gets": reader_provider.range_gets,
        **cost,
    }
    print(json.dumps(report, indent=2), flush=True)
    assert cost["projected_r2_usd"] < 0.05


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
