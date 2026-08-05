"""Real signed fixtures and lifecycle fences for live Worker contention."""
from collections import Counter
from types import SimpleNamespace
import threading
from urllib.parse import urlsplit

import pytest

from bench import cloudflare_http_contention as contention
from core.access import AccessGate
from core.object_store import (
    ABSENT,
    Applied,
    CREATED,
    OutcomeUnknown,
    VersionToken,
    Versioned,
)
from core.writer_head import (
    HeadSlot,
    decode_slot_at,
    encode_slot,
    head_slot_key,
)
from core.store import FsStore
from core.writer_repository import OpaqueHeadGate


class HttpResponse:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self.body = body
        self.headers = {} if headers is None else headers

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


def _replace_head(store, workspace, device, head):
    key = head_slot_key(workspace, device)
    opened = store.read_versioned(key)
    assert isinstance(opened, Versioned)
    previous = decode_slot_at(key, opened.value)
    result = store.cas(key, opened.token, encode_slot(HeadSlot(
        workspace,
        device,
        head,
        previous.removal_root,
        previous.permit,
    )))
    assert isinstance(result, Applied)


def test_real_fixture_has_same_base_race_and_independent_signed_writers(
        tmp_path):
    fixture = contention.build_fixture(
        tmp_path / "fixture", 4, 3, now=10_000_000)

    assert len(fixture.raced) == 4
    assert len(fixture.independent) == 3
    assert len({candidate.device for candidate in fixture.raced}) == 1
    assert len({candidate.device for candidate in fixture.independent}) == 3
    assert fixture.raced[0].device not in {
        candidate.device for candidate in fixture.independent
    }
    assert all(fixture.store.has("obj/" + candidate.head)
               for candidate in (*fixture.raced, *fixture.independent))


def test_seed_uses_create_only_for_objects_and_cas_for_mutable_slots(tmp_path):
    fixture = contention.build_fixture(
        tmp_path / "fixture", 2, 1, now=10_000_000)

    class SeedStore:
        def __init__(self):
            self.creates = []
            self.registers = []

        def put_if_absent(self, key, value):
            self.creates.append((key, value))
            return CREATED

        def cas(self, key, token, value):
            self.registers.append((key, token, value))
            return Applied(VersionToken("opaque"))

    target = SeedStore()
    count = contention.seed(target, fixture)

    assert count == len(fixture.store.list(""))
    assert target.creates
    assert all(key.startswith(("obj/", "removal-node/"))
               for key, _value in target.creates)
    assert target.registers
    assert all(token is ABSENT for _key, token, _value in target.registers)
    assert {key for key, _token, _value in target.registers} == {
        key for key in fixture.store.list("")
        if key == "removal" or key.startswith("heads/")
    }


def test_seed_reconciles_a_durable_create_with_a_lost_response(tmp_path):
    fixture = contention.build_fixture(
        tmp_path / "fixture", 2, 1, now=10_000_000)

    class UnknownOnceStore:
        def __init__(self):
            self.data = {}
            self.unknown = True

        def put_if_absent(self, key, value):
            self.data[key] = value
            if self.unknown:
                self.unknown = False
                raise OutcomeUnknown("response lost")
            return CREATED

        def get_bounded(self, key, _maximum):
            return self.data.get(key)

        def cas(self, key, token, value):
            assert token is ABSENT
            self.data[key] = value
            return Applied(VersionToken("opaque"))

    target = UnknownOnceStore()

    assert contention.seed(target, fixture) == len(fixture.store.list(""))
    assert target.data == {
        key: fixture.store.get(key) for key in fixture.store.list("")
    }


def test_overlapped_http_results_verify_exact_final_slots(tmp_path):
    fixture = contention.build_fixture(
        tmp_path / "fixture", 4, 2, now=10_000_000)
    winner = fixture.raced[2]
    accepted = {winner.head, *(item.head for item in fixture.independent)}

    def opener(request, timeout):
        assert timeout == contention.HTTP_TIMEOUT_SECONDS
        head = urlsplit(request.full_url).path.split("/")[-1]
        return HttpResponse(201 if head in accepted else 412)

    candidates = (*fixture.raced, *fixture.independent)
    outcomes, performance = contention.contend(
        "https://worker.example",
        fixture.workspace,
        candidates,
        opener=opener,
    )
    _replace_head(
        fixture.store, fixture.workspace, winner.device, winner.head)
    for candidate in fixture.independent:
        _replace_head(
            fixture.store,
            fixture.workspace,
            candidate.device,
            candidate.head,
        )

    report = contention.verify_slots(fixture.store, fixture, outcomes)

    assert Counter(
        status for _candidate, status, _latency, _attempts in outcomes
    ) == {
        201: 3,
        412: 3,
    }
    assert report == {
        "raced_writer": fixture.raced[0].device,
        "same_writer_candidates": 4,
        "same_writer_applied": 1,
        "same_writer_acknowledged": 1,
        "same_writer_conflicts": 3,
        "same_writer_retryable": 0,
        "independent_applied": 2,
        "independent_acknowledged": 2,
        "final_slots_verified": 3,
        "final_initial": 0,
        "final_candidate": 3,
        "invalid_or_torn_slots": 0,
        "status_counts": {201: 3, 412: 3},
        "raced_status_counts": {201: 1, 412: 3},
        "independent_status_counts": {201: 2},
        "no_clobber": True,
    }
    assert performance["logical_requests"] == 6
    assert performance["http_attempts"] == 6
    assert performance["attempt_status_counts"] == {201: 3, 412: 3}
    assert performance["requests_per_second"] > 0
    assert performance["latency_ms_max"] >= performance["latency_ms_p50"]


def test_same_writer_losers_rebase_publish_and_cold_sync_every_message(
        tmp_path):
    fixture = contention.build_fixture(
        tmp_path / "fixture", 4, 2, now=10_000_000)
    target = FsStore(str(tmp_path / "target"))
    contention.seed(target, fixture)
    winner = fixture.raced[2]
    _replace_head(target, fixture.workspace, winner.device, winner.head)
    outcomes = tuple(
        (candidate, 201 if candidate == winner else 412, 1.0,
         (201 if candidate == winner else 412,))
        for candidate in fixture.raced
    )
    access = AccessGate(fixture.workspace, target)
    heads = OpaqueHeadGate(target, access.authorize_head)

    async def advance_head(proof, proposed):
        return await heads.advance(
            proof,
            proposed,
            contention.time.time_ns() // 1_000_000,
        )

    report = contention.recover_same_writer(
        target,
        fixture,
        outcomes,
        "https://unused.example",
        tmp_path / "cold-receiver",
        advance_head=advance_head,
    )

    assert report["losing_closures_rebased"] == 3
    assert report["rebased_sequence"] == 5
    assert report["publisher_status"] == "applied"
    assert report["published_piles"] == 3
    assert report["raced_message_facts_expected"] == 4
    assert report["raced_message_facts_present"] == 4
    assert report["all_raced_writes_reachable"] is True
    assert report["cold_listed"] == 3
    assert report["cold_changed"] == 3
    assert report["cold_piles"] == 7
    assert report["http"] == {}


def test_activation_requires_one_concurrently_ready_probe_round(monkeypatch):
    lock = threading.Lock()
    calls = 0

    def opener(_request, timeout):
        nonlocal calls
        assert timeout == 10
        with lock:
            calls += 1
            ordinal = calls
        if ordinal <= 2:
            return HttpResponse(404)
        return HttpResponse(200, b'{"ok":true}')

    monkeypatch.setattr(contention.time, "sleep", lambda _seconds: None)

    report = contention._activate(
        "https://worker.example", 3, opener=opener)

    assert calls == 6
    assert report == {
        "rounds": 2,
        "requests": 6,
        "status_counts": {200: 4, 404: 2},
    }


def test_contention_retries_only_transient_http_outcomes(
        tmp_path, monkeypatch):
    fixture = contention.build_fixture(
        tmp_path / "fixture", 2, 1, now=10_000_000)
    winner = fixture.raced[0]
    accepted = {winner.head, fixture.independent[0].head}
    attempts = Counter()
    lock = threading.Lock()

    def opener(request, timeout):
        assert timeout == contention.HTTP_TIMEOUT_SECONDS
        head = urlsplit(request.full_url).path.split("/")[-1]
        with lock:
            attempts[head] += 1
            attempt = attempts[head]
        if attempt == 1:
            return HttpResponse(500)
        return HttpResponse(201 if head in accepted else 412)

    monkeypatch.setattr(contention.time, "sleep", lambda _seconds: None)
    outcomes, performance = contention.contend(
        "https://worker.example",
        fixture.workspace,
        (*fixture.raced, *fixture.independent),
        opener=opener,
    )

    assert all(values == (500, status)
               for _candidate, status, _latency, values in outcomes)
    assert performance["logical_requests"] == 3
    assert performance["http_attempts"] == 6
    assert performance["attempt_status_counts"] == {
        201: 2,
        412: 1,
        500: 3,
    }


def test_control_conflict_retries_only_for_exact_commit_recovery(
        monkeypatch):
    calls = []

    def opener(_request, timeout):
        assert timeout == contention.HTTP_TIMEOUT_SECONDS
        calls.append(1)
        return HttpResponse(409)

    monkeypatch.setattr(contention.time, "sleep", lambda _seconds: None)
    status, _body, evidence = contention._post_control(
        "https://worker.example",
        "a" * 64,
        "b" * 64,
        "commit",
        b"permit",
        opener=opener,
    )
    assert status == 409
    assert evidence["attempt_statuses"] == [409]
    assert len(calls) == 1

    calls.clear()
    status, _body, evidence = contention._post_control(
        "https://worker.example",
        "a" * 64,
        "b" * 64,
        "commit",
        b"permit",
        retry_conflict=True,
        opener=opener,
    )
    assert status == 409
    assert evidence["attempt_statuses"] == [409] * contention.HTTP_MAX_ATTEMPTS
    assert len(calls) == contention.HTTP_MAX_ATTEMPTS


def test_wrong_workspace_requires_a_response_from_the_running_worker(
        tmp_path, monkeypatch):
    fixture = contention.build_fixture(
        tmp_path / "fixture", 2, 1, now=10_000_000)
    responses = iter((
        HttpResponse(404, b"edge route absent"),
        HttpResponse(404, headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        }),
    ))
    sleeps = []
    monkeypatch.setattr(contention.time, "sleep", sleeps.append)

    assert contention._wrong_workspace(
        "https://worker.example",
        fixture,
        opener=lambda _request, timeout: next(responses),
    ) == 404
    assert sleeps == [0.25]


class CleanupClient:
    def __init__(self, store):
        self.store = store

    def delete_objects(self, **request):
        assert request["Bucket"] == "test"
        assert request["Delete"]["Quiet"] is True
        for item in request["Delete"]["Objects"]:
            self.store.keys.remove(item["Key"])


class CleanupStore:
    def __init__(self, prefix, logical=()):
        self.prefix = prefix
        self.config = SimpleNamespace(bucket="test")
        self.keys = {f"{prefix}/{key}" for key in logical}
        self._mutation_client = CleanupClient(self)

    def list(self, _prefix):
        return sorted(
            key.removeprefix(self.prefix + "/") for key in self.keys)

    def _read_args(self, key):
        return {"Bucket": "test", "Key": f"{self.prefix}/{key}"}


def test_cleanup_is_fenced_to_one_generated_prefix_and_verifies_absence():
    prefix = "poc16-http-contention/run-" + "1" * 32
    store = CleanupStore(prefix, ("removal", "obj/abc", "heads/ws/dev"))

    assert contention.cleanup(store, prefix) == {
        "deleted": 3,
        "remaining": 0,
    }
    assert store.keys == set()
    with pytest.raises(ValueError, match="outside HTTP contention prefix"):
        contention.cleanup(store, "workspaces/production")


def test_live_failure_after_deploy_attempt_still_deletes_worker_and_prefix(
        monkeypatch):
    prefix_store = []
    deleted = []
    fixture = SimpleNamespace(workspace="a" * 64)
    environment = {
        "POC16_LIVE_CF_HTTP": "1",
        "POC16_R2_ACCOUNT_ID": "b" * 32,
        "POC16_R2_BUCKET": "bucket",
        "POC16_R2_ACCESS_KEY_ID": "access",
        "POC16_R2_SECRET_ACCESS_KEY": "secret",
        "CLOUDFLARE_API_TOKEN": "worker-token",
    }

    monkeypatch.setattr(
        contention, "build_fixture", lambda *_args, **_kwargs: fixture)

    def make_store(prefix, _environment):
        store = CleanupStore(prefix)
        prefix_store.append(store)
        return store

    monkeypatch.setattr(contention, "_r2_store", make_store)
    monkeypatch.setattr(contention, "seed", lambda *_args: 7)
    monkeypatch.setattr(contention.manage, "_secrets", lambda _env: {})
    monkeypatch.setattr(
        contention.manage,
        "generated_config",
        lambda _env, smoke: {
            "name": "poc16-smoke-test",
            "vars": {"WORKSPACE": fixture.workspace},
        },
    )
    monkeypatch.setattr(
        contention.manage,
        "_worker_settings",
        lambda _config: contention.manage._ABSENT,
    )
    monkeypatch.setattr(
        contention.manage,
        "_deploy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("deploy response lost")),
    )
    monkeypatch.setattr(
        contention.manage,
        "_delete",
        lambda config, **options: deleted.append((config, options)),
    )

    with pytest.raises(RuntimeError, match="deploy response lost"):
        contention.live_run(environment=environment)

    assert len(prefix_store) == 1
    assert deleted == [(
        {"name": "poc16-smoke-test", "vars": {
            "WORKSPACE": fixture.workspace}},
        {"force": True, "timeout": 60},
    )]


def test_manage_stress_prints_live_report(monkeypatch, capsys):
    monkeypatch.setattr(
        contention,
        "live_run",
        lambda: {"correctness": {"no_clobber": True}},
    )

    assert contention.manage.main(["manage.py", "stress"]) == 0
    assert '"no_clobber": true' in capsys.readouterr().out
