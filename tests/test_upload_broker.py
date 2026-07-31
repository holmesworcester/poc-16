"""Running exact-pile OPEN/FINALIZE broker boundary."""
import asyncio
import base64
import json

import facts
import pytest

from core.close import encode_pile
from core.crypto import h
from core.http import AsyncFromSyncReader, HttpGate
from core.limits import MAX_PILE_BYTES
from core.staged_intent import staging_key
from deploy.upload_broker import (
    AuthorizedPilePut,
    MAX_CAPABILITY_HEADERS,
    MAX_CAPABILITY_HEADER_NAME_BYTES,
    MAX_CAPABILITY_HEADER_VALUE_BYTES,
    MAX_CAPABILITY_QUERY_BYTES,
    MAX_CAPABILITY_URL_BYTES,
    UploadBroker,
    UploadUnavailable,
)
from deploy.upload_session import (
    InvalidUploadSession,
    MAX_SESSION_BYTES,
    SessionKey,
    UploadLeaf,
    UploadSessionPolicy,
)
from deploy.upload_wire import (
    FinalizedUpload,
    OpenedUpload,
    UploadCapability,
    encode_finalize_response,
    encode_open_response,
    finalize_document,
    open_document,
)
from facts.auth import request
from full_peer.node import FullPeer
from .util import add_member


NOW = 100_000
SESSION = bytes.fromhex("d" * 32)
KEY = SessionKey("key00001", b"k" * 32, 0, 10**12)


class Clock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


class RecordingSigner:
    provider_binding = "test-ingress-v2"

    def __init__(self, clock, lifetime_ms=60_000):
        self.clock, self.lifetime_ms, self.puts = clock, lifetime_ms, []

    def sign(self, put):
        assert isinstance(put, AuthorizedPilePut)
        self.puts.append(put)
        return UploadCapability(
            "https://uploads.example/" + put.key + "?signed=1",
            (
                ("content-length", str(put.size)),
                ("content-type", "application/octet-stream"),
                ("if-none-match", "*"),
                ("x-checksum-sha256", put.digest),
            ),
            min(self.clock() + self.lifetime_ms, put.not_after_ms),
        )


class RecordingApplier:
    def __init__(self, status="applied"):
        self.status, self.calls = status, []

    async def __call__(self, key, digest):
        self.calls.append((key, digest))
        return self.status


def policy(*, ttl_ms=600_000, max_bytes=MAX_SESSION_BYTES):
    return UploadSessionPolicy(
        "test-broker-v2", KEY.key_id, (KEY,), ttl_ms=ttl_ms,
        max_ttl_ms=600_000, clock_skew_ms=1_000, max_bytes=max_bytes)


def world(tmp_path, *, apply=None, signer=None, clock=None, lease=None):
    clock = clock or Clock()
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    public = node.identity_id(workspace)
    proof = encode_pile(request.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    signer = signer or RecordingSigner(clock)
    apply = apply or RecordingApplier()
    broker = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)),
        workspace,
        signer,
        clock,
        lease or policy(),
        apply_exact=apply,
        nonce=lambda count: SESSION if count == 16 else b"",
    )
    return node, workspace, public[:16], proof, clock, signer, apply, broker


def pile(raw=b"one exact closed pile"):
    return UploadLeaf(h(raw), len(raw))


def opened(broker, proof, leaf=None):
    return asyncio.run(broker.open(proof, leaf or pile()))


def cold(broker, store=None, apply=None, signer=None):
    return UploadBroker(
        store or broker.store,
        broker.workspace,
        signer or broker.signer,
        broker.now,
        broker.session_policy,
        apply_exact=apply or broker.apply_exact,
        nonce=lambda count: SESSION if count == 16 else b"",
    )


def test_open_returns_the_only_put_and_finalize_invokes_exact_applier(tmp_path):
    _, workspace, member, proof, _, signer, apply, broker = world(tmp_path)
    leaf = pile()

    result = opened(broker, proof, leaf)
    assert isinstance(result, OpenedUpload)
    assert result.session == "d" * 32
    assert len(signer.puts) == 1
    expected = staging_key(
        workspace, member, result.session, "pile", leaf.digest)
    assert signer.puts[0].key == expected
    assert expected in result.capability.url

    final = asyncio.run(broker.finalize(result.cursor))
    assert final == FinalizedUpload("applied")
    assert apply.calls == [(expected, leaf.digest)]
    assert json.loads(encode_open_response(result)) == open_document(result)
    assert json.loads(encode_finalize_response(final)) == \
        finalize_document(final)


@pytest.mark.parametrize("raw_status,wire_status", [
    ("admitted", "applied"),
    ("confirmed", "applied"),
    ("noop", "noop"),
    ("rejected-staging", "rejected"),
    ("missing", "retryable"),
    ("stale", "retryable"),
])
def test_finalize_has_one_small_provider_neutral_result(
        tmp_path, raw_status, wire_status):
    apply = RecordingApplier(raw_status)
    *_, proof, _clock, _signer, _apply, broker = world(
        tmp_path, apply=apply)
    lease = opened(broker, proof)
    assert asyncio.run(broker.finalize(lease.cursor)) \
        == FinalizedUpload(wire_status)


def test_cold_finalize_never_rereads_repository_and_replay_is_idempotent(
        tmp_path):
    *_, proof, _clock, _signer, apply, broker = world(tmp_path)
    lease = opened(broker, proof)

    class NoReads:
        async def get_bounded(self, _key, _maximum):
            raise AssertionError("FINALIZE reread repository state")

    restarted = cold(broker, store=NoReads())
    assert asyncio.run(restarted.finalize(lease.cursor)).status == "applied"
    assert asyncio.run(restarted.finalize(lease.cursor)).status == "applied"
    assert len(apply.calls) == 2
    assert apply.calls[0] == apply.calls[1]


def test_removal_is_observed_by_new_open_not_an_existing_fixed_lease(tmp_path):
    clock = Clock()
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    proof = encode_pile(request.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    apply, signer = RecordingApplier(), RecordingSigner(clock)
    broker = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)), workspace, signer, clock,
        policy(ttl_ms=100), apply_exact=apply,
        nonce=lambda count: SESSION if count == 16 else b"")
    lease = opened(broker, proof)

    node.bind_identity(workspace, founder)
    facts.auth.removal.evict(node, workspace, bob)
    with pytest.raises(InvalidUploadSession, match="authorization"):
        opened(broker, proof)

    clock.value = lease.expires_at_ms - 1
    assert asyncio.run(cold(broker).finalize(lease.cursor)).status == "applied"
    clock.value = lease.expires_at_ms
    with pytest.raises(InvalidUploadSession, match="cursor"):
        asyncio.run(cold(broker).finalize(lease.cursor))


def test_pile_limit_and_bad_authorization_fail_before_provider_effects(tmp_path):
    _, _, _, proof, _, signer, apply, broker = world(tmp_path)
    with pytest.raises(ValueError, match="upload pile"):
        UploadLeaf("e" * 64, MAX_PILE_BYTES + 1)
    with pytest.raises(InvalidUploadSession, match="authorization"):
        opened(broker, b"not a proof")
    assert signer.puts == []
    assert apply.calls == []


class StaticSigner:
    provider_binding = RecordingSigner.provider_binding

    def __init__(self, capability):
        self.capability = capability

    def sign(self, _put):
        return self.capability


@pytest.mark.parametrize("capability", (
    UploadCapability(
        "https://uploads.example/pile?" +
        "q" * (MAX_CAPABILITY_QUERY_BYTES + 1), (), NOW + 1),
    UploadCapability(
        "https://uploads.example/" +
        "x" * MAX_CAPABILITY_URL_BYTES, (), NOW + 1),
    UploadCapability(
        "https://uploads.example/pile",
        tuple((f"x-{index}", "v")
              for index in range(MAX_CAPABILITY_HEADERS + 1)), NOW + 1),
    UploadCapability(
        "https://uploads.example/pile",
        (("x" * (MAX_CAPABILITY_HEADER_NAME_BYTES + 1), "v"),), NOW + 1),
    UploadCapability(
        "https://uploads.example/pile",
        (("x", "v" * (MAX_CAPABILITY_HEADER_VALUE_BYTES + 1)),), NOW + 1),
    UploadCapability("http://uploads.example/pile", (), NOW + 1),
    UploadCapability("https://uploads.example/pile", (), NOW),
))
def test_provider_signer_output_is_bounded_and_session_scoped(
        tmp_path, capability):
    *_, proof, clock, _signer, apply, broker = world(tmp_path)
    hostile = cold(
        broker, signer=StaticSigner(capability), apply=apply)
    with pytest.raises(UploadUnavailable):
        opened(hostile, proof)


def gateway_call(gateway, workspace, proof):
    body = json.dumps({
        "pile": base64.b64encode(proof).decode(), "ws": workspace,
    }).encode()
    return asyncio.run(gateway.handle(
        "POST", "/mint", {"ws": workspace}, {}, body))


def test_upload_purpose_is_broker_only(tmp_path):
    node, workspace, _, upload_proof, _, _, _, broker = world(tmp_path)
    gateway = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: NOW)
    sync_proof = encode_pile(request.payload(
        node, workspace, "sync", NOW + 60_000, NOW))

    assert gateway_call(gateway, workspace, upload_proof).status == 403
    assert gateway_call(gateway, workspace, sync_proof).status == 200
    with pytest.raises(InvalidUploadSession, match="authorization"):
        opened(broker, sync_proof)
    assert opened(broker, upload_proof)


def test_provider_read_failure_is_retryable_not_bad_authorization(tmp_path):
    node, workspace, _, proof, clock, signer, apply, _ = world(tmp_path)

    class Failing:
        async def get_bounded(self, _key, _maximum):
            raise OSError("injected outage")

    broker = UploadBroker(
        Failing(), workspace, signer, clock, policy(), apply_exact=apply)
    with pytest.raises(UploadUnavailable, match="root unavailable"):
        opened(broker, proof)

    healthy = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)), workspace, signer, clock,
        policy(), apply_exact=apply)
    with pytest.raises(InvalidUploadSession, match="authorization"):
        opened(healthy, b"not a proof")
