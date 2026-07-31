"""Cloudflare broker Worker composes with the private exact Applier RPC."""
import asyncio
from io import BytesIO
import os
from types import SimpleNamespace
import urllib.error
from urllib.parse import unquote, urlsplit

import facts
import pytest

from core.close import encode_pile
from core.crypto import h
from core.limits import PayloadTooLarge
from core.object_store import ABSENT, Applied
from core.repository_reader import RepositoryReader
from deploy.cloudflare_upload.boundary import Deployment
from deploy.cloudflare_upload.reader import (
    R2CanonicalReader,
    R2FetchRequest,
    R2ReadConfig,
)
from deploy.cloudflare_upload.signer import R2UploadSigner
from deploy.cloudflare_upload.worker import applier_runtime, runtime
from deploy.repository_apply_wire import encode_apply_result
from deploy.upload_keyring import UploadKeyring, encode_keyring
from deploy.upload_session import SessionKey, UploadLeaf, UploadSessionPolicy
from facts.auth import request as request_fact
from facts import _bao
from facts.content import file as file_family
from full_peer.node import FullPeer
from full_peer import upload_journal
from full_peer.upload_client import (
    CREATED,
    UploadClient,
    UploadCreateConflict,
    UploadRetryable,
    UploadSessionRejected,
)
from full_peer.upload_client_http import HttpBrokerTransport

from .test_r2_worker_store import Bucket
from .util import all_fids, closed_subset


NOW = 5_000_000
READ_ACCESS = "reader-access"
READ_SECRET = "reader-secret"
INGRESS_ACCESS = "parent-access"
INGRESS_SECRET = "parent-secret"
SESSION = b"s" * 16


def run(awaitable):
    return asyncio.run(awaitable)


class Clock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


def deployment(workspace):
    return Deployment(
        account_id="a" * 32,
        workspace=workspace,
        canonical_bucket="poc16-canonical",
        ingress_bucket="poc16-untrusted-ingress",
        owner="production-west",
        broker_name="poc16-upload-broker",
        applier_name="poc16-repository-applier",
        read_permission_group_id="c" * 32,
        write_permission_group_id="d" * 32,
        broker_domain="uploads.example.com",
        presign_ttl_seconds=60,
    )


class Headers:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def items(self):
        return self.values.items()

    def get(self, name):
        return self.values.get(name)


class StreamResult:
    def __init__(self, done, value=None):
        self.done, self.value = done, value


class Reader:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.reads, self.cancelled, self.released = 0, None, False

    async def read(self):
        self.reads += 1
        return StreamResult(False, self.chunks.pop(0)) \
            if self.chunks else StreamResult(True)

    async def cancel(self, reason):
        self.cancelled = reason

    def releaseLock(self):
        self.released = True


class Stream:
    def __init__(self, chunks):
        self.reader = Reader(chunks)

    def getReader(self):
        return self.reader


class Request:
    def __init__(self, method, url, body=b"", headers=None, stream=True):
        self.method, self.url = method, url
        self.headers = Headers(headers)
        self.body = Stream([body]) if stream else None


class FetchResponse:
    def __init__(self, status, body=b"", *, declared=True):
        self.status = status
        self.headers = Headers(
            {"content-length": str(len(body))} if declared else {})
        self.body = Stream([body])


class CanonicalFetch:
    def __init__(self, candidate, bucket):
        self.candidate, self.bucket, self.requests = candidate, bucket, []

    async def __call__(self, request):
        assert isinstance(request, R2FetchRequest)
        self.requests.append(request)
        parsed = urlsplit(request.url)
        prefix = (
            f"/{self.candidate.canonical_bucket}/"
            f"{self.candidate.canonical_prefix}/"
        )
        assert parsed.path.startswith(prefix)
        logical = unquote(parsed.path.removeprefix(prefix))
        physical = f"{self.candidate.canonical_prefix}/{logical}"
        raw = self.bucket.data.get(physical)
        return FetchResponse(404 if raw is None else 200, raw or b"")


class ApplierService:
    def __init__(self, env):
        self.env, self.calls, self.override = env, [], None
        self.responses = []

    async def apply(self, key, digest):
        self.calls.append((key, digest))
        if self.responses:
            response = self.responses.pop(0)
            if response is not None:
                return response
        if self.override is not None:
            return self.override
        return encode_apply_result(
            await applier_runtime.apply(self.env, key, digest))


class WorkerResponse:
    def __init__(self, response):
        self.status, self.headers, self.body = (
            response.status, response.headers, response.body)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, maximum):
        return self.body[:maximum]


class WorkerOpener:
    def __init__(self, environment, fetch, clock):
        self.environment, self.fetch, self.clock = environment, fetch, clock
        self.requests = []

    def __call__(self, request, timeout):
        del timeout
        incoming = Request(
            request.method, request.full_url, request.data,
            dict(request.header_items()))
        self.requests.append(incoming)
        response = run(runtime.handle(
            incoming, self.environment, fetch=self.fetch, clock=self.clock,
            nonce=lambda count: SESSION if count == len(SESSION) else b""))
        wrapped = WorkerResponse(response)
        if response.status >= 400:
            raise urllib.error.HTTPError(
                request.full_url, response.status, "rejected",
                response.headers, BytesIO(response.body))
        return wrapped


class R2Put:
    """Exercise the real upload client against the fake provider bucket."""

    def __init__(self, candidate, bucket):
        self.candidate, self.bucket, self.keys = candidate, bucket, []

    def put(self, capability, body, size):
        raw = body.read(size + 1)
        assert len(raw) == size
        path = unquote(urlsplit(capability.url).path)
        prefix = f"/{self.candidate.ingress_bucket}/"
        assert path.startswith(prefix)
        key = path.removeprefix(prefix)
        if key in self.bucket.data:
            raise UploadCreateConflict("incumbent")
        _put(self.bucket, key, raw)
        self.keys.append(key)
        return CREATED


def _put(bucket, key, raw):
    bucket.data[key] = raw
    bucket.etags[key] = bucket._token()


def world(tmp_path, *, clock=None):
    clock = clock or Clock()
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    proof = encode_pile(request_fact.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    backing = node.store(workspace)
    candidate = deployment(workspace)
    canonical, ingress = Bucket(), Bucket()
    for key in backing.list(""):
        _put(canonical, f"{candidate.canonical_prefix}/{key}", backing.get(key))

    facts.content.message.post(
        node, workspace, "general", "through exact R2", ts=10)
    pile = closed_subset(node, workspace, all_fids(node, workspace))

    applier_env = SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="applier",
        WORKSPACE=workspace,
        CANONICAL_PREFIX=candidate.canonical_prefix,
        INGRESS_PREFIX=candidate.ingress_prefix,
        CANONICAL=canonical,
        INGRESS=ingress,
    )
    service = ApplierService(applier_env)
    signer = R2UploadSigner(
        candidate, INGRESS_ACCESS, INGRESS_SECRET, clock=clock)
    key = SessionKey("key00001", b"k" * 32, 0, NOW + 10_000_000)
    policy = UploadSessionPolicy(
        candidate.upload_issuer, key.key_id, (key,),
        ttl_ms=120_000, max_ttl_ms=120_000, clock_skew_ms=1_000,
    )
    environment = SimpleNamespace(
        POC16_DEPLOYMENT_ROLE="broker",
        CANONICAL_BUCKET_PROFILE="dedicated-workspace",
        UPLOAD_PROTOCOL="exact-pile-v2",
        WORKSPACE=workspace,
        R2_ENDPOINT=candidate.endpoint,
        CANONICAL_BUCKET=candidate.canonical_bucket,
        CANONICAL_PREFIX=candidate.canonical_prefix,
        INGRESS_BUCKET=candidate.ingress_bucket,
        INGRESS_PREFIX=candidate.ingress_prefix,
        PRESIGN_TTL_SECONDS=candidate.presign_ttl_seconds,
        UPLOAD_ISSUER=candidate.upload_issuer,
        CANONICAL_READ_ACCESS_KEY_ID=READ_ACCESS,
        CANONICAL_READ_SECRET_ACCESS_KEY=READ_SECRET,
        INGRESS_PARENT_ACCESS_KEY_ID=INGRESS_ACCESS,
        INGRESS_PARENT_SECRET_ACCESS_KEY=INGRESS_SECRET,
        UPLOAD_SESSION_KEYRING=encode_keyring(UploadKeyring(
            signer.provider_binding, policy)).decode("ascii"),
        APPLIER=service,
    )
    fetch = CanonicalFetch(candidate, canonical)
    opener = WorkerOpener(environment, fetch, clock)
    return (
        node, workspace, proof, pile, candidate, canonical, ingress,
        service, opener, HttpBrokerTransport(
            "https://uploads.example.com", opener=opener),
    )


def install_canonical(recipient, workspace, candidate, canonical):
    """Install one hosted snapshot as a recipient's passive local store."""
    store = recipient.store(workspace)
    prefix = candidate.canonical_prefix + "/"
    root = canonical.data[prefix + "root"]
    for physical, raw in canonical.data.items():
        if physical.startswith(prefix + "obj/"):
            store.put_if_absent(physical.removeprefix(prefix), raw)
    assert isinstance(store.cas("root", ABSENT, root), Applied)


def install_direct_runner(
        monkeypatch, node, transport, candidate, ingress, clock):
    provider = R2Put(candidate, ingress)
    live_sources = []
    create = node.create_upload

    def observed_create(workspace, raw):
        source = create(workspace, raw)
        upload_root = os.path.join(node.dir, "uploads")
        live_sources.append(sum(
            len(name) == 64 for name in os.listdir(upload_root)))
        return source

    def run_upload(source, broker_url, provider_origin, proof):
        assert broker_url == "https://uploads.example.com"
        return UploadClient(
            source, transport, provider, clock,
            provider_origin=provider_origin,
        ).run(proof)

    monkeypatch.setattr(node, "create_upload", observed_create)
    monkeypatch.setattr(node, "run_upload", run_upload)
    monkeypatch.setattr(node, "now_ms", clock)
    return provider, live_sources


def test_open_put_finalize_calls_real_db_free_applier_and_advances_root(
        tmp_path):
    (node, workspace, proof, raw, candidate, canonical, ingress,
     service, opener, transport) = world(tmp_path)
    leaf = UploadLeaf(h(raw), len(raw))

    opened = transport.open(proof, leaf)
    parsed = urlsplit(opened.capability.url)
    key = unquote(parsed.path).removeprefix(
        f"/{candidate.ingress_bucket}/")
    _put(ingress, key, raw)
    result = transport.finalize(opened.cursor)

    assert result.status == "applied"
    assert service.calls == [(key, leaf.digest)]
    assert [request.url.rsplit("/", 1)[-1] for request in opener.requests] == [
        "open", "finalize"]
    assert not any(call[0] in {"list", "delete"}
                   for call in canonical.calls + ingress.calls)
    root = canonical.data[f"{candidate.canonical_prefix}/root"]
    reader = RepositoryReader(
        workspace, root,
        lambda oid: canonical.data.get(
            f"{candidate.canonical_prefix}/obj/{oid}"))
    message = max(node.by_type(workspace, "msg"), key=lambda fact: fact.ts)
    assert reader.worker().fact_active(message.fid)


def test_two_slice_file_uses_exact_provider_path_then_recipient_projection(
        tmp_path, monkeypatch):
    (node, workspace, _proof, _raw, candidate, canonical, ingress,
     service, _opener, transport) = world(tmp_path)
    provider, live_sources = install_direct_runner(
        monkeypatch, node, transport, candidate, ingress, Clock())
    data = b"two-slice-provider-path" * (
        _bao.WIDTH // len(b"two-slice-provider-path") + 1)
    data = data[:_bao.WIDTH + 17]
    source = tmp_path / "two-slice.bin"
    source.write_bytes(data)

    uploaded = file_family.upload(
        node, workspace, "general", source,
        "https://uploads.example.com", candidate.endpoint, ts=10)

    assert uploaded["piles"] == 3
    assert len(provider.keys) == len(service.calls) == 3
    assert live_sources == [1, 1, 1]
    assert node.upload_status(workspace)["uploads"] == []
    assert not any(call[0] in {"list", "delete"}
                   for call in canonical.calls + ingress.calls)

    recipient = FullPeer(str(tmp_path / "recipient"))
    recipient.add_workspace(workspace, "hosted copy", [])
    install_canonical(recipient, workspace, candidate, canonical)
    output = tmp_path / "recipient.out"
    saved = file_family.save(
        recipient, workspace, uploaded["fid"], output)
    assert saved["bytes"] == len(data)
    assert output.read_bytes() == data


def test_terminal_slice_rejection_stops_and_retains_only_that_source(
        tmp_path, monkeypatch):
    (node, workspace, _proof, _raw, candidate, _canonical, ingress,
     service, _opener, transport) = world(tmp_path)
    service.responses = [
        None,
        encode_apply_result(SimpleNamespace(status="rejected")),
    ]
    provider, live_sources = install_direct_runner(
        monkeypatch, node, transport, candidate, ingress, Clock())
    source = tmp_path / "rejected.bin"
    source.write_bytes(b"r" * (_bao.WIDTH + 1))

    with pytest.raises(ValueError, match="retained source") as failure:
        file_family.upload(
            node, workspace, "general", source,
            "https://uploads.example.com", candidate.endpoint, ts=10)

    assert len(provider.keys) == len(service.calls) == 2
    assert live_sources == [1, 1]
    retained = node.upload_status(workspace)["uploads"]
    assert len(retained) == 1
    assert retained[0]["state"] == "rejected"
    assert retained[0]["source_id"] in str(failure.value)


def test_all_direct_upload_families_collect_success_and_retain_rejection(
        tmp_path, monkeypatch):
    (node, workspace, _proof, _raw, candidate, _canonical, ingress,
     service, _opener, transport) = world(tmp_path)
    provider, live_sources = install_direct_runner(
        monkeypatch, node, transport, candidate, ingress, Clock())
    monkeypatch.setattr(upload_journal, "MAX_UPLOAD_SOURCES", 1)

    for ordinal in range(2):
        sent = facts.content.message.upload(
            node, workspace, "general", f"success-{ordinal}",
            "https://uploads.example.com", candidate.endpoint,
            ts=20 + ordinal)
        assert sent["status"] == "applied"
        assert set(sent) == {"fid", "session", "status"}
        assert node.upload_status(workspace)["uploads"] == []

    service.responses = [
        encode_apply_result(SimpleNamespace(status="rejected"))]
    rejected = facts.content.message.upload(
        node, workspace, "general", "retained rejection",
        "https://uploads.example.com", candidate.endpoint, ts=30)

    assert rejected["status"] == "rejected"
    assert set(rejected) == {"fid", "session", "status", "upload"}
    retained = node.upload_status(workspace)["uploads"]
    assert len(retained) == 1 and retained[0]["state"] == "rejected"
    assert rejected["upload"] == retained[0]["source_id"]
    assert len(provider.keys) == len(service.calls) == 3
    assert live_sources == [1, 1, 1]


def test_malformed_private_service_result_is_retryable(tmp_path):
    values = world(tmp_path)
    proof, raw, service, transport = (
        values[2], values[3], values[7], values[9])
    opened = transport.open(proof, UploadLeaf(h(raw), len(raw)))
    service.override = {"status": "applied"}

    with pytest.raises(UploadRetryable):
        transport.finalize(opened.cursor)


def test_expired_cursor_never_calls_private_service(tmp_path):
    clock = Clock()
    values = world(tmp_path, clock=clock)
    proof, raw, service, transport = (
        values[2], values[3], values[7], values[9])
    opened = transport.open(proof, UploadLeaf(h(raw), len(raw)))
    clock.value = opened.expires_at_ms

    with pytest.raises(UploadSessionRejected):
        transport.finalize(opened.cursor)
    assert service.calls == []


def test_worker_bounds_streamed_request_and_canonical_response(tmp_path):
    values = world(tmp_path)
    environment, fetch = values[8].environment, values[8].fetch
    limit = runtime.upload_request_body_limit("/upload/finalize")
    request = Request(
        "POST", "https://uploads.example.com/upload/finalize", b"",
        {"content-type": "application/json"})
    request.body = Stream([b"x" * limit, b"x", b"unread"])

    response = run(runtime.handle(
        request, environment, fetch=fetch, clock=lambda: NOW))

    assert response.status == 413
    assert request.body.reader.reads == 2
    assert request.body.reader.cancelled
    assert request.body.reader.released

    config = R2ReadConfig(
        "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
        "poc16-canonical", "workspaces/" + "b" * 64)

    async def oversized(_request):
        return FetchResponse(200, b"12345")

    reader = R2CanonicalReader(
        config, READ_ACCESS, READ_SECRET, oversized, clock=lambda: NOW)
    with pytest.raises(PayloadTooLarge):
        run(reader.get_bounded("root", 4))


def test_settings_require_private_applier_and_redact_secrets(tmp_path):
    values = world(tmp_path)
    environment = values[8].environment
    settings = runtime.Settings.from_env(environment, clock=lambda: NOW)
    rendered = repr(settings)
    assert READ_SECRET not in rendered
    assert INGRESS_SECRET not in rendered

    missing = SimpleNamespace(**vars(environment))
    del missing.APPLIER
    response = run(runtime.handle(
        Request("POST", "https://uploads.example.com/upload/finalize", b"{}",
                {"content-type": "application/json"}),
        missing, fetch=values[8].fetch, clock=lambda: NOW))
    assert response.status == 500
