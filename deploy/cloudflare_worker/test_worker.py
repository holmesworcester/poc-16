"""Cloudflare Worker boundary, package, and deployment-command tests."""
import asyncio
import base64
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import urlsplit

import pytest

import facts

from core import limits, peer_capability
from core.object_store import MAX_STORE_PREFIX_BYTES
from core.close import encode_pile
from core.crypto import (
    h,
    load_sk,
    seal_to as native_seal,
    unseal as native_unseal,
)
from core.grants import make_token
from core.pack_access import (
    MAX_PACK_BYTES,
    MAX_SCOPED_TTL_MS,
    PackOpen,
    decode_scoped_request,
    encode_pack_open,
)
from full_peer.node import FullPeer
from deploy.cloudflare_worker import crypto_compat, manage, runtime
from deploy.python_role_modules import REPOSITORY_READER_CORE_MODULES
from facts.auth import request as request_fact

TEST_PACK_TTL_SECONDS = 30


class R2Object:
    def __init__(self, value):
        self.value = value
        self.size = len(value)

    async def arrayBuffer(self):
        return self.value


class Bucket:
    def __init__(self, data):
        self.data = dict(data)
        self.calls = []

    async def get(self, key):
        self.calls.append(("get", key))
        value = self.data.get(key)
        return None if value is None else R2Object(value)

    async def head(self, key):
        self.calls.append(("head", key))
        return None if key not in self.data else R2Object(b"")

    async def put(self, *args, **kwargs):
        raise AssertionError("read-only Worker attempted R2 put")

    async def delete(self, *args, **kwargs):
        raise AssertionError("read-only Worker attempted R2 delete")


class Request:
    def __init__(self, method, url, body=b"", headers=None, stream=None):
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = Stream([body]) if stream is None and body else stream
        self._body = body
        self.bytes_calls = 0

    async def bytes(self):
        self.bytes_calls += 1
        return self._body


class StreamResult:
    def __init__(self, done, value=None):
        self.done = done
        self.value = value


class Reader:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.reads = 0
        self.cancelled = False
        self.released = False

    async def read(self):
        self.reads += 1
        if self.chunks:
            return StreamResult(False, self.chunks.pop(0))
        return StreamResult(True)

    async def cancel(self, reason):
        self.cancelled = reason

    def releaseLock(self):
        self.released = True


class Stream:
    def __init__(self, chunks):
        self.reader = Reader(chunks)

    def getReader(self):
        return self.reader


class SentinelPackBody:
    """A virtual maximum-size body that Python must never inspect."""

    async def arrayBuffer(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack PUT called arrayBuffer")

    def getReader(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack PUT entered bounded body reader")

    def __iter__(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack PUT iterated request body")

    def __bytes__(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack PUT copied request body")


class PackBucket(Bucket):
    def __init__(self, data):
        super().__init__(data)
        self.pack_puts = []

    async def put(self, key, value, **options):
        self.pack_puts.append((key, value, options))
        return SimpleNamespace(key=key)


def deployed_entry(monkeypatch, environment):
    workers = ModuleType("workers")

    class WorkerEntrypoint:
        pass

    class WorkerResponse:
        def __init__(self, body, *, status, headers):
            self.body = body
            self.status = status
            self.headers = dict(headers)

    workers.WorkerEntrypoint = WorkerEntrypoint
    workers.Response = WorkerResponse
    monkeypatch.setitem(sys.modules, "workers", workers)
    sys.modules.pop("deploy.cloudflare_worker.entry", None)
    entry = importlib.import_module("deploy.cloudflare_worker.entry")
    service = entry.Default()
    service.env = environment
    return service


def run(awaitable):
    return asyncio.run(awaitable)


def worker_world(tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    now = 100
    pile = encode_pile(request_fact.payload(
        node, workspace, "sync", now + runtime.MAX_GRANT_TTL_MS, now))
    prefix = f"workspaces/{workspace}"
    store = node.store(workspace)
    bucket = Bucket({
        f"{prefix}/{key}": store.get(key)
        for key in store.list("")
    })
    environment = SimpleNamespace(
        BUCKET=bucket,
        WORKSPACE=workspace,
        STORE_PREFIX=prefix,
        GRANT_SECRET=base64.b64encode(
            b"s" * runtime.EDGE_SECRET_BYTES).decode(),
        R2_ENDPOINT=(
            "https://" + "c" * 32 + ".r2.cloudflarestorage.com"),
        PACK_BUCKET="poc16-packs",
        PACK_PUT_ENDPOINT="https://worker.example",
        PACK_TTL_SECONDS=TEST_PACK_TTL_SECONDS,
        PACK_TICKET_SECRET=base64.b64encode(
            b"p" * runtime.EDGE_SECRET_BYTES).decode(),
        R2_ACCESS_KEY_ID="worker-access-key",
        R2_SECRET_ACCESS_KEY="worker-secret-key",
        **runtime._BUDGETS,
    )
    monkeypatch.setattr(runtime, "now_ms", lambda: now)
    return node, workspace, pile, bucket, environment


def test_runtime_mints_and_reads_through_only_the_direct_r2_binding(
        tmp_path, monkeypatch):
    node, workspace, pile, bucket, environment = worker_world(
        tmp_path, monkeypatch)
    request_body = json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }).encode()
    minted = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        request_body,
        {"Content-Type": "application/json"},
    ), environment))

    assert minted.status == 200
    value = json.loads(minted.body)
    assert value["cap"] == "sync-v1/read"
    token = native_unseal(
        node.identity(workspace)[0],
        base64.b64decode(value["grant"]),
    ).decode()
    root = run(runtime.handle(Request(
        "GET", f"https://worker.example/root?ws={workspace}",
        headers={"Authorization": "Bearer " + token},
    ), environment))
    assert root.status == 200
    assert root.body == node.store(workspace).get("root")
    assert root.headers["Cache-Control"] == "no-store"
    assert root.headers["X-Content-Type-Options"] == "nosniff"
    assert {call[0] for call in bucket.calls} <= {"get", "head"}


def test_deployed_entry_issues_exact_gets_and_streams_native_pack_put(
        tmp_path, monkeypatch):
    _, workspace, _, bucket, environment = worker_world(
        tmp_path, monkeypatch)
    pack_bucket = PackBucket(bucket.data)
    environment.BUCKET = pack_bucket
    service = deployed_entry(monkeypatch, environment)
    # This is exactly the capability advertised by this gateway's /mint.
    # It can open reads, but it deliberately cannot authorize pack creation.
    assert runtime.gateway(runtime.Settings.from_env(
        environment)).sync_profile == peer_capability.READ_ONLY
    member = h(b"pack reader")
    token = make_token(
        b"s" * runtime.EDGE_SECRET_BYTES,
        member,
        workspace,
        capability=peer_capability.READ_ONLY,
        issued_at=100,
        ttl_ms=runtime.MAX_GRANT_TTL_MS,
    )
    headers = {"Authorization": "Bearer " + token}
    oid = h(b"virtual maximum pack")
    whole = PackOpen("GET", oid, MAX_PACK_BYTES)
    ranged = PackOpen("GET", oid, MAX_PACK_BYTES, 17, 31)
    put = PackOpen("PUT", oid, MAX_PACK_BYTES)

    issued = []
    for opened in (whole, ranged):
        response = run(service.fetch(Request(
            "POST",
            f"https://worker.example/pack/open?ws={workspace}",
            encode_pack_open(opened),
            headers,
        )))
        assert response.status == 200
        issued.append(decode_scoped_request(response.body))

    denied = run(service.fetch(Request(
        "POST",
        f"https://worker.example/pack/open?ws={workspace}",
        encode_pack_open(put),
        headers,
    )))
    assert denied.status == 401

    whole_request, range_request = issued
    assert whole_request.method == "GET" and whole_request.headers == ()
    assert range_request.method == "GET"
    assert range_request.headers == (("range", "bytes=17-47"),)
    assert urlsplit(whole_request.url).path == (
        f"/poc16-packs/{environment.STORE_PREFIX}/pack/{oid}")
    assert urlsplit(range_request.url).path == urlsplit(
        whole_request.url).path
    # Pack creation authority belongs to the upload-purpose front door. This
    # read-only gateway deliberately cannot mint a push-capable grant.
    put_request = runtime.Settings.from_env(environment).issue_packs(
        lambda: 100)(h(b"upload broker member"), put, 100)
    assert put_request.method == "PUT"
    assert urlsplit(put_request.url).path == f"/pack/{oid}"

    sentinel = SentinelPackBody()
    direct = Request(
        "PUT",
        put_request.url,
        headers=dict(put_request.headers),
        stream=sentinel,
    )
    stored = run(service.fetch(direct))

    assert stored.status == 201
    assert direct.body is sentinel and direct.bytes_calls == 0
    assert pack_bucket.pack_puts == [(
        f"{environment.STORE_PREFIX}/pack/{oid}",
        sentinel,
        {"onlyIf": {"If-None-Match": "*"}, "sha256": oid},
    )]


@pytest.mark.parametrize(("name", "value"), (
    ("PACK_TICKET_SECRET", "not-base64"),
    ("R2_ACCESS_KEY_ID", "short"),
    ("R2_SECRET_ACCESS_KEY", "short"),
    ("R2_ENDPOINT", "http://r2.example"),
    ("PACK_BUCKET", "Bad_Bucket"),
    ("PACK_PUT_ENDPOINT", "http://worker.example"),
    ("PACK_TTL_SECONDS", MAX_SCOPED_TTL_MS // 1000 + 1),
    ("BUCKET", None),
))
def test_pack_bindings_fail_readiness_and_requests_shut(
        tmp_path, monkeypatch, name, value):
    _, _, _, bucket, environment = worker_world(tmp_path, monkeypatch)
    setattr(environment, name, value)

    response = run(runtime.handle(Request(
        "GET", "https://worker.example/healthz"), environment))

    assert response.status == 500
    assert bucket.calls == []


def test_missing_pack_secret_fails_readiness_shut(tmp_path, monkeypatch):
    _, _, _, bucket, environment = worker_world(tmp_path, monkeypatch)
    del environment.PACK_TICKET_SECRET

    response = run(runtime.handle(Request(
        "GET", "https://worker.example/healthz"), environment))

    assert response.status == 500
    assert bucket.calls == []


def test_runtime_fails_closed_for_scope_config_and_malformed_content_length(
        tmp_path, monkeypatch):
    _, workspace, _, _, environment = worker_world(tmp_path, monkeypatch)

    wrong = run(runtime.handle(Request(
        "GET", "https://worker.example/root?ws=wrong"), environment))
    malformed = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        headers={"Content-Length": "not-an-integer"},
    ), environment))
    invalid_secret = SimpleNamespace(
        **{**vars(environment), "GRANT_SECRET": "not-base64"})
    misconfigured = run(runtime.handle(Request(
        "GET", "https://worker.example/healthz"), invalid_secret))

    assert wrong.status == 404
    assert malformed.status == 400
    assert misconfigured.status == 500


def test_runtime_bounds_and_authenticates_r2_object_reads(
        tmp_path, monkeypatch):
    node, workspace, pile, bucket, environment = worker_world(
        tmp_path, monkeypatch)
    minted = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        json.dumps({
            "pile": base64.b64encode(pile).decode(),
            "ws": workspace,
        }).encode(),
    ), environment))
    token = native_unseal(
        node.identity(workspace)[0],
        base64.b64decode(json.loads(minted.body)["grant"]),
    ).decode()
    headers = {"Authorization": "Bearer " + token}
    prefix = environment.STORE_PREFIX
    raw, oid = b"object", h(b"object")
    bucket.data[f"{prefix}/obj/{oid}"] = raw

    found = run(runtime.handle(Request(
        "GET", f"https://worker.example/page/{oid}?ws={workspace}",
        headers=headers,
    ), environment))
    missing = run(runtime.handle(Request(
        "GET", f"https://worker.example/page/{'0' * 64}?ws={workspace}",
        headers=headers,
    ), environment))
    bucket.data[f"{prefix}/obj/{oid}"] = b"corrupt"
    corrupt = run(runtime.handle(Request(
        "GET", f"https://worker.example/page/{oid}?ws={workspace}",
        headers=headers,
    ), environment))
    read_only = run(runtime.handle(Request(
        "PUT", f"https://worker.example/pile/member/id?ws={workspace}",
        headers=headers,
    ), environment))

    assert found.status == 200 and found.body == raw
    assert missing.status == 404
    assert corrupt.status == 503
    assert read_only.status == 405
    assert not hasattr(runtime.ReadOnlyStore(bucket, prefix), "put")


def test_runtime_rejects_route_oversize_before_r2_arraybuffer(
        tmp_path, monkeypatch):
    node, workspace, pile, healthy, environment = worker_world(
        tmp_path, monkeypatch)
    mint_body = json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }).encode()
    minted = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        mint_body,
    ), environment))
    token = native_unseal(
        node.identity(workspace)[0],
        base64.b64decode(json.loads(minted.body)["grant"]),
    ).decode()
    headers = {"Authorization": "Bearer " + token}

    class OversizedObject:
        def __init__(self, size):
            self.size = size
            self.array_calls = 0

        async def arrayBuffer(self):
            self.array_calls += 1
            raise AssertionError("oversized R2 body was allocated")

    class OversizedBucket:
        def __init__(self, healthy_root=None):
            self.healthy_root = healthy_root
            self.objects = []

        async def get(self, key):
            if self.healthy_root is not None and key.endswith("/root"):
                return R2Object(self.healthy_root)
            limit = runtime.MAX_ROOT_BYTES \
                if key.endswith("/root") else runtime.MAX_OBJECT_BYTES
            obj = OversizedObject(limit + 1)
            self.objects.append(obj)
            return obj

    oversized = OversizedBucket()
    environment.BUCKET = oversized
    oid = "0" * 64
    results = [
        run(runtime.handle(Request(
            "GET", f"https://worker.example/root?ws={workspace}",
            headers=headers,
        ), environment)),
        run(runtime.handle(Request(
            "GET", f"https://worker.example/invite/code?ws={workspace}",
        ), environment)),
        run(runtime.handle(Request(
            "GET", f"https://worker.example/page/{oid}?ws={workspace}",
            headers=headers,
        ), environment)),
        run(runtime.handle(Request(
            "POST", f"https://worker.example/page?ws={workspace}",
            json.dumps([oid]).encode(), headers,
        ), environment)),
    ]

    assert [result.status for result in results] == [503, 413, 413, 413]
    assert len(oversized.objects) == len(results)
    assert all(obj.array_calls == 0 for obj in oversized.objects)

    prefix = environment.STORE_PREFIX
    selective = OversizedBucket(healthy.data[f"{prefix}/root"])
    environment.BUCKET = selective
    mint_oversize = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        mint_body,
    ), environment))

    assert mint_oversize.status == 503
    assert selective.objects
    assert all(obj.array_calls == 0 for obj in selective.objects)


def test_runtime_applies_mint_fetch_byte_budget_at_the_binding(
        tmp_path, monkeypatch):
    _, workspace, pile, _, environment = worker_world(tmp_path, monkeypatch)
    environment.MAX_MINT_FETCH_BYTES = 1
    body = json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }).encode()

    denied = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}", body),
        environment))
    malformed = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}", b"{"),
        environment))

    assert denied.status == 403
    assert malformed.status == 400


def test_runtime_streams_request_body_only_to_its_hard_limit(
        tmp_path, monkeypatch):
    _, workspace, _, _, environment = worker_world(tmp_path, monkeypatch)
    environment.MAX_REQUEST_BYTES = 5
    stream = Stream([b"123", b"456", b"must-not-be-read"])
    request = Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        stream=stream)

    response = run(runtime.handle(request, environment))

    assert response.status == 413
    assert stream.reader.reads == 2
    assert stream.reader.cancelled == "request body limit"
    assert stream.reader.released
    assert request.bytes_calls == 0

    declared = Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        headers={"Content-Length": "6"})
    assert run(runtime.handle(declared, environment)).status == 413
    assert declared.bytes_calls == 0


def test_runtime_never_falls_back_to_whole_request_bytes():
    empty = Request("GET", "https://worker.example/healthz")
    assert run(runtime._bounded_body(empty, 8)) == b""
    assert empty.bytes_calls == 0

    malformed = Request(
        "POST",
        "https://worker.example/mint",
        b"x",
        stream=object(),
    )
    with pytest.raises(ValueError, match="body stream"):
        run(runtime._bounded_body(malformed, 8))
    assert malformed.bytes_calls == 0


def test_runtime_bounds_query_bytes_and_field_count_before_gateway_io(
        tmp_path, monkeypatch):
    _, workspace, _, bucket, environment = worker_world(
        tmp_path, monkeypatch)
    environment.MAX_QUERY_BYTES = 80
    environment.MAX_QUERY_FIELDS = 3
    before = list(bucket.calls)

    exact_query = "ws=" + "a" * 77
    exact = run(runtime.handle(Request(
        "GET", f"https://worker.example/root?{exact_query}"), environment))
    over = run(runtime.handle(Request(
        "GET", f"https://worker.example/root?{exact_query}a"), environment))
    fields = run(runtime.handle(Request(
        "GET", "https://worker.example/healthz?a=1&b=2&c=3"),
        environment))
    too_many = run(runtime.handle(Request(
        "GET", "https://worker.example/healthz?a=1&b=2&c=3&d=4"),
        environment))

    assert exact.status == 404
    assert over.status == 414
    assert fields.status == 200
    assert too_many.status == 400
    assert bucket.calls == before


@pytest.mark.parametrize("query", (
    "ws=%",
    "ws=%2",
    "ws=%GG",
    "ws=%FF",
))
def test_runtime_rejects_malformed_query_encoding_before_gateway_io(
        tmp_path, monkeypatch, query):
    _, _, _, bucket, environment = worker_world(tmp_path, monkeypatch)
    before = list(bucket.calls)

    response = run(runtime.handle(Request(
        "GET", f"https://worker.example/root?{query}"), environment))

    assert response.status == 400
    assert bucket.calls == before


def test_workerd_sealed_box_is_wire_compatible_with_native_pynacl():
    secret = load_sk("24" * 32)
    public = secret.verify_key.encode().hex()

    worker_sealed = crypto_compat.seal_to(public, b"worker")
    native_sealed = native_seal(public, b"native")

    assert native_unseal(secret, worker_sealed) == b"worker"
    assert crypto_compat.unseal(secret, native_sealed) == b"native"


def test_edge_import_graph_excludes_host_only_modules():
    script = """
import json
import sys
import deploy.cloudflare_worker.runtime
print(json.dumps(sorted(set(sys.modules) & {
    "fcntl", "sqlite3", "threading", "multiprocessing",
    "adapters.s3", "adapters.r2.s3",
    "deploy.upload_broker", "deploy.cloudflare_upload.signer"
})))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=manage.REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout) == []


def test_stage_is_minimal_current_and_patches_pynacl(tmp_path, monkeypatch):
    vendored = tmp_path / "python_modules"
    sodium = vendored / "nacl" / "_sodium.test.so"
    sodium.parent.mkdir(parents=True)
    sodium.write_bytes(
        b"\x00asm-prefix-__start_em_asm-middle-__stop_em_asm-suffix")
    bindings = vendored / "nacl" / "bindings" / "__init__.py"
    bindings.parent.mkdir()
    bindings.write_text("# Initialize Sodium\nsodium_init()\n")
    build = tmp_path / "build"
    monkeypatch.setattr(manage, "VENDORED", vendored)
    monkeypatch.setattr(manage, "BUILD", build)
    monkeypatch.setattr(manage, "WORKER", build / "worker")

    manage.stage()
    manage.stage()

    staged = build / "worker"
    assert (staged / "core" / "repository_reader.py").read_bytes() == (
        manage.REPOSITORY / "core" / "repository_reader.py").read_bytes()
    assert {
        path.name for path in (staged / "core").glob("*.py")
    } == set(REPOSITORY_READER_CORE_MODULES)
    assert (staged / "facts" / "auth" / "request.py").read_bytes() == (
        manage.REPOSITORY / "facts" / "auth" / "request.py").read_bytes()
    assert (staged / "adapters" / "r2" / "worker.py").read_bytes() == (
        manage.REPOSITORY / "adapters" / "r2" / "worker.py").read_bytes()
    assert (staged / "adapters" / "r2" / "reader.py").read_bytes() == (
        manage.REPOSITORY / "adapters" / "r2" / "reader.py").read_bytes()
    for relative in (
            "deploy/cloudflare_sigv4.py",
            "deploy/cloudflare_pack/contract.py",
            "deploy/cloudflare_pack/issuer.py",
            "deploy/cloudflare_pack/put.py"):
        assert (staged / relative).read_bytes() == (
            manage.REPOSITORY / relative).read_bytes()
    assert not (staged / "core" / "store.py").exists()
    assert not (staged / "core" / "node.py").exists()
    assert not (staged / "core" / "mint.py").exists()
    assert not (staged / "core" / "repository_applier.py").exists()
    assert not (staged / "core" / "writer_repository.py").exists()
    assert not (staged / "adapters" / "r2" / "s3.py").exists()
    assert not (staged / "adapters" / "s3").exists()
    assert not (staged / "deploy" / "aws_lambda").exists()
    assert not (staged / "full_peer").exists()
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import deploy.cloudflare_pack.issuer, deploy.cloudflare_pack.put",
        ],
        cwd=staged,
        env={**os.environ, "PYTHONPATH": str(staged)},
        check=True,
        capture_output=True,
        text=True,
    )
    patched = sodium.read_bytes()
    assert b"__start_em_asm" not in patched
    assert b"__start_em_xsm" in patched
    assert "sodium_init()" not in bindings.read_text()


def test_generated_config_is_single_workspace_least_privilege():
    environment = {
        "CF_WORKSPACE": "a" * 64,
        "CF_R2_BUCKET": "production",
        "CF_R2_PREVIEW_BUCKET": "preview",
        "CF_R2_ENDPOINT": (
            "https://" + "b" * 32 + ".r2.cloudflarestorage.com"),
        "CF_PACK_PUT_ENDPOINT": "https://gateway.example.com",
        "CF_WORKER_NAME": "gateway",
        "CF_DEPLOYMENT_OWNER": "production-primary",
        "CF_ROUTE": "gateway.example.com/*",
        "CF_ZONE_NAME": "example.com",
    }

    config = manage.generated_config(environment)

    assert config["name"] == "gateway"
    assert config["workers_dev"] is False
    assert config["routes"] == [{
        "pattern": "gateway.example.com/*",
        "zone_name": "example.com",
    }]
    assert config["r2_buckets"] == [{
        "binding": "BUCKET",
        "bucket_name": "production",
        "preview_bucket_name": "preview",
        "remote": False,
    }]
    assert config["vars"]["WORKSPACE"] == "a" * 64
    assert config["vars"]["STORE_PREFIX"] == f"workspaces/{'a' * 64}"
    assert config["vars"]["R2_ENDPOINT"] == environment["CF_R2_ENDPOINT"]
    assert config["vars"]["PACK_BUCKET"] == "production"
    assert config["vars"]["PACK_PUT_ENDPOINT"] \
        == "https://gateway.example.com"
    assert config["vars"]["PACK_TTL_SECONDS"] \
        == manage.DEFAULT_PACK_TTL_SECONDS
    assert config["vars"][manage.OWNER_BINDING] == "production-primary"
    assert config["secrets"]["required"] == list(manage.SECRET_NAMES)
    assert not set(manage.SECRET_NAMES) & set(config["vars"])


def test_deploy_secrets_are_exact_and_validated_before_wrangler():
    environment = {
        "GRANT_SECRET": base64.b64encode(
            b"g" * manage.EDGE_SECRET_BYTES).decode(),
        "PACK_TICKET_SECRET": base64.b64encode(
            b"p" * manage.EDGE_SECRET_BYTES).decode(),
        "R2_ACCESS_KEY_ID": "pack-reader-access",
        "R2_SECRET_ACCESS_KEY": "pack-reader-secret",
    }

    assert manage._secrets(environment) == environment
    for name in manage.SECRET_NAMES:
        malformed = dict(environment)
        malformed[name] = "bad"
        with pytest.raises(ValueError, match=name):
            manage._secrets(malformed)
    malformed = dict(environment, PACK_TICKET_SECRET=object())
    with pytest.raises(ValueError, match="PACK_TICKET_SECRET"):
        manage._secrets(malformed)


def test_manage_and_runtime_share_exact_store_prefix_budget(
        tmp_path, monkeypatch):
    environment = {
        "CF_WORKSPACE": "a" * 64,
        "CF_R2_BUCKET": "production",
        "CF_R2_ENDPOINT": (
            "https://" + "b" * 32 + ".r2.cloudflarestorage.com"),
        "CF_PACK_PUT_ENDPOINT": "https://gateway.example.com",
        "CF_DEPLOYMENT_OWNER": "production-primary",
        "CF_ROUTE": "gateway.example.com/*",
        "CF_STORE_PREFIX": "a" * MAX_STORE_PREFIX_BYTES,
    }
    assert manage.generated_config(environment)["vars"]["STORE_PREFIX"] \
        == environment["CF_STORE_PREFIX"]
    environment["CF_STORE_PREFIX"] += "a"
    with pytest.raises(ValueError, match="CF_STORE_PREFIX"):
        manage.generated_config(environment)

    _, _, _, _, runtime_env = worker_world(tmp_path, monkeypatch)
    runtime_env.STORE_PREFIX = "a" * MAX_STORE_PREFIX_BYTES
    assert runtime.Settings.from_env(runtime_env).prefix \
        == runtime_env.STORE_PREFIX
    runtime_env.STORE_PREFIX += "a"
    with pytest.raises(ValueError, match="STORE_PREFIX"):
        runtime.Settings.from_env(runtime_env)


def test_worker_budget_bindings_match_runtime_and_core_ceilings():
    config = json.loads(manage.TEMPLATE.read_text())

    assert runtime.EDGE_SECRET_BYTES == manage.EDGE_SECRET_BYTES
    assert {
        name: config["vars"][name]
        for name in runtime._BUDGETS
    } == runtime._BUDGETS
    assert runtime.MAX_REQUEST_BYTES <= limits.MAX_MINT_REQUEST_BYTES
    assert runtime.MAX_ROOT_BYTES <= limits.MAX_ROOT_BYTES
    # Bao slice payloads are inline ordinary facts. Authenticated repository
    # reads apply their narrower page/fact bound at the gate call site rather
    # than shrinking this shared object-response ceiling.
    assert runtime.MAX_OBJECT_BYTES == limits.MAX_OBJECT_BYTES \
        == limits.MAX_REPOSITORY_OBJECT_BYTES == limits.MAX_PILE_BYTES
    assert limits.MAX_FACT_BYTES < runtime.MAX_OBJECT_BYTES
    assert runtime.MAX_BATCH_COUNT <= limits.PAGE_BATCH
    assert runtime.MAX_BATCH_BYTES == limits.MAX_PAGE_BATCH_BYTES
    assert runtime.MAX_MINT_FETCHES <= limits.MAX_MINT_FETCHES
    assert runtime.MAX_MINT_FETCH_BYTES <= limits.MAX_MINT_FETCH_BYTES


@pytest.mark.parametrize("field,value", [
    ("CF_WORKSPACE", "not-a-workspace"),
    ("CF_R2_BUCKET", ""),
    ("CF_R2_ENDPOINT", "http://r2.example"),
    ("CF_PACK_PUT_ENDPOINT", "http://gateway.example.com"),
    ("CF_PACK_TTL_SECONDS", str(MAX_SCOPED_TTL_MS // 1000 + 1)),
    ("CF_ROUTE", ""),
    ("CF_STORE_PREFIX", "../escape"),
    ("CF_DEPLOYMENT_OWNER", "short"),
    ("CF_WORKER_NAME", "Unsafe Worker"),
])
def test_generated_config_rejects_ambiguous_deployment_input(field, value):
    environment = {
        "CF_WORKSPACE": "a" * 64,
        "CF_R2_BUCKET": "production",
        "CF_R2_ENDPOINT": (
            "https://" + "b" * 32 + ".r2.cloudflarestorage.com"),
        "CF_PACK_PUT_ENDPOINT": "https://gateway.example.com",
        "CF_DEPLOYMENT_OWNER": "production-primary",
        "CF_ROUTE": "gateway.example.com/*",
        field: value,
    }
    with pytest.raises(ValueError):
        manage.generated_config(environment)


def deployment_config(name="gateway", owner="production-primary"):
    return {
        "name": name,
        "vars": {manage.OWNER_BINDING: owner},
    }


class APIResponse:
    def __init__(self, document):
        self.raw = document if isinstance(document, bytes) else json.dumps(
            document).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, amount):
        assert amount == manage.API_RESPONSE_BYTES + 1
        return self.raw[:amount]


def api_document(owner="production-primary"):
    binding = [] if owner is None else [{
        "name": manage.OWNER_BINDING,
        "type": "plain_text",
        "text": owner,
    }]
    return {"success": True, "result": {"bindings": binding}}


def control_environment():
    return {
        "CLOUDFLARE_ACCOUNT_ID": "a" * 32,
        "CLOUDFLARE_API_TOKEN": "not-logged",
    }


def test_worker_ownership_lookup_uses_bounded_direct_api_response(
        monkeypatch):
    seen = []

    def open_api(request, timeout):
        seen.append((request, timeout))
        return APIResponse(api_document())

    monkeypatch.setattr(manage, "urlopen", open_api)

    owner = manage._worker_settings(
        deployment_config(),
        control_environment(),
    )

    assert owner == "production-primary"
    request, timeout = seen[0]
    assert request.full_url.endswith(
        "/accounts/" + "a" * 32 + "/workers/scripts/gateway/settings")
    assert request.get_header("Authorization") == "Bearer not-logged"
    assert timeout == 15


@pytest.mark.parametrize("response", (
    b"{",
    json.dumps({"success": False, "result": {}}).encode(),
    json.dumps({"success": True, "result": []}).encode(),
    b"x" * (manage.API_RESPONSE_BYTES + 1),
))
def test_worker_ownership_lookup_rejects_malformed_or_oversized_api(
        monkeypatch, response):
    monkeypatch.setattr(
        manage,
        "urlopen",
        lambda *_args, **_kwargs: APIResponse(response),
    )

    with pytest.raises(RuntimeError):
        manage._worker_settings(
            deployment_config(),
            control_environment(),
        )


def test_worker_ownership_lookup_distinguishes_absence(monkeypatch):
    def missing(request, timeout):
        raise HTTPError(request.full_url, 404, "missing", {}, None)

    monkeypatch.setattr(manage, "urlopen", missing)

    assert manage._worker_settings(
        deployment_config(),
        control_environment(),
    ) is manage._ABSENT


def test_deploy_and_remove_subprocesses_have_control_plane_deadlines(
        monkeypatch):
    calls = []
    monkeypatch.setattr(manage, "_write_config", lambda config: None)
    monkeypatch.setattr(
        manage,
        "_pywrangler",
        lambda *arguments, **options: calls.append((arguments, options)),
    )

    config = deployment_config()
    manage._deploy(config, {"secret": "value"})
    manage._delete(config)

    assert [options["timeout"] for _, options in calls] == [
        manage.CONTROL_TIMEOUT_SECONDS,
        manage.CONTROL_TIMEOUT_SECONDS,
    ]
    assert calls[0][0][0:2] == ("deploy", "--strict")


@pytest.mark.parametrize("observed", (None, "someone-else", manage._ABSENT))
def test_deploy_refuses_unowned_existing_or_implicit_creation(
        monkeypatch, observed):
    calls = []
    monkeypatch.setattr(manage, "_worker_settings", lambda config: observed)
    monkeypatch.setattr(
        manage,
        "_deploy",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError):
        manage._preflight_deploy(
            deployment_config(),
            allow_create=False,
        )
    assert calls == []


def test_deploy_allows_only_exact_owner_or_explicit_first_creation(
        monkeypatch):
    config = deployment_config()

    monkeypatch.setattr(
        manage,
        "_worker_settings",
        lambda candidate: "production-primary",
    )
    manage._preflight_deploy(config, allow_create=False)

    monkeypatch.setattr(
        manage,
        "_worker_settings",
        lambda candidate: manage._ABSENT,
    )
    manage._preflight_deploy(config, allow_create=True)


def test_deploy_verifies_exact_owner_after_wrangle_upload(monkeypatch):
    config = deployment_config()
    observed = iter(("production-primary", "production-primary"))
    calls = []
    monkeypatch.setattr(manage, "generated_config", lambda: config)
    monkeypatch.setattr(
        manage, "_secrets", lambda environment: {"secret": "value"})
    monkeypatch.setattr(
        manage,
        "_worker_settings",
        lambda candidate: next(observed),
    )
    monkeypatch.setattr(
        manage,
        "_deploy",
        lambda candidate, secret: calls.append((candidate, secret)),
    )

    manage.deploy()

    assert calls == [(config, {"secret": "value"})]


def test_deploy_reports_post_upload_owner_mismatch(monkeypatch):
    config = deployment_config()
    observed = iter(("production-primary", "someone-else"))
    uploads = []
    monkeypatch.setattr(manage, "generated_config", lambda: config)
    monkeypatch.setattr(
        manage, "_secrets", lambda environment: {"secret": "value"})
    monkeypatch.setattr(
        manage,
        "_worker_settings",
        lambda candidate: next(observed),
    )
    monkeypatch.setattr(
        manage,
        "_deploy",
        lambda candidate, secret: uploads.append(candidate),
    )

    with pytest.raises(RuntimeError, match="unowned Worker"):
        manage.deploy()
    assert uploads == [config]


@pytest.mark.parametrize("observed", (None, "someone-else", manage._ABSENT))
def test_remove_refuses_absent_or_unowned_worker(
        monkeypatch, observed):
    calls = []
    monkeypatch.setattr(manage, "_worker_settings", lambda config: observed)
    monkeypatch.setattr(
        manage,
        "_delete",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError):
        manage.remove(config=deployment_config())
    assert calls == []


def test_remove_deletes_only_the_exact_owned_worker(monkeypatch):
    config = deployment_config()
    calls = []
    monkeypatch.setattr(
        manage,
        "_worker_settings",
        lambda candidate: "production-primary",
    )
    monkeypatch.setattr(
        manage,
        "_delete",
        lambda candidate, **options: calls.append((candidate, options)),
    )

    manage.remove(force=True, config=config)

    assert calls == [(config, {"force": True})]


def smoke_environment(tmp_path, monkeypatch):
    mint = tmp_path / "mint.json"
    mint.write_bytes(b"{}")
    values = {
        "CF_LIVE_SMOKE": "1",
        "CF_SMOKE_MINT_FILE": str(mint),
        "CF_WORKSPACE": "a" * 64,
        "CF_R2_BUCKET": "production",
        "CF_R2_ENDPOINT": (
            "https://" + "b" * 32 + ".r2.cloudflarestorage.com"),
        "CF_PACK_PUT_ENDPOINT": "https://gateway.example.com",
        "CF_DEPLOYMENT_OWNER": "smoke-owner",
        "GRANT_SECRET": base64.b64encode(
            b"s" * manage.EDGE_SECRET_BYTES).decode(),
        "PACK_TICKET_SECRET": base64.b64encode(
            b"p" * manage.EDGE_SECRET_BYTES).decode(),
        "R2_ACCESS_KEY_ID": "smoke-access-key",
        "R2_SECRET_ACCESS_KEY": "smoke-secret-key",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_smoke_cleans_exact_unique_worker_after_possibly_applied_deploy(
        tmp_path, monkeypatch):
    smoke_environment(tmp_path, monkeypatch)
    applied, deleted = [], []
    monkeypatch.setattr(
        manage,
        "_worker_settings",
        lambda config: manage._ABSENT,
    )

    def fail_after_apply(config, secret, capture=False):
        applied.append(config)
        raise RuntimeError("deployment response was lost")

    monkeypatch.setattr(manage, "_deploy", fail_after_apply)
    monkeypatch.setattr(
        manage,
        "_delete",
        lambda config, **options: deleted.append((config, options)),
    )

    with pytest.raises(RuntimeError, match="response was lost"):
        manage.smoke()

    assert len(deleted) == 1
    config, options = deleted[0]
    assert config is applied[0]
    assert config["name"].startswith("poc16-smoke-")
    assert len(config["name"].removeprefix("poc16-smoke-")) == 32
    assert config["workers_dev"] is True
    assert config["routes"] == []
    assert options == {"force": True, "timeout": 60}


def test_smoke_does_not_delete_when_absence_preflight_fails(
        tmp_path, monkeypatch):
    smoke_environment(tmp_path, monkeypatch)
    deleted = []
    monkeypatch.setattr(
        manage,
        "_worker_settings",
        lambda config: (_ for _ in ()).throw(
            RuntimeError("ambiguous preflight")),
    )
    monkeypatch.setattr(
        manage,
        "_delete",
        lambda *args, **kwargs: deleted.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError, match="ambiguous preflight"):
        manage.smoke()
    assert deleted == []


def test_smoke_reports_primary_and_cleanup_failures(
        tmp_path, monkeypatch):
    smoke_environment(tmp_path, monkeypatch)
    monkeypatch.setattr(
        manage,
        "_worker_settings",
        lambda config: manage._ABSENT,
    )
    monkeypatch.setattr(
        manage,
        "_deploy",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("primary deploy failure")),
    )
    monkeypatch.setattr(
        manage,
        "_delete",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("cleanup failure")),
    )

    with pytest.raises(ExceptionGroup) as caught:
        manage.smoke()

    assert [str(error) for error in caught.value.exceptions] == [
        "primary deploy failure",
        "cleanup failure",
    ]
