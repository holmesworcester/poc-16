"""Cloudflare Worker boundary, package, and deployment-command tests."""
import asyncio
import base64
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core import cmds, limits
from core.close import encode_pile
from core.crypto import (
    h,
    load_sk,
    seal_to as native_seal,
    unseal as native_unseal,
)
from core.node import Node
from deploy.cloudflare_worker import crypto_compat, manage, runtime
from facts.auth import request as request_fact


class R2Object:
    def __init__(self, value):
        self.value = value

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
        self.body = stream
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


def run(awaitable):
    return asyncio.run(awaitable)


def worker_world(tmp_path, monkeypatch):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    now = 100
    pile = encode_pile(request_fact.payload(
        node, workspace, "sync", now + 60_000, now))
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
        GRANT_SECRET=base64.b64encode(b"s" * 32).decode(),
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
    "adapters.s3", "adapters.r2.s3"
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
    assert (staged / "core" / "mint.py").read_bytes() == (
        manage.REPOSITORY / "core" / "mint.py").read_bytes()
    assert (staged / "facts" / "auth" / "request.py").read_bytes() == (
        manage.REPOSITORY / "facts" / "auth" / "request.py").read_bytes()
    assert (staged / "adapters" / "r2" / "worker.py").read_bytes() == (
        manage.REPOSITORY / "adapters" / "r2" / "worker.py").read_bytes()
    assert not (staged / "core" / "store.py").exists()
    assert not (staged / "core" / "node.py").exists()
    assert not (staged / "adapters" / "r2" / "s3.py").exists()
    assert not (staged / "adapters" / "s3").exists()
    patched = sodium.read_bytes()
    assert b"__start_em_asm" not in patched
    assert b"__start_em_xsm" in patched
    assert "sodium_init()" not in bindings.read_text()


def test_generated_config_is_single_workspace_least_privilege():
    environment = {
        "CF_WORKSPACE": "a" * 64,
        "CF_R2_BUCKET": "production",
        "CF_R2_PREVIEW_BUCKET": "preview",
        "CF_WORKER_NAME": "gateway",
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
    assert config["secrets"]["required"] == ["GRANT_SECRET"]
    assert "GRANT_SECRET" not in config["vars"]


def test_worker_budget_bindings_match_runtime_and_core_ceilings():
    config = json.loads(manage.TEMPLATE.read_text())

    assert {
        name: config["vars"][name]
        for name in runtime._BUDGETS
    } == runtime._BUDGETS
    assert runtime.MAX_REQUEST_BYTES <= limits.MAX_MINT_REQUEST_BYTES
    assert runtime.MAX_ROOT_BYTES <= limits.MAX_ROOT_BYTES
    assert runtime.MAX_OBJECT_BYTES <= min(
        limits.MAX_OBJECT_BYTES, limits.MAX_PAGE_BATCH_BYTES)
    assert runtime.MAX_BATCH_COUNT <= limits.PAGE_BATCH
    assert runtime.MAX_BATCH_BYTES <= limits.MAX_PAGE_BATCH_BYTES
    assert runtime.MAX_MINT_FETCHES <= limits.MAX_MINT_FETCHES
    assert runtime.MAX_MINT_FETCH_BYTES <= limits.MAX_MINT_FETCH_BYTES
    assert runtime.MAX_OBJECT_BYTES == runtime.MAX_BATCH_BYTES \
        == 4 * 1024 * 1024


@pytest.mark.parametrize("field,value", [
    ("CF_WORKSPACE", "not-a-workspace"),
    ("CF_R2_BUCKET", ""),
    ("CF_ROUTE", ""),
    ("CF_STORE_PREFIX", "../escape"),
])
def test_generated_config_rejects_ambiguous_deployment_input(field, value):
    environment = {
        "CF_WORKSPACE": "a" * 64,
        "CF_R2_BUCKET": "production",
        "CF_ROUTE": "gateway.example.com/*",
        field: value,
    }
    with pytest.raises(ValueError):
        manage.generated_config(environment)
