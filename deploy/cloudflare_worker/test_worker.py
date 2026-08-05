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
from urllib.parse import parse_qs, urlsplit

import pytest

import facts

from core import limits, peer_capability
from core.access import AccessGate, LookupActive
from core.object_store import MAX_STORE_PREFIX_BYTES
from core.crypto import (
    h,
    keypair,
    load_sk,
    seal_to as native_seal,
    unseal as native_unseal,
)
from core.grants import make_token
from core.http import (
    encode_head_commit_request,
    encode_head_permit_request,
)
from core.pack_access import (
    MAX_PACK_BYTES,
    MAX_SCOPED_TTL_MS,
    ObjectOpen,
    PackOpen,
    ScopedRequest,
    decode_scoped_request,
    encode_object_open,
    encode_pack_open,
)
from core.removal_path import decode as decode_removal_path
from core.removal_tree import decode_root
from core.suppression import scoped_id, suppression_slot
from core.writer_head import (
    head_slot_key,
    writer_store_binding,
)
from core.writer_repository import WriterLog
from adapters.r2.worker import R2BindingStore
from full_peer.node import FullPeer
from deploy.cloudflare_worker import crypto_compat, manage, runtime
from deploy.python_role_modules import HOSTED_GATE_CORE_MODULES
from facts.auth.removal import removal
from facts.auth.signature import signature
from facts.content.message import message
from tests.test_access_gate import (
    access_proof,
    head_proof as current_head_proof,
    signed,
)
from tests.test_removal_state import world as removal_world

TEST_PACK_TTL_SECONDS = 30


class R2Object:
    def __init__(self, value, *, key="", etag=None):
        self.value = value
        self.size = len(value)
        self.key = key
        self.etag = etag or "opaque-" + h(value)
        self.body = Stream([value])

    async def arrayBuffer(self):
        return self.value


class Bucket:
    def __init__(self, data):
        self.data = dict(data)
        self.etags = {
            key: f"opaque-{index}"
            for index, key in enumerate(sorted(self.data), 1)
        }
        self.generation = len(self.etags)
        self.calls = []
        self.conditional_gets = 0

    def _etag(self, key):
        if key not in self.etags:
            self.generation += 1
            self.etags[key] = f"opaque-{self.generation}"
        return self.etags[key]

    async def get(self, key, options=None):
        self.calls.append(("get", key))
        value = self.data.get(key)
        condition = options.get("onlyIf") \
            if isinstance(options, dict) else None
        if value is not None and isinstance(condition, dict) \
                and condition.get("etagDoesNotMatch") == self._etag(key):
            self.conditional_gets += 1
            return SimpleNamespace(
                body=None,
                etag=self._etag(key),
                key=key,
                size=len(value),
            )
        return None if value is None else R2Object(
            value, key=key, etag=self._etag(key))

    async def head(self, key):
        self.calls.append(("head", key))
        return None if key not in self.data else R2Object(
            b"", key=key, etag=self._etag(key))

    async def put(self, key, value, **options):
        self.calls.append(("put", key))
        condition = options.get("onlyIf")
        if isinstance(condition, dict) \
                and condition.get("If-None-Match") == "*" \
                and key in self.data:
            return None
        if isinstance(condition, dict) and "etagMatches" in condition \
                and self.etags.get(key) != condition["etagMatches"]:
            return None
        value = bytes(value)
        self.generation += 1
        self.data[key] = value
        self.etags[key] = f"opaque-{self.generation}"
        return R2Object(
            b"", key=key, etag=self.etags[key])

    async def list(self, prefix, limit, cursor=None):
        self.calls.append(("list", prefix))
        keys = sorted(key for key in self.data if key.startswith(prefix))
        start = int(cursor or 0)
        stop = min(len(keys), start + limit)
        return SimpleNamespace(
            objects=[R2Object(
                b"", key=key, etag=self.etags[key])
                for key in keys[start:stop]],
            truncated=stop < len(keys),
            cursor=str(stop) if stop < len(keys) else None,
        )

    async def delete(self, *args, **kwargs):
        raise AssertionError("owner Worker attempted R2 delete")


class StaleRemovalOnceBucket(Bucket):
    """Return one real R2-shaped conditional-write conflict on demand."""

    def __init__(self, data):
        super().__init__(data)
        self.fail_removal_once = False

    async def put(self, key, value, **options):
        condition = options.get("onlyIf")
        if self.fail_removal_once and key.endswith("/removal") \
                and isinstance(condition, dict) \
                and "etagMatches" in condition:
            self.calls.append(("put", key))
            self.fail_removal_once = False
            return None
        return await super().put(key, value, **options)


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

    async def get(self, key):  # pragma: no cover - failure is the assertion
        raise AssertionError(
            f"direct capability route read R2 object body {key}")


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


def worker_environment(bucket, workspace, prefix):
    return SimpleNamespace(
        BUCKET=bucket,
        WORKSPACE=workspace,
        STORE_PREFIX=prefix,
        GRANT_SECRET=base64.b64encode(
            b"s" * runtime.EDGE_SECRET_BYTES).decode(),
        PERMIT_SECRET=base64.b64encode(
            b"m" * runtime.PERMIT_SECRET_BYTES).decode(),
        R2_ENDPOINT=(
            "https://" + "c" * 32 + ".r2.cloudflarestorage.com"),
        PACK_BUCKET="poc16-packs",
        PACK_PUT_ENDPOINT="https://worker.example",
        PACK_TTL_SECONDS=TEST_PACK_TTL_SECONDS,
        PACK_TICKET_SECRET=base64.b64encode(
            b"p" * runtime.PACK_TICKET_SECRET_BYTES).decode(),
        R2_ACCESS_KEY_ID="worker-access-key",
        R2_SECRET_ACCESS_KEY="worker-secret-key",
        **runtime._BUDGETS,
    )


def worker_world(tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    now = 100
    root = node.fact_of(workspace, workspace)
    secret, member = node.identity(workspace)
    gate = AccessGate(workspace, node.store(workspace))
    assert run(gate.state.bootstrap(
        signed(secret, member, root, (root,)))).status in {"applied", "noop"}
    basis = run(gate.state.pin()).root_oid
    pile = access_proof(secret, member, root, basis=basis)
    prefix = f"workspaces/{workspace}"
    store = node.store(workspace)
    bucket = Bucket({
        f"{prefix}/{key}": store.get(key)
        for key in store.list("")
    })
    environment = worker_environment(bucket, workspace, prefix)
    monkeypatch.setattr(runtime, "now_ms", lambda: now)
    return node, workspace, pile, bucket, environment


def proof_body(workspace, pile):
    return json.dumps({
        "pile": base64.b64encode(pile).decode(),
        "ws": workspace,
    }).encode()


def test_runtime_permit_commits_one_terminal_self_removal_head():
    value = removal_world()
    prefix = f"workspaces/{value.root.fid}"
    bucket = StaleRemovalOnceBucket({})
    environment = worker_environment(bucket, value.root.fid, prefix)
    bootstrap = signed(
        value.founder_secret,
        value.founder,
        value.root,
        (value.root,),
    )
    published = run(runtime.handle(Request(
        "POST",
        f"https://worker.example/removal/bootstrap?ws={value.root.fid}",
        bootstrap,
    ), environment, clock=lambda: 10))
    assert published.status == 201
    path = h(bucket.data[f"{prefix}/removal"])

    current = access_proof(
        value.founder_secret, value.founder,
        value.root, basis=path)
    minted = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={value.root.fid}",
        proof_body(value.root.fid, current),
    ), environment, clock=lambda: 10))
    assert minted.status == 200
    token = native_unseal(
        value.founder_secret,
        base64.b64decode(json.loads(minted.body)["grant"]),
    ).decode()
    headers = {"Authorization": "Bearer " + token}
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/authority?ws={value.root.fid}",
        bootstrap,
        headers,
    ), environment, clock=lambda: 10)).status == 404

    evicted = removal(
        value.root.fid, value.founder, value.founder, 8)
    evicted_sig = signature(
        value.founder_secret, value.founder, evicted, 8)
    control = signed(
        value.founder_secret,
        value.founder,
        value.root,
        (value.root, evicted_sig, evicted),
    )
    writer = WriterLog(
        value.root.fid,
        value.founder,
        value.founder,
        writer_store_binding(value.root.fid, value.founder),
        value.founder_secret,
        R2BindingStore(bucket, prefix),
    )
    update = run(writer.prepare(((
        value.root, evicted_sig, evicted),
    )))
    run(writer.establish(update))
    proposed = update.head_oid
    proof = current_head_proof(
        value.founder_secret, value.founder,
        value.root, (value.root,), path, proposed)
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{h(b'wrong')}?ws={value.root.fid}",
        proof,
    ), environment, clock=lambda: 10)).status == 403

    private_node = decode_root(
        bucket.data[f"{prefix}/removal"], value.root.fid).root
    assert run(runtime.handle(Request(
        "GET",
        f"https://worker.example/obj/{private_node}?ws={value.root.fid}",
        headers={"Authorization": "Bearer " + token},
    ), environment, clock=lambda: 10)).status == 404

    other = h(b"other member")
    forged = access_proof(
        value.founder_secret, value.founder, value.root,
        basis=path, owner=other)
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/mint?ws={value.root.fid}",
        proof_body(value.root.fid, forged),
    ), environment, clock=lambda: 10)).status == 403

    ordinary = message(
        value.root.fid, value.founder,
        "general", "not removal control", 9)
    ordinary_sig = signature(
        value.founder_secret, value.founder, ordinary, 9)
    ordinary_pile = signed(
        value.founder_secret,
        value.founder,
        value.root,
        (value.root, ordinary_sig, ordinary),
    )

    removal_key = f"{prefix}/removal"
    removal_before = bucket.data[removal_key]
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/removal/apply?ws={value.root.fid}",
        control, headers,
    ), environment, clock=lambda: 10)).status == 404
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{proposed}/permit?ws="
        f"{value.root.fid}",
        b"not a control-head frame",
    ), environment, clock=lambda: 10)).status == 403
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{proposed}/permit?ws="
        f"{value.root.fid}",
        encode_head_permit_request(proof, (ordinary_pile,)),
    ), environment, clock=lambda: 10)).status == 403
    assert bucket.data[removal_key] == removal_before

    bucket.calls.clear()
    permit_response = run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{proposed}/permit?ws="
        f"{value.root.fid}",
        encode_head_permit_request(proof, (control,)),
    ), environment, clock=lambda: 10))
    assert permit_response.status == 200
    permit = permit_response.body
    assert encode_head_commit_request(permit) == permit
    slot_key = f"{prefix}/heads/{value.root.fid}/{value.founder}"
    assert slot_key not in bucket.data

    tampered = bytearray(permit)
    tampered[len(tampered) // 2] ^= 1
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{proposed}/commit?ws="
        f"{value.root.fid}",
        encode_head_commit_request(bytes(tampered)),
    ), environment, clock=lambda: 10)).status == 403
    assert bucket.data[removal_key] == removal_before

    # Grant rotation cannot invalidate a non-expiring exact control permit;
    # changing the separate permit verifier key does fail closed.
    environment.GRANT_SECRET = base64.b64encode(
        b"g" * runtime.EDGE_SECRET_BYTES).decode()
    wrong_permit_environment = SimpleNamespace(**{
        **vars(environment),
        "PERMIT_SECRET": base64.b64encode(
            b"w" * runtime.PERMIT_SECRET_BYTES).decode(),
    })
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{proposed}/commit?ws="
        f"{value.root.fid}",
        permit,
    ), wrong_permit_environment, clock=lambda: 10)).status == 403
    assert bucket.data[removal_key] == removal_before
    assert slot_key not in bucket.data

    bucket.fail_removal_once = True
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{proposed}/commit?ws="
        f"{value.root.fid}",
        encode_head_commit_request(permit),
    ), environment, clock=lambda: 10)).status == 201
    assert bucket.data[removal_key] != removal_before
    accepted_slot = bucket.data[slot_key]
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{proposed}/commit?ws="
        f"{value.root.fid}",
        encode_head_commit_request(permit),
    ), environment, clock=lambda: 10)).status == 204
    assert bucket.data[slot_key] == accepted_slot
    assert not any(operation == "list" for operation, _key in bucket.calls)
    update_keys = {
        f"{prefix}/obj/{oid}" for oid, _raw in update.objects}
    assert all(
        key == removal_key
        or key.startswith(f"{prefix}/removal-node/")
        or key == slot_key
        or key in update_keys
        for _operation, key in bucket.calls)
    assert not any("cursor" in key for key in bucket.data)

    rejected_head = h(b"cloudflare head after member removal")
    bucket.data[f"{prefix}/obj/{rejected_head}"] = (
        b"cloudflare head after member removal")
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{rejected_head}?ws={value.root.fid}",
        current_head_proof(
            value.founder_secret, value.founder,
            value.root, (value.root,), path, rejected_head),
    ), environment, clock=lambda: 10)).status == 403
    assert bucket.data[slot_key] == accepted_slot
    assert run(runtime.handle(Request(
        "POST",
        f"https://worker.example/head/{rejected_head}/permit?ws="
        f"{value.root.fid}",
        encode_head_permit_request(current_head_proof(
            value.founder_secret, value.founder,
            value.root, (value.root,), path, rejected_head), (control,)),
    ), environment, clock=lambda: 10)).status == 403
    stale = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={value.root.fid}",
        proof_body(value.root.fid, current),
    ), environment, clock=lambda: 10))
    assert stale.status == 403
    rejected = json.loads(stale.body)
    assert rejected["error"] == "removed"
    assert rejected["tip"] == h(bucket.data[f"{prefix}/removal"])
    assert base64.b64decode(rejected["path"], validate=True)


def test_runtime_mints_and_reads_the_writer_directory_from_r2(
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
    assert value["cap"] == "sync-v1/owner"
    token = native_unseal(
        node.identity(workspace)[0],
        base64.b64decode(value["grant"]),
    ).decode()
    heads = run(runtime.handle(Request(
        "GET", f"https://worker.example/heads?ws={workspace}",
        headers={"Authorization": "Bearer " + token},
    ), environment))
    assert heads.status == 200
    directory = json.loads(heads.body)
    assert len(directory["heads"]) == 1
    assert directory["heads"][0][0].endswith(
        "/" + node.identity_id(workspace))
    assert heads.headers["Cache-Control"] == "no-store"
    assert heads.headers["X-Content-Type-Options"] == "nosniff"
    assert {call[0] for call in bucket.calls} <= {"get", "list"}


def test_worker_and_full_peer_make_identical_lookup_gate_decisions(
        tmp_path, monkeypatch):
    """The two runtimes differ only at the private-store adapter boundary."""
    node, workspace, clear_proof, bucket, environment = worker_world(
        tmp_path, monkeypatch)
    secret, member = node.identity(workspace)
    root = node.fact_of(workspace, workspace)
    peer_gate = node.access_gate(workspace)

    peer_clear = run(peer_gate.authorize_access(clear_proof, 100))
    worker_clear = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        proof_body(workspace, clear_proof),
    ), environment))
    assert worker_clear.status == 200
    assert json.loads(worker_clear.body)["tip"] == peer_clear[2]

    _other_secret, other = keypair()
    unknown_proof = access_proof(
        secret, member, root, basis=peer_clear[2], owner=other)
    assert run(peer_gate.authorize_access(unknown_proof, 100)) is None
    worker_unknown = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        proof_body(workspace, unknown_proof),
    ), environment))
    assert (worker_unknown.status, worker_unknown.body) == (403, b"")

    active = ((
        scoped_id("member", member),
        suppression_slot(h(b"cross-runtime removal")),
    ),)
    assert run(peer_gate.state.tree.apply(active)).status == "applied"
    worker_state = AccessGate(
        workspace,
        R2BindingStore(bucket, f"workspaces/{workspace}"),
    )
    assert run(worker_state.state.tree.apply(active)).status == "applied"

    with pytest.raises(LookupActive) as peer_active:
        run(peer_gate.authorize_access(clear_proof, 100))
    worker_active = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        proof_body(workspace, clear_proof),
    ), environment))
    assert worker_active.status == 403
    body = json.loads(worker_active.body)
    worker_path = decode_removal_path(base64.b64decode(
        body["path"], validate=True))
    peer_path = decode_removal_path(peer_active.value.path)
    assert body["tip"] == worker_path.root == peer_active.value.tip
    assert tuple(sid for sid, _proof in worker_path.proofs) == tuple(
        sid for sid, _proof in peer_path.proofs)


def test_worker_warm_lookup_uses_one_conditional_root_get_without_body(
        tmp_path, monkeypatch):
    _node, workspace, proof, bucket, environment = worker_world(
        tmp_path, monkeypatch)
    def mint_request():
        return Request(
            "POST", f"https://worker.example/mint?ws={workspace}",
            proof_body(workspace, proof),
        )

    first = run(runtime.handle(mint_request(), environment))
    before = len(bucket.calls)
    second = run(runtime.handle(mint_request(), environment))
    warm_calls = bucket.calls[before:]

    assert first.status == second.status == 200
    assert bucket.conditional_gets == 1
    removal_key = f"workspaces/{workspace}/removal"
    assert warm_calls.count(("get", removal_key)) == 1


def test_deployed_entry_issues_direct_object_and_pack_requests(
        tmp_path, monkeypatch):
    _, workspace, _, bucket, environment = worker_world(
        tmp_path, monkeypatch)
    pack_bucket = PackBucket(bucket.data)
    environment.BUCKET = pack_bucket
    service = deployed_entry(monkeypatch, environment)
    # This is exactly the capability advertised by this hosted gateway: it
    # may establish immutable owner objects but cannot invoke /mirror gossip.
    assert runtime.gateway(runtime.Settings.from_env(
        environment)).sync_profile == peer_capability.OWNER
    member = h(b"pack reader")
    token = make_token(
        b"s" * runtime.EDGE_SECRET_BYTES,
        member,
        workspace,
        capability=peer_capability.OWNER,
        issued_at=100,
        ttl_ms=runtime.MAX_GRANT_TTL_MS,
    )
    headers = {"Authorization": "Bearer " + token}
    object_oid = h(b"virtual maximum ordinary object")
    opened_object = ObjectOpen(
        "GET", object_oid, limits.MAX_DIRECT_OBJECT_BYTES)
    assert opened_object.object_bytes > runtime.MAX_OBJECT_BYTES
    unauthorized = run(service.fetch(Request(
        "POST",
        f"https://worker.example/obj/open?ws={workspace}",
        encode_object_open(opened_object),
    )))
    object_response = run(service.fetch(Request(
        "POST",
        f"https://worker.example/obj/open?ws={workspace}",
        encode_object_open(opened_object),
        headers,
    )))

    assert unauthorized.status == 401
    assert object_response.status == 200
    object_request = decode_scoped_request(object_response.body)
    assert object_request.method == "GET" and object_request.headers == ()
    assert urlsplit(object_request.url).path == (
        f"/poc16-packs/{environment.STORE_PREFIX}/obj/{object_oid}")
    assert parse_qs(urlsplit(object_request.url).query)[
        "X-Amz-SignedHeaders"] == ["host"]
    assert object_request.expires_at_ms \
        == TEST_PACK_TTL_SECONDS * 1000
    assert pack_bucket.calls == []

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

    opened_put = run(service.fetch(Request(
        "POST",
        f"https://worker.example/pack/open?ws={workspace}",
        encode_pack_open(put),
        headers,
    )))
    assert opened_put.status == 200

    whole_request, range_request = issued
    assert whole_request.method == "GET" and whole_request.headers == ()
    assert range_request.method == "GET"
    assert range_request.headers == (("range", "bytes=17-47"),)
    assert urlsplit(whole_request.url).path == (
        f"/poc16-packs/{environment.STORE_PREFIX}/pack/{oid}")
    assert urlsplit(range_request.url).path == urlsplit(
        whole_request.url).path
    put_request = decode_scoped_request(opened_put.body)
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

    object_put = ObjectOpen(
        "PUT", object_oid, limits.MAX_DIRECT_OBJECT_BYTES)
    opened_object_put = run(service.fetch(Request(
        "POST",
        f"https://worker.example/obj/open?ws={workspace}",
        encode_object_open(object_put),
        headers,
    )))
    assert opened_object_put.status == 200
    object_request = decode_scoped_request(opened_object_put.body)
    object_body = SentinelPackBody()
    direct_object = Request(
        "PUT",
        object_request.url,
        headers=dict(object_request.headers),
        stream=object_body,
    )
    object_stored = run(service.fetch(direct_object))

    assert object_stored.status == 201
    assert direct_object.body is object_body \
        and direct_object.bytes_calls == 0
    assert pack_bucket.pack_puts[-1] == (
        f"{environment.STORE_PREFIX}/obj/{object_oid}",
        object_body,
        {"onlyIf": {"If-None-Match": "*"}, "sha256": object_oid},
    )


def test_deployed_entry_confines_a_widened_object_issuer(
        tmp_path, monkeypatch):
    _, workspace, _, bucket, environment = worker_world(
        tmp_path, monkeypatch)
    pack_bucket = PackBucket(bucket.data)
    environment.BUCKET = pack_bucket
    opened = ObjectOpen(
        "GET", h(b"confined object"), limits.MAX_DIRECT_OBJECT_BYTES)
    token = make_token(
        b"s" * runtime.EDGE_SECRET_BYTES,
        h(b"object reader"),
        workspace,
        capability=peer_capability.READ_ONLY,
        issued_at=100,
        ttl_ms=runtime.MAX_GRANT_TTL_MS,
    )

    class WidenedIssuer:
        def __init__(self, *args, **kwargs):
            pass

        def open_pack(self, member, request, trusted_now):
            raise AssertionError("pack issuer unexpectedly called")

        def open_object(self, member, request, trusted_now):
            return ScopedRequest(
                "GET",
                "https://example.com/obj/" + h(b"wrong object"),
                (),
                trusted_now + TEST_PACK_TTL_SECONDS * 1000,
            )

    monkeypatch.setattr(runtime, "R2PackIssuer", WidenedIssuer)
    service = deployed_entry(monkeypatch, environment)
    response = run(service.fetch(Request(
        "POST",
        f"https://worker.example/obj/open?ws={workspace}",
        encode_object_open(opened),
        {"Authorization": "Bearer " + token},
    )))

    assert response.status == 503
    assert pack_bucket.calls == []


@pytest.mark.parametrize(("name", "value"), (
    ("PERMIT_SECRET", "not-base64"),
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
        "GET", "https://worker.example/heads?ws=wrong"), environment))
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


def test_runtime_keeps_grant_and_permit_secrets_stable_and_distinct(
        tmp_path, monkeypatch):
    _, _, _, bucket, environment = worker_world(tmp_path, monkeypatch)

    first = runtime.Settings.from_env(environment)
    second = runtime.Settings.from_env(environment)
    assert first.grant_secret == second.grant_secret \
        == b"s" * runtime.EDGE_SECRET_BYTES
    assert first.permit_secret == second.permit_secret \
        == b"m" * runtime.PERMIT_SECRET_BYTES
    assert first.grant_secret != first.permit_secret

    rotated_grant = SimpleNamespace(**{
        **vars(environment),
        "GRANT_SECRET": base64.b64encode(
            b"g" * runtime.EDGE_SECRET_BYTES).decode(),
    })
    assert runtime.Settings.from_env(rotated_grant).permit_secret \
        == first.permit_secret

    reused = SimpleNamespace(**{
        **vars(environment),
        "PERMIT_SECRET": environment.GRANT_SECRET,
    })
    with pytest.raises(ValueError, match="must differ"):
        runtime.Settings.from_env(reused)


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
        "GET", f"https://worker.example/obj/{oid}?ws={workspace}",
        headers=headers,
    ), environment))
    missing = run(runtime.handle(Request(
        "GET", f"https://worker.example/obj/{'0' * 64}?ws={workspace}",
        headers=headers,
    ), environment))
    bucket.data[f"{prefix}/obj/{oid}"] = b"corrupt"
    corrupt = run(runtime.handle(Request(
        "GET", f"https://worker.example/obj/{oid}?ws={workspace}",
        headers=headers,
    ), environment))
    retired = run(runtime.handle(Request(
        "PUT", f"https://worker.example/pile/member/id?ws={workspace}",
        headers=headers,
    ), environment))

    assert found.status == 200 and found.body == raw
    assert missing.status == 404
    assert corrupt.status == 503
    assert retired.status == 404


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
        def __init__(self, healthy_removal=None):
            self.healthy_removal = healthy_removal
            self.objects = []

        async def get(self, key):
            if self.healthy_removal is not None \
                    and key.endswith("/removal"):
                return R2Object(self.healthy_removal)
            limit = limits.MAX_ROOT_BYTES \
                if key.endswith("/removal") \
                else runtime.MAX_OBJECT_BYTES
            obj = OversizedObject(limit + 1)
            self.objects.append(obj)
            return obj

    oversized = OversizedBucket()
    environment.BUCKET = oversized
    oid = "0" * 64
    results = [
        run(runtime.handle(Request(
            "GET", f"https://worker.example/invite/code?ws={workspace}",
        ), environment)),
        run(runtime.handle(Request(
            "GET", f"https://worker.example/obj/{oid}?ws={workspace}",
            headers=headers,
        ), environment)),
        run(runtime.handle(Request(
            "POST", f"https://worker.example/obj?ws={workspace}",
            json.dumps([oid]).encode(), headers,
        ), environment)),
    ]

    assert [result.status for result in results] == [413, 413, 413]
    assert len(oversized.objects) == len(results)
    assert all(obj.array_calls == 0 for obj in oversized.objects)

    oversized_root = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        mint_body,
    ), environment))
    assert oversized_root.status == 503
    assert len(oversized.objects) == len(results) + 1
    assert all(obj.array_calls == 0 for obj in oversized.objects)

    prefix = environment.STORE_PREFIX
    selective = OversizedBucket(healthy.data[f"{prefix}/removal"])
    environment.BUCKET = selective
    self_contained = run(runtime.handle(Request(
        "POST", f"https://worker.example/mint?ws={workspace}",
        mint_body,
    ), environment))

    assert self_contained.status == 200
    assert selective.objects == []


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


def test_runtime_applies_route_specific_exact_body_limits(
        tmp_path, monkeypatch):
    _, workspace, _, _, environment = worker_world(tmp_path, monkeypatch)
    environment.MAX_REQUEST_BYTES = 3
    environment.MAX_CONTROL_BYTES = 5
    calls = []

    class Probe:
        async def handle(self, *request):
            calls.append(request)
            return runtime.Response(200)

    monkeypatch.setattr(runtime, "gateway", lambda *_args, **_kwargs: Probe())
    permit = (
        f"https://worker.example/head/{'b' * 64}/permit?ws={workspace}")
    commit = (
        f"https://worker.example/head/{'b' * 64}/commit?ws={workspace}")
    mint_url = f"https://worker.example/mint?ws={workspace}"

    assert run(runtime.handle(Request(
        "POST", permit, b"12345"), environment)).status == 200
    assert calls[-1][-1] == b"12345"
    assert run(runtime.handle(Request(
        "POST", permit, b"123456"), environment)).status == 413
    assert run(runtime.handle(Request(
        "POST", commit, b"123"), environment)).status == 200
    assert calls[-1][-1] == b"123"
    assert run(runtime.handle(Request(
        "POST", commit, b"1234"), environment)).status == 413
    assert run(runtime.handle(Request(
        "POST", mint_url, b"123"), environment)).status == 200
    assert run(runtime.handle(Request(
        "POST", mint_url, b"1234"), environment)).status == 413
    assert len(calls) == 3


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
        "GET", f"https://worker.example/heads?{exact_query}"), environment))
    over = run(runtime.handle(Request(
        "GET", f"https://worker.example/heads?{exact_query}a"), environment))
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
        "GET", f"https://worker.example/heads?{query}"), environment))

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
    assert (staged / "core" / "access.py").read_bytes() == (
        manage.REPOSITORY / "core" / "access.py").read_bytes()
    assert (staged / "core" / "removal_state.py").read_bytes() == (
        manage.REPOSITORY / "core" / "removal_state.py").read_bytes()
    assert {
        path.name for path in (staged / "core").glob("*.py")
    } == set(HOSTED_GATE_CORE_MODULES)
    assert (staged / "facts" / "auth" / "request.py").read_bytes() == (
        manage.REPOSITORY / "facts" / "auth" / "request.py").read_bytes()
    assert (staged / "adapters" / "r2" / "worker.py").read_bytes() == (
        manage.REPOSITORY / "adapters" / "r2" / "worker.py").read_bytes()
    assert (staged / "adapters" / "r2" / "reader.py").read_bytes() == (
        manage.REPOSITORY / "adapters" / "r2" / "reader.py").read_bytes()
    assert (staged / "adapters" / "r2" / "listing.py").read_bytes() == (
        manage.REPOSITORY / "adapters" / "r2" / "listing.py").read_bytes()
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
    assert not (staged / "core" / "authority.py").exists()
    assert not (staged / "core" / "repository_applier.py").exists()
    assert not (staged / "core" / "repository_reader.py").exists()
    assert not (staged / "adapters" / "r2" / "s3.py").exists()
    assert not (staged / "adapters" / "s3").exists()
    assert not (staged / "deploy" / "aws_lambda").exists()
    assert not (staged / "full_peer").exists()
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from deploy.cloudflare_pack.issuer import R2PackIssuer; "
            "from deploy.cloudflare_pack.put import R2ImmutablePut; "
            "from runtime import Settings; "
            "assert callable(R2PackIssuer.open_object); "
            "assert callable(R2ImmutablePut.handle); "
            "assert Settings.__name__ == 'Settings'",
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
        "PERMIT_SECRET": base64.b64encode(
            b"m" * manage.PERMIT_SECRET_BYTES).decode(),
        "PACK_TICKET_SECRET": base64.b64encode(
            b"p" * manage.PACK_TICKET_SECRET_BYTES).decode(),
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
    same_key = dict(
        environment, PERMIT_SECRET=environment["GRANT_SECRET"])
    with pytest.raises(ValueError, match="must differ"):
        manage._secrets(same_key)


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
    assert runtime.PERMIT_SECRET_BYTES == manage.PERMIT_SECRET_BYTES
    assert runtime.PACK_TICKET_SECRET_BYTES \
        == manage.PACK_TICKET_SECRET_BYTES
    assert {
        name: config["vars"][name]
        for name in runtime._BUDGETS
    } == runtime._BUDGETS
    assert runtime.MAX_REQUEST_BYTES <= limits.MAX_MINT_REQUEST_BYTES
    assert runtime.MAX_CONTROL_BYTES \
        == runtime.MAX_HEAD_CONTROL_REQUEST_BYTES
    # Bao slice payloads are inline ordinary facts. Authenticated repository
    # reads apply their narrower page/fact bound at the gate call site rather
    # than shrinking this shared object-response ceiling.
    assert runtime.MAX_OBJECT_BYTES == limits.MAX_OBJECT_BYTES \
        == limits.MAX_REPOSITORY_OBJECT_BYTES == limits.MAX_FACT_BYTES
    assert limits.MAX_DIRECT_OBJECT_BYTES == limits.MAX_WRITER_PACK_BYTES \
        > limits.MAX_SEMANTIC_PILE_BYTES > runtime.MAX_OBJECT_BYTES
    assert runtime.MAX_BATCH_COUNT <= limits.PAGE_BATCH
    assert runtime.MAX_BATCH_BYTES == limits.MAX_PAGE_BATCH_BYTES
    assert config["limits"]["subrequests"] \
        == limits.CLOUDFLARE_SUBREQUEST_LIMIT == 10_000
    assert limits.MAX_HEAD_COMMIT_SUBREQUESTS \
        <= config["limits"]["subrequests"]


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
        "PERMIT_SECRET": base64.b64encode(
            b"m" * manage.PERMIT_SECRET_BYTES).decode(),
        "PACK_TICKET_SECRET": base64.b64encode(
            b"p" * manage.PACK_TICKET_SECRET_BYTES).decode(),
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
