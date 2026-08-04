"""AWS Function URL packaging around the real database-free gateway."""
import asyncio
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
from urllib.parse import urlencode

import facts
import pytest

from adapters.s3 import S3Config
from core import peer_capability
from core.access import AccessGate
from core.crypto import h, unseal
from core.grants import check_token
from core.limits import MAX_MINT_REQUEST_BYTES, PAGE_BATCH
from full_peer.node import FullPeer
from deploy.aws_lambda import app
from deploy.aws_lambda.config import (
    BUCKET_PATTERN,
    DEPLOYMENT_ID_TAG,
    DEPLOYMENT_MARKER,
    DEPLOYMENT_TAG,
    FUNCTION_TIMEOUT_SECONDS,
    MAX_LOG_METHOD_CHARS,
    MAX_LOG_PATH_CHARS,
    MAX_LOG_RECORD_BYTES,
    MAX_QUERY_BYTES,
    MAX_QUERY_FIELDS,
    MAX_READINESS_RESPONSE_BYTES,
    MAX_STORE_PREFIX_LENGTH,
    PREFIX_PATTERN,
    SDK_CLEANUP_MARGIN_SECONDS,
    SDK_CONNECT_TIMEOUT_SECONDS,
    SDK_READ_TIMEOUT_SECONDS,
    SDK_TOTAL_ATTEMPTS,
    validate_sdk_budget,
)
from deploy.aws_lambda.s3_bucket_policy import policy
from core.http import AsyncFromSyncReader, HttpGate, Response
from core.object_store import (
    MAX_INVITE_ID_BYTES,
    MAX_LOGICAL_KEY_BYTES,
    MAX_PROVIDER_KEY_BYTES,
)
from deploy.python_role_modules import HOSTED_GATE_CORE_MODULES
from core.suppression_tree import decode_root
from core.writer_repository import OpaqueHeadGate
from facts.auth.removal import removal
from facts.auth.removal_path_request import removal_path_request
from facts.auth.signature import signature
from core.store import FsStore
from tests.test_access_gate import (
    access_proof,
    head_proof as current_head_proof,
    path_proof,
    signed,
)
from tests.test_removal_state import accept_one, world as removal_world

ROOT = Path(__file__).resolve().parents[1]
LAMBDA = ROOT / "deploy" / "aws_lambda"


def run(awaitable):
    return asyncio.run(awaitable)


def event(
        method, path, workspace=None, body=None, headers=None, *,
        raw_query=None, base64_body=True):
    encoded = None
    if body is not None:
        encoded = base64.b64encode(body).decode() \
            if base64_body else body.decode()
    return {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": raw_query if raw_query is not None else (
            urlencode({"ws": workspace}) if workspace is not None else ""),
        "headers": headers or {},
        "requestContext": {"http": {"method": method}},
        "body": encoded,
        "isBase64Encoded": body is not None and base64_body,
    }


def response(result):
    return result["statusCode"], result["headers"], base64.b64decode(
        result["body"])


def load_manage(name="lambda_manage"):
    spec = importlib.util.spec_from_file_location(
        name, LAMBDA / "manage.py")
    manage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manage)
    return manage


def deployment_args(**changes):
    values = {
        "alarm_action_arn": None,
        "bucket": "test-bucket",
        "create": True,
        "deployment_id": "edge-west-2",
        "expected_owner": None,
        "kms_key_arn": None,
        "prefix": "tenant",
        "profile": None,
        "region": "us-west-2",
        "stack": "poc16-edge",
        "update": False,
        "workspace": "a" * 64,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def world(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    now = 100
    root = node.fact_of(workspace, workspace)
    secret, member = node.identity(workspace)
    gate = AccessGate(workspace, node.store(workspace))
    assert run(gate.state.bootstrap(
        signed(secret, member, root, (root,)))).status in {"applied", "noop"}
    path = run(gate.removal_path(
        path_proof(secret, member, root, (root,)), now))
    pile = access_proof(secret, member, root, (root,), path)
    app._gateway_cache = local_gateway(node, workspace, now)
    return node, workspace, now, pile


def local_gateway(node, workspace, now):
    store = AsyncFromSyncReader(node.store(workspace))
    gate = AccessGate(workspace, store)

    return HttpGate(
        store,
        workspace,
        b"s" * 32,
        lambda: now,
        head_advance=OpaqueHeadGate(store, gate.authorize_head).advance,
        mint_authorize=gate.authorize_access,
        path_authorize=gate.removal_path,
        removal_bootstrap=gate.state.bootstrap,
        removal_advance=gate.state.advance_leaf,
        sync_profile=peer_capability.OWNER,
    )


def proof_body(workspace, pile):
    return json.dumps({
        "ws": workspace,
        "pile": base64.b64encode(pile).decode(),
    }).encode()


def mint(node, workspace, pile):
    status, _, raw = response(app.handler(
        event("POST", "/mint", workspace, proof_body(workspace, pile)), None))
    body = json.loads(raw)
    token = unseal(
        node.identity(workspace)[0],
        base64.b64decode(body["grant"])).decode()
    return status, body, token


def test_lambda_runs_confined_removal_gate_then_advances_one_owner_head(
        tmp_path, monkeypatch):
    value = removal_world()
    store = FsStore(str(tmp_path / "repository"))
    config = S3Config("test-bucket", "tenant")
    monkeypatch.setattr(app, "_s3_config", lambda: config)
    monkeypatch.setattr(
        app, "_store", lambda _config: AsyncFromSyncReader(store))
    monkeypatch.setattr(
        app, "_pack_issuer", lambda _config: SimpleNamespace(
            open_pack=lambda *_args: None,
            open_object=lambda *_args: None,
        ))
    monkeypatch.setattr(app, "_secret", lambda: b"s" * 32)
    monkeypatch.setattr(app.time, "time", lambda: 0.010)
    monkeypatch.setenv("TINYP2P_WORKSPACE_ID", value.root.fid)
    app._gateway_cache = None

    bootstrap = signed(
        value.member_secret,
        value.member,
        value.root,
        value.membership,
    )
    assert response(app.handler(event(
        "POST", "/removal/bootstrap",
        value.root.fid, bootstrap), None))[0] == 201

    historical = path_proof(
        value.member_secret, value.member,
        value.root, value.membership)
    status, _, path = response(app.handler(event(
        "POST", "/removal/path", value.root.fid,
        proof_body(value.root.fid, historical)), None))
    assert status == 200

    current = access_proof(
        value.member_secret, value.member,
        value.root, value.membership, path)
    status, _, raw_mint = response(app.handler(event(
        "POST", "/mint", value.root.fid,
        proof_body(value.root.fid, current)), None))
    assert status == 200
    token = unseal(
        value.member_secret,
        base64.b64decode(json.loads(raw_mint)["grant"]),
    ).decode()
    assert response(app.handler(event(
        "POST", "/authority", value.root.fid, bootstrap,
        headers={"Authorization": "Bearer " + token}), None))[0] == 404

    proposed = h(b"lambda opaque writer head")
    store.put_if_absent(
        "obj/" + proposed, b"lambda opaque writer head")
    proof = current_head_proof(
        value.member_secret, value.member,
        value.root, value.membership, path, proposed)
    assert response(app.handler(event(
        "POST", "/head/" + proposed,
        value.root.fid, proof), None))[0] == 201
    assert store.get(
        f"heads/{value.root.fid}/{value.member}") is not None
    assert response(app.handler(event(
        "POST", "/head/" + h(b"wrong"),
        value.root.fid, proof), None))[0] == 403

    private_node = decode_root(
        store.get("removal"), value.root.fid).root
    assert response(app.handler(event(
        "GET", "/obj/" + private_node, value.root.fid,
        headers={"Authorization": "Bearer " + token}), None))[0] == 404

    other = h(b"other member")
    relabeled = removal_path_request(
        value.root.fid, value.member, other, 1_000, 7)
    relabeled_sig = signature(
        value.member_secret, value.member, relabeled, 7)
    forged = signed(
        value.member_secret,
        value.member,
        value.root,
        (*value.membership, relabeled_sig, relabeled),
    )
    assert response(app.handler(event(
        "POST", "/removal/path", value.root.fid,
        proof_body(value.root.fid, forged)), None))[0] == 403

    evicted = removal(
        value.root.fid, value.founder, value.member, 8)
    evicted_sig = signature(
        value.founder_secret, value.founder, evicted, 8)
    run(accept_one(
        store,
        value.founder_secret,
        value.founder,
        value.founder,
        value.root,
        (*value.membership, evicted_sig, evicted),
    ))
    assert response(app.handler(event(
        "POST", f"/removal/advance/{value.founder}/1",
        value.root.fid), None))[0] == 201
    stale = response(app.handler(event(
        "POST", "/mint", value.root.fid,
        proof_body(value.root.fid, current)), None))
    assert stale[0] == 409
    assert json.loads(stale[2]) == {"error": "proof_refresh_required"}
    refreshed = response(app.handler(event(
        "POST", "/removal/path", value.root.fid,
        proof_body(value.root.fid, historical)), None))
    assert refreshed[0] == 200
    denied = access_proof(
        value.member_secret, value.member,
        value.root, value.membership, refreshed[2])
    assert response(app.handler(event(
        "POST", "/mint", value.root.fid,
        proof_body(value.root.fid, denied)), None))[0] == 403


def test_lambda_mints_and_serves_writer_directory_objects(tmp_path):
    node, workspace, now, pile = world(tmp_path)
    status, body, token = mint(node, workspace, pile)

    assert status == 200
    assert body["cap"] == "sync-v1/owner"
    assert check_token(
        b"s" * 32, "Bearer " + token, workspace,
        trusted_now=now) == node.identity_id(workspace)
    assert check_token(
        b"s" * 32, "Bearer " + token, workspace,
        trusted_now=now, require_push=True) is None
    assert check_token(
        b"s" * 32, "Bearer " + token, workspace,
        trusted_now=now, require_object_put=True) \
        == node.identity_id(workspace)

    headers = {"authorization": "Bearer " + token}
    status, root_headers, raw_heads = response(app.handler(
        event("GET", "/heads", workspace, headers=headers), None))
    assert status == 200
    heads = json.loads(raw_heads)
    assert len(heads["heads"]) == 1
    assert heads["heads"][0][0].startswith(
        f"heads/{workspace}/")
    assert root_headers["Cache-Control"] == "no-store"

    raw = b"served through the function URL"
    node.store(workspace).put_if_absent("obj/" + h(raw), raw)
    status, _, fetched = response(app.handler(
        event("GET", "/obj/" + h(raw), workspace, headers=headers), None))
    assert (status, fetched) == (200, raw)

    # Immutable creation is issued through /obj/open; the buffered mutation
    # route is deliberately absent even when a grant is read-only.
    assert response(app.handler(
        event("PUT", "/obj/" + h(b"x"), workspace, b"x",
              headers=headers), None))[0] == 404


def test_lambda_rejects_a_request_pile_from_another_workspace(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    first = facts.auth.workspace.create(node, "first", ts=1)
    second = facts.auth.workspace.create(node, "second", ts=2)
    now = 100
    root = node.fact_of(first, first)
    secret, member = node.identity(first)
    first_gate = AccessGate(first, node.store(first))
    assert run(first_gate.state.bootstrap(
        signed(secret, member, root, (root,)))).status in {
            "applied", "noop"}
    path = run(first_gate.removal_path(
        path_proof(secret, member, root, (root,)), now))
    pile = access_proof(secret, member, root, (root,), path)
    app._gateway_cache = local_gateway(node, second, now)
    request_body = json.dumps({
        "ws": second,
        "pile": base64.b64encode(pile).decode(),
    }).encode()

    status, _, _ = response(app.handler(
        event("POST", "/mint", second, request_body), None))
    assert status == 403


def test_lambda_denies_bad_proofs_and_malformed_function_events(tmp_path):
    _, workspace, _, _ = world(tmp_path)
    denied = json.dumps({
        "ws": workspace,
        "pile": base64.b64encode(b"not a pile").decode(),
    }).encode()

    assert response(app.handler(
        event("POST", "/mint", workspace, denied), None))[0] == 403
    assert response(app.handler(
        {"version": "1.0"}, None))[0] == 400

    oversized = event(
        "POST", "/mint", workspace,
        b"x" * (MAX_MINT_REQUEST_BYTES + 1))
    assert response(app.handler(oversized, None))[0] == 413


def test_lambda_bounds_query_bytes_and_fields_before_parsing(tmp_path):
    _, workspace, _, _ = world(tmp_path)

    byte_over = event(
        "GET", "/heads", raw_query="x" * (MAX_QUERY_BYTES + 1))
    assert response(app.handler(byte_over, None))[0] == 413

    fields_over = event(
        "GET", "/heads",
        raw_query="&".join(
            [f"ws={workspace}"]
            + [f"k{index}=v" for index in range(MAX_QUERY_FIELDS)]))
    assert response(app.handler(fields_over, None))[0] == 413

    plain = event(
        "POST", "/mint", workspace, b"not-json",
        base64_body=False)
    assert response(app.handler(plain, None))[0] == 400


def test_lambda_rejects_malformed_query_encoding_before_gateway_io(
        tmp_path):
    _, workspace, _, _ = world(tmp_path)
    calls = []

    class Probe:
        async def handle(self, *request):
            calls.append(request)
            return Response(200)

    app._gateway_cache = Probe()
    for malformed in ("%", "%2", "%GG", "%FF"):
        request_event = event(
            "GET", "/heads",
            raw_query=f"ws={workspace}&bad={malformed}")
        assert response(app.handler(request_event, None))[0] == 400
    assert calls == []

    valid = event(
        "GET", "/heads",
        raw_query=f"ws={workspace}&ok=%E2%9C%93")
    assert response(app.handler(valid, None))[0] == 200
    assert calls[0][2]["ok"] == ["✓"]


def test_lambda_logs_handled_5xx_without_request_secrets(
        tmp_path, caplog):
    _, workspace, _, _ = world(tmp_path)

    class Failure:
        async def handle(self, *_request):
            return Response(503)

    app._gateway_cache = Failure()
    request_event = event(
        "GET", "/obj/" + "0" * 64, workspace,
        headers={"authorization": "Bearer top-secret-token"})
    context = SimpleNamespace(aws_request_id="request-123")

    with caplog.at_level("ERROR", logger=app.__name__):
        result = app.handler(request_event, context)

    assert response(result)[0] == 503
    record = json.loads(caplog.records[-1].message)
    assert record == {
        "error_type": None,
        "event": "poc16_gateway_failure",
        "kind": "gateway_response",
        "method": "GET",
        "path": "/obj/" + "0" * 64,
        "request_id": "request-123",
        "status": 503,
    }
    assert "top-secret-token" not in caplog.text
    assert workspace not in caplog.text


def test_lambda_failure_telemetry_has_exact_attacker_field_bounds(caplog):
    exact_method = "M" * MAX_LOG_METHOD_CHARS
    exact_path = "/" + "p" * (MAX_LOG_PATH_CHARS - 1)
    over_method = exact_method + "OVER"
    over_path = exact_path + "OVER"

    with caplog.at_level("ERROR", logger=app.__name__):
        app._log_failure(
            "gateway_response",
            request=(exact_method, exact_path),
            status=503)
        app._log_failure(
            "gateway_response",
            request=(over_method, over_path),
            status=503)

    exact, over = (
        json.loads(record.message) for record in caplog.records[-2:])
    assert exact["method"] == exact_method
    assert exact["path"] == exact_path
    assert over["method"] == exact_method
    assert over["path"] == exact_path
    assert all(
        len(record.message.encode()) <= MAX_LOG_RECORD_BYTES
        for record in caplog.records[-2:])


def test_lambda_cold_sandboxes_load_one_stable_external_secret(
        tmp_path, monkeypatch):
    node, workspace, _, _ = world(tmp_path)
    calls = []
    config = S3Config(
        "test-bucket", "tenant", region_name="us-west-2")

    class Secrets:
        def get_secret_value(self, **request):
            calls.append(request)
            return {"SecretString": "z" * 64}

    class Boto:
        @staticmethod
        def client(name, **options):
            assert name == "secretsmanager"
            assert options == {"config": "bounded-botocore"}
            return Secrets()

    monkeypatch.setitem(sys.modules, "boto3", Boto)
    monkeypatch.setattr(
        app, "_botocore_config", lambda: "bounded-botocore")
    monkeypatch.setattr(app, "_s3_config", lambda: config)
    monkeypatch.setattr(
        app, "_store",
        lambda value: AsyncFromSyncReader(node.store(workspace)))
    monkeypatch.setattr(
        app, "_pack_issuer",
        lambda value: SimpleNamespace(
            open_pack=lambda *_args: None,
            open_object=lambda *_args: None,
        ))
    monkeypatch.setenv("TINYP2P_WORKSPACE_ID", workspace)
    monkeypatch.setenv("TINYP2P_GRANT_SECRET_ARN", "stable-secret")
    app._gateway_cache = None

    first = app._gateway()
    second = app._gateway()

    assert first is second
    assert first.secret == b"z" * 64
    assert calls == [{"SecretId": "stable-secret"}]


def test_lambda_sdk_deadline_budget_precedes_hard_timeout(monkeypatch):
    connect, read, attempts = validate_sdk_budget()
    assert attempts == 1
    assert connect + read <= (
        FUNCTION_TIMEOUT_SECONDS - SDK_CLEANUP_MARGIN_SECONDS)

    monkeypatch.setenv("TINYP2P_AWS_TOTAL_ATTEMPTS", "2")
    with pytest.raises(RuntimeError, match="deadline budget"):
        app._sdk_budget()


def test_lambda_store_uses_the_validated_one_attempt_deadline(
        monkeypatch):
    captured = []

    class Store:
        def __init__(self, config):
            captured.append(config)

    monkeypatch.setattr(app, "S3Store", Store)
    monkeypatch.setenv("TINYP2P_S3_BUCKET", "test-bucket")
    monkeypatch.setenv("TINYP2P_S3_PREFIX", "tenant")
    monkeypatch.delenv("TINYP2P_AWS_TOTAL_ATTEMPTS", raising=False)
    wrapped = app._store()

    assert isinstance(wrapped.reader, Store)
    assert len(captured) == 1
    assert captured[0].connect_timeout == SDK_CONNECT_TIMEOUT_SECONDS
    assert captured[0].read_timeout == SDK_READ_TIMEOUT_SECONDS
    assert captured[0].read_total_max_attempts == SDK_TOTAL_ATTEMPTS
    assert captured[0].probe_access_denied_missing is True


def test_lambda_stage_is_an_explicit_importable_allowlist(tmp_path):
    manage = load_manage()
    staged = manage.stage(tmp_path / "stage")

    assert (staged / "core" / "access.py").is_file()
    assert (staged / "core" / "removal_state.py").is_file()
    assert {
        path.name for path in (staged / "core").glob("*.py")
    } == set(HOSTED_GATE_CORE_MODULES)
    assert (staged / "facts" / "auth" / "request.py").is_file()
    assert (staged / "adapters" / "s3" / "store.py").is_file()
    assert (staged / "deploy" / "aws_lambda" / "app.py").is_file()
    assert (staged / "deploy" / "aws_lambda" / "config.py").is_file()
    assert (staged / "deploy" / "aws_lambda" / "pack_issuer.py").is_file()
    assert (staged / "deploy" / "aws_lambda" / "sdk_smoke.py").is_file()
    assert (
        staged / "deploy" / "aws_lambda" / "s3_bucket_policy.py").is_file()
    assert not (staged / "deploy" / "upload_broker.py").exists()
    assert not (staged / "deploy" / "aws_upload_broker").exists()
    for forbidden in (
            "authority.py",
            "catalog.py",
            "client_projection.py",
            "mint.py",
            "node.py",
            "pile_sender.py",
            "repository_applier.py",
            "repository_reader.py",
            "store.py",
            "suppression_state.py"):
        assert not (staged / "core" / forbidden).exists()
    assert not (staged / "adapters" / "host.py").exists()
    assert not (staged / "adapters" / "r2").exists()
    assert not (staged / "tests").exists()
    assert not (staged / "native").exists()
    assert not (staged / "README.md").exists()
    subprocess.run(
        [
            sys.executable, "-c",
            "import deploy.aws_lambda.app; print('lambda-import-ok')",
        ],
        cwd=staged,
        env={**os.environ, "PYTHONPATH": str(staged)},
        check=True,
        capture_output=True,
        text=True,
    )


def test_lambda_template_bounds_direct_immutable_writes_to_obj_and_pack():
    template = (LAMBDA / "template.yaml").read_text()
    requirements = (LAMBDA / "requirements.txt").read_text()

    assert "Runtime: python3.13" in template
    assert "Architectures: [x86_64]" in template
    assert "ReservedConcurrentExecutions:" in template
    assert "AuthType: NONE" in template
    assert "CodeUri: stage/" in template
    assert "secretsmanager:GetSecretValue" in template
    assert "s3:GetObject" in template
    assert template.count("Action: s3:PutObject") == 4
    assert "s3:DeleteObject" not in template
    assert "Action: s3:ListBucket" in template
    assert "s3:prefix:" in template
    assert '${StorePrefix}/authority' not in template
    assert '${StorePrefix}/removal' in template
    assert '${StorePrefix}/removal-node/*' in template
    assert '${StorePrefix}/heads/${WorkspaceId}/*' in template
    assert '${StorePrefix}/root' not in template
    assert '${StorePrefix}/obj/*' in template
    assert '${StorePrefix}/invite/*' in template
    assert template.count('${Prefix}/obj/*') == 2
    assert template.count('${Prefix}/removal"') == 2
    assert template.count('${Prefix}/removal-node/*') == 2
    assert template.count('${Prefix}/pack/*') == 2
    assert "s3:authType: REST-QUERY-STRING" in template
    assert "s3:signatureversion: AWS4-HMAC-SHA256" in template
    assert 's3:if-none-match: "false"' in template
    assert "s3:signatureAge: 60000" in template
    assert 'TINYP2P_PACK_TTL_SECONDS: "60"' in template
    assert "TINYP2P_MINT_MAX_FETCH" not in template
    assert "MetricName: Url5xxCount" in template
    assert "MetricName: Errors" not in template
    assert "AlarmActions: !If" in template
    assert "Action: kms:Decrypt" in template
    assert "Resource: !Ref KmsKeyArn" in template
    assert "Action: kms:*" not in template
    assert f"Value: {DEPLOYMENT_MARKER}" in template
    assert "Value: !Ref DeploymentId" in template
    assert f"Timeout: {FUNCTION_TIMEOUT_SECONDS}" in template
    assert (
        f'TINYP2P_AWS_CONNECT_TIMEOUT_SECONDS: '
        f'"{SDK_CONNECT_TIMEOUT_SECONDS}"') in template
    assert (
        f'TINYP2P_AWS_READ_TIMEOUT_SECONDS: '
        f'"{SDK_READ_TIMEOUT_SECONDS}"') in template
    assert (
        f'TINYP2P_AWS_TOTAL_ATTEMPTS: '
        f'"{SDK_TOTAL_ATTEMPTS}"') in template
    assert f"AllowedPattern: '{BUCKET_PATTERN}'" in template
    assert f"AllowedPattern: '{PREFIX_PATTERN}'" in template
    assert f"MaxLength: {MAX_STORE_PREFIX_LENGTH}" in template

    assert "--require-hashes" in requirements
    assert "--only-binary=:all:" in requirements
    for package in (
            "boto3==1.43.51", "botocore==1.43.51", "cffi==2.1.0",
            "jmespath==1.1.0", "pycparser==3.0", "PyNaCl==1.6.2",
            "python-dateutil==2.9.0.post0", "s3transfer==0.19.2",
            "six==1.17.0", "urllib3==2.7.0"):
        assert package in requirements
    assert requirements.count("--hash=sha256:") == 10


def test_cloudformation_bucket_and_prefix_constraints_refine_s3_config():
    bucket_re, prefix_re = re.compile(BUCKET_PATTERN), re.compile(
        PREFIX_PATTERN)
    for bucket in (
            "abc", "workspace-bucket", "a.b-c",
            "0" * 62 + "a"):
        assert bucket_re.fullmatch(bucket)
        S3Config(bucket=bucket, prefix="tenant")
    for bucket in (
            "xn--bucket", "sthree-bucket", "192.168.1.1",
            "bad..bucket", "directory--x-s3", "alias-s3alias"):
        assert not bucket_re.fullmatch(bucket)
        with pytest.raises(ValueError):
            S3Config(bucket=bucket, prefix="tenant")

    for prefix in (
            "tenant", "tenant/workspace",
            "a" * MAX_STORE_PREFIX_LENGTH):
        assert len(prefix) <= MAX_STORE_PREFIX_LENGTH
        assert prefix_re.fullmatch(prefix)
        S3Config(bucket="test-bucket", prefix=prefix)
    for prefix in (
            "/tenant", "tenant/", "tenant//workspace",
            "tenant/../workspace"):
        assert not prefix_re.fullmatch(prefix)
        with pytest.raises(ValueError):
            S3Config(bucket="test-bucket", prefix=prefix)

    # The longest public key is invite/<256 bytes>; this is exactly the
    # provider's physical-key ceiling at the accepted prefix maximum.
    assert MAX_LOGICAL_KEY_BYTES \
        == len("invite/") + MAX_INVITE_ID_BYTES
    assert MAX_STORE_PREFIX_LENGTH + 1 + MAX_LOGICAL_KEY_BYTES \
        == MAX_PROVIDER_KEY_BYTES


def test_list_permission_is_limited_to_gateway_read_namespaces():
    template = (LAMBDA / "template.yaml").read_text()
    parameter = template.split("HeadPageKeys:", 1)[1].split(
        "KmsKeyArn:", 1)[0]
    block = template.split(
        "- Sid: DistinguishMissingWorkspaceKeys", 1)[1].split(
        "- Sid: ReadPrivateRemovalState", 1)[0]

    assert f"Default: {PAGE_BATCH}" in parameter
    assert f"AllowedValues: [{PAGE_BATCH}]" in parameter
    assert "Action: s3:ListBucket" in block
    assert '"arn:${AWS::Partition}:s3:::${BucketName}"' in block
    assert block.count("!Sub") == 6
    assert '${StorePrefix}/authority' not in block
    assert '${StorePrefix}/removal' in block
    assert '${StorePrefix}/removal-node/*' in block
    assert '${StorePrefix}/heads/${WorkspaceId}/*' in block
    assert '${StorePrefix}/obj/*' in block
    assert '${StorePrefix}/invite/*' in block
    assert '${StorePrefix}/*' not in block
    assert "s3:max-keys: !Ref HeadPageKeys" in block


def test_lambda_private_removal_permissions_are_internal_and_conditional():
    template = (LAMBDA / "template.yaml").read_text()
    private_reads = template.split(
        "- Sid: ReadPrivateRemovalState", 1)[1].split(
        "- Sid: ReadWriterHeads", 1)[0]
    ordinary_reads = template.split(
        "- Sid: ReadImmutableObjects", 1)[1].split(
        "- Sid: ReadImmutablePacksByScopedRequest", 1)[0]
    private_writes = template.split(
        "- Sid: CreatePrivateRemovalNodes", 1)[1].split(
        "- Sid: CreateImmutablePacksByScopedRequest", 1)[0]
    mutable_writes = template.split(
        "- Sid: AdvanceRemovalAndOwnerHeads", 1)[1].split(
        "- Sid: ReadGrantSecret", 1)[0]
    public_pack_grants = "\n".join((
        template.split(
            "- Sid: ReadImmutablePacksByScopedRequest", 1)[1].split(
            "- Sid: CreateImmutableObjects", 1)[0],
        template.split(
            "- Sid: CreateImmutablePacksByScopedRequest", 1)[1].split(
            "- Sid: AdvanceRemovalAndOwnerHeads", 1)[0],
    ))

    assert private_reads.count('${Prefix}/removal"') == 1
    assert private_reads.count('${Prefix}/removal-node/*') == 1
    assert "removal" not in ordinary_reads
    assert private_writes.count('${Prefix}/removal-node/*') == 1
    assert 's3:if-none-match: "false"' in private_writes
    assert mutable_writes.count('${Prefix}/removal"') == 1
    assert '${Prefix}/removal-node/*' not in mutable_writes
    assert "s3:if-match" not in private_writes
    assert "removal" not in public_pack_grants


def test_gateway_bucket_guard_denies_deletes_and_unconditional_writes():
    document = policy(
        "workspace-bucket", "tenant", profile="bucket-wide")
    statements = {
        statement["Sid"]: statement
        for statement in document["Statement"]
    }

    deletion = statements["DenyAuthoritativeDeletion"]
    assert set(deletion["Action"]) == {
        "s3:DeleteObject", "s3:DeleteObjectVersion"}
    authoritative_resources = [
        "arn:aws:s3:::workspace-bucket/tenant/removal",
        "arn:aws:s3:::workspace-bucket/tenant/heads/*",
        "arn:aws:s3:::workspace-bucket/tenant/obj/*",
        "arn:aws:s3:::workspace-bucket/tenant/removal-node/*",
    ]
    assert deletion["Resource"] == authoritative_resources
    metadata = statements["DenyAuthoritativeMetadataMutation"]
    assert set(metadata["Action"]) == {
        "s3:DeleteObjectAnnotation",
        "s3:DeleteObjectTagging",
        "s3:DeleteObjectVersionTagging",
        "s3:PutObjectAcl",
        "s3:PutObjectVersionAcl",
        "s3:PutObjectAnnotation",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging",
        "s3:UpdateObjectEncryption",
    }
    assert metadata["Resource"] == authoritative_resources
    assert all(
        statement["Principal"] == "*"
        for statement in document["Statement"])
    assert statements["RequireImmutableObjectCreate"]["Condition"] == {
        "Null": {"s3:if-none-match": "true"}}
    assert statements["RequireImmutableObjectCreate"]["Resource"] == [
        "arn:aws:s3:::workspace-bucket/tenant/obj/*",
        "arn:aws:s3:::workspace-bucket/tenant/pack/*",
        "arn:aws:s3:::workspace-bucket/tenant/removal-node/*",
    ]
    assert statements["RequireMutableCompareAndSwap"]["Condition"] == {
        "Null": {
            "s3:if-match": "true",
            "s3:if-none-match": "true",
        }}
    assert statements["RequireMutableCompareAndSwap"]["Resource"] == [
        "arn:aws:s3:::workspace-bucket/tenant/removal",
        "arn:aws:s3:::workspace-bucket/tenant/heads/*",
    ]
    assert statements["DenyLifecycleMutation"]["Action"] \
        == "s3:PutLifecycleConfiguration"
    guarded_actions = {
        action
        for statement in document["Statement"]
        for action in (
            [statement["Action"]]
            if isinstance(statement["Action"], str)
            else statement["Action"])
    }
    trusted_replication_actions = {
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ReplicateTags",
        "s3:ReplicateObjectAnnotation",
        "s3:ObjectOwnerOverrideToBucketOwner",
    }
    assert guarded_actions.isdisjoint(trusted_replication_actions)


def test_single_gateway_policy_names_its_residual_trust_boundary():
    principal = "arn:aws:iam::123456789012:role/poc16-gateway"
    document = policy(
        "workspace-bucket", "tenant", principal,
        profile="single-gateway")

    assert all(
        statement["Principal"] == {"AWS": principal}
        for statement in document["Statement"])
    with pytest.raises(ValueError, match="does not accept one gateway"):
        policy(
            "workspace-bucket", "tenant", principal,
            profile="bucket-wide")
    with pytest.raises(ValueError, match="principal"):
        policy(
            "workspace-bucket", "tenant",
            profile="single-gateway")


def test_deploy_validates_inputs_and_requires_readiness(monkeypatch):
    manage = load_manage("lambda_manage_deploy")
    calls = []
    monkeypatch.setattr(
        manage, "build", lambda _args: calls.append("build"))
    monkeypatch.setattr(
        manage, "_deploy_stack",
        lambda _args: calls.append("deploy"))
    monkeypatch.setattr(
        manage, "_stack_url",
        lambda _args: "https://gateway.lambda-url.example")
    monkeypatch.setattr(
        manage, "_readiness",
        lambda url: calls.append(("ready", url)))

    manage.deploy(deployment_args())
    assert calls == [
        "build", "deploy",
        ("ready", "https://gateway.lambda-url.example"),
    ]

    calls.clear()
    with pytest.raises(ValueError, match="bucket"):
        manage.deploy(deployment_args(bucket="directory--x-s3"))
    assert calls == []
    with pytest.raises(ValueError, match="prefix"):
        manage.deploy(deployment_args(
            prefix="a" * (MAX_STORE_PREFIX_LENGTH + 1)))
    assert calls == []


def test_deploy_passes_exact_kms_alarm_and_ownership_inputs(monkeypatch):
    manage = load_manage("lambda_manage_parameters")
    calls = []
    monkeypatch.setattr(
        manage, "_run", lambda command: calls.append(command))
    monkeypatch.setattr(
        manage, "_stack_for_deploy", lambda _args: _args.stack)
    kms = "arn:aws:kms:us-west-2:123456789012:key/key-id"
    alarm = "arn:aws:sns:us-west-2:123456789012:poc16-alerts"

    manage._deploy_stack(deployment_args(
        expected_owner="123456789012",
        kms_key_arn=kms,
        alarm_action_arn=alarm))

    command = calls[0]
    assert f"ExpectedBucketOwner=123456789012" in command
    assert f"KmsKeyArn={kms}" in command
    assert f"AlarmActionArn={alarm}" in command
    assert "--tags" in command
    assert f"{DEPLOYMENT_TAG}={DEPLOYMENT_MARKER}" in command
    assert f"{DEPLOYMENT_ID_TAG}=edge-west-2" in command
    assert "DeploymentId=edge-west-2" in command


def test_remove_requires_same_account_region_tag_and_output(
        monkeypatch):
    manage = load_manage("lambda_manage_remove")
    args = deployment_args()

    def stack(**changes):
        value = {
            "StackName": args.stack,
            "StackId": (
                "arn:aws:cloudformation:us-west-2:123456789012:"
                f"stack/{args.stack}/opaque"),
            "StackStatus": "UPDATE_COMPLETE",
            "Tags": [{
                "Key": DEPLOYMENT_TAG,
                "Value": DEPLOYMENT_MARKER,
            }, {
                "Key": DEPLOYMENT_ID_TAG,
                "Value": args.deployment_id,
            }],
            "Outputs": [
                {
                    "OutputKey": "DeploymentMarker",
                    "OutputValue": DEPLOYMENT_MARKER,
                },
                {
                    "OutputKey": "DeploymentId",
                    "OutputValue": args.deployment_id,
                },
            ],
        }
        value.update(changes)
        return value

    selected = [stack()]
    commands = []
    monkeypatch.setattr(
        manage, "_describe_stack", lambda _args: selected[0])
    monkeypatch.setattr(
        manage, "_caller_account", lambda _args: "123456789012")
    monkeypatch.setattr(
        manage, "_run", lambda command: commands.append(command))

    manage.remove(args)
    assert commands == [[
        "sam", "delete", "--stack-name", selected[0]["StackId"],
        "--no-prompts",
        "--region", "us-west-2",
    ]]

    commands.clear()
    wrong_id_tag = stack()
    wrong_id_tag["Tags"][1]["Value"] = "another-deployment"
    wrong_id_output = stack()
    wrong_id_output["Outputs"][1]["OutputValue"] = "another-deployment"
    bad_stacks = [
        stack(Tags=[]),
        stack(Outputs=[]),
        wrong_id_tag,
        wrong_id_output,
        stack(StackName="unrelated"),
        stack(StackStatus="DELETE_IN_PROGRESS"),
        stack(StackId=(
            "arn:aws:cloudformation:eu-west-1:123456789012:"
            f"stack/{args.stack}/opaque")),
        stack(StackId=(
            "arn:aws:cloudformation:us-west-2:999999999999:"
            f"stack/{args.stack}/opaque")),
    ]
    for candidate in bad_stacks:
        selected[0] = candidate
        with pytest.raises(RuntimeError):
            manage.remove(args)
    assert commands == []


def test_deploy_mode_refuses_collisions_and_targets_owned_stack_id(
        monkeypatch):
    manage = load_manage("lambda_manage_deploy_identity")
    args = deployment_args()
    stack_id = (
        "arn:aws:cloudformation:us-west-2:123456789012:"
        f"stack/{args.stack}/opaque")
    owned = {
        "StackName": args.stack,
        "StackId": stack_id,
        "StackStatus": "UPDATE_COMPLETE",
        "Tags": [{
            "Key": DEPLOYMENT_TAG,
            "Value": DEPLOYMENT_MARKER,
        }, {
            "Key": DEPLOYMENT_ID_TAG,
            "Value": args.deployment_id,
        }],
        "Outputs": [
            {
                "OutputKey": "DeploymentMarker",
                "OutputValue": DEPLOYMENT_MARKER,
            },
            {
                "OutputKey": "DeploymentId",
                "OutputValue": args.deployment_id,
            },
        ],
    }
    selected = [None]
    monkeypatch.setattr(
        manage, "_stack_or_none", lambda _args: selected[0])
    monkeypatch.setattr(
        manage, "_caller_account", lambda _args: "123456789012")

    assert manage._stack_for_deploy(args) == args.stack
    selected[0] = owned
    with pytest.raises(RuntimeError, match="absent"):
        manage._stack_for_deploy(args)

    args.create, args.update = False, True
    assert manage._stack_for_deploy(args) == stack_id
    args.deployment_id = "another-deployment"
    with pytest.raises(RuntimeError, match="deployment ID"):
        manage._stack_for_deploy(args)
    args.deployment_id = "edge-west-2"
    selected[0] = None
    with pytest.raises(RuntimeError, match="existing"):
        manage._stack_for_deploy(args)

    args.create = args.update = False
    with pytest.raises(ValueError, match="exactly one"):
        manage._stack_for_deploy(args)


def test_generated_remove_treats_true_absence_as_safe(monkeypatch):
    manage = load_manage("lambda_manage_absent_cleanup")
    args = deployment_args(generated_smoke=True)
    commands = []
    monkeypatch.setattr(
        manage, "_stack_or_none", lambda _args: None)
    monkeypatch.setattr(
        manage, "_run", lambda command: commands.append(command))

    assert manage.remove(args) is False
    assert commands == []


def test_stack_absence_classification_never_hides_access_errors(
        monkeypatch):
    manage = load_manage("lambda_manage_absence")
    args = deployment_args()
    errors = [
        subprocess.CalledProcessError(
            255, ["aws"], stderr=(
                "An error occurred (ValidationError): Stack with id "
                "poc16-edge does not exist")),
        subprocess.CalledProcessError(
            255, ["aws"], stderr=(
                "An error occurred (AccessDenied): denied")),
    ]

    def fail(_command):
        raise errors.pop(0)

    monkeypatch.setattr(manage, "_json_command", fail)
    with pytest.raises(manage.StackAbsent):
        manage._describe_stack(args)
    with pytest.raises(subprocess.CalledProcessError):
        manage._describe_stack(args)


def test_live_smoke_never_cleans_a_collision_and_preserves_dual_failures(
        tmp_path, monkeypatch):
    manage = load_manage("lambda_manage_live_outcomes")
    args = deployment_args(state=str(tmp_path))
    calls = []
    monkeypatch.setattr(manage, "build", lambda _args: calls.append("build"))

    def collision(_args):
        raise RuntimeError("stack collision")

    monkeypatch.setattr(manage, "_stack_for_deploy", collision)
    monkeypatch.setattr(
        manage, "remove",
        lambda _args: calls.append("unexpected cleanup"))
    with pytest.raises(RuntimeError, match="stack collision"):
        manage.live_smoke(args)
    assert calls == ["build"]

    calls.clear()
    monkeypatch.setattr(
        manage, "_stack_for_deploy", lambda deploy_args: deploy_args.stack)

    def possibly_applied(_args, _target):
        calls.append("deploy attempted")
        raise RuntimeError("deploy response lost")

    def cleanup_failed(_args):
        calls.append("cleanup attempted")
        raise RuntimeError("cleanup failed")

    monkeypatch.setattr(manage, "_deploy_stack", possibly_applied)
    monkeypatch.setattr(manage, "remove", cleanup_failed)
    with pytest.raises(ExceptionGroup) as caught:
        manage.live_smoke(args)

    assert calls == [
        "build", "deploy attempted", "cleanup attempted"]
    assert [str(error) for error in caught.value.exceptions] == [
        "deploy response lost", "cleanup failed"]


def test_management_subprocesses_have_distinct_finite_deadlines(
        monkeypatch):
    manage = load_manage("lambda_manage_timeouts")
    calls = []

    def run(command, **options):
        calls.append((command, options))
        return SimpleNamespace(stdout="{}")

    monkeypatch.setattr(manage.subprocess, "run", run)
    manage._run(["sam", "build"])
    assert manage._json_command(["aws", "sts", "get-caller-identity"]) == {}

    assert calls[0][1]["timeout"] == manage.MUTATION_TIMEOUT_SECONDS
    assert calls[1][1]["timeout"] == manage.METADATA_TIMEOUT_SECONDS
    assert 0 < calls[1][1]["timeout"] < calls[0][1]["timeout"]

    def timeout(command, **_options):
        raise subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(manage.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        manage._run(["sam", "deploy"])


def test_package_smoke_executes_sam_artifact_in_lambda_runtime(
        tmp_path, monkeypatch):
    manage = load_manage("lambda_manage_package")
    artifact = tmp_path / "GatewayFunction"
    artifact.mkdir()
    calls = []
    monkeypatch.setattr(manage, "ARTIFACT", artifact)
    monkeypatch.setattr(
        manage, "build", lambda _args: calls.append("build"))
    monkeypatch.setattr(
        manage, "_run", lambda command: calls.append(command))

    manage.package_smoke(SimpleNamespace())

    assert calls[0] == "build"
    command = calls[1]
    assert command[:5] == [
        "docker", "run", "--rm", "--platform", "linux/amd64"]
    assert "/var/lang/bin/python3.13" in command
    assert f"{artifact}:/var/task:ro" in command
    assert manage.LAMBDA_RUNTIME_IMAGE in command
    assert command[-2:] == [
        "-m", "deploy.aws_lambda.sdk_smoke"]


def test_readiness_is_bounded_and_requires_explicit_ok(monkeypatch):
    manage = load_manage("lambda_manage_readiness")
    observed = []

    class Reply:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def read(amount):
            assert amount == MAX_READINESS_RESPONSE_BYTES + 1
            return b'{"ok":true}'

    def open_request(request, timeout):
        observed.append((request.full_url, timeout))
        return Reply()

    monkeypatch.setattr(manage.urllib.request, "urlopen", open_request)

    assert manage._readiness(
        "https://gateway.lambda-url.example") == {"ok": True}
    assert observed == [
        ("https://gateway.lambda-url.example/readyz", 10)]


def test_live_smoke_always_removes_its_generated_stack(
        tmp_path, monkeypatch):
    manage = load_manage("lambda_manage_smoke")
    calls = []
    monkeypatch.setattr(manage, "build", lambda args: calls.append("build"))
    monkeypatch.setattr(
        manage, "_stack_for_deploy", lambda args: args.stack)
    monkeypatch.setattr(
        manage, "_deploy_stack",
        lambda args, target: calls.append(("deploy", target)))
    monkeypatch.setattr(
        manage, "_stack_url",
        lambda args: "https://generated.lambda-url.example")

    def fail_smoke(url, state, workspace):
        calls.append(("smoke", url, state, workspace))
        raise RuntimeError("injected live failure")

    monkeypatch.setattr(manage, "_smoke_endpoint", fail_smoke)
    monkeypatch.setattr(
        manage, "remove",
        lambda args: calls.append(("remove", args.stack)))
    args = SimpleNamespace(
        state=str(tmp_path), workspace="a" * 64,
        bucket="test-bucket", prefix="tenant",
        expected_owner=None, region=None, profile=None)

    with pytest.raises(RuntimeError, match="injected live failure"):
        manage.live_smoke(args)

    assert calls[0] == "build"
    assert calls[1][0] == "deploy"
    assert calls[1][1].startswith("poc16-smoke-")
    assert len(calls[1][1].removeprefix("poc16-smoke-")) == 32
    assert calls[-1] == ("remove", calls[1][1])
