"""AWS Function URL packaging around the real database-free gateway."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from core import cmds
from core.close import encode_pile
from core.crypto import h, unseal
from core.grants import check_token
from core.limits import MAX_MINT_REQUEST_BYTES
from core.node import Node
from deploy.aws_lambda import app
from deploy.aws_lambda.s3_bucket_policy import policy
from deploy.gateway import AsyncFromSyncReader, Gateway
from facts.auth import request

ROOT = Path(__file__).resolve().parents[1]
LAMBDA = ROOT / "deploy" / "aws_lambda"


def event(method, path, workspace=None, body=None, headers=None):
    encoded = base64.b64encode(body).decode() if body is not None else None
    return {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": urlencode({"ws": workspace})
        if workspace is not None else "",
        "headers": headers or {},
        "requestContext": {"http": {"method": method}},
        "body": encoded,
        "isBase64Encoded": body is not None,
    }


def response(result):
    return result["statusCode"], result["headers"], base64.b64decode(
        result["body"])


def world(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    now = 100
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    app._gateway_cache = Gateway(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: now)
    return node, workspace, now, pile


def mint(node, workspace, pile):
    request_body = json.dumps({
        "ws": workspace,
        "pile": base64.b64encode(pile).decode(),
    }).encode()
    status, _, raw = response(app.handler(
        event("POST", "/mint", workspace, request_body), None))
    body = json.loads(raw)
    token = unseal(
        node.identity(workspace)[0],
        base64.b64decode(body["grant"])).decode()
    return status, body, token


def test_lambda_mints_and_serves_authenticated_snapshot_objects(tmp_path):
    node, workspace, now, pile = world(tmp_path)
    status, body, token = mint(node, workspace, pile)

    assert status == 200
    assert body["cap"] == "sync-v1/read"
    assert check_token(
        b"s" * 32, "Bearer " + token, workspace,
        trusted_now=now) == node.identity_id(workspace)[:16]
    assert check_token(
        b"s" * 32, "Bearer " + token, workspace,
        trusted_now=now, require_push=True) is None

    headers = {"authorization": "Bearer " + token}
    status, root_headers, root = response(app.handler(
        event("GET", "/root", workspace, headers=headers), None))
    assert status == 200
    assert root == node.store(workspace).get("root")
    assert root_headers["Cache-Control"] == "no-store"

    raw = b"served through the function URL"
    node.store(workspace).put_if_absent("obj/" + h(raw), raw)
    status, _, fetched = response(app.handler(
        event("GET", "/page/" + h(raw), workspace, headers=headers), None))
    assert (status, fetched) == (200, raw)

    assert response(app.handler(
        event("PUT", "/pile/member/fid", workspace, b"x",
              headers=headers), None))[0] == 405


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


def test_lambda_cold_sandboxes_load_one_stable_external_secret(
        tmp_path, monkeypatch):
    node, workspace, _, _ = world(tmp_path)
    calls = []

    class Secrets:
        def get_secret_value(self, **request):
            calls.append(request)
            return {"SecretString": "z" * 64}

    class Boto:
        @staticmethod
        def client(name):
            assert name == "secretsmanager"
            return Secrets()

    monkeypatch.setitem(sys.modules, "boto3", Boto)
    monkeypatch.setattr(
        app, "_store",
        lambda: AsyncFromSyncReader(node.store(workspace)))
    monkeypatch.setenv("TINYP2P_WORKSPACE_ID", workspace)
    monkeypatch.setenv("TINYP2P_GRANT_SECRET_ARN", "stable-secret")
    app._gateway_cache = None

    first = app._gateway()
    second = app._gateway()

    assert first is second
    assert first.secret == b"z" * 64
    assert calls == [{"SecretId": "stable-secret"}]


def test_lambda_stage_is_an_explicit_importable_allowlist(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "lambda_manage", LAMBDA / "manage.py")
    manage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manage)
    staged = manage.stage(tmp_path / "stage")

    assert (staged / "core" / "mint.py").is_file()
    assert (staged / "facts" / "auth" / "request.py").is_file()
    assert (staged / "adapters" / "s3" / "store.py").is_file()
    assert (staged / "deploy" / "aws_lambda" / "app.py").is_file()
    assert (staged / "deploy" / "aws_lambda" / "sdk_smoke.py").is_file()
    assert (
        staged / "deploy" / "aws_lambda" / "s3_bucket_policy.py").is_file()
    assert not (staged / "tests").exists()
    assert not (staged / "native").exists()
    assert not (staged / "README.md").exists()
    subprocess.run(
        [
            sys.executable, "-c",
            "import deploy.aws_lambda.app; print('lambda-import-ok')",
        ],
        cwd=staged, check=True, capture_output=True, text=True)


def test_lambda_template_is_read_only_bounded_and_reproducible():
    template = (LAMBDA / "template.yaml").read_text()
    requirements = (
        LAMBDA / "requirements.txt").read_text().splitlines()

    assert "Runtime: python3.13" in template
    assert "Architectures: [x86_64]" in template
    assert "ReservedConcurrentExecutions:" in template
    assert "AuthType: NONE" in template
    assert "CodeUri: stage/" in template
    assert "secretsmanager:GetSecretValue" in template
    assert "s3:GetObject" in template
    assert "s3:PutObject" not in template
    assert "s3:DeleteObject" not in template
    assert "s3:ListBucket" not in template
    assert "AWS::CloudWatch::Alarm" in template
    assert requirements == [
        "boto3==1.43.51",
        "botocore==1.43.51",
        "PyNaCl==1.6.2",
    ]


def test_publisher_bucket_guard_denies_deletes_and_unconditional_writes():
    principal = "arn:aws:iam::123456789012:role/poc16-publisher"
    document = policy("workspace-bucket", "tenant", principal)
    statements = {
        statement["Sid"]: statement
        for statement in document["Statement"]
    }

    deletion = statements["DenyAuthoritativeDeletion"]
    assert set(deletion["Action"]) == {
        "s3:DeleteObject", "s3:DeleteObjectVersion"}
    assert deletion["Resource"] == [
        "arn:aws:s3:::workspace-bucket/tenant/root",
        "arn:aws:s3:::workspace-bucket/tenant/obj/*",
    ]
    assert statements["RequireImmutableObjectCreate"]["Condition"] == {
        "Null": {"s3:if-none-match": "true"}}
    assert statements["RequireRootCompareAndSwap"]["Condition"] == {
        "Null": {
            "s3:if-match": "true",
            "s3:if-none-match": "true",
        }}
    assert statements["DenyPublisherLifecycleMutation"]["Action"] \
        == "s3:PutLifecycleConfiguration"


def test_live_smoke_always_removes_its_generated_stack(
        tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "lambda_manage_smoke", LAMBDA / "manage.py")
    manage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manage)
    calls = []
    monkeypatch.setattr(manage, "build", lambda args: calls.append("build"))
    monkeypatch.setattr(
        manage, "_deploy_stack",
        lambda args: calls.append(("deploy", args.stack)))
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
    assert calls[-1] == ("remove", calls[1][1])
