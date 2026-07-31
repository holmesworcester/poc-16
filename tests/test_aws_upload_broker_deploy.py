"""AWS upload-broker packaging, IAM, and safe lifecycle tests."""
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import urllib.error

import pytest

from deploy.aws_upload_broker import manage
from deploy.aws_upload_broker.config import (
    BUCKET_PATTERN,
    DEPLOYMENT_ID_TAG,
    DEPLOYMENT_MARKER,
    DEPLOYMENT_TAG,
    FUNCTION_TIMEOUT_SECONDS,
    PREFIX_PATTERN,
    SDK_CONNECT_TIMEOUT_SECONDS,
    SDK_READ_TIMEOUT_SECONDS,
    SDK_TOTAL_ATTEMPTS,
)
from deploy.aws_upload_broker.signer import (
    S3_UPLOAD_BUCKET_PATTERN,
    S3UploadConfig,
    s3_provider_binding,
)
from deploy.python_role_modules import UPLOAD_BROKER_CORE_MODULES
from deploy.upload_keyring import decode_keyring


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "deploy" / "aws_upload_broker"


def args(**changes):
    values = {
        "alarm_action_arn": None,
        "canonical_bucket": "canonical-bucket",
        "create": True,
        "deployment_id": "upload-west-2",
        "expected_owner": "123456789012",
        "ingress_bucket": "isolated-ingress-bucket",
        "issuer": "aws-upload-production",
        "keyring_secret_arn": (
            "arn:aws:secretsmanager:us-west-2:123456789012:"
            "secret:poc16/upload-keyring-AbCdEf"
        ),
        "keyring_version_id": "v" * 32,
        "kms_key_arn": None,
        "prefix": "workspaces/" + "a" * 64,
        "presign_ttl_seconds": 60,
        "profile": None,
        "region": "us-west-2",
        "stack": "poc16-upload",
        "update": False,
        "workspace": "a" * 64,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def stack(candidate=None):
    candidate = args() if candidate is None else candidate
    return {
        "StackName": candidate.stack,
        "StackId": (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/poc16-upload/uuid"
        ),
        "StackStatus": "CREATE_COMPLETE",
        "Tags": [
            {"Key": DEPLOYMENT_TAG, "Value": DEPLOYMENT_MARKER},
            {
                "Key": DEPLOYMENT_ID_TAG,
                "Value": candidate.deployment_id,
            },
        ],
        "Outputs": [
            {
                "OutputKey": "DeploymentMarker",
                "OutputValue": DEPLOYMENT_MARKER,
            },
            {
                "OutputKey": "DeploymentId",
                "OutputValue": candidate.deployment_id,
            },
            {
                "OutputKey": "UploadBrokerUrl",
                "OutputValue": "https://broker.lambda-url.example/",
            },
            {
                "OutputKey": "UploadKeyringSecretArn",
                "OutputValue": candidate.keyring_secret_arn,
            },
            {
                "OutputKey": "UploadKeyringVersionId",
                "OutputValue": candidate.keyring_version_id,
            },
        ],
    }


def keyring_args(**changes):
    values = {
        "deployment_id": "upload-west-2",
        "expected_owner": "123456789012",
        "ingress_bucket": "isolated-ingress-bucket",
        "issuer": "aws-upload-production",
        "key_lifetime_days": 90,
        "kms_key_arn": None,
        "name": "poc16/upload-west-2/session-keyring",
        "profile": None,
        "region": "us-west-2",
        "session_ttl_seconds": 15 * 60,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_stage_is_an_explicit_importable_broker_only_allowlist(tmp_path):
    staged = manage.stage(tmp_path / "stage")

    for relative in (
            "core/validated_set.py",
            "core/repository_reader.py",
            "facts/auth/request.py",
            "adapters/s3/store.py",
            "deploy/upload_broker.py",
            "deploy/upload_broker_http.py",
            "deploy/upload_keyring.py",
            "deploy/upload_session.py",
            "deploy/upload_wire.py",
            "deploy/aws_upload_broker/app.py",
            "deploy/aws_upload_broker/config.py",
            "deploy/aws_upload_broker/signer.py"):
        assert (staged / relative).is_file()
    assert {
        path.name for path in (staged / "core").glob("*.py")
    } == set(UPLOAD_BROKER_CORE_MODULES)
    for forbidden in (
            "catalog.py",
            "client_projection.py",
            "mint.py",
            "node.py",
            "pile_sender.py",
            "repository_applier.py",
            "store.py",
            "suppression_state.py"):
        assert not (staged / "core" / forbidden).exists()
    assert not (staged / "deploy" / "upload_client.py").exists()
    assert not (staged / "adapters" / "host.py").exists()
    assert not (staged / "adapters" / "r2").exists()
    assert not (staged / "deploy" / "aws_lambda").exists()
    assert not (staged / "deploy" / "cloudflare_upload").exists()
    assert not (staged / "tests").exists()
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import deploy.aws_upload_broker.app; print('broker-import-ok')",
        ],
        cwd=staged,
        env={**os.environ, "PYTHONPATH": str(staged)},
        check=True,
        capture_output=True,
        text=True,
    )


def test_template_has_only_broker_authority_and_external_data_ownership():
    template = (PACKAGE / "template.yaml").read_text()
    requirements = (PACKAGE / "requirements.txt").read_text()

    assert f"Value: {DEPLOYMENT_MARKER}" in template
    assert "Runtime: python3.13" in template
    assert "Architectures: [x86_64]" in template
    assert f"Timeout: {FUNCTION_TIMEOUT_SECONDS}" in template
    assert "Handler: deploy.aws_upload_broker.app.handler" in template
    assert "AuthType: NONE" in template
    assert "ReservedConcurrentExecutions:" in template
    assert "secretsmanager:GetSecretValue" in template
    assert "Action: s3:GetObject" in template
    assert "Action: s3:PutObject" in template
    assert "Action: s3:ListBucket" in template
    assert "s3:DeleteObject" not in template
    assert "s3:DeleteObjectVersion" not in template
    assert "s3:PutLifecycleConfiguration" not in template
    assert "s3:DeleteLifecycleConfiguration" not in template
    assert "s3:PutBucket" not in template
    assert "s3:DeleteBucket" not in template
    assert "s3:PutObjectAcl" not in template
    assert "s3:authType: REST-QUERY-STRING" in template
    assert "s3:signatureversion: AWS4-HMAC-SHA256" in template
    assert "s3:if-none-match" in template
    assert template.count(
        "s3:ResourceAccount: !Ref ExpectedBucketOwner") == 3
    assert 's3:signatureAge: !Sub "${PresignTtlSeconds}000"' in template
    assert "s3:signatureAge: 900000" not in template
    kms = template.split(
        "- Sid: DecryptDeploymentValues", 1)[1].split(
            "- Sid: WriteFunctionLogs", 1)[0]
    assert "Action: kms:Decrypt" in kms
    assert "kms:CallerAccount: !Ref AWS::AccountId" in kms
    assert (
        "kms:EncryptionContext:SecretARN:\n"
        "                        !Ref UploadKeyringSecretArn"
    ) in kms
    assert (
        '"secretsmanager.${AWS::Region}.${AWS::URLSuffix}"'
        in kms
    )
    assert "SecretVersionId" not in kms
    assert (
        "ingress/v1/workspaces/${WorkspaceId}/objects/*"
        in template
    )
    assert (
        "ingress/v1/workspaces/${WorkspaceId}/piles/*"
        in template
    )
    assert "Type: AWS::SecretsManager::Secret" not in template
    assert "Type: AWS::S3::Bucket" not in template
    assert "Value: !Ref UploadKeyringSecretArn" in template.rsplit(
        "UploadKeyringSecretArn:", 1)[1]
    assert "Value: !Ref UploadKeyringVersionId" in template.rsplit(
        "UploadKeyringVersionId:", 1)[1]
    assert f"AllowedPattern: '{BUCKET_PATTERN}'" in template
    assert f"AllowedPattern: '{S3_UPLOAD_BUCKET_PATTERN}'" in template
    assert f"AllowedPattern: '{PREFIX_PATTERN}'" in template
    assert 'ExpectedBucketOwner:\n    Type: String\n    AllowedPattern: "^[0-9]{12}$"' in template
    assert "HasExpectedOwner" not in template
    assert (
        "TINYP2P_UPLOAD_EXPECTED_BUCKET_OWNER: "
        "!Ref ExpectedBucketOwner"
    ) in template
    assert (
        'TINYP2P_UPLOAD_AWS_CONNECT_TIMEOUT_SECONDS: '
        f'"{SDK_CONNECT_TIMEOUT_SECONDS}"'
    ) in template
    assert (
        'TINYP2P_UPLOAD_AWS_READ_TIMEOUT_SECONDS: '
        f'"{SDK_READ_TIMEOUT_SECONDS}"'
    ) in template
    assert (
        'TINYP2P_UPLOAD_AWS_TOTAL_ATTEMPTS: '
        f'"{SDK_TOTAL_ATTEMPTS}"'
    ) in template

    canonical = template.split(
        "- Sid: ReadCanonicalAuthorizationSnapshot", 1)[1].split(
            "- Sid: PresignExactIngressPut", 1)[0]
    ingress = template.split(
        "- Sid: PresignExactIngressPut", 1)[1].split(
            "- Sid: ReadUploadSessionKeyring", 1)[0]
    assert "s3:GetObject" in canonical
    assert "s3:PutObject" not in canonical
    assert "${Prefix}/root" in canonical
    assert "${Prefix}/obj/*" in canonical
    assert canonical.count("Prefix: !Ref CanonicalPrefix") == 2
    assert "s3:PutObject" in ingress
    assert "s3:GetObject" not in ingress
    assert "s3:ListBucket" not in ingress
    assert "s3:DeleteObject" not in ingress

    assert requirements == (
        ROOT / "deploy" / "aws_lambda" / "requirements.txt").read_text()


def test_ingress_lifecycle_preflight_accepts_absence_and_rejects_rules(
        monkeypatch):
    candidate = args()
    commands = []

    def absent(command):
        commands.append(command)
        raise subprocess.CalledProcessError(
            255,
            command,
            stderr="NoSuchLifecycleConfiguration",
        )

    monkeypatch.setattr(manage, "_json_command", absent)
    manage._assert_no_ingress_lifecycle(candidate)
    command = commands[0]
    assert command[:3] == [
        "aws", "s3api", "get-bucket-lifecycle-configuration"]
    assert command[command.index("--bucket") + 1] == (
        candidate.ingress_bucket)
    assert command[command.index("--expected-bucket-owner") + 1] == (
        candidate.expected_owner)

    monkeypatch.setattr(
        manage, "_json_command", lambda _command: {"Rules": []})
    manage._assert_no_ingress_lifecycle(candidate)

    monkeypatch.setattr(
        manage,
        "_json_command",
        lambda _command: {"Rules": [{
            "ID": "unproved-age-delete",
            "Status": "Enabled",
        }]},
    )
    with pytest.raises(RuntimeError, match="erase acknowledged"):
        manage._assert_no_ingress_lifecycle(candidate)


@pytest.mark.parametrize("outcome", (
    {},
    {"Rules": None},
    subprocess.CalledProcessError(
        254, ["aws"], stderr="AccessDenied"),
))
def test_ingress_lifecycle_preflight_rejects_ambiguous_outcome(
        monkeypatch, outcome):
    def lookup(_command):
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(manage, "_json_command", lookup)

    with pytest.raises(RuntimeError, match="lifecycle"):
        manage._assert_no_ingress_lifecycle(args())


def test_deploy_checks_ingress_retention_before_build_or_stack_mutation(
        monkeypatch):
    candidate = args()
    events = []
    target = "arn:aws:cloudformation:us-west-2:123456789012:stack/x/id"
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: events.append("target") or target)
    monkeypatch.setattr(
        manage, "_assert_no_ingress_lifecycle",
        lambda _args: events.append("retention"))
    monkeypatch.setattr(
        manage, "build", lambda _args: events.append("build"))
    monkeypatch.setattr(
        manage, "_deploy_stack",
        lambda _args, observed: events.append(("deploy", observed)))
    monkeypatch.setattr(
        manage, "_stack_url",
        lambda _args: events.append("url") or "https://broker.example")
    monkeypatch.setattr(
        manage, "_readiness",
        lambda url: events.append(("ready", url)))

    manage.deploy(candidate)

    assert events == [
        "target",
        "retention",
        "build",
        ("deploy", target),
        "url",
        ("ready", "https://broker.example"),
    ]


def test_keyring_create_keeps_secret_out_of_argv_and_returns_exact_version(
        monkeypatch):
    candidate = keyring_args()
    captured = {}
    values = {
        6: b"a" * 6,
        16: b"v" * 16,
        32: b"k" * 32,
    }

    def random_bytes(count):
        return values[count]

    def command_result(command):
        secret_argument = command[
            command.index("--secret-string") + 1]
        assert secret_argument.startswith("file://")
        path = Path(secret_argument.removeprefix("file://"))
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        raw = path.read_bytes()
        loaded = decode_keyring(raw)
        captured.update({
            "command": command,
            "path": path,
            "raw": raw,
            "loaded": loaded,
        })
        return {
            "ARN": (
                "arn:aws:secretsmanager:us-west-2:123456789012:"
                "secret:poc16/upload-west-2/session-keyring-AbCdEf"
            ),
            "VersionId": (b"v" * 16).hex(),
        }

    monkeypatch.setattr(manage, "_json_command", command_result)

    result = manage.keyring_create(
        candidate,
        now_ms=7_000_000,
        random_bytes=random_bytes,
    )

    assert result == {
        "keyring_secret_arn": (
            "arn:aws:secretsmanager:us-west-2:123456789012:"
            "secret:poc16/upload-west-2/session-keyring-AbCdEf"
        ),
        "keyring_version_id": (b"v" * 16).hex(),
    }
    assert not captured["path"].exists()
    flattened = "\0".join(captured["command"])
    assert captured["raw"].decode() not in flattened
    assert "kkkkkkkk" not in flattened
    assert "--client-request-token" in captured["command"]
    assert captured["loaded"].provider_binding == s3_provider_binding(
        S3UploadConfig(
            candidate.ingress_bucket,
            candidate.region,
            expected_bucket_owner=candidate.expected_owner,
        ))
    policy = captured["loaded"].policy
    assert policy.issuer == candidate.issuer
    assert policy.active_key_id == "YWFhYWFh"
    assert policy.ttl_ms == candidate.session_ttl_seconds * 1000


@pytest.mark.parametrize(
    "changes",
    (
        {"name": "has space"},
        {"issuer": "has space"},
        {"session_ttl_seconds": 0},
        {"session_ttl_seconds": 24 * 60 * 60 + 1},
        {"key_lifetime_days": 0},
        {"key_lifetime_days": 1, "session_ttl_seconds": 24 * 60 * 60},
    ),
)
def test_keyring_create_rejects_invalid_or_insufficient_lifetime(changes):
    with pytest.raises(ValueError):
        manage._validate_keyring_create_args(
            keyring_args(**changes))


@pytest.mark.parametrize(
    "changes",
    (
        {"canonical_bucket": "same", "ingress_bucket": "same"},
        {"expected_owner": None},
        {"expected_owner": ""},
        {"ingress_bucket": "dotted.ingress.bucket"},
        {"prefix": ""},
        {"region": None},
        {"workspace": "A" * 64},
        {"issuer": "has space"},
        {"keyring_secret_arn": "not-an-arn"},
        {"keyring_version_id": "short"},
        {"keyring_version_id": "é" * 32},
        {"presign_ttl_seconds": 0},
        {"presign_ttl_seconds": 901},
        {"prefix": "/absolute"},
    ),
)
def test_deploy_validation_rejects_authority_ambiguity(changes):
    with pytest.raises(ValueError):
        manage._validate_deploy_args(args(**changes))


def test_parsers_require_region_and_exact_bucket_owner():
    deploy = [
        "deploy", "--create",
        "--stack", "poc16-upload",
        "--deployment-id", "upload-west-2",
        "--workspace", "a" * 64,
        "--canonical-bucket", "canonical-bucket",
        "--prefix", "workspaces/" + "a" * 64,
        "--ingress-bucket", "isolated-ingress-bucket",
        "--issuer", "aws-upload-production",
        "--keyring-secret-arn",
        (
            "arn:aws:secretsmanager:us-west-2:123456789012:"
            "secret:poc16/upload-keyring-AbCdEf"
        ),
        "--keyring-version-id", "v" * 32,
    ]
    with pytest.raises(SystemExit):
        manage.parser().parse_args(deploy)
    with pytest.raises(SystemExit):
        manage.parser().parse_args([
            "keyring-create",
            "--name", "poc16/keyring",
            "--deployment-id", "upload-west-2",
            "--issuer", "aws-upload-production",
            "--ingress-bucket", "isolated-ingress-bucket",
            "--region", "us-west-2",
        ])


def test_update_and_remove_target_only_the_owned_stack_id(monkeypatch):
    candidate = args(create=False, update=True)
    owned = stack(candidate)
    calls = []
    monkeypatch.setattr(
        manage, "_stack_or_none", lambda _args: owned)
    monkeypatch.setattr(
        manage, "_caller_account", lambda _args: "123456789012")
    monkeypatch.setattr(
        manage, "_run", lambda command, **_options: calls.append(command))

    manage._deploy_stack(candidate)
    manage.remove(candidate)

    exact_id = owned["StackId"]
    assert calls[0][calls[0].index("--stack-name") + 1] == exact_id
    assert calls[1] == [
        "sam", "delete", "--stack-name", exact_id, "--no-prompts",
        "--region", "us-west-2",
    ]
    flattened = " ".join(" ".join(call) for call in calls)
    assert "secretsmanager delete-secret" not in flattened
    assert "s3 rm" not in flattened
    assert "delete-bucket" not in flattened


def test_create_refuses_existing_stack_and_remove_refuses_foreign_owner(
        monkeypatch):
    candidate = args()
    existing = stack(candidate)
    monkeypatch.setattr(
        manage, "_stack_or_none", lambda _args: existing)
    with pytest.raises(RuntimeError, match="absent stack"):
        manage._stack_for_deploy(candidate)

    foreign = {
        **existing,
        "Tags": [{
            "Key": DEPLOYMENT_TAG,
            "Value": "someone-else",
        }],
    }
    monkeypatch.setattr(
        manage, "_stack_or_none", lambda _args: foreign)
    monkeypatch.setattr(
        manage, "_caller_account", lambda _args: "123456789012")
    calls = []
    monkeypatch.setattr(
        manage, "_run", lambda command, **_options: calls.append(command))
    with pytest.raises(RuntimeError, match="unowned stack"):
        manage.remove(candidate)
    assert calls == []


def test_readiness_requires_the_shared_body_free_rejection(monkeypatch):
    requests = []

    def rejected(request, timeout):
        requests.append((request, timeout))
        raise urllib.error.HTTPError(
            request.full_url,
            400,
            "expected malformed FINALIZE",
            {},
            None,
        )

    monkeypatch.setattr(
        manage.urllib.request, "urlopen", rejected)

    manage._readiness("https://broker.example")

    request, timeout = requests[0]
    assert request.full_url == (
        "https://broker.example/upload/finalize")
    assert request.method == "POST"
    assert request.data == b"{}"
    assert timeout == manage.READINESS_TIMEOUT_SECONDS
