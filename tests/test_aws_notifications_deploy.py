"""AWS notification packaging, authority, and lifecycle tests."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.crypto import h, load_sk
from core.fact import canon
from deploy.notification_launch import (
    MAX_LAUNCH_RECORD_BYTES,
    launch_record as encode_launch_record,
)
from deploy.aws_notifications import manage
from deploy.aws_notifications.config import (
    BOOTSTRAP_RESULT_SCHEMA,
    BOOTSTRAP_SCHEMA,
    DEPLOYMENT_ID_TAG,
    DEPLOYMENT_MARKER,
    DEPLOYMENT_TAG,
    DIRECT_SMOKE_RESULT_SCHEMA,
    DIRECT_SMOKE_SCHEMA,
    DLQ_RETENTION_SECONDS,
    QUEUE_RETENTION_SECONDS,
    SCAN_RESULT_SCHEMA,
    SCAN_WAKE_SCHEMA,
)
from deploy.aws_notifications.secret import push_node_id
from notifications.hints import NotificationHint, encode_hint


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "deploy" / "aws_notifications"
WORKSPACE = "a" * 64
HINT_OWNER = "c" * 64
GENERATION = "e" * 64
ACCOUNT = "123456789012"
SECRET_ARN = (
    f"arn:aws:secretsmanager:us-west-2:{ACCOUNT}:"
    "secret:poc16/notification-AbCdEf"
)
SECRET_VERSION = "a" * 32
SECRET_SEED = "11" * 32
PUSH_NODE = push_node_id(load_sk(SECRET_SEED))
SOFTWARE_DIGEST = "f" * 64
DELIVERY_VERSION_ARN = (
    f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
    "function:poc16-notification-delivery:7")
SCANNER_VERSION_ARN = (
    f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
    "function:poc16-notification-scanner:5")
NEW_DELIVERY_VERSION_ARN = DELIVERY_VERSION_ARN[:-1] + "8"
NEW_SCANNER_VERSION_ARN = SCANNER_VERSION_ARN[:-1] + "6"
QUEUE_ARN = f"arn:aws:sqs:us-west-2:{ACCOUNT}:poc16-notifications"
QUEUE_URL = (
    f"https://sqs.us-west-2.amazonaws.com/{ACCOUNT}/poc16-notifications"
)
DLQ_ARN = QUEUE_ARN + "-dlq"
DLQ_URL = QUEUE_URL + "-dlq"


def args(**changes):
    values = {
        "alarm_action_arn": None,
        "canonical_bucket": "canonical-bucket",
        "canonical_prefix": f"workspaces/{WORKSPACE}",
        "confirm_live_fcm": False,
        "create": True,
        "delivery_concurrency": 10,
        "deployment_id": "notify-west-2",
        "destroy_carrier": False,
        "enable": None,
        "expected_owner": ACCOUNT,
        "ios_launch_record": None,
        "android_launch_record": None,
        "max_per_second": 10,
        "max_receive_count": 5,
        "notification_secret_arn": SECRET_ARN,
        "notification_secret_version_id": SECRET_VERSION,
        "profile": None,
        "region": "us-west-2",
        "repository_kms_key_arn": None,
        "scanner_concurrency": 2,
        "schedule": "rate(1 minute)",
        "secret_kms_key_arn": None,
        "stack_name": "poc16-notifications",
        "state_bucket": "notification-state-bucket",
        "state_kms_key_arn": None,
        "state_prefix": f"notifications/{WORKSPACE}",
        "update": False,
        "workspace": WORKSPACE,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _output_rows(values):
    return [
        {"OutputKey": name, "OutputValue": str(value)}
        for name, value in values.items()
    ]


def stack(candidate=None, *, delivery_version=DELIVERY_VERSION_ARN,
          enabled=True, push_node=PUSH_NODE,
          scanner_version=SCANNER_VERSION_ARN,
          software_digest=SOFTWARE_DIGEST):
    candidate = args() if candidate is None else candidate
    outputs = {
        "CanonicalBucketName": candidate.canonical_bucket,
        "CanonicalPrefix": candidate.canonical_prefix,
        "DeploymentId": candidate.deployment_id,
        "DeploymentMarker": DEPLOYMENT_MARKER,
        "Enabled": "true" if enabled else "false",
        "ExpectedBucketOwner": candidate.expected_owner,
        "NotificationDeadLetterQueueArn": DLQ_ARN,
        "NotificationDeadLetterQueueUrl": DLQ_URL,
        "NotificationDeadLetterRetentionSeconds": DLQ_RETENTION_SECONDS,
        "NotificationDeliveryVersionArn": delivery_version,
        "NotificationQueueArn": QUEUE_ARN,
        "NotificationQueueUrl": QUEUE_URL,
        "NotificationQueueRetentionSeconds": QUEUE_RETENTION_SECONDS,
        "NotificationScannerVersionArn": scanner_version,
        "NotificationSecretArn": candidate.notification_secret_arn,
        "NotificationSecretKmsKeyArn": candidate.secret_kms_key_arn or "",
        "NotificationSecretVersionId": (
            candidate.notification_secret_version_id),
        "NotificationStateBucketName": candidate.state_bucket,
        "NotificationStateKmsKeyArn": candidate.state_kms_key_arn or "",
        "NotificationStatePrefix": candidate.state_prefix,
        "PushNodeId": push_node,
        "RepositoryKmsKeyArn": candidate.repository_kms_key_arn or "",
        "SoftwareDigest": software_digest,
        "WorkspaceId": candidate.workspace,
    }
    return {
        "Outputs": _output_rows(outputs),
        "StackId": (
            f"arn:aws:cloudformation:us-west-2:{ACCOUNT}:"
            "stack/poc16-notifications/uuid"),
        "StackName": candidate.stack_name,
        "StackStatus": "CREATE_COMPLETE",
        "Tags": [
            {"Key": DEPLOYMENT_TAG, "Value": DEPLOYMENT_MARKER},
            {"Key": DEPLOYMENT_ID_TAG, "Value": candidate.deployment_id},
        ],
    }


def launch_binding(candidate, *, stack_id=None, push_node=PUSH_NODE,
                   software_digest=SOFTWARE_DIGEST):
    return {
        "canonical_bucket": candidate.canonical_bucket,
        "canonical_prefix": candidate.canonical_prefix,
        "deployment_id": candidate.deployment_id,
        "delivery_version_arn": DELIVERY_VERSION_ARN,
        "expected_bucket_owner": candidate.expected_owner,
        "notification_secret_arn": candidate.notification_secret_arn,
        "notification_secret_version_id": (
            candidate.notification_secret_version_id),
        "notification_state_bucket": candidate.state_bucket,
        "notification_state_prefix": candidate.state_prefix,
        "provider": "aws",
        "push_node_id": push_node,
        "scanner_version_arn": SCANNER_VERSION_ARN,
        "software_digest": software_digest,
        "stack_id": stack(candidate)["StackId"] if stack_id is None
        else stack_id,
        "workspace": candidate.workspace,
    }


def traffic_change_set(candidate, stack_id, *, enabled=True, changes=None,
                       push_node=PUSH_NODE,
                       software_digest=SOFTWARE_DIGEST):
    values = manage._parameter_values(
        candidate, enabled, push_node, software_digest)
    resources = manage.TRAFFIC_RESOURCES if changes is None else changes
    return {
        "ChangeSetId": "change-set",
        "Changes": [{
            "ResourceChange": {
                "Action": "Modify",
                "LogicalResourceId": name,
                "Replacement": "False",
                "ResourceType": resource_type,
                "Scope": ["Properties"],
            },
            "Type": "Resource",
        } for name, resource_type in resources.items()],
        "ExecutionStatus": "AVAILABLE",
        "Parameters": [
            ({"ParameterKey": name, "ParameterValue": value}
             if name == "Enabled" else
             {"ParameterKey": name, "UsePreviousValue": True})
            for name, value in values.items()
        ],
        "StackId": stack_id,
        "Status": "CREATE_COMPLETE",
    }


def release_change_set(candidate, stack_id, *,
                       software_digest=SOFTWARE_DIGEST):
    values = manage._parameter_values(
        candidate, False, PUSH_NODE, software_digest)
    return {
        "ChangeSetId": "change-set",
        "Changes": [{
            "ResourceChange": {
                "Action": "Modify",
                "LogicalResourceId": name,
                "Replacement": "True" if name.endswith("Version")
                else "False",
                "ResourceType": "AWS::Lambda::Version"
                if name.endswith("Version") else "AWS::Lambda::Function",
                "Scope": ["Properties"],
            },
            "Type": "Resource",
        } for name in (
            "NotificationScannerFunction",
            "NotificationDeliveryFunction",
            "NotificationScannerVersion",
            "NotificationDeliveryVersion",
        )],
        "ExecutionStatus": "AVAILABLE",
        "Parameters": [
            {"ParameterKey": name, "ParameterValue": value}
            for name, value in values.items()
        ],
        "StackId": stack_id,
        "Status": "CREATE_COMPLETE",
    }


def launch_record(candidate, platform, *, stack_id=None,
                  push_node=PUSH_NODE, software_digest=SOFTWARE_DIGEST):
    return encode_launch_record(platform, launch_binding(
        candidate,
        stack_id=stack_id,
        push_node=push_node,
        software_digest=software_digest,
    ))


def write_launch_records(directory, candidate, *, stack_id=None):
    for platform in ("ios", "android"):
        path = directory / f"{platform}.json"
        path.write_bytes(launch_record(
            candidate, platform, stack_id=stack_id))
        setattr(candidate, f"{platform}_launch_record", str(path))


def _secret_response(*, version=SECRET_VERSION, arn=SECRET_ARN,
                     seed=SECRET_SEED):
    return {
        "ARN": arn,
        "SecretString": json.dumps({
            "firebase_apps": [{
                "application": "poc16.mobile",
                "credential": {"project_id": "project"},
                "environment": "production",
            }],
            "push_node_seed": seed,
        }),
        "VersionId": version,
    }


def test_stage_is_importable_and_contains_only_shared_read_side(tmp_path):
    staged = manage.stage(tmp_path / "stage")
    for relative in (
            "adapters/aws/sqs.py",
            "adapters/gcp/firebase.py",
            "adapters/s3/store.py",
            "core/repository_reader.py",
            "deploy/notification_launch.py",
            "deploy/aws_notifications/app.py",
            "deploy/aws_notifications/secret.py",
            "facts/auth/push_endpoint.py",
            "notifications/discovery.py",
            "notifications/hints.py",
            "notifications/worker.py"):
        assert (staged / relative).is_file()
    for forbidden in (
            "core/repository_applier.py",
            "core/store.py",
            "core/grants.py",
            "core/http.py",
            "core/peer_capability.py",
            "full_peer/node.py",
            "full_peer/sql_store.py"):
        assert not (staged / forbidden).exists()
    completed = subprocess.run(
        [sys.executable, "-c", "import deploy.aws_notifications.app"],
        cwd=staged,
        env={**os.environ, "PYTHONPATH": str(staged)},
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout == ""


def test_template_keeps_roles_narrow_and_traffic_switches_non_destructive():
    template = (PACKAGE / "template.yaml").read_text()
    scanner = template.split("NotificationScannerRole:", 1)[1].split(
        "NotificationDeliveryRole:", 1)[0]
    delivery = template.split("NotificationDeliveryRole:", 1)[1].split(
        "NotificationScannerFunction:", 1)[0]
    source_queue = template.split(
        "NotificationQueue:", 1)[1].split("NotificationScannerRole:", 1)[0]
    dead_queue = template.split(
        "NotificationDeadLetterQueue:", 1)[1].split(
            "NotificationQueue:", 1)[0]

    assert template.count('Default: "false"') == 1
    assert "Condition: NotificationsEnabled" not in template
    assert "Enabled: !If [NotificationsEnabled, true, false]" in template
    assert "State: !If [NotificationsEnabled, ENABLED, DISABLED]" in template
    assert f"MessageRetentionPeriod: {QUEUE_RETENTION_SECONDS}" \
        in source_queue
    assert f"MessageRetentionPeriod: {DLQ_RETENTION_SECONDS}" in dead_queue
    assert QUEUE_RETENTION_SECONDS < DLQ_RETENTION_SECONDS
    assert "NotificationStateMinimumRetentionDays" not in template
    assert "TINYP2P_NOTIFICATION_SECRET_VERSION_ID" in template
    assert "TINYP2P_NOTIFICATION_PUSH_NODE_ID" in template
    assert "TINYP2P_NOTIFICATION_DIRECT_SMOKE_ENABLED" not in template
    assert template.count("TINYP2P_NOTIFICATION_SOFTWARE_DIGEST") == 2
    assert template.count("Type: AWS::Lambda::Version") == 2
    assert template.count("Description: !Ref SoftwareDigest") == 2
    assert template.count("RuntimeManagementConfig:") == 2
    assert template.count("RuntimePolicy:") == 2
    assert template.count("UpdateRuntimeOn: FunctionUpdate") == 4
    assert "DirectSmokeEnabled" not in template
    assert template.count(
        "FunctionName: !Ref NotificationDeliveryVersion") == 1
    assert template.count(
        "FunctionName: !Ref NotificationScannerVersion") == 1
    assert "Arn: !Ref NotificationScannerVersion" in template
    assert "NotificationScannerFunctionArn:" not in template
    assert "NotificationDeliveryFunctionArn:" not in template
    assert "SoftwareDigest" in template
    assert "Handler: deploy.aws_notifications.app.scanner_handler" in template
    assert "Handler: deploy.aws_notifications.app.delivery_handler" in template
    assert "FunctionResponseTypes:\n        - ReportBatchItemFailures" in template
    assert "RedrivePolicy:" in template

    assert "s3:GetObject" in scanner
    assert "s3:PutObject" in scanner
    assert "sqs:SendMessage" in scanner
    assert "sqs:ReceiveMessage" not in scanner
    assert "secretsmanager:GetSecretValue" not in scanner
    assert "s3:GetObject" in delivery
    assert delivery.count("s3:PutObject") == 1
    assert "sqs:SendMessage" not in delivery
    assert "secretsmanager:GetSecretValue" in delivery
    assert "kms:EncryptionContext:SecretARN" in delivery
    assert "sqs:ReceiveMessage" in delivery

    for forbidden in (
            "s3:ListBucket", "s3:DeleteObject", "AWS::S3::Bucket",
            "RepositoryApplier", "full_peer", "sqlite", "FactOrder"):
        assert forbidden not in template
    historical = delivery.split("ReadHistoricalNotificationRoot", 1)[1]
    assert "${NotificationStatePrefix}/obj/*" in historical
    completion = historical.split("CompleteNotificationCursor", 1)[1].split(
        "ReadExactNotificationSecret", 1)[0]
    historical = historical.split("CompleteNotificationCursor", 1)[0]
    assert "s3:PutObject" not in historical
    assert "${NotificationStatePrefix}/root" not in historical
    assert "s3:PutObject" in completion
    assert "${NotificationStatePrefix}/root" in completion
    assert "${NotificationStatePrefix}/obj/*" not in completion


def test_requirements_are_hash_locked_for_lambda_and_firebase():
    requirements = (PACKAGE / "requirements.txt").read_text()
    assert "--only-binary=:all:" in requirements
    assert "--require-hashes" in requirements
    assert "firebase-admin==7.5.0" in requirements
    assert "boto3==1.43.51" in requirements
    assert requirements.count("--hash=sha256:") >= 40


def test_notification_state_requires_a_dedicated_bucket():
    with pytest.raises(ValueError, match="dedicated bucket"):
        manage._validated(args(
            state_bucket="canonical-bucket",
            state_prefix=f"notification-state/{WORKSPACE}",
        ))
    assert manage._validated(args()).workspace == WORKSPACE


@pytest.mark.parametrize("version", ("x" * 31, "x" * 65))
def test_secret_version_id_is_exact_not_awscurrent(version):
    with pytest.raises(ValueError, match="secret version ID"):
        manage._validated(args(notification_secret_version_id=version))
    assert manage._validated(args(
        notification_secret_version_id="x" * 32)).workspace == WORKSPACE


def test_state_lifecycle_accepts_absence_and_never_mutates_bucket(monkeypatch):
    calls = []
    error = subprocess.CalledProcessError(
        255, ["aws"], stderr="NoSuchLifecycleConfiguration")

    def run(command, **_kwargs):
        calls.append(command)
        raise error

    monkeypatch.setattr(manage, "_run", run)

    assert manage._verify_state_lifecycle(args()) is None
    assert calls == [[
        "aws", "s3api", "get-bucket-lifecycle-configuration",
        "--bucket", "notification-state-bucket",
        "--expected-bucket-owner", ACCOUNT,
        "--output", "json", "--region", "us-west-2",
    ]]


def test_state_lifecycle_rejects_enabled_expiration_but_allows_transition(
        monkeypatch):
    response = SimpleNamespace(stdout=json.dumps({"Rules": [{
        "Expiration": {"Days": 31},
        "ID": "expire",
        "Status": "Enabled",
    }]}))
    monkeypatch.setattr(manage, "_run", lambda *_args, **_kwargs: response)
    with pytest.raises(RuntimeError, match="enabled expiration"):
        manage._verify_state_lifecycle(args())

    response.stdout = json.dumps({"Rules": [{
        "ID": "archive",
        "Status": "Enabled",
        "Transitions": [{"Days": 30, "StorageClass": "GLACIER"}],
    }, {
        "Expiration": {"Days": 31},
        "ID": "disabled-expiration",
        "Status": "Disabled",
    }]})
    assert manage._verify_state_lifecycle(args()) is None


def test_pinned_secret_fetch_derives_stable_push_identity(monkeypatch):
    calls = []
    monkeypatch.setattr(manage, "_run", lambda command, **_kwargs: (
        calls.append(command) or SimpleNamespace(
            stdout=json.dumps(_secret_response()))))

    assert manage._secret_binding(args()) == PUSH_NODE
    command = calls[0]
    assert command[1:3] == ["secretsmanager", "get-secret-value"]
    assert command[command.index("--version-id") + 1] == SECRET_VERSION
    assert "AWSCURRENT" not in command


def test_pinned_secret_response_must_match_requested_version(monkeypatch):
    private = "private-seed-must-not-leak"
    response = _secret_response(version="b" * 32)
    response["SecretString"] = private
    monkeypatch.setattr(manage, "_run", lambda *_args, **_kwargs:
                        SimpleNamespace(stdout=json.dumps(response)))

    with pytest.raises(RuntimeError, match="invalid pinned") as caught:
        manage._secret_binding(args())
    assert private not in str(caught.value)


@pytest.mark.parametrize("enabled", (False, True))
def test_update_without_switch_preserves_incumbent_traffic(
        monkeypatch, enabled):
    candidate = args(create=False, update=True, enable=None)
    current = stack(candidate, enabled=enabled)
    monkeypatch.setattr(manage, "_stack_or_none", lambda _args: current)
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args, _stack=None: current)

    target, resolved_enabled, outputs = manage._stack_for_deploy(candidate)
    assert target == current["StackId"]
    assert resolved_enabled is enabled
    assert outputs == manage._outputs(current)


def test_explicit_disable_retains_queues_and_functions(monkeypatch):
    candidate = args(create=False, update=True, enable=False)
    current = stack(candidate, enabled=True)
    monkeypatch.setattr(manage, "_stack_or_none", lambda _args: current)
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args, _stack=None: current)

    result = manage._stack_for_deploy(candidate)
    assert result[:2] == (current["StackId"], False)
    template = (PACKAGE / "template.yaml").read_text()
    for name in (
            "NotificationQueue", "NotificationDeadLetterQueue",
            "NotificationScannerFunction", "NotificationDeliveryFunction"):
        resource = template.split(f"  {name}:\n", 1)[1].split("\n  ", 1)[0]
        assert "Condition:" not in resource


def test_stack_operations_require_a_stable_cloudformation_state(monkeypatch):
    candidate = args()
    current = stack(candidate, enabled=False)
    current["StackStatus"] = "UPDATE_IN_PROGRESS"
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)

    with pytest.raises(RuntimeError, match="not operable"):
        manage._owned_stack(candidate, current)


def test_create_cannot_skip_explicit_bootstrap(monkeypatch):
    candidate = args(enable=True)
    monkeypatch.setattr(manage, "_stack_or_none", lambda _args: None)

    with pytest.raises(RuntimeError, match="bootstrap explicitly"):
        manage._stack_for_deploy(candidate)


def test_launch_gate_requires_exact_ios_and_android_records(tmp_path):
    candidate = args(create=False, update=True, enable=True)
    target = stack(candidate)["StackId"]
    write_launch_records(tmp_path, candidate, stack_id=target)

    outputs = manage._outputs(stack(candidate))
    assert manage._check_launch_gate(candidate, target, outputs) is None

    candidate.android_launch_record = None
    with pytest.raises(RuntimeError, match="android.*required"):
        manage._check_launch_gate(candidate, target, outputs)


def test_launch_binding_is_read_from_exact_disabled_stack(monkeypatch):
    candidate = args()
    current = stack(candidate, enabled=False)
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: current)

    assert manage.launch_binding(candidate) == launch_binding(
        candidate, stack_id=current["StackId"])

    current["Outputs"] = _output_rows({
        **manage._outputs(current), "Enabled": "true",
    })
    with pytest.raises(RuntimeError, match="disable.*before launch test"):
        manage.launch_binding(candidate)


@pytest.mark.parametrize(("field", "value"), (
    ("deployment_id", "another-deployment"),
    ("delivery_version_arn", DELIVERY_VERSION_ARN[:-1] + "8"),
    ("notification_secret_version_id", "b" * 32),
    ("platform", "android"),
    ("push_node_id", "b" * 64),
    ("result", "accepted"),
    ("schema", "poc16-mobile-notification-launch-v0"),
    ("stack_id", "another-stack"),
    ("software_digest", "b" * 64),
    ("scanner_version_arn", SCANNER_VERSION_ARN[:-1] + "6"),
    ("workspace", "b" * 64),
    ("unexpected", "field"),
))
def test_launch_gate_rejects_stale_or_inexact_evidence(
        tmp_path, field, value):
    candidate = args(create=False, update=True, enable=True)
    target = stack(candidate)["StackId"]
    write_launch_records(tmp_path, candidate, stack_id=target)
    document = json.loads(launch_record(
        candidate, "ios", stack_id=target))
    if field in {"platform", "result", "schema"}:
        document[field] = value
    else:
        document["binding"][field] = value
    Path(candidate.ios_launch_record).write_bytes(canon(document))

    with pytest.raises(RuntimeError, match="invalid ios"):
        manage._check_launch_gate(
            candidate, target, manage._outputs(stack(candidate)))


@pytest.mark.parametrize("raw", (
    b"{}\n",
    b"x" * (MAX_LAUNCH_RECORD_BYTES + 1),
    b"",
))
def test_launch_gate_rejects_noncanonical_or_unbounded_records(
        tmp_path, raw):
    candidate = args(create=False, update=True, enable=True)
    target = stack(candidate)["StackId"]
    write_launch_records(tmp_path, candidate, stack_id=target)
    Path(candidate.ios_launch_record).write_bytes(raw)

    with pytest.raises(RuntimeError, match="invalid ios"):
        manage._check_launch_gate(
            candidate, target, manage._outputs(stack(candidate)))


def test_launch_records_cannot_be_supplied_without_explicit_enable(tmp_path):
    candidate = args(ios_launch_record=str(tmp_path / "ios.json"))
    with pytest.raises(ValueError, match="require explicit --enable"):
        manage._validated(candidate)


@pytest.mark.parametrize("changes", (
    {"NotificationDeliveryVersionArn": None},
    {"NotificationScannerVersionArn": (
        f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
        "function:poc16-notification-scanner")},
    {"NotificationScannerVersionArn": (
        f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
        "function:poc16-notification-scanner:$LATEST")},
    {"NotificationScannerVersionArn": (
        f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
        "function:poc16-notification-scanner:production")},
    {"NotificationDeliveryVersionArn": DELIVERY_VERSION_ARN[:-1] + "0"},
    {"NotificationDeliveryVersionArn": DELIVERY_VERSION_ARN.replace(
        ACCOUNT, "210987654321")},
))
def test_deployment_requires_exact_immutable_lambda_versions(changes):
    current = stack(enabled=False)
    outputs = manage._outputs(current)
    outputs.update(changes)
    with pytest.raises(RuntimeError, match="immutable versions"):
        manage._version_arns(outputs, current["StackId"])


def test_create_is_fully_disabled_by_default_and_checks_real_bindings(
        monkeypatch):
    candidate = args()
    final = stack(candidate, enabled=False)
    commands = []
    checks = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: ("stack", False, None))
    monkeypatch.setattr(manage, "_secret_binding", lambda _args: PUSH_NODE)
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle", lambda _args: checks.append(
            "lifecycle"))
    monkeypatch.setattr(
        manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "build", lambda _args, **_kwargs: checks.append("build"))
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: final)
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kwargs: (
        commands.append(command) or SimpleNamespace(stdout="")))

    outputs = manage.deploy(candidate)

    command = next(row for row in commands if row[:2] == ["sam", "deploy"])
    assert "Enabled=false" in command
    assert f"NotificationSecretVersionId={SECRET_VERSION}" in command
    assert f"PushNodeId={PUSH_NODE}" in command
    assert f"SoftwareDigest={SOFTWARE_DIGEST}" in command
    assert checks == ["lifecycle", "build"]
    assert outputs["NotificationQueueUrl"] == QUEUE_URL


def test_explicit_enable_is_inspected_traffic_only_change_set(
        tmp_path, monkeypatch):
    candidate = args(create=False, update=True, enable=True)
    target = stack(candidate)["StackId"]
    write_launch_records(tmp_path, candidate, stack_id=target)
    incumbent = manage._outputs(stack(candidate, enabled=False))
    final = stack(candidate, enabled=True)
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (target, True, incumbent))
    monkeypatch.setattr(manage, "_secret_binding", lambda _args: PUSH_NODE)
    monkeypatch.setattr(manage, "_verify_state_lifecycle", lambda _args: None)
    monkeypatch.setattr(
        manage, "_prepare_software", lambda:
            pytest.fail("activation prepared mutable software"))
    monkeypatch.setattr(
        manage, "_check_initialized", lambda *_args: effects.append(
            "initialized"))
    monkeypatch.setattr(
        manage, "build", lambda *_args, **_kwargs:
            pytest.fail("activation rebuilt mutable software"))
    observed = iter([stack(candidate, enabled=False), final])
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: next(observed))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)

    def run(command, **_kwargs):
        effects.append(command)
        if command[1:3] == ["cloudformation", "create-change-set"]:
            return SimpleNamespace(stdout=json.dumps({
                "Id": "change-set", "StackId": target,
            }))
        if command[1:3] == ["cloudformation", "describe-change-set"]:
            return SimpleNamespace(stdout=json.dumps(
                traffic_change_set(candidate, target)))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(manage, "_run", run)

    manage.deploy(candidate)

    assert effects[0] == "initialized"
    commands = [effect for effect in effects if isinstance(effect, list)]
    create = next(row for row in commands
                  if row[1:3] == ["cloudformation", "create-change-set"])
    assert "--use-previous-template" in create
    assert "ParameterKey=Enabled,ParameterValue=true" in create
    assert all("UsePreviousValue=true" in value for value in create[
        create.index("--parameters") + 2:create.index("--output")])
    assert any(row[1:3] == ["cloudformation", "describe-change-set"]
               for row in commands)
    assert any(row[1:3] == ["cloudformation", "execute-change-set"]
               for row in commands)
    assert not any(row[0] == "sam" for row in commands)


def test_emergency_disable_needs_no_source_or_deployment_binding(monkeypatch):
    candidate = manage.parser().parse_args([
        "deploy", "--stack-name", "poc16-notifications",
        "--deployment-id", "notify-west-2", "--region", "us-west-2",
        "--update", "--disable",
    ])
    target = stack(candidate)["StackId"]
    incumbent_stack = stack(candidate, enabled=True)
    incumbent = manage._outputs(incumbent_stack)
    final = stack(candidate, enabled=False)
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (target, False, incumbent))
    for name in ("_secret_binding", "_verify_state_lifecycle",
                 "_prepare_software", "build"):
        monkeypatch.setattr(
            manage, name, lambda *_args, _name=name, **_kwargs:
                pytest.fail(f"emergency disable called {_name}"))
    observed = iter([incumbent_stack, final])
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: next(observed))

    def run(command, **_kwargs):
        effects.append(command)
        if command[1:3] == ["cloudformation", "create-change-set"]:
            return SimpleNamespace(stdout=json.dumps({
                "Id": "change-set", "StackId": target,
            }))
        if command[1:3] == ["cloudformation", "describe-change-set"]:
            return SimpleNamespace(stdout=json.dumps(
                traffic_change_set(candidate, target, enabled=False)))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(manage, "_run", run)

    assert manage.deploy(candidate)["Enabled"] == "false"
    create = next(row for row in effects
                  if row[1:3] == ["cloudformation", "create-change-set"])
    assert "ParameterKey=Enabled,ParameterValue=false" in create
    assert "--use-previous-template" in create
    assert not any(row[0] == "sam" for row in effects)


@pytest.mark.parametrize("mutation", ("resource", "replacement", "parameter"))
def test_activation_change_set_rejects_any_nontraffic_change(
        monkeypatch, mutation):
    candidate = args(create=False, update=True, enable=True)
    target = stack(candidate)["StackId"]
    document = traffic_change_set(candidate, target)
    if mutation == "resource":
        document["Changes"].append({
            "ResourceChange": {
                "Action": "Modify",
                "LogicalResourceId": "NotificationDeliveryFunction",
                "Replacement": "False",
                "ResourceType": "AWS::Lambda::Function",
                "Scope": ["Properties"],
            },
            "Type": "Resource",
        })
        message = "resource scope"
    elif mutation == "replacement":
        document["Changes"][0]["ResourceChange"]["Replacement"] = "True"
        message = "resource scope"
    else:
        next(row for row in document["Parameters"]
             if row["ParameterKey"] == "SoftwareDigest")[
                 "UsePreviousValue"] = False
        message = "parameters"
    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        if command[1:3] == ["cloudformation", "create-change-set"]:
            return SimpleNamespace(stdout=json.dumps({
                "Id": "change-set", "StackId": target,
            }))
        if command[1:3] == ["cloudformation", "describe-change-set"]:
            return SimpleNamespace(stdout=json.dumps(document))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(manage, "_run", run)
    with pytest.raises(RuntimeError, match=message):
        manage._create_traffic_change_set(candidate, target, True)
    assert any(row[1:3] == ["cloudformation", "delete-change-set"]
               for row in commands)
    assert not any(row[1:3] == ["cloudformation", "execute-change-set"]
                   for row in commands)


def test_activation_rechecks_disabled_exact_versions_after_change_set(
        tmp_path, monkeypatch):
    candidate = args(create=False, update=True, enable=True)
    target = stack(candidate)["StackId"]
    write_launch_records(tmp_path, candidate, stack_id=target)
    incumbent = manage._outputs(stack(candidate, enabled=False))
    stale_stack = stack(candidate, enabled=False)
    stale = manage._outputs(stale_stack)
    stale["NotificationDeliveryVersionArn"] = (
        DELIVERY_VERSION_ARN[:-1] + "8")
    stale_stack["Outputs"] = _output_rows(stale)
    discarded = []
    monkeypatch.setattr(manage, "_check_initialized", lambda *_args: None)
    monkeypatch.setattr(
        manage, "_create_traffic_change_set",
        lambda *_args: "change-set")
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: stale_stack)
    monkeypatch.setattr(
        manage, "_discard_change_set",
        lambda _args, change_set: discarded.append(change_set))
    monkeypatch.setattr(
        manage, "_run", lambda *_args, **_kwargs:
            pytest.fail("stale activation executed"))

    with pytest.raises(RuntimeError, match="preflight became stale"):
        manage._set_production(
            candidate, target, True, incumbent,
            manage._binding(candidate, PUSH_NODE), PUSH_NODE)
    assert discarded == ["change-set"]


def test_enable_with_missing_launch_evidence_stops_before_build(
        tmp_path, monkeypatch):
    candidate = args(create=False, update=True, enable=True)
    target = stack(candidate)["StackId"]
    ios = tmp_path / "ios.json"
    ios.write_bytes(launch_record(candidate, "ios", stack_id=target))
    candidate.ios_launch_record = str(ios)
    incumbent = manage._outputs(stack(candidate, enabled=False))
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (target, True, incumbent))
    monkeypatch.setattr(manage, "_secret_binding", lambda _args: PUSH_NODE)
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle",
        lambda _args: effects.append("lifecycle"))
    monkeypatch.setattr(
        manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "_check_initialized",
        lambda *_args: effects.append("initialized"))
    monkeypatch.setattr(
        manage, "build", lambda _args, **_kwargs: effects.append("build"))

    with pytest.raises(RuntimeError, match="android.*required"):
        manage.deploy(candidate)
    assert effects == ["lifecycle"]


def test_enabled_update_rejects_untested_software_before_build(
        monkeypatch):
    candidate = args(create=False, update=True)
    incumbent = manage._outputs(stack(
        candidate, enabled=True, software_digest="e" * 64))
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: ("stack", True, incumbent))
    monkeypatch.setattr(manage, "_secret_binding", lambda _args: PUSH_NODE)
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle",
        lambda _args: effects.append("lifecycle"))
    monkeypatch.setattr(
        manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "build", lambda *_args, **_kwargs: effects.append("build"))

    with pytest.raises(
            RuntimeError, match="disable.*before updating deployment"):
        manage.deploy(candidate)
    assert effects == ["lifecycle"]


def test_already_disabled_update_can_stage_new_software(monkeypatch):
    candidate = args(create=False, update=True)
    target = stack(candidate)["StackId"]
    incumbent = manage._outputs(stack(
        candidate, enabled=False, software_digest="e" * 64))
    final = stack(
        candidate, delivery_version=NEW_DELIVERY_VERSION_ARN,
        enabled=False, scanner_version=NEW_SCANNER_VERSION_ARN,
        software_digest=SOFTWARE_DIGEST)
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (target, False, incumbent))
    monkeypatch.setattr(manage, "_secret_binding", lambda _args: PUSH_NODE)
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle", lambda _args: None)
    monkeypatch.setattr(
        manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "build", lambda _args, **_kwargs: effects.append("build"))
    observed = iter([stack(
        candidate, enabled=False, software_digest="e" * 64), final])
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: next(observed))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)

    def run(command, **_kwargs):
        effects.append(command)
        if command[1:3] == ["cloudformation", "create-change-set"]:
            return SimpleNamespace(stdout=json.dumps({
                "Id": "change-set", "StackId": target,
            }))
        if command[1:3] == ["cloudformation", "describe-change-set"]:
            return SimpleNamespace(stdout=json.dumps(
                release_change_set(candidate, target)))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(manage, "_run", run)

    outputs = manage.deploy(candidate)

    assert outputs["SoftwareDigest"] == SOFTWARE_DIGEST
    assert effects[0] == "build"
    commands = [effect for effect in effects if isinstance(effect, list)]
    assert any(row[:2] == ["sam", "package"] for row in commands)
    assert any(row[1:3] == ["cloudformation", "create-change-set"]
               for row in commands)
    assert any(row[1:3] == ["cloudformation", "execute-change-set"]
               for row in commands)
    assert not any(row[:2] == ["sam", "deploy"] for row in commands)


def test_release_change_set_requires_new_functions_and_exact_versions(
        monkeypatch):
    candidate = args(create=False, update=True)
    target = stack(candidate)["StackId"]
    document = release_change_set(candidate, target)
    document["Changes"] = [
        row for row in document["Changes"]
        if row["ResourceChange"]["LogicalResourceId"]
        != "NotificationDeliveryVersion"
    ]
    commands = []
    monkeypatch.setattr(manage, "_package_release", lambda _args: None)

    def run(command, **_kwargs):
        commands.append(command)
        if command[1:3] == ["cloudformation", "create-change-set"]:
            return SimpleNamespace(stdout=json.dumps({
                "Id": "change-set", "StackId": target,
            }))
        if command[1:3] == ["cloudformation", "describe-change-set"]:
            return SimpleNamespace(stdout=json.dumps(document))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(manage, "_run", run)

    with pytest.raises(RuntimeError, match="publish exact Lambda versions"):
        manage._create_release_change_set(
            candidate, target, PUSH_NODE, SOFTWARE_DIGEST, "e" * 64)
    assert any(row[1:3] == ["cloudformation", "delete-change-set"]
               for row in commands)


def test_release_rechecks_disabled_predecessor_after_change_set(monkeypatch):
    candidate = args(create=False, update=True)
    target = stack(candidate)["StackId"]
    incumbent = manage._outputs(stack(
        candidate, enabled=False, software_digest="e" * 64))
    concurrently_enabled = stack(
        candidate, enabled=True, software_digest="e" * 64)
    discarded = []
    monkeypatch.setattr(
        manage, "_create_release_change_set", lambda *_args: "change-set")
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: concurrently_enabled)
    monkeypatch.setattr(
        manage, "_discard_change_set",
        lambda _args, change_set: discarded.append(change_set))
    monkeypatch.setattr(
        manage, "_run", lambda *_args, **_kwargs:
            pytest.fail("stale release executed"))

    with pytest.raises(RuntimeError, match="release preflight became stale"):
        manage._deploy_release(
            candidate, target, incumbent,
            manage._binding(candidate, PUSH_NODE), PUSH_NODE,
            SOFTWARE_DIGEST)
    assert discarded == ["change-set"]


def test_build_refuses_prepared_input_change(monkeypatch):
    calls = []
    monkeypatch.setattr(manage, "_software_digest", lambda: "b" * 64)
    monkeypatch.setattr(
        manage, "_run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(RuntimeError, match="inputs changed"):
        manage.build(expected_digest="a" * 64)
    assert calls == []


def test_enable_preflight_is_one_normal_wake_and_fails_closed(monkeypatch):
    candidate = args()
    outputs = manage._outputs(stack(candidate, enabled=False))
    calls = []
    monkeypatch.setattr(manage, "_invoke", lambda _args, function, payload: (
        calls.append((function, payload)) or {
            "schema": SCAN_RESULT_SCHEMA,
            "status": "idle",
        }))

    assert manage._check_initialized(candidate, outputs) is None
    assert calls == [(
        outputs["NotificationScannerVersionArn"],
        {"schema": SCAN_WAKE_SCHEMA, "workspace": WORKSPACE},
    )]

    monkeypatch.setattr(
        manage, "_invoke", lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("uninitialized")))
    with pytest.raises(RuntimeError, match="bootstrap.*before enabling"):
        manage._check_initialized(candidate, outputs)


@pytest.mark.parametrize(("changes", "push", "field"), (
    ({"workspace": "b" * 64}, PUSH_NODE, "WorkspaceId"),
    ({"canonical_bucket": "other-canonical"}, PUSH_NODE,
     "CanonicalBucketName"),
    ({"canonical_prefix": "other/canonical"}, PUSH_NODE,
     "CanonicalPrefix"),
    ({"state_bucket": "other-state"}, PUSH_NODE,
     "NotificationStateBucketName"),
    ({"state_prefix": "other/state"}, PUSH_NODE,
     "NotificationStatePrefix"),
    ({"notification_secret_arn": SECRET_ARN + "-other"}, PUSH_NODE,
     "NotificationSecretArn"),
    ({"notification_secret_version_id": "b" * 32}, PUSH_NODE,
     "NotificationSecretVersionId"),
    ({"repository_kms_key_arn": (
        f"arn:aws:kms:us-west-2:{ACCOUNT}:key/repository")}, PUSH_NODE,
     "RepositoryKmsKeyArn"),
    ({}, "b" * 64, "PushNodeId"),
))
def test_update_rejects_immutable_binding_change_before_sam_effects(
        monkeypatch, changes, push, field):
    base = args(create=False, update=True)
    candidate = args(create=False, update=True, **changes)
    incumbent = manage._outputs(stack(base, enabled=True))
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: ("stack", True, incumbent))
    monkeypatch.setattr(manage, "_secret_binding", lambda _args: push)
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle", lambda _args: effects.append(
            "lifecycle"))
    monkeypatch.setattr(manage, "build", lambda _args: effects.append("build"))

    with pytest.raises(RuntimeError, match=field):
        manage.deploy(candidate)
    assert effects == []


@pytest.mark.parametrize(
    "unobservable_state", ("stale-zero", "in-flight-publish", "consumer-lease"))
def test_default_remove_never_inferrs_carrier_emptiness(
        monkeypatch, unobservable_state):
    candidate = args()
    calls = []
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(
            candidate, enabled=False))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kwargs: calls.append(
        (unobservable_state, command)))

    with pytest.raises(RuntimeError, match="--destroy-carrier"):
        manage.remove(candidate)
    assert calls == []


def test_destructive_remove_requires_quiescence_and_explicit_flag(
        monkeypatch):
    candidate = args(destroy_carrier=True)
    calls = []
    current = stack(candidate, enabled=True)
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: current)
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kwargs: calls.append(
        command) or SimpleNamespace(stdout=""))

    with pytest.raises(RuntimeError, match="disable production"):
        manage.remove(candidate)
    assert calls == []

    current = stack(candidate, enabled=False)
    manage.remove(candidate)
    assert calls[0][:3] == ["aws", "cloudformation", "delete-stack"]
    assert calls[0][calls[0].index("--stack-name") + 1] == current["StackId"]
    assert all("get-queue-attributes" not in command for command in calls)
    assert all("s3" not in command for command in calls)


def test_disabled_carrier_can_be_redriven_before_restart(monkeypatch):
    candidate = args(max_per_second=25)
    calls = []
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(
            candidate, enabled=False))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kwargs: (
        calls.append(command) or SimpleNamespace(stdout=json.dumps({
            "TaskHandle": "move-task-1"}))))

    assert manage.redrive(candidate) == "move-task-1"
    command = calls[0]
    assert command[:3] == ["aws", "sqs", "start-message-move-task"]
    assert command[command.index("--source-arn") + 1] == DLQ_ARN
    assert command[command.index("--destination-arn") + 1] == QUEUE_ARN


@pytest.mark.parametrize("mode", ("current", "backfill"))
def test_bootstrap_is_explicit_and_uses_the_disabled_scanner(
        monkeypatch, mode):
    candidate = args(bootstrap_mode=mode)
    outputs = manage._outputs(stack(candidate, enabled=False))
    calls = []
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(
            candidate, enabled=False))
    monkeypatch.setattr(manage, "_invoke", lambda _args, function, payload: (
        calls.append((function, payload)) or {
            "mode": mode,
            "schema": BOOTSTRAP_RESULT_SCHEMA,
            "status": "initialized",
        }))

    result = manage.bootstrap(candidate)

    assert result["mode"] == mode
    assert calls == [(
        outputs["NotificationScannerVersionArn"],
        {
            "mode": mode,
            "schema": BOOTSTRAP_SCHEMA,
            "workspace": WORKSPACE,
        },
    )]


def test_bootstrap_refuses_an_enabled_deployment(monkeypatch):
    candidate = args(bootstrap_mode="current")
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(candidate, enabled=True))
    monkeypatch.setattr(manage, "_invoke", lambda *_args, **_kwargs:
                        pytest.fail("enabled bootstrap invoked Lambda"))

    with pytest.raises(RuntimeError, match="disable.*before bootstrap"):
        manage.bootstrap(candidate)


def test_direct_smoke_is_independent_of_production_and_proves_acceptance(
        tmp_path, monkeypatch):
    candidate = args(
        hint_file=str(tmp_path / "hint.json"), confirm_live_fcm=True)
    raw = encode_hint(NotificationHint(
        WORKSPACE, HINT_OWNER, GENERATION,
        h(b"event root"), (h(b"event"),)))
    Path(candidate.hint_file).write_bytes(raw)
    calls = []
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(
            candidate, enabled=False))
    monkeypatch.setattr(manage, "_invoke", lambda _args, function, payload: (
        calls.append((function, payload)) or {
            "accepted_count": 1,
            "retry_count": 0,
            "schema": DIRECT_SMOKE_RESULT_SCHEMA,
            "terminal_count": 0,
        }))

    result = manage.direct_smoke(candidate)

    assert result["accepted_count"] == 1
    assert len(calls) == 1
    function, payload = calls[0]
    assert function == DELIVERY_VERSION_ARN
    assert payload["schema"] == DIRECT_SMOKE_SCHEMA
    assert "Records" not in payload
    assert base64.b64decode(payload["body"], validate=True) == raw


def test_direct_smoke_requires_explicit_live_fcm_confirmation(monkeypatch):
    candidate = args(hint_file="unused")
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args:
            pytest.fail("unconfirmed smoke inspected AWS"))
    monkeypatch.setattr(
        manage, "_invoke", lambda *_args, **_kwargs:
            pytest.fail("disabled direct smoke invoked Lambda"))

    with pytest.raises(RuntimeError, match="confirm live FCM"):
        manage.direct_smoke(candidate)


def test_direct_smoke_requires_disabled_production(monkeypatch):
    candidate = args(hint_file="unused", confirm_live_fcm=True)
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(candidate, enabled=True))
    monkeypatch.setattr(
        manage, "_invoke", lambda *_args, **_kwargs:
            pytest.fail("enabled deployment invoked direct smoke"))

    with pytest.raises(RuntimeError, match="disable.*before smoke"):
        manage.direct_smoke(candidate)


@pytest.mark.parametrize("counts", (
    (0, 0, 0),
    (1, 1, 0),
    (1, 0, 1),
))
def test_direct_smoke_rejects_no_recipient_retry_and_terminal_outcomes(
        tmp_path, monkeypatch, counts):
    candidate = args(
        hint_file=str(tmp_path / "hint.json"), confirm_live_fcm=True)
    Path(candidate.hint_file).write_bytes(encode_hint(NotificationHint(
        WORKSPACE, HINT_OWNER, GENERATION,
        h(b"root"), (h(b"event"),))))
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(
            candidate, enabled=False))
    accepted, retry, terminal = counts
    monkeypatch.setattr(manage, "_invoke", lambda *_args, **_kwargs: {
        "accepted_count": accepted,
        "retry_count": retry,
        "schema": DIRECT_SMOKE_RESULT_SCHEMA,
        "terminal_count": terminal,
    })

    with pytest.raises(RuntimeError, match="no clean provider acceptance"):
        manage.direct_smoke(candidate)


def test_direct_smoke_and_production_defaults_are_separate():
    parsed = manage.parser().parse_args([
        "deploy", "--stack-name", "stack", "--deployment-id", "deploy-id",
        "--workspace", WORKSPACE,
        "--canonical-bucket", "canonical-bucket",
        "--canonical-prefix", "canonical/root",
        "--state-bucket", "state-bucket",
        "--state-prefix", "notification/root",
        "--expected-owner", ACCOUNT,
        "--notification-secret-arn", SECRET_ARN,
        "--notification-secret-version-id", SECRET_VERSION,
        "--create",
    ])
    assert parsed.enable is None
    assert parsed.ios_launch_record is None
    assert parsed.android_launch_record is None
    assert manage.parser().parse_args(["build"]).command == "build"
