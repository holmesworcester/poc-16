"""AWS notification packaging, authority, and lifecycle tests."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.crypto import h
from deploy.aws_notifications import manage
from deploy.aws_notifications.config import (
    DEPLOYMENT_ID_TAG,
    DEPLOYMENT_MARKER,
    DEPLOYMENT_TAG,
)
from notifications.hints import NotificationHint, encode_hint


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "deploy" / "aws_notifications"
WORKSPACE = "a" * 64
ACCOUNT = "123456789012"
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
        "create": True,
        "delivery_concurrency": 10,
        "deployment_id": "notify-west-2",
        "discard_pending": False,
        "enable": None,
        "expected_owner": ACCOUNT,
        "max_per_second": 10,
        "max_receive_count": 5,
        "notification_secret_arn": (
            f"arn:aws:secretsmanager:us-west-2:{ACCOUNT}:"
            "secret:poc16/notification-AbCdEf"
        ),
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
        "state_retention_days": 30,
        "update": False,
        "workspace": WORKSPACE,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def stack(candidate=None, *, enabled=True):
    candidate = args() if candidate is None else candidate
    outputs = [
        {"OutputKey": "DeploymentMarker", "OutputValue": DEPLOYMENT_MARKER},
        {"OutputKey": "DeploymentId", "OutputValue": candidate.deployment_id},
        {"OutputKey": "WorkspaceId", "OutputValue": WORKSPACE},
        {"OutputKey": "Enabled", "OutputValue": (
            "true" if enabled else "false")},
        {
            "OutputKey": "NotificationStateMinimumRetentionDays",
            "OutputValue": str(candidate.state_retention_days),
        },
    ]
    outputs.extend((
        {"OutputKey": "NotificationQueueArn", "OutputValue": QUEUE_ARN},
        {"OutputKey": "NotificationQueueUrl", "OutputValue": QUEUE_URL},
        {
            "OutputKey": "NotificationDeadLetterQueueArn",
            "OutputValue": DLQ_ARN,
        },
        {
            "OutputKey": "NotificationDeadLetterQueueUrl",
            "OutputValue": DLQ_URL,
        },
    ))
    if enabled:
        outputs.extend((
            {
                "OutputKey": "NotificationScannerFunctionArn",
                "OutputValue": (
                    f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
                    "function:poc16-notification-scanner"),
            },
            {
                "OutputKey": "NotificationDeliveryFunctionArn",
                "OutputValue": (
                    f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
                    "function:poc16-notification-delivery"),
            },
        ))
    return {
        "Outputs": outputs,
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


def test_stage_is_importable_and_contains_only_shared_read_side(tmp_path):
    staged = manage.stage(tmp_path / "stage")
    for relative in (
            "adapters/aws/sqs.py",
            "adapters/gcp/firebase.py",
            "adapters/s3/store.py",
            "core/repository_reader.py",
            "deploy/aws_notifications/app.py",
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


def test_template_separates_roles_and_has_no_repository_write_door():
    template = (PACKAGE / "template.yaml").read_text()
    scanner = template.split("NotificationScannerRole:", 1)[1].split(
        "NotificationDeliveryRole:", 1)[0]
    delivery = template.split("NotificationDeliveryRole:", 1)[1].split(
        "NotificationScannerFunction:", 1)[0]

    assert "Default: \"false\"" in template
    assert template.count("Condition: NotificationsEnabled") >= 8
    assert "Handler: deploy.aws_notifications.app.scanner_handler" in template
    assert "Handler: deploy.aws_notifications.app.delivery_handler" in template
    assert "FunctionResponseTypes:\n        - ReportBatchItemFailures" in template
    assert "VisibilityTimeout: 360" in template
    assert "Timeout: 60" in template
    assert "MinValue: 5" in template
    assert "RedrivePolicy:" in template
    assert "NotificationStateMinimumRetentionDays:" in template
    assert "MinValue: 30" in template
    assert "ApproximateAgeOfOldestMessage" in template
    assert "ApproximateNumberOfMessagesVisible" in template
    assert "AWS::SQS::Queue" in template
    assert "FifoQueue" not in template
    source_queue = template.split(
        "NotificationQueue:", 1)[1].split("NotificationScannerRole:", 1)[0]
    dead_queue = template.split(
        "NotificationDeadLetterQueue:", 1)[1].split(
            "NotificationQueue:", 1)[0]
    assert "Condition: NotificationsEnabled" not in source_queue
    assert "Condition: NotificationsEnabled" not in dead_queue

    assert "s3:GetObject" in scanner
    assert "s3:PutObject" in scanner
    assert "sqs:SendMessage" in scanner
    assert "sqs:ReceiveMessage" not in scanner
    assert "secretsmanager:GetSecretValue" not in scanner
    assert "s3:GetObject" in delivery
    assert "s3:PutObject" not in delivery
    assert "sqs:SendMessage" not in delivery
    assert "secretsmanager:GetSecretValue" in delivery
    assert "kms:EncryptionContext:SecretARN" in delivery
    assert '"secretsmanager.${AWS::Region}.${AWS::URLSuffix}"' in delivery
    assert "kms:CallerAccount: !Ref AWS::AccountId" in delivery
    assert "sqs:ChangeMessageVisibility" in delivery
    assert "sqs:DeleteMessage" in delivery
    assert "sqs:ReceiveMessage" in delivery

    for forbidden in (
            "s3:ListBucket", "s3:DeleteObject", "AWS::S3::Bucket",
            "RepositoryApplier", "full_peer", "sqlite", "FactOrder"):
        assert forbidden not in template
    assert "${CanonicalPrefix}/root" in scanner
    assert "${CanonicalPrefix}/root" in delivery
    # Delivery reads retained event-root objects, never the cursor CAS root.
    historical = delivery.split("ReadHistoricalNotificationRoot", 1)[1]
    assert "${NotificationStatePrefix}/obj/*" in historical
    assert "${NotificationStatePrefix}/root" not in historical


def test_requirements_are_hash_locked_for_lambda_and_firebase():
    requirements = (PACKAGE / "requirements.txt").read_text()
    assert "--only-binary=:all:" in requirements
    assert "--require-hashes" in requirements
    assert "firebase-admin==7.5.0" in requirements
    assert "boto3==1.43.51" in requirements
    assert requirements.count("--hash=sha256:") >= 40


def test_same_bucket_requires_disjoint_state_and_repository_prefixes():
    with pytest.raises(ValueError, match="prefixes overlap"):
        manage._validated(args(
            state_bucket="canonical-bucket",
            state_prefix=f"workspaces/{WORKSPACE}/notifications",
        ))
    assert manage._validated(args(
        state_bucket="canonical-bucket",
        state_prefix=f"notification-state/{WORKSPACE}",
    )).workspace == WORKSPACE


def test_state_root_retention_covers_source_and_dlq_horizons():
    with pytest.raises(ValueError, match="state retention"):
        manage._validated(args(state_retention_days=29))
    assert manage._validated(args(
        state_retention_days=30)).state_retention_days == 30


def test_deploy_is_disabled_unless_operator_explicitly_enables(
        monkeypatch):
    candidate = args()
    commands = []
    monkeypatch.setattr(manage, "build", lambda _args: None)
    monkeypatch.setattr(
        manage, "_stack_for_deploy", lambda _args: ("stack", False))
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(candidate, enabled=False))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kw: commands.append(
        command) or SimpleNamespace(stdout=""))

    outputs = manage.deploy(candidate)

    command = next(row for row in commands if row[:2] == ["sam", "deploy"])
    assert "Enabled=false" in command
    assert outputs["Enabled"] == "false"
    assert outputs["NotificationQueueUrl"] == QUEUE_URL


@pytest.mark.parametrize("incumbent", (False, True))
def test_update_without_switch_preserves_incumbent_traffic_state(
        monkeypatch, incumbent):
    candidate = args(create=False, update=True, enable=None)
    current = stack(candidate, enabled=incumbent)
    monkeypatch.setattr(manage, "_stack_or_none", lambda _args: current)
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args, _stack=None: current)

    assert manage._stack_for_deploy(candidate) == (
        current["StackId"], incumbent)


def test_explicit_disable_retains_both_carrier_queues(monkeypatch):
    candidate = args(create=False, update=True, enable=False)
    current = stack(candidate, enabled=True)
    monkeypatch.setattr(manage, "_stack_or_none", lambda _args: current)
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args, _stack=None: current)

    assert manage._stack_for_deploy(candidate) == (
        current["StackId"], False)
    template = (PACKAGE / "template.yaml").read_text()
    for name in (
            "NotificationQueue", "NotificationDeadLetterQueue"):
        resource = template.split(f"  {name}:\n", 1)[1].split("\n  ", 1)[0]
        assert "Condition:" not in resource


def test_enabled_deploy_checks_exact_queue_identity(monkeypatch):
    candidate = args(enable=True)
    commands = []
    monkeypatch.setattr(manage, "build", lambda _args: None)
    monkeypatch.setattr(
        manage, "_stack_for_deploy", lambda _args: ("stack", True))
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(candidate, enabled=True))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kw: commands.append(
        command) or SimpleNamespace(stdout=""))

    outputs = manage.deploy(candidate)

    command = next(row for row in commands if row[:2] == ["sam", "deploy"])
    assert "Enabled=true" in command
    assert outputs["NotificationQueueArn"] == QUEUE_ARN


def test_remove_never_treats_approximate_zero_as_safe_deletion(monkeypatch):
    candidate = args()
    calls = []
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(candidate, enabled=True))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kw: calls.append(
        command))

    with pytest.raises(RuntimeError, match="durable notification carrier"):
        manage.remove(candidate)
    assert calls == []


def test_explicit_discard_removes_only_the_owned_stack(monkeypatch):
    candidate = args(discard_pending=True)
    calls = []
    owned = stack(candidate, enabled=True)
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: owned)
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kw: calls.append(
        command) or SimpleNamespace(stdout=""))

    manage.remove(candidate)

    assert calls[0][:3] == ["aws", "cloudformation", "delete-stack"]
    assert calls[0][calls[0].index("--stack-name") + 1] == owned["StackId"]
    assert all("s3" not in command for command in calls)


def test_redrive_is_explicit_bounded_and_targets_the_source_queue(
        monkeypatch):
    candidate = args(max_per_second=25)
    calls = []
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(candidate, enabled=True))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kw: calls.append(
        command) or SimpleNamespace(stdout=json.dumps({
            "TaskHandle": "move-task-1"})))

    assert manage.redrive(candidate) == "move-task-1"
    command = calls[0]
    assert command[:3] == ["aws", "sqs", "start-message-move-task"]
    assert command[command.index("--source-arn") + 1] == DLQ_ARN
    assert command[command.index("--destination-arn") + 1] == QUEUE_ARN
    assert command[command.index(
        "--max-number-of-messages-per-second") + 1] == "25"


def test_live_firebase_smoke_is_never_part_of_build_or_deploy():
    parsed = manage.parser().parse_args(["build"])
    assert parsed.command == "build"
    assert "live-smoke" not in manage._parameters(args())


def test_opt_in_live_smoke_invokes_scanner_and_real_delivery_shape(
        tmp_path, monkeypatch):
    candidate = args(hint_file=str(tmp_path / "hint.json"))
    raw = encode_hint(NotificationHint(
        WORKSPACE, h(b"event root"), (h(b"event"),)))
    Path(candidate.hint_file).write_bytes(raw)
    calls = []
    monkeypatch.setattr(
        manage, "_owned_stack", lambda _args: stack(candidate, enabled=True))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)

    def invoke(_args, function, payload):
        calls.append((function, payload))
        return {"batchItemFailures": []} \
            if "delivery" in function else {
                "schema": "poc16-notification-scan-result-v1",
                "status": "idle",
            }

    monkeypatch.setattr(manage, "_invoke", invoke)

    result = manage.live_smoke(candidate)

    assert len(calls) == 2
    scanner_function, scanner_payload = calls[0]
    assert "scanner" in scanner_function
    assert scanner_payload["workspace"] == WORKSPACE
    delivery_function, delivery_payload = calls[1]
    assert "delivery" in delivery_function
    record = delivery_payload["Records"][0]
    assert record["eventSourceARN"] == QUEUE_ARN
    assert base64.b64decode(record["body"], validate=True) == raw
    assert result["delivery"] == {"batchItemFailures": []}
