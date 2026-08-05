"""AWS notification packaging, authority, and lifecycle tests."""
import base64
import hashlib
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
from notifications.hints import EventRef, NotificationHint, encode_hint


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
DELIVERY_DOMAIN = "d" * 64
SCANNER_CODE_SHA256 = base64.b64encode(
    hashlib.sha256(b"scanner zip").digest()).decode("ascii")
DELIVERY_CODE_SHA256 = base64.b64encode(
    hashlib.sha256(b"delivery zip").digest()).decode("ascii")
CODE_HASHES = {
    "ScannerCodeSha256": SCANNER_CODE_SHA256,
    "DeliveryCodeSha256": DELIVERY_CODE_SHA256,
}
NEW_SCANNER_CODE_SHA256 = base64.b64encode(
    hashlib.sha256(b"new scanner zip").digest()).decode("ascii")
NEW_DELIVERY_CODE_SHA256 = base64.b64encode(
    hashlib.sha256(b"new delivery zip").digest()).decode("ascii")
NEW_CODE_HASHES = {
    "ScannerCodeSha256": NEW_SCANNER_CODE_SHA256,
    "DeliveryCodeSha256": NEW_DELIVERY_CODE_SHA256,
}
DELIVERY_VERSION_ARN = (
    f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
    "function:poc16-notifications-notification-delivery:7")
SCANNER_VERSION_ARN = (
    f"arn:aws:lambda:us-west-2:{ACCOUNT}:"
    "function:poc16-notifications-notification-scanner:5")
NEW_DELIVERY_VERSION_ARN = DELIVERY_VERSION_ARN[:-1] + "8"
NEW_SCANNER_VERSION_ARN = SCANNER_VERSION_ARN[:-1] + "6"
QUEUE_ARN = f"arn:aws:sqs:us-west-2:{ACCOUNT}:poc16-notifications"
QUEUE_URL = (
    f"https://sqs.us-west-2.amazonaws.com/{ACCOUNT}/poc16-notifications"
)
DLQ_ARN = QUEUE_ARN + "-dlq"
DLQ_URL = QUEUE_URL + "-dlq"
MAPPING_UUID = "11111111-2222-3333-4444-555555555555"
SCHEDULE_NAME = "poc16-notifications-notification-scan"
SCANNER_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/poc16-notifications-scanner")
DELIVERY_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/poc16-notifications-delivery")


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
          delivery_code=DELIVERY_CODE_SHA256,
          delivery_domain=DELIVERY_DOMAIN, enabled=True, push_node=PUSH_NODE,
          scanner_version=SCANNER_VERSION_ARN,
          scanner_code=SCANNER_CODE_SHA256,
          software_digest=SOFTWARE_DIGEST):
    candidate = args() if candidate is None else candidate
    outputs = {
        "AwsPartition": "aws",
        "CanonicalBucketName": candidate.canonical_bucket,
        "CanonicalPrefix": candidate.canonical_prefix,
        "DeploymentId": candidate.deployment_id,
        "DeploymentMarker": DEPLOYMENT_MARKER,
        "DeliveryCodeSha256": delivery_code,
        "DeliveryDomainId": delivery_domain,
        "Enabled": "true" if enabled else "false",
        "ExpectedBucketOwner": candidate.expected_owner,
        "NotificationDeadLetterQueueArn": DLQ_ARN,
        "NotificationDeadLetterQueueUrl": DLQ_URL,
        "NotificationDeadLetterRetentionSeconds": DLQ_RETENTION_SECONDS,
        "NotificationDeliveryVersionArn": delivery_version,
        "NotificationDeliveryMappingUuid": MAPPING_UUID,
        "NotificationDeliveryRoleArn": DELIVERY_ROLE_ARN,
        "NotificationDeliveryReservedConcurrency": str(
            candidate.delivery_concurrency),
        "NotificationQueueArn": QUEUE_ARN,
        "NotificationQueueUrl": QUEUE_URL,
        "NotificationQueueRetentionSeconds": QUEUE_RETENTION_SECONDS,
        "NotificationMaxReceiveCount": str(candidate.max_receive_count),
        "NotificationLogRetentionDays": str(manage.LOG_RETENTION_DAYS),
        "NotificationAlarmActionArn": candidate.alarm_action_arn or "",
        "NotificationScannerVersionArn": scanner_version,
        "NotificationScannerRoleArn": SCANNER_ROLE_ARN,
        "NotificationScannerReservedConcurrency": str(
            candidate.scanner_concurrency),
        "NotificationScanScheduleName": SCHEDULE_NAME,
        "NotificationScanScheduleExpression": candidate.schedule,
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
        "ScannerCodeSha256": scanner_code,
        "StackAccountId": ACCOUNT,
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
                   delivery_domain=DELIVERY_DOMAIN,
                   software_digest=SOFTWARE_DIGEST):
    return {
        "aws_partition": "aws",
        "canonical_bucket": candidate.canonical_bucket,
        "canonical_prefix": candidate.canonical_prefix,
        "deployment_id": candidate.deployment_id,
        "delivery_domain_id": delivery_domain,
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
        "stack_account_id": ACCOUNT,
        "stack_id": stack(candidate)["StackId"] if stack_id is None
        else stack_id,
        "workspace": candidate.workspace,
    }


def traffic_change_set(candidate, stack_id, *, enabled=True, changes=None,
                       push_node=PUSH_NODE,
                       software_digest=SOFTWARE_DIGEST):
    values = manage._parameter_values(
        candidate, enabled, push_node, DELIVERY_DOMAIN, software_digest,
        CODE_HASHES)
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
                       code_hashes=CODE_HASHES,
                       resources=None,
                       software_digest=SOFTWARE_DIGEST):
    values = manage._parameter_values(
        candidate, False, PUSH_NODE, DELIVERY_DOMAIN, software_digest,
        code_hashes)
    resources = resources or (
        "NotificationScannerFunction",
        "NotificationDeliveryFunction",
        "NotificationScannerVersion",
        "NotificationDeliveryVersion",
    )
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
        } for name in resources],
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


def _live_documents(candidate=None, *, enabled=False):
    candidate = args() if candidate is None else candidate
    current = stack(candidate, enabled=enabled)
    outputs = manage._outputs(current)
    versions = manage._version_arns(outputs, current["StackId"])
    documents = {}
    for role in ("scanner", "delivery"):
        arn = versions[f"{role}_version_arn"]
        documents[("lambda", role)] = {
            "Architectures": ["x86_64"],
            "CodeSha256": outputs[f"{role.title()}CodeSha256"],
            "Description": outputs["SoftwareDigest"] if role == "scanner"
            else (f'{outputs["SoftwareDigest"]}:'
                  f'{outputs["NotificationSecretVersionId"]}'),
            "Environment": {
                "Variables": manage._expected_version_environment(
                    outputs, role),
            },
            "FunctionArn": arn,
            "FunctionName": arn.split(":")[-2],
            "Handler": (
                f"deploy.aws_notifications.app.{role}_handler"),
            "LastUpdateStatus": "Successful",
            "MemorySize": 1024,
            "PackageType": "Zip",
            "Role": outputs[f"Notification{role.title()}RoleArn"],
            "Runtime": "python3.13",
            "RuntimeVersionConfig": {
                "RuntimeVersionArn": (
                    f"arn:aws:lambda:us-west-2::{role}-runtime"),
            },
            "State": "Active",
            "Timeout": 60,
            "Version": arn.rsplit(":", 1)[1],
        }
        documents[("runtime", role)] = {
            "FunctionArn": arn,
            "RuntimeVersionArn": None,
            "UpdateRuntimeOn": "FunctionUpdate",
        }
        documents[("concurrency", role)] = {
            "ReservedConcurrentExecutions": int(outputs[
                f"Notification{role.title()}ReservedConcurrency"]),
        }
    documents["mapping"] = {
        "BatchSize": 10,
        "EventSourceArn": outputs["NotificationQueueArn"],
        "FunctionArn": versions["delivery_version_arn"],
        "FunctionResponseTypes": ["ReportBatchItemFailures"],
        "State": "Enabled" if enabled else "Disabled",
        "UUID": outputs["NotificationDeliveryMappingUuid"],
    }
    documents["rule"] = {
        "Arn": (
            f"arn:aws:events:us-west-2:{ACCOUNT}:rule/{SCHEDULE_NAME}"),
        "CreatedBy": ACCOUNT,
        "EventBusName": "default",
        "Name": outputs["NotificationScanScheduleName"],
        "ScheduleExpression": outputs["NotificationScanScheduleExpression"],
        "State": "ENABLED" if enabled else "DISABLED",
    }
    documents["targets"] = {"Targets": [{
        "Arn": versions["scanner_version_arn"],
        "Id": "notification-scanner",
    }]}
    return outputs, versions, documents


def _live_run(documents, calls):
    def run(command, **_kwargs):
        calls.append(command)
        if command[1:3] == ["lambda", "get-function-configuration"]:
            role = "scanner" if "scanner" in command[4] else "delivery"
            value = documents[("lambda", role)]
        elif command[1:3] == ["lambda", "get-function-concurrency"]:
            role = "scanner" if "scanner" in command[4] else "delivery"
            value = documents[("concurrency", role)]
        elif command[1:3] == ["lambda", "get-runtime-management-config"]:
            role = "scanner" if "scanner" in command[4] else "delivery"
            value = documents[("runtime", role)]
        elif command[1:3] == ["lambda", "get-event-source-mapping"]:
            value = documents["mapping"]
        elif command[1:3] == ["events", "describe-rule"]:
            value = documents["rule"]
        elif command[1:3] == ["events", "list-targets-by-rule"]:
            value = documents["targets"]
        else:
            raise AssertionError(command)
        return SimpleNamespace(stdout=json.dumps(value))
    return run


def test_stage_is_importable_and_contains_only_shared_consumer_side(tmp_path):
    staged = manage.stage(tmp_path / "stage")
    for relative in (
            "adapters/aws/sqs.py",
            "adapters/gcp/firebase.py",
            "adapters/s3/store.py",
            "core/writer_repository.py",
            "deploy/notification_launch.py",
            "deploy/aws_notifications/app.py",
            "deploy/aws_notifications/secret.py",
            "facts/auth/push_endpoint.py",
            "notifications/discovery.py",
            "notifications/forest.py",
            "notifications/hints.py",
            "notifications/worker.py"):
        assert (staged / relative).is_file()
    for forbidden in (
            "core/repository_applier.py",
            "core/repository_reader.py",
            "core/repository_snapshot.py",
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
    scanner_function = template.split(
        "  NotificationScannerFunction:\n", 1)[1].split(
            "\n  NotificationDeliveryFunction:", 1)[0]
    delivery_function = template.split(
        "  NotificationDeliveryFunction:\n", 1)[1].split(
            "\n  NotificationScannerVersion:", 1)[0]

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
    assert "TINYP2P_NOTIFICATION_DELIVERY_DOMAIN_ID" in scanner_function
    assert "TINYP2P_NOTIFICATION_SECRET_ARN" not in scanner_function
    assert "TINYP2P_NOTIFICATION_SECRET_VERSION_ID" not in scanner_function
    assert "TINYP2P_NOTIFICATION_PUSH_NODE_ID" not in scanner_function
    assert "TINYP2P_NOTIFICATION_SECRET_VERSION_ID" in delivery_function
    assert "TINYP2P_NOTIFICATION_PUSH_NODE_ID" in delivery_function
    assert "TINYP2P_NOTIFICATION_SCANNER_VERSION_ARN" in delivery_function
    assert "TINYP2P_NOTIFICATION_DIRECT_SMOKE_ENABLED" not in template
    assert template.count("TINYP2P_NOTIFICATION_SOFTWARE_DIGEST") == 2
    assert template.count("Type: AWS::Lambda::Version") == 2
    assert template.count("Description: !Ref SoftwareDigest") == 1
    assert 'Description: !Sub "${SoftwareDigest}:' \
        '${NotificationSecretVersionId}"' in template
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
    assert "s3:ListBucket" in scanner
    assert "s3:PutObject" in scanner
    assert "sqs:SendMessage" in scanner
    assert "sqs:ReceiveMessage" not in scanner
    assert "secretsmanager:GetSecretValue" not in scanner
    assert "s3:GetObject" in delivery
    assert "s3:ListBucket" in delivery
    assert delivery.count("s3:PutObject") == 1
    assert "sqs:SendMessage" not in delivery
    assert "lambda:InvokeFunction" in delivery
    assert "Resource: !Ref NotificationScannerVersion" in delivery
    assert "secretsmanager:GetSecretValue" in delivery
    assert "kms:EncryptionContext:SecretARN" in delivery
    assert "sqs:ReceiveMessage" in delivery

    for forbidden in (
            "s3:DeleteObject", "AWS::S3::Bucket",
            "RepositoryApplier", "full_peer", "sqlite", "FactOrder"):
        assert forbidden not in template
    assert template.count("ListCanonicalWriterHeads") == 2
    assert template.count(
        "${CanonicalPrefix}/heads/${WorkspaceId}/*") == 4
    historical = delivery.split("ReadPendingNotificationFacts", 1)[1]
    assert "${NotificationStatePrefix}/obj/*" in historical
    completion = historical.split("CompleteNotificationCursor", 1)[1].split(
        "ReadExactNotificationSecret", 1)[0]
    historical = historical.split("CompleteNotificationCursor", 1)[0]
    assert "s3:PutObject" not in historical
    assert "${NotificationStatePrefix}/cursor" not in historical
    assert "s3:PutObject" in completion
    assert "${NotificationStatePrefix}/cursor" in completion
    assert "${NotificationStatePrefix}/obj/*" not in completion


def test_requirements_are_hash_locked_for_lambda_and_firebase():
    requirements = (PACKAGE / "requirements.txt").read_text()
    assert "--only-binary=:all:" in requirements
    assert "--require-hashes" in requirements
    assert "firebase-admin==7.5.0" in requirements
    assert "boto3==1.43.51" in requirements
    assert requirements.count("--hash=sha256:") >= 40


def test_packaging_hashes_exact_provider_zip_snapshot_and_detects_mutation(
        tmp_path, monkeypatch):
    packaged = tmp_path / "packaged.json"
    monkeypatch.setattr(manage, "PACKAGED", packaged)
    artifacts = {
        ("sam-artifacts", "scanner.zip", "scanner-version"): b"scanner-v1",
        ("sam-artifacts", "delivery.zip", None): b"delivery-v1",
    }
    commands = []
    document = {
        "Resources": {
            "NotificationScannerFunction": {"Properties": {"CodeUri": {
                "Bucket": "sam-artifacts",
                "Key": "scanner.zip",
                "Version": "scanner-version",
            }}},
            "NotificationDeliveryFunction": {"Properties": {
                "CodeUri": "s3://sam-artifacts/delivery.zip",
            }},
        },
    }

    def run(command, **_kwargs):
        commands.append(command)
        if command[:2] == ["sam", "package"]:
            packaged.write_text(json.dumps(document))
            return SimpleNamespace(stdout="")
        if command[1:3] == ["sts", "get-caller-identity"]:
            return SimpleNamespace(stdout=json.dumps({"Account": ACCOUNT}))
        assert command[1:3] == ["s3api", "get-object"]
        bucket = command[command.index("--bucket") + 1]
        key = command[command.index("--key") + 1]
        version = command[command.index("--version-id") + 1] \
            if "--version-id" in command else None
        Path(command[-1]).write_bytes(artifacts[(bucket, key, version)])
        return SimpleNamespace(stdout="{}")

    monkeypatch.setattr(manage, "_run", run)

    first = manage._package_release(args())
    artifacts[("sam-artifacts", "delivery.zip", None)] = b"delivery-v2"
    second = manage._package_release(args())

    encode = lambda value: base64.b64encode(
        hashlib.sha256(value).digest()).decode("ascii")
    assert first == {
        "ScannerCodeSha256": encode(b"scanner-v1"),
        "DeliveryCodeSha256": encode(b"delivery-v1"),
    }
    assert second == {
        "ScannerCodeSha256": encode(b"scanner-v1"),
        "DeliveryCodeSha256": encode(b"delivery-v2"),
    }
    gets = [row for row in commands
            if row[1:3] == ["s3api", "get-object"]]
    assert all(row[row.index("--expected-bucket-owner") + 1] == ACCOUNT
               for row in gets)
    assert any("--version-id" in row for row in gets)
    assert all("--use-json" in row for row in commands
               if row[:2] == ["sam", "package"])


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


def test_authoritative_lifecycles_accept_absence_and_never_mutate_buckets(
        monkeypatch):
    calls = []
    error = subprocess.CalledProcessError(
        255, ["aws"], stderr="NoSuchLifecycleConfiguration")

    def run(command, **_kwargs):
        calls.append(command)
        raise error

    monkeypatch.setattr(manage, "_run", run)

    assert manage._verify_state_lifecycle(args()) is None
    expected = lambda bucket: [
        "aws", "s3api", "get-bucket-lifecycle-configuration",
        "--bucket", bucket,
        "--expected-bucket-owner", ACCOUNT,
        "--output", "json", "--region", "us-west-2",
    ]
    assert calls == [
        expected("canonical-bucket"),
        expected("notification-state-bucket"),
    ]


@pytest.mark.parametrize(("field", "label", "storage", "message"), (
    ("Expiration", "canonical", None, "may expire"),
    ("NoncurrentVersionExpiration", "canonical", None, "may expire"),
    ("Transitions", "canonical", "GLACIER", "require restore"),
    ("NoncurrentVersionTransitions", "canonical", "DEEP_ARCHIVE",
     "require restore"),
    ("Transitions", "canonical", "INTELLIGENT_TIERING", "require restore"),
    ("Transitions", "canonical", "FUTURE_UNKNOWN", "require restore"),
    ("Expiration", "notification-state", None, "may expire"),
    ("Transitions", "notification-state", "GLACIER", "require restore"),
))
def test_authoritative_lifecycles_reject_expiration_and_archive_transition(
        monkeypatch, field, label, storage, message):
    buckets = []
    value = {"Days": 31} if storage is None else [{
        "Days": 30, "StorageClass": storage}]

    def run(command, **_kwargs):
        bucket = command[command.index("--bucket") + 1]
        buckets.append(bucket)
        if (label == "canonical") == (bucket == "canonical-bucket"):
            return SimpleNamespace(stdout=json.dumps({"Rules": [{
                field: value,
                "ID": "unsafe",
                "Status": "Enabled",
            }]}))
        return SimpleNamespace(stdout=json.dumps({"Rules": []}))

    monkeypatch.setattr(manage, "_run", run)
    with pytest.raises(RuntimeError, match=(f"{label}.*{message}")):
        manage._verify_state_lifecycle(args())
    assert buckets[-1] == (
        "canonical-bucket" if label == "canonical"
        else "notification-state-bucket")


def test_authoritative_lifecycles_allow_disabled_rules(monkeypatch):
    response = SimpleNamespace(stdout=json.dumps({"Rules": [{
        "Expiration": {"Days": 31},
        "ID": "disabled-expiration",
        "Status": "Disabled",
        "Transitions": [{"Days": 30, "StorageClass": "GLACIER"}],
    }]}))
    monkeypatch.setattr(manage, "_run", lambda *_args, **_kwargs: response)
    assert manage._verify_state_lifecycle(args()) is None


@pytest.mark.parametrize(
    "storage", ("STANDARD_IA", "ONEZONE_IA", "GLACIER_IR"))
def test_authoritative_lifecycles_allow_synchronously_readable_transitions(
        monkeypatch, storage):
    response = SimpleNamespace(stdout=json.dumps({"Rules": [{
        "Filter": {"Prefix": ""},
        "ID": "synchronous",
        "Status": "Enabled",
        "Transitions": [{"Days": 30, "StorageClass": storage}],
    }]}))
    monkeypatch.setattr(manage, "_run", lambda *_args, **_kwargs: response)
    assert manage._verify_state_lifecycle(args()) is None


def test_authoritative_lifecycle_ignores_provably_disjoint_prefix(
        monkeypatch):
    response = SimpleNamespace(stdout=json.dumps({"Rules": [{
        "Expiration": {"Days": 1},
        "Filter": {"Prefix": "ingress/"},
        "ID": "unrelated",
        "Status": "Enabled",
        "Transitions": [{"Days": 0, "StorageClass": "DEEP_ARCHIVE"}],
    }]}))
    monkeypatch.setattr(manage, "_run", lambda *_args, **_kwargs: response)
    assert manage._verify_state_lifecycle(args()) is None


@pytest.mark.parametrize("prefix", (
    "workspaces/",
    f"workspaces/{WORKSPACE}/obj/",
))
def test_authoritative_lifecycle_rejects_broader_or_narrower_overlap(
        monkeypatch, prefix):
    responses = iter((
        SimpleNamespace(stdout=json.dumps({"Rules": [{
            "Expiration": {"Days": 1},
            "Filter": {"And": {
                "Prefix": prefix,
                "Tags": [{"Key": "tier", "Value": "temporary"}],
            }},
            "ID": "overlap",
            "Status": "Enabled",
        }]})),
        SimpleNamespace(stdout=json.dumps({"Rules": []})),
    ))
    monkeypatch.setattr(
        manage, "_run", lambda *_args, **_kwargs: next(responses))
    with pytest.raises(RuntimeError, match="canonical.*may expire"):
        manage._verify_state_lifecycle(args())


def test_authoritative_lifecycle_rejects_unknown_filter(monkeypatch):
    response = SimpleNamespace(stdout=json.dumps({"Rules": [{
        "Expiration": {"Days": 1},
        "Filter": {"FuturePredicate": "value"},
        "ID": "unknown",
        "Status": "Enabled",
    }]}))
    monkeypatch.setattr(manage, "_run", lambda *_args, **_kwargs: response)
    with pytest.raises(RuntimeError, match="malformed canonical.*filter"):
        manage._verify_state_lifecycle(args())


def test_pinned_secret_fetch_derives_stable_push_and_delivery_identity(
        monkeypatch):
    calls = []
    monkeypatch.setattr(manage, "_run", lambda command, **_kwargs: (
        calls.append(command) or SimpleNamespace(
            stdout=json.dumps(_secret_response()))))

    push_node, delivery_domain = manage._secret_binding(args())
    assert push_node == PUSH_NODE
    assert delivery_domain == manage.delivery_domain_id(PUSH_NODE, (
        ("poc16.mobile", "production", "project"),
    ))
    command = calls[0]
    assert command[1:3] == ["secretsmanager", "get-secret-value"]
    assert command[command.index("--version-id") + 1] == SECRET_VERSION
    assert "AWSCURRENT" not in command


def test_same_project_credential_bytes_and_secret_version_keep_domain(
        monkeypatch):
    candidate = args()
    rotated = args(notification_secret_version_id="b" * 32)
    responses = []
    for version, private_key in (
            (SECRET_VERSION, "old-private-material"),
            ("b" * 32, "rotated-private-material")):
        response = _secret_response(version=version)
        document = json.loads(response["SecretString"])
        document["firebase_apps"][0]["credential"]["private_key"] = private_key
        response["SecretString"] = json.dumps(document)
        responses.append(SimpleNamespace(stdout=json.dumps(response)))
    iterator = iter(responses)
    monkeypatch.setattr(
        manage, "_run", lambda *_args, **_kwargs: next(iterator))

    first = manage._secret_binding(candidate)
    second = manage._secret_binding(rotated)

    assert first == second


def test_changed_firebase_project_changes_delivery_domain(monkeypatch):
    responses = []
    for project in ("project-one", "project-two"):
        response = _secret_response()
        document = json.loads(response["SecretString"])
        document["firebase_apps"][0]["credential"]["project_id"] = project
        response["SecretString"] = json.dumps(document)
        responses.append(SimpleNamespace(stdout=json.dumps(response)))
    iterator = iter(responses)
    monkeypatch.setattr(
        manage, "_run", lambda *_args, **_kwargs: next(iterator))

    first = manage._secret_binding(args())
    second = manage._secret_binding(args())

    assert first[0] == second[0] == PUSH_NODE
    assert first[1] != second[1]


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


@pytest.mark.parametrize("enabled", (False, True))
def test_live_traffic_binds_exact_version_configuration_and_fair_wakes(
        monkeypatch, enabled):
    outputs, versions, documents = _live_documents(enabled=enabled)
    calls = []
    monkeypatch.setattr(manage, "_run", _live_run(documents, calls))

    assert manage._live_traffic(
        args(), outputs, versions, enabled) is None
    assert [command[1:3] for command in calls] == [
        ["lambda", "get-function-configuration"],
        ["lambda", "get-function-concurrency"],
        ["lambda", "get-runtime-management-config"],
        ["lambda", "get-function-configuration"],
        ["lambda", "get-function-concurrency"],
        ["lambda", "get-runtime-management-config"],
        ["lambda", "get-event-source-mapping"],
        ["events", "describe-rule"],
        ["events", "list-targets-by-rule"],
    ]
    assert calls[0][4] == SCANNER_VERSION_ARN
    assert calls[1][4] == SCANNER_VERSION_ARN.rsplit(":", 1)[0]
    assert calls[3][4] == DELIVERY_VERSION_ARN
    assert calls[4][4] == DELIVERY_VERSION_ARN.rsplit(":", 1)[0]


@pytest.mark.parametrize(("mutation", "message"), (
    ("code", "delivery version drift"),
    ("environment", "scanner version drift"),
    ("role", "delivery version drift"),
    ("layer", "scanner version drift"),
    ("durable", "scanner version drift"),
    ("tenancy", "delivery version drift"),
    ("unknown-version-field", "scanner version drift"),
    ("concurrency-zero", "scanner reserved concurrency drift"),
    ("concurrency-substitution", "delivery reserved concurrency drift"),
    ("runtime-mode", "scanner runtime management drift"),
    ("filter", "event source mapping drift"),
    ("scaling", "event source mapping drift"),
    ("schedule", "schedule drift"),
    ("event-pattern", "schedule drift"),
    ("rule-role", "schedule drift"),
    ("managed-rule", "schedule drift"),
    ("event-bus", "schedule drift"),
    ("unknown-rule-field", "schedule drift"),
    ("input", "schedule target drift"),
    ("target-retry", "schedule target drift"),
))
def test_live_traffic_rejects_provider_configuration_drift(
        monkeypatch, mutation, message):
    outputs, versions, documents = _live_documents(enabled=True)
    if mutation == "code":
        documents[("lambda", "delivery")]["CodeSha256"] = (
            NEW_DELIVERY_CODE_SHA256)
    elif mutation == "environment":
        documents[("lambda", "scanner")]["Environment"]["Variables"][
            "TINYP2P_NOTIFICATION_CANONICAL_BUCKET"] = "substituted"
    elif mutation == "role":
        documents[("lambda", "delivery")]["Role"] = SCANNER_ROLE_ARN
    elif mutation == "layer":
        documents[("lambda", "scanner")]["Layers"] = [{
            "Arn": (
                f"arn:aws:lambda:us-west-2:{ACCOUNT}:layer:substitute:1"),
            "CodeSize": 10,
        }]
    elif mutation == "durable":
        documents[("lambda", "scanner")]["DurableConfig"] = {
            "RetentionPeriodInDays": 7,
        }
    elif mutation == "tenancy":
        documents[("lambda", "delivery")]["TenancyConfig"] = {
            "TenantIsolationMode": "PER_TENANT",
        }
    elif mutation == "unknown-version-field":
        documents[("lambda", "scanner")]["FutureBehaviorConfig"] = {
            "Enabled": True,
        }
    elif mutation == "concurrency-zero":
        documents[("concurrency", "scanner")][
            "ReservedConcurrentExecutions"] = 0
    elif mutation == "concurrency-substitution":
        documents[("concurrency", "delivery")][
            "ReservedConcurrentExecutions"] = args().scanner_concurrency
    elif mutation == "runtime-mode":
        documents[("runtime", "scanner")]["UpdateRuntimeOn"] = "Auto"
    elif mutation == "filter":
        documents["mapping"]["FilterCriteria"] = {
            "Filters": [{"Pattern": '{"never":["matches"]}'}],
        }
    elif mutation == "scaling":
        documents["mapping"]["ScalingConfig"] = {"MaximumConcurrency": 2}
    elif mutation == "schedule":
        documents["rule"]["ScheduleExpression"] = "rate(365 days)"
    elif mutation == "event-pattern":
        documents["rule"]["EventPattern"] = '{"source":["aws.s3"]}'
    elif mutation == "rule-role":
        documents["rule"]["RoleArn"] = DELIVERY_ROLE_ARN
    elif mutation == "managed-rule":
        documents["rule"]["ManagedBy"] = "events.amazonaws.com"
    elif mutation == "event-bus":
        documents["rule"]["EventBusName"] = "substituted"
    elif mutation == "unknown-rule-field":
        documents["rule"]["FutureBehaviorConfig"] = {"Enabled": True}
    elif mutation == "input":
        documents["targets"]["Targets"][0]["Input"] = "{}"
    elif mutation == "target-retry":
        documents["targets"]["Targets"][0]["RetryPolicy"] = {
            "MaximumRetryAttempts": 0,
        }
    monkeypatch.setattr(manage, "_run", _live_run(documents, []))

    with pytest.raises(RuntimeError, match=message):
        manage._live_traffic(args(), outputs, versions, True)


def test_create_is_fully_disabled_by_default_and_checks_real_bindings(
        monkeypatch):
    candidate = args()
    final = stack(candidate, enabled=False)
    commands = []
    checks = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: ("stack", False, None))
    monkeypatch.setattr(
        manage, "_secret_binding",
        lambda _args: (PUSH_NODE, DELIVERY_DOMAIN))
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle", lambda _args: checks.append(
            "lifecycle"))
    monkeypatch.setattr(
        manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "build", lambda _args, **_kwargs: checks.append("build"))
    monkeypatch.setattr(
        manage, "_package_release", lambda _args: CODE_HASHES)
    monkeypatch.setattr(
        manage, "_live_traffic",
        lambda *_args: checks.append("live-traffic"))
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: final)
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_run", lambda command, **_kwargs: (
        commands.append(command) or SimpleNamespace(stdout="")))

    outputs = manage.deploy(candidate)

    command = next(row for row in commands if row[:2] == ["sam", "deploy"])
    assert "Enabled=false" in command
    assert f"NotificationSecretVersionId={SECRET_VERSION}" in command
    assert f"PushNodeId={PUSH_NODE}" in command
    assert f"DeliveryDomainId={DELIVERY_DOMAIN}" in command
    assert f"ScannerCodeSha256={SCANNER_CODE_SHA256}" in command
    assert f"DeliveryCodeSha256={DELIVERY_CODE_SHA256}" in command
    assert f"SoftwareDigest={SOFTWARE_DIGEST}" in command
    assert checks == ["lifecycle", "build", "live-traffic"]
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
    monkeypatch.setattr(
        manage, "_secret_binding",
        lambda _args: (PUSH_NODE, DELIVERY_DOMAIN))
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
    monkeypatch.setattr(
        manage, "_live_traffic",
        lambda _args, _outputs, _versions, enabled:
            effects.append(("live", enabled)))
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

    assert effects[:2] == ["initialized", ("live", False)]
    assert effects[-1] == ("live", True)
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


def test_enable_rejects_requested_secret_version_different_from_stack(
        monkeypatch):
    deployed = args(create=False, update=True)
    candidate = args(
        create=False, update=True, enable=True,
        notification_secret_version_id="b" * 32)
    target = stack(deployed)["StackId"]
    incumbent = manage._outputs(stack(deployed, enabled=False))
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (target, True, incumbent))
    monkeypatch.setattr(
        manage, "_secret_binding",
        lambda _args: (PUSH_NODE, DELIVERY_DOMAIN))
    monkeypatch.setattr(manage, "_verify_state_lifecycle", lambda _args: None)
    monkeypatch.setattr(
        manage, "_check_launch_gate",
        lambda *_args: effects.append("launch"))
    monkeypatch.setattr(
        manage, "_create_traffic_change_set",
        lambda *_args: effects.append("change-set"))

    with pytest.raises(
            RuntimeError, match="NotificationSecretVersionId"):
        manage.deploy(candidate)
    assert effects == []


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
    monkeypatch.setattr(
        manage, "_live_traffic",
        lambda _args, _outputs, _versions, enabled:
            effects.append(("live", enabled)))

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
    assert effects[-1] == ("live", False)
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
    monkeypatch.setattr(manage, "_live_traffic", lambda *_args: None)
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
            manage._binding(candidate, PUSH_NODE, DELIVERY_DOMAIN), PUSH_NODE)
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
    monkeypatch.setattr(
        manage, "_secret_binding",
        lambda _args: (PUSH_NODE, DELIVERY_DOMAIN))
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
    monkeypatch.setattr(
        manage, "_secret_binding",
        lambda _args: (PUSH_NODE, DELIVERY_DOMAIN))
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
        delivery_code=NEW_DELIVERY_CODE_SHA256,
        enabled=False, scanner_version=NEW_SCANNER_VERSION_ARN,
        scanner_code=NEW_SCANNER_CODE_SHA256,
        software_digest=SOFTWARE_DIGEST)
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (target, False, incumbent))
    monkeypatch.setattr(
        manage, "_secret_binding",
        lambda _args: (PUSH_NODE, DELIVERY_DOMAIN))
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle", lambda _args: None)
    monkeypatch.setattr(
        manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(
        manage, "build", lambda _args, **_kwargs: effects.append("build"))
    monkeypatch.setattr(
        manage, "_package_release",
        lambda _args: effects.append("package") or NEW_CODE_HASHES)
    monkeypatch.setattr(manage, "_live_traffic", lambda *_args: None)
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
                release_change_set(
                    candidate, target, code_hashes=NEW_CODE_HASHES)))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(manage, "_run", run)

    outputs = manage.deploy(candidate)

    assert outputs["SoftwareDigest"] == SOFTWARE_DIGEST
    assert effects[:2] == ["build", "package"]
    commands = [effect for effect in effects if isinstance(effect, list)]
    assert any(row[1:3] == ["cloudformation", "create-change-set"]
               for row in commands)
    assert any(row[1:3] == ["cloudformation", "execute-change-set"]
               for row in commands)
    assert not any(row[:2] == ["sam", "deploy"] for row in commands)


def test_same_project_secret_rotation_publishes_delivery_version_only(
        tmp_path, monkeypatch):
    previous = args(create=False, update=True)
    candidate = args(
        create=False, update=True,
        notification_secret_version_id="b" * 32)
    target = stack(previous)["StackId"]
    incumbent_stack = stack(previous, enabled=False)
    incumbent = manage._outputs(incumbent_stack)
    final = stack(
        candidate,
        delivery_version=NEW_DELIVERY_VERSION_ARN,
        enabled=False,
        scanner_version=SCANNER_VERSION_ARN)
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (target, False, incumbent))
    monkeypatch.setattr(
        manage, "_secret_binding",
        lambda _args: (PUSH_NODE, DELIVERY_DOMAIN))
    monkeypatch.setattr(manage, "_verify_state_lifecycle", lambda _args: None)
    monkeypatch.setattr(manage, "_prepare_software", lambda: SOFTWARE_DIGEST)
    monkeypatch.setattr(manage, "build", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manage, "_package_release", lambda _args: CODE_HASHES)
    monkeypatch.setattr(manage, "_live_traffic", lambda *_args: None)
    observed = iter([incumbent_stack, final])
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: next(observed))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)

    def run(command, **_kwargs):
        effects.append(command)
        if command[1:3] == ["cloudformation", "create-change-set"]:
            return SimpleNamespace(stdout=json.dumps({
                "Id": "change-set", "StackId": target,
            }))
        if command[1:3] == ["cloudformation", "describe-change-set"]:
            return SimpleNamespace(stdout=json.dumps(release_change_set(
                candidate, target,
                resources=(
                    "NotificationDeliveryFunction",
                    "NotificationDeliveryVersion",
                ))))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(manage, "_run", run)

    outputs = manage.deploy(candidate)

    assert outputs["NotificationScannerVersionArn"] == SCANNER_VERSION_ARN
    assert outputs["NotificationDeliveryVersionArn"] \
        == NEW_DELIVERY_VERSION_ARN
    assert outputs["DeliveryDomainId"] == incumbent["DeliveryDomainId"]
    assert outputs["NotificationSecretVersionId"] == "b" * 32
    assert manage._expected_version_environment(incumbent, "scanner") \
        == manage._expected_version_environment(outputs, "scanner")

    write_launch_records(tmp_path, previous, stack_id=target)
    candidate.ios_launch_record = previous.ios_launch_record
    candidate.android_launch_record = previous.android_launch_record
    with pytest.raises(RuntimeError, match="invalid ios"):
        manage._check_launch_gate(candidate, target, outputs)


def test_secret_rotation_rejects_unexpected_scanner_version_churn(
        monkeypatch):
    previous = args(create=False, update=True)
    candidate = args(
        create=False, update=True,
        notification_secret_version_id="b" * 32)
    incumbent = manage._outputs(stack(previous, enabled=False))
    final = stack(
        candidate,
        delivery_version=NEW_DELIVERY_VERSION_ARN,
        enabled=False,
        scanner_version=NEW_SCANNER_VERSION_ARN)
    observed = iter([stack(previous, enabled=False), final])
    monkeypatch.setattr(
        manage, "_create_release_change_set", lambda *_args: "change-set")
    monkeypatch.setattr(manage, "_owned_stack", lambda _args: next(observed))
    monkeypatch.setattr(manage, "_caller_account", lambda _args: ACCOUNT)
    monkeypatch.setattr(manage, "_checked_queues", lambda *_args: None)
    monkeypatch.setattr(manage, "_live_traffic", lambda *_args: None)
    monkeypatch.setattr(manage, "_execute_change_set", lambda *_args: None)

    with pytest.raises(RuntimeError, match="release postcondition"):
        manage._deploy_release(
            candidate, stack(previous)["StackId"], incumbent,
            manage._binding(candidate, PUSH_NODE, DELIVERY_DOMAIN),
            PUSH_NODE, DELIVERY_DOMAIN, SOFTWARE_DIGEST, CODE_HASHES)


def test_enabled_secret_rotation_stops_before_build_or_provider_change(
        monkeypatch):
    candidate = args(
        create=False, update=True,
        notification_secret_version_id="b" * 32)
    incumbent = manage._outputs(stack(
        args(create=False, update=True), enabled=True))
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (stack()["StackId"], True, incumbent))
    monkeypatch.setattr(
        manage, "_secret_binding",
        lambda _args: (PUSH_NODE, DELIVERY_DOMAIN))
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle",
        lambda _args: effects.append("lifecycle"))
    monkeypatch.setattr(
        manage, "_prepare_software",
        lambda: pytest.fail("enabled rotation staged software"))
    monkeypatch.setattr(
        manage, "build",
        lambda *_args, **_kwargs: pytest.fail("enabled rotation built"))
    monkeypatch.setattr(
        manage, "_package_release",
        lambda *_args: pytest.fail("enabled rotation packaged"))

    with pytest.raises(RuntimeError, match="disable.*before updating"):
        manage.deploy(candidate)
    assert effects == ["lifecycle"]


def test_changed_project_domain_rejects_release_before_effects(monkeypatch):
    candidate = args(create=False, update=True)
    incumbent = manage._outputs(stack(candidate, enabled=False))
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: (stack()["StackId"], False, incumbent))
    monkeypatch.setattr(
        manage, "_secret_binding", lambda _args: (PUSH_NODE, "c" * 64))
    monkeypatch.setattr(
        manage, "_verify_state_lifecycle",
        lambda _args: effects.append("lifecycle"))
    monkeypatch.setattr(
        manage, "build", lambda *_args, **_kwargs: effects.append("build"))

    with pytest.raises(RuntimeError, match="DeliveryDomainId"):
        manage.deploy(candidate)
    assert effects == []


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
            candidate, target, PUSH_NODE, DELIVERY_DOMAIN, SOFTWARE_DIGEST,
            manage._outputs(stack(
                candidate, enabled=False, software_digest="e" * 64)),
            CODE_HASHES)
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
            manage._binding(candidate, PUSH_NODE, DELIVERY_DOMAIN), PUSH_NODE,
            DELIVERY_DOMAIN, SOFTWARE_DIGEST, CODE_HASHES)
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


@pytest.mark.parametrize(("changes", "identity", "field"), (
    ({"workspace": "b" * 64}, (PUSH_NODE, DELIVERY_DOMAIN), "WorkspaceId"),
    ({"canonical_bucket": "other-canonical"},
     (PUSH_NODE, DELIVERY_DOMAIN),
     "CanonicalBucketName"),
    ({"canonical_prefix": "other/canonical"},
     (PUSH_NODE, DELIVERY_DOMAIN),
     "CanonicalPrefix"),
    ({"state_bucket": "other-state"}, (PUSH_NODE, DELIVERY_DOMAIN),
     "NotificationStateBucketName"),
    ({"state_prefix": "other/state"}, (PUSH_NODE, DELIVERY_DOMAIN),
     "NotificationStatePrefix"),
    ({"notification_secret_arn": SECRET_ARN + "-other"},
     (PUSH_NODE, DELIVERY_DOMAIN),
     "NotificationSecretArn"),
    ({"repository_kms_key_arn": (
        f"arn:aws:kms:us-west-2:{ACCOUNT}:key/repository")},
     (PUSH_NODE, DELIVERY_DOMAIN),
     "RepositoryKmsKeyArn"),
    ({}, ("b" * 64, "c" * 64), "DeliveryDomainId"),
))
def test_update_rejects_immutable_binding_change_before_sam_effects(
        monkeypatch, changes, identity, field):
    base = args(create=False, update=True)
    candidate = args(create=False, update=True, **changes)
    incumbent = manage._outputs(stack(base, enabled=True))
    effects = []
    monkeypatch.setattr(
        manage, "_stack_for_deploy",
        lambda _args: ("stack", True, incumbent))
    monkeypatch.setattr(manage, "_secret_binding", lambda _args: identity)
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
        "d" * 64, None, h(b"writer head"),
        (EventRef(h(b"event"), h(b"event bytes")),)))
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
        "d" * 64, None, h(b"writer head"),
        (EventRef(h(b"event"), h(b"event bytes")),))))
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
        "--canonical-prefix", "canonical/data",
        "--state-bucket", "state-bucket",
        "--state-prefix", "notification/state",
        "--expected-owner", ACCOUNT,
        "--notification-secret-arn", SECRET_ARN,
        "--notification-secret-version-id", SECRET_VERSION,
        "--create",
    ])
    assert parsed.enable is None
    assert parsed.ios_launch_record is None
    assert parsed.android_launch_record is None
    assert manage.parser().parse_args(["build"]).command == "build"
