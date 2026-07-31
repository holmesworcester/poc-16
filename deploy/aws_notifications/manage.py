#!/usr/bin/env python3
"""Build, deploy, inspect, redrive, and remove AWS notifications safely."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

from adapters.aws import queue_binding
from adapters.s3 import S3Config
from core.object_store import validate_store_prefix
from core.shape import valid_fid
from deploy.notification_launch import require_mobile_launches, tree_digest
from notifications.hints import decode_hint

from .config import (
    ALARM_ACTION_ARN_RE,
    BOOTSTRAP_RESULT_SCHEMA,
    BOOTSTRAP_SCHEMA,
    DEPLOYMENT_ID_RE,
    DEPLOYMENT_ID_TAG,
    DEPLOYMENT_MARKER,
    DEPLOYMENT_TAG,
    DIRECT_SMOKE_RESULT_SCHEMA,
    DIRECT_SMOKE_SCHEMA,
    DLQ_RETENTION_SECONDS,
    KMS_KEY_ARN_RE,
    LAMBDA_VERSION_ARN_RE,
    MAX_RECEIVE_COUNT,
    OWNER_RE,
    QUEUE_RETENTION_SECONDS,
    SCAN_RESULT_SCHEMA,
    SCAN_WAKE_SCHEMA,
    SECRET_ARN_RE,
    SECRET_VERSION_RE,
)
from .secret import decode_secret, push_node_id


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
STAGE = HERE / "stage"
BUILD = HERE / ".aws-sam"
PACKAGED = BUILD / "packaged.yaml"
LOG_RETENTION_DAYS = 14
OPERABLE_STACK_STATUSES = frozenset({
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
})
TEMPLATE_PARAMETERS = (
    "Enabled",
    "DeploymentId",
    "SoftwareDigest",
    "WorkspaceId",
    "CanonicalBucketName",
    "CanonicalPrefix",
    "NotificationStateBucketName",
    "NotificationStatePrefix",
    "ExpectedBucketOwner",
    "NotificationSecretArn",
    "NotificationSecretVersionId",
    "PushNodeId",
    "RepositoryKmsKeyArn",
    "NotificationStateKmsKeyArn",
    "NotificationSecretKmsKeyArn",
    "ScheduleExpression",
    "ScannerReservedConcurrency",
    "DeliveryReservedConcurrency",
    "MaxReceiveCount",
    "LogRetentionDays",
    "AlarmActionArn",
)
TRAFFIC_RESOURCES = {
    "NotificationDeliveryMapping": "AWS::Lambda::EventSourceMapping",
    "NotificationScanSchedule": "AWS::Events::Rule",
}
SOURCE_PACKAGES = ("facts", "notifications")
SOURCE_TREES = ("adapters/aws", "adapters/gcp", "adapters/s3")
NOTIFICATION_CORE_MODULES = (
    "__init__.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "fact_index.py",
    "fetch_budget.py",
    "http_body.py",
    "indexes.py",
    "ingress.py",
    "kernel.py",
    "limits.py",
    "merkle_map.py",
    "object_store.py",
    "repository_reader.py",
    "repository_snapshot.py",
    "shape.py",
    "snapshot.py",
    "suppression.py",
    "validated_set.py",
    "worker.py",
)
DEPLOY_FILES = (
    "deploy/__init__.py",
    "deploy/notification_launch.py",
    "deploy/aws_notifications/__init__.py",
    "deploy/aws_notifications/app.py",
    "deploy/aws_notifications/config.py",
    "deploy/aws_notifications/secret.py",
)


class StackAbsent(RuntimeError):
    """The exact CloudFormation stack name is definitively absent."""


def _copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def stage(destination=STAGE):
    """Create an importable artifact with no Applier, SQL, or full-peer code."""
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name in NOTIFICATION_CORE_MODULES:
        _copy(REPOSITORY / "core" / name, destination / "core" / name)
    for package in SOURCE_PACKAGES:
        shutil.copytree(
            REPOSITORY / package,
            destination / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    _copy(
        REPOSITORY / "adapters" / "__init__.py",
        destination / "adapters" / "__init__.py",
    )
    for tree in SOURCE_TREES:
        shutil.copytree(
            REPOSITORY / tree,
            destination / tree,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for relative in DEPLOY_FILES:
        _copy(REPOSITORY / relative, destination / relative)
    _copy(HERE / "requirements.txt", destination / "requirements.txt")
    verify_stage(destination)
    return destination


def verify_stage(directory):
    paths = {
        path.relative_to(directory).as_posix()
        for path in Path(directory).rglob("*") if path.is_file()
    }
    required = {
        "adapters/aws/sqs.py",
        "adapters/gcp/firebase.py",
        "adapters/s3/store.py",
        "core/repository_reader.py",
        "deploy/aws_notifications/app.py",
        "deploy/aws_notifications/secret.py",
        "facts/auth/push_endpoint.py",
        "notifications/discovery.py",
        "notifications/hints.py",
        "notifications/worker.py",
        "requirements.txt",
    }
    if required - paths:
        raise RuntimeError(
            f"notification stage omitted {sorted(required - paths)}")
    forbidden = {
        "core/repository_applier.py",
        "core/store.py",
        "full_peer/node.py",
        "full_peer/sql_store.py",
        "full_peer/pile_sender.py",
    } & paths
    if forbidden or any(path.startswith(("full_peer/", "tests/"))
                        for path in paths):
        raise RuntimeError(
            f"notification stage contains forbidden authority: "
            f"{sorted(forbidden)}")


def _run(command, *, capture=False):
    return subprocess.run(
        command,
        cwd=REPOSITORY,
        check=True,
        capture_output=capture,
        text=capture,
        timeout=30 * 60,
    )


def _software_digest():
    stage_hash = tree_digest(STAGE)
    template_hash = hashlib.sha256(
        (HERE / "template.yaml").read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(
        {"stage": stage_hash, "template": template_hash},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _prepare_software():
    stage()
    return _software_digest()


def build(_args=None, *, expected_digest=None):
    digest = _prepare_software() if expected_digest is None \
        else _software_digest()
    if expected_digest is not None and digest != expected_digest:
        raise RuntimeError("notification deploy inputs changed during build")
    _run([
        "sam", "build",
        "--template-file", str(HERE / "template.yaml"),
        "--build-dir", str(BUILD),
        "--use-container",
    ])
    return digest


def _provider_flags(args):
    flags = []
    if getattr(args, "region", None):
        flags += ["--region", args.region]
    if getattr(args, "profile", None):
        flags += ["--profile", args.profile]
    return flags


def _optional_arn(value, pattern, label):
    if value is not None and value != "" and pattern.fullmatch(value) is None:
        raise ValueError(label)
    return value or ""


def _validated(args):
    if DEPLOYMENT_ID_RE.fullmatch(args.deployment_id or "") is None:
        raise ValueError("deployment ID")
    if not valid_fid(args.workspace):
        raise ValueError("workspace")
    if OWNER_RE.fullmatch(args.expected_owner or "") is None:
        raise ValueError("expected bucket owner")
    for value, label in (
            (args.canonical_prefix, "canonical prefix"),
            (args.state_prefix, "notification-state prefix")):
        try:
            validate_store_prefix(value)
        except (TypeError, ValueError) as error:
            raise ValueError(label) from error
    S3Config(
        bucket=args.canonical_bucket,
        prefix=args.canonical_prefix,
        expected_bucket_owner=args.expected_owner,
    )
    S3Config(
        bucket=args.state_bucket,
        prefix=args.state_prefix,
        expected_bucket_owner=args.expected_owner,
    )
    if args.canonical_bucket == args.state_bucket:
        raise ValueError("notification state requires a dedicated bucket")
    if SECRET_ARN_RE.fullmatch(args.notification_secret_arn or "") is None:
        raise ValueError("notification secret ARN")
    if SECRET_VERSION_RE.fullmatch(
            args.notification_secret_version_id or "") is None:
        raise ValueError("notification secret version ID")
    for name, label in (
            ("repository_kms_key_arn", "repository KMS key ARN"),
            ("state_kms_key_arn", "notification-state KMS key ARN"),
            ("secret_kms_key_arn", "notification-secret KMS key ARN")):
        _optional_arn(getattr(args, name), KMS_KEY_ARN_RE, label)
    _optional_arn(
        args.alarm_action_arn, ALARM_ACTION_ARN_RE, "alarm action ARN")
    if type(args.scanner_concurrency) is not int \
            or not 1 <= args.scanner_concurrency <= 100:
        raise ValueError("scanner concurrency")
    if type(args.delivery_concurrency) is not int \
            or not 1 <= args.delivery_concurrency <= 1000:
        raise ValueError("delivery concurrency")
    if type(args.max_receive_count) is not int \
            or not MAX_RECEIVE_COUNT <= args.max_receive_count <= 100:
        raise ValueError("notification max receive count")
    if not isinstance(args.schedule, str) or len(args.schedule) > 256 \
            or not args.schedule.startswith(("rate(", "cron(")) \
            or not args.schedule.endswith(")"):
        raise ValueError("notification schedule")
    launch_records = (
        getattr(args, "ios_launch_record", None),
        getattr(args, "android_launch_record", None),
    )
    if args.enable is not True and any(
            value is not None for value in launch_records):
        raise ValueError("launch records require explicit --enable")
    return args


def _stack(args):
    try:
        result = _run([
            "aws", "cloudformation", "describe-stacks",
            "--stack-name", args.stack_name,
            "--output", "json",
            *_provider_flags(args),
        ], capture=True)
    except subprocess.CalledProcessError as error:
        detail = error.stderr if isinstance(error.stderr, str) else ""
        if "ValidationError" in detail and "does not exist" in detail:
            raise StackAbsent(args.stack_name) from error
        raise
    try:
        value = json.loads(result.stdout)["Stacks"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed CloudFormation stack") from error
    if not isinstance(value, list) or len(value) != 1 \
            or not isinstance(value[0], dict):
        raise RuntimeError("malformed CloudFormation stack")
    return value[0]


def _caller_account(args):
    result = _run([
        "aws", "sts", "get-caller-identity", "--output", "json",
        *_provider_flags(args),
    ], capture=True)
    try:
        account = json.loads(result.stdout)["Account"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed AWS caller identity") from error
    if OWNER_RE.fullmatch(account if isinstance(account, str) else "") is None:
        raise RuntimeError("malformed AWS caller identity")
    return account


def _verify_state_lifecycle(args):
    """Fail closed unless the dedicated state bucket has no expiration."""
    try:
        result = _run([
            "aws", "s3api", "get-bucket-lifecycle-configuration",
            "--bucket", args.state_bucket,
            "--expected-bucket-owner", args.expected_owner,
            "--output", "json",
            *_provider_flags(args),
        ], capture=True)
    except subprocess.CalledProcessError as error:
        detail = " ".join(value for value in (
            error.stdout, error.stderr) if isinstance(value, str))
        if "NoSuchLifecycleConfiguration" in detail:
            return
        raise RuntimeError(
            "cannot verify notification-state bucket lifecycle") from error
    try:
        rules = json.loads(result.stdout)["Rules"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            "malformed notification-state bucket lifecycle") from error
    if not isinstance(rules, list) or not all(
            isinstance(rule, dict) for rule in rules):
        raise RuntimeError("malformed notification-state bucket lifecycle")
    for rule in rules:
        if rule.get("Status") not in {"Enabled", "Disabled"}:
            raise RuntimeError(
                "malformed notification-state bucket lifecycle")
        if rule["Status"] == "Enabled" and any(
                name in rule for name in (
                    "Expiration", "NoncurrentVersionExpiration")):
            raise RuntimeError(
                "notification-state bucket has enabled expiration")


def _secret_binding(args):
    """Read and verify exactly the secret version the stack will use."""
    result = _run([
        "aws", "secretsmanager", "get-secret-value",
        "--secret-id", args.notification_secret_arn,
        "--version-id", args.notification_secret_version_id,
        "--output", "json",
        *_provider_flags(args),
    ], capture=True)
    try:
        response = json.loads(result.stdout)
        if response.get("ARN") != args.notification_secret_arn \
                or response.get("VersionId") \
                != args.notification_secret_version_id:
            raise ValueError
        secret, _rows = decode_secret(response.get("SecretString"))
        return push_node_id(secret)
    except (AttributeError, RuntimeError, TypeError, ValueError,
            json.JSONDecodeError):
        raise RuntimeError("invalid pinned notification secret") from None


def _outputs(stack):
    return {
        row.get("OutputKey"): row.get("OutputValue")
        for row in stack.get("Outputs", ()) if isinstance(row, dict)
    }


def _binding(args, push_node):
    return {
        "WorkspaceId": args.workspace,
        "CanonicalBucketName": args.canonical_bucket,
        "CanonicalPrefix": args.canonical_prefix,
        "NotificationStateBucketName": args.state_bucket,
        "NotificationStatePrefix": args.state_prefix,
        "ExpectedBucketOwner": args.expected_owner,
        "NotificationSecretArn": args.notification_secret_arn,
        "NotificationSecretVersionId": args.notification_secret_version_id,
        "PushNodeId": push_node,
        "RepositoryKmsKeyArn": args.repository_kms_key_arn or "",
        "NotificationStateKmsKeyArn": args.state_kms_key_arn or "",
        "NotificationSecretKmsKeyArn": args.secret_kms_key_arn or "",
    }


def _check_binding(outputs, expected):
    changed = sorted(
        name for name, value in expected.items()
        if outputs.get(name) != value)
    if changed:
        raise RuntimeError(
            "immutable notification binding differs: " + ", ".join(changed))


def _checked_queues(args, outputs):
    account = _caller_account(args)
    source = queue_binding(
        outputs.get("NotificationQueueArn"),
        outputs.get("NotificationQueueUrl"),
        region=args.region,
        account=account,
    )
    dead = queue_binding(
        outputs.get("NotificationDeadLetterQueueArn"),
        outputs.get("NotificationDeadLetterQueueUrl"),
        region=args.region,
        account=account,
    )
    if source == dead:
        raise RuntimeError("notification source and DLQ must differ")
    if outputs.get("NotificationQueueRetentionSeconds") \
            != str(QUEUE_RETENTION_SECONDS) \
            or outputs.get("NotificationDeadLetterRetentionSeconds") \
            != str(DLQ_RETENTION_SECONDS) \
            or not QUEUE_RETENTION_SECONDS < DLQ_RETENTION_SECONDS:
        raise RuntimeError("notification queue retention binding")
    return outputs


def _owned_stack(args, stack=None):
    stack = _stack(args) if stack is None else stack
    if stack.get("StackName") != args.stack_name:
        raise RuntimeError("CloudFormation returned a different stack")
    stack_id = stack.get("StackId")
    parts = stack_id.split(":", 5) if isinstance(stack_id, str) else ()
    if len(parts) != 6 or parts[2] != "cloudformation" \
            or not parts[3] or OWNER_RE.fullmatch(parts[4]) is None:
        raise RuntimeError("notification stack identity ARN")
    if args.region and parts[3] != args.region:
        raise RuntimeError("notification stack region mismatch")
    if parts[4] != _caller_account(args):
        raise RuntimeError("notification stack account mismatch")
    tags = {
        row.get("Key"): row.get("Value")
        for row in stack.get("Tags", ()) if isinstance(row, dict)
    }
    outputs = _outputs(stack)
    if tags.get(DEPLOYMENT_TAG) != DEPLOYMENT_MARKER \
            or tags.get(DEPLOYMENT_ID_TAG) != args.deployment_id \
            or outputs.get("DeploymentMarker") != DEPLOYMENT_MARKER \
            or outputs.get("DeploymentId") != args.deployment_id:
        raise RuntimeError("refusing to operate on an unowned stack")
    if stack.get("StackStatus") not in OPERABLE_STACK_STATUSES:
        raise RuntimeError("notification stack is not operable")
    return stack


def _stack_or_none(args):
    try:
        return _stack(args)
    except StackAbsent:
        return None


def _stack_for_deploy(args):
    if bool(args.create) == bool(args.update):
        raise ValueError("choose exactly one of create or update")
    incumbent = _stack_or_none(args)
    if args.create:
        if incumbent is not None:
            raise RuntimeError("create requires an absent stack name")
        if args.enable is True:
            raise RuntimeError(
                "create disabled, bootstrap explicitly, then enable")
        return (
            args.stack_name,
            bool(args.enable),
            None,
        )
    if incumbent is None:
        raise RuntimeError("update requires an existing owned stack")
    owned = _owned_stack(args, incumbent)
    outputs = _outputs(owned)
    incumbent = outputs.get("Enabled")
    if incumbent not in {"true", "false"}:
        raise RuntimeError("notification stack has no traffic state")
    enabled = incumbent == "true" if args.enable is None else args.enable
    return owned["StackId"], enabled, outputs


def _parameter_values(args, enabled, push_node, software_digest):
    if type(enabled) is not bool or not valid_fid(push_node) \
            or not valid_fid(software_digest):
        raise TypeError("notification deployment state")
    values = {
        "Enabled": "true" if enabled else "false",
        "DeploymentId": args.deployment_id,
        "SoftwareDigest": software_digest,
        "WorkspaceId": args.workspace,
        "CanonicalBucketName": args.canonical_bucket,
        "CanonicalPrefix": args.canonical_prefix,
        "NotificationStateBucketName": args.state_bucket,
        "NotificationStatePrefix": args.state_prefix,
        "ExpectedBucketOwner": args.expected_owner,
        "NotificationSecretArn": args.notification_secret_arn,
        "NotificationSecretVersionId": args.notification_secret_version_id,
        "PushNodeId": push_node,
        "RepositoryKmsKeyArn": args.repository_kms_key_arn or "",
        "NotificationStateKmsKeyArn": args.state_kms_key_arn or "",
        "NotificationSecretKmsKeyArn": args.secret_kms_key_arn or "",
        "ScheduleExpression": args.schedule,
        "ScannerReservedConcurrency": str(args.scanner_concurrency),
        "DeliveryReservedConcurrency": str(args.delivery_concurrency),
        "MaxReceiveCount": str(args.max_receive_count),
        "LogRetentionDays": str(LOG_RETENTION_DAYS),
        "AlarmActionArn": args.alarm_action_arn or "",
    }
    if tuple(values) != TEMPLATE_PARAMETERS:
        raise AssertionError("notification template parameter drift")
    return values


def _parameters(args, enabled, push_node, software_digest):
    return tuple(
        f"{name}={value}" for name, value in _parameter_values(
            args, enabled, push_node, software_digest).items())


def _version_arns(outputs, stack_id=None):
    if not isinstance(outputs, dict):
        raise RuntimeError("notification deployment has no immutable versions")
    values = {
        "delivery_version_arn": outputs.get("NotificationDeliveryVersionArn"),
        "scanner_version_arn": outputs.get("NotificationScannerVersionArn"),
    }
    if any(LAMBDA_VERSION_ARN_RE.fullmatch(value or "") is None
           for value in values.values()):
        raise RuntimeError("notification deployment has no immutable versions")
    if stack_id is not None:
        parts = stack_id.split(":", 5) if isinstance(stack_id, str) else ()
        boundaries = [
            value.split(":", 6) for value in values.values()
        ]
        if len(parts) != 6 or any(
                len(value) != 7 or value[1] != parts[1]
                or value[3:5] != parts[3:5]
                for value in boundaries):
            raise RuntimeError(
                "notification immutable versions cross stack boundary")
    return values


def _launch_binding(stack_id, outputs):
    result = {
        "canonical_bucket": outputs.get("CanonicalBucketName"),
        "canonical_prefix": outputs.get("CanonicalPrefix"),
        "deployment_id": outputs.get("DeploymentId"),
        **_version_arns(outputs, stack_id),
        "expected_bucket_owner": outputs.get("ExpectedBucketOwner"),
        "notification_secret_arn": outputs.get("NotificationSecretArn"),
        "notification_secret_version_id": outputs.get(
            "NotificationSecretVersionId"),
        "notification_state_bucket": outputs.get(
            "NotificationStateBucketName"),
        "notification_state_prefix": outputs.get("NotificationStatePrefix"),
        "provider": "aws",
        "push_node_id": outputs.get("PushNodeId"),
        "software_digest": outputs.get("SoftwareDigest"),
        "stack_id": stack_id,
        "workspace": outputs.get("WorkspaceId"),
    }
    if not all(isinstance(value, str) and value for value in result.values()) \
            or not all(valid_fid(result[name]) for name in (
                "push_node_id", "software_digest", "workspace")):
        raise RuntimeError("notification launch binding is incomplete")
    return result


def _check_launch_gate(args, stack_id, outputs):
    """Require exact, deployment-bound evidence from both mobile platforms."""
    require_mobile_launches({
        "ios": getattr(args, "ios_launch_record", None),
        "android": getattr(args, "android_launch_record", None),
    }, _launch_binding(stack_id, outputs))


def _traffic_parameters(enabled):
    if type(enabled) is not bool:
        raise TypeError("notification traffic state")
    return (
        f"ParameterKey=Enabled,ParameterValue={'true' if enabled else 'false'}",
        *(f"ParameterKey={name},UsePreviousValue=true"
          for name in TEMPLATE_PARAMETERS if name != "Enabled"),
    )


def _change_set_document(result, label):
    try:
        value = json.loads(result.stdout)
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"malformed notification {label}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"malformed notification {label}")
    return value


def _discard_change_set(args, change_set):
    try:
        _run([
            "aws", "cloudformation", "delete-change-set",
            "--change-set-name", change_set,
            *_provider_flags(args),
        ])
    except subprocess.CalledProcessError:
        pass


def _start_change_set(args, stack_id, kind, options):
    name = f"poc16-notification-{kind}-" + uuid.uuid4().hex
    created = _change_set_document(_run([
        "aws", "cloudformation", "create-change-set",
        "--stack-name", stack_id,
        "--change-set-name", name,
        "--change-set-type", "UPDATE",
        *options,
        "--output", "json",
        *_provider_flags(args),
    ], capture=True), f"{kind} creation response")
    change_set = created.get("Id")
    if not isinstance(change_set, str) or not change_set \
            or created.get("StackId") != stack_id:
        raise RuntimeError(f"malformed {kind} creation response")
    return change_set


def _ready_change_set(args, stack_id, change_set, kind):
    _run([
        "aws", "cloudformation", "wait",
        "change-set-create-complete",
        "--change-set-name", change_set,
        *_provider_flags(args),
    ])
    document = _change_set_document(_run([
        "aws", "cloudformation", "describe-change-set",
        "--change-set-name", change_set,
        "--no-paginate",
        "--output", "json",
        *_provider_flags(args),
    ], capture=True), f"{kind} change set")
    if document.get("ChangeSetId") != change_set \
            or document.get("StackId") != stack_id \
            or document.get("Status") != "CREATE_COMPLETE" \
            or document.get("ExecutionStatus") != "AVAILABLE" \
            or document.get("NextToken") is not None:
        raise RuntimeError(f"{kind} change set is not executable")
    return document


def _create_traffic_change_set(args, stack_id, enabled):
    """Create and prove one traffic-only, previous-template stack update."""
    action = "enable" if enabled else "disable"
    change_set = _start_change_set(args, stack_id, action, [
        "--use-previous-template",
        "--capabilities", "CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND",
        "--parameters", *_traffic_parameters(enabled),
    ])
    try:
        document = _ready_change_set(
            args, stack_id, change_set, "traffic")
        parameters = {}
        for row in document.get("Parameters", ()):
            if not isinstance(row, dict) \
                    or not isinstance(row.get("ParameterKey"), str) \
                    or row["ParameterKey"] in parameters:
                raise RuntimeError("traffic change set parameters")
            parameters[row["ParameterKey"]] = row
        if set(parameters) != set(TEMPLATE_PARAMETERS) \
                or parameters["Enabled"].get("ParameterValue") \
                != ("true" if enabled else "false") \
                or any(parameters[name].get("UsePreviousValue") is not True
                       for name in TEMPLATE_PARAMETERS if name != "Enabled"):
            raise RuntimeError("traffic change set parameters")
        changes = {}
        for row in document.get("Changes", ()):
            change = row.get("ResourceChange") \
                if isinstance(row, dict) and row.get("Type") == "Resource" \
                else None
            logical = change.get("LogicalResourceId") \
                if isinstance(change, dict) else None
            if not isinstance(logical, str) or logical in changes:
                raise RuntimeError("traffic change set resource scope")
            changes[logical] = change
        if set(changes) != set(TRAFFIC_RESOURCES) or any(
                change.get("Action") != "Modify"
                or change.get("ResourceType") != TRAFFIC_RESOURCES[name]
                or change.get("Replacement") != "False"
                or set(change.get("Scope", ())) != {"Properties"}
                for name, change in changes.items()):
            raise RuntimeError("traffic change set resource scope")
    except Exception:
        _discard_change_set(args, change_set)
        raise
    return change_set


def _release_parameters(args, push_node, software_digest):
    return tuple(
        f"ParameterKey={name},ParameterValue={value}"
        for name, value in _parameter_values(
            args, False, push_node, software_digest).items())


def _package_release(args):
    _run([
        "sam", "package",
        "--template-file", str(BUILD / "template.yaml"),
        "--output-template-file", str(PACKAGED),
        "--resolve-s3",
        *_provider_flags(args),
    ])


def _create_release_change_set(
        args, stack_id, push_node, software_digest, previous_digest):
    """Package a release, then create but do not execute its exact update."""
    _package_release(args)
    expected = _parameter_values(args, False, push_node, software_digest)
    change_set = _start_change_set(args, stack_id, "release", [
        "--template-body", "file://" + str(PACKAGED),
        "--capabilities", "CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND",
        "--parameters", *_release_parameters(
            args, push_node, software_digest),
    ])
    try:
        document = _ready_change_set(
            args, stack_id, change_set, "release")
        parameters = {}
        for row in document.get("Parameters", ()):
            if not isinstance(row, dict) \
                    or not isinstance(row.get("ParameterKey"), str) \
                    or not isinstance(row.get("ParameterValue"), str) \
                    or row["ParameterKey"] in parameters:
                raise RuntimeError("release change set parameters")
            parameters[row["ParameterKey"]] = row["ParameterValue"]
        if parameters != expected or parameters.get("Enabled") != "false":
            raise RuntimeError("release change set parameters")
        changes = document.get("Changes")
        if not isinstance(changes, list) or not changes:
            raise RuntimeError("release change set has no resource changes")
        logical = set()
        for row in changes:
            change = row.get("ResourceChange") \
                if isinstance(row, dict) and row.get("Type") == "Resource" \
                else None
            name = change.get("LogicalResourceId") \
                if isinstance(change, dict) else None
            if not isinstance(name, str) or not name or name in logical:
                raise RuntimeError("release change set resource scope")
            logical.add(name)
        if software_digest != previous_digest and not {
                "NotificationScannerFunction",
                "NotificationDeliveryFunction",
                "NotificationScannerVersion",
                "NotificationDeliveryVersion",
        }.issubset(logical):
            raise RuntimeError("release did not publish exact Lambda versions")
    except Exception:
        _discard_change_set(args, change_set)
        raise
    return change_set


def _execute_change_set(args, stack_id, change_set):
    _run([
        "aws", "cloudformation", "execute-change-set",
        "--change-set-name", change_set,
        "--client-request-token", uuid.uuid4().hex,
        *_provider_flags(args),
    ])
    _run([
        "aws", "cloudformation", "wait", "stack-update-complete",
        "--stack-name", stack_id,
        *_provider_flags(args),
    ])


def _set_production(
        args, stack_id, enabled, incumbent, binding=None, push_node=None):
    """Toggle only the two traffic resources for exact deployed versions."""
    initial = "false" if enabled else "true"
    if incumbent.get("Enabled") != initial:
        raise RuntimeError(
            f"explicit {'enable' if enabled else 'disable'} requires an "
            f"{'disabled' if enabled else 'enabled'} deployment")
    software_digest = incumbent.get("SoftwareDigest")
    if not valid_fid(software_digest):
        raise RuntimeError("notification deployment has no software digest")
    versions = _version_arns(incumbent, stack_id)
    if enabled:
        _check_launch_gate(args, stack_id, incumbent)
        _check_initialized(args, incumbent, stack_id)
    change_set = _create_traffic_change_set(args, stack_id, enabled)
    current_stack = _owned_stack(args)
    current = _outputs(current_stack)
    try:
        if current_stack.get("StackId") != stack_id \
                or current.get("Enabled") != initial \
                or current.get("SoftwareDigest") != software_digest \
                or _version_arns(current, stack_id) != versions \
                or {name: value for name, value in current.items()
                    if name != "Enabled"} != {
                    name: value for name, value in incumbent.items()
                    if name != "Enabled"}:
            raise RuntimeError("notification traffic preflight became stale")
        if enabled:
            _check_binding(current, binding)
            _checked_queues(args, current)
    except Exception:
        _discard_change_set(args, change_set)
        raise
    _execute_change_set(args, stack_id, change_set)
    final_stack = _owned_stack(args)
    outputs = _outputs(final_stack)
    if final_stack.get("StackId") != stack_id \
            or outputs.get("Enabled") != ("true" if enabled else "false") \
            or outputs.get("SoftwareDigest") != software_digest \
            or _version_arns(outputs, stack_id) != versions \
            or {name: value for name, value in outputs.items()
                if name != "Enabled"} != {
                name: value for name, value in incumbent.items()
                if name != "Enabled"}:
        raise RuntimeError("notification traffic postcondition failed")
    if enabled:
        _check_binding(outputs, binding)
        _checked_queues(args, outputs)
    return outputs


def _deploy_release(
        args, stack_id, incumbent, binding, push_node, software_digest):
    """Execute a built release only against the same disabled predecessor."""
    previous_digest = incumbent.get("SoftwareDigest")
    if not valid_fid(previous_digest):
        raise RuntimeError("notification deployment has no software digest")
    previous_versions = _version_arns(incumbent, stack_id)
    change_set = _create_release_change_set(
        args, stack_id, push_node, software_digest, previous_digest)
    current_stack = _owned_stack(args)
    current = _outputs(current_stack)
    try:
        if current_stack.get("StackId") != stack_id \
                or current.get("Enabled") != "false" \
                or current != incumbent \
                or _version_arns(current, stack_id) != previous_versions:
            raise RuntimeError("notification release preflight became stale")
        _check_binding(current, binding)
        _checked_queues(args, current)
    except Exception:
        _discard_change_set(args, change_set)
        raise
    _execute_change_set(args, stack_id, change_set)
    final_stack = _owned_stack(args)
    outputs = _outputs(final_stack)
    versions = _version_arns(outputs, stack_id)
    if final_stack.get("StackId") != stack_id \
            or outputs.get("Enabled") != "false" \
            or outputs.get("SoftwareDigest") != software_digest \
            or (software_digest != previous_digest
                and versions == previous_versions):
        raise RuntimeError("notification release postcondition failed")
    _check_binding(outputs, binding)
    _checked_queues(args, outputs)
    return outputs


def deploy(args):
    """Create disabled; updates preserve state without an explicit switch."""
    if args.update and args.enable is False:
        if DEPLOYMENT_ID_RE.fullmatch(args.deployment_id or "") is None:
            raise ValueError("deployment ID")
        target, enabled, incumbent = _stack_for_deploy(args)
        return _set_production(args, target, enabled, incumbent)
    args = _validated(args)
    target, enabled, incumbent = _stack_for_deploy(args)
    push_node = _secret_binding(args)
    binding = _binding(args, push_node)
    if incumbent is not None:
        _check_binding(incumbent, binding)
    _verify_state_lifecycle(args)
    if args.enable is True:
        return _set_production(
            args, target, enabled, incumbent, binding, push_node)
    if incumbent is not None and incumbent.get("Enabled") != "false":
        raise RuntimeError(
            "disable notification production before updating deployment")
    software_digest = _prepare_software()
    build(args, expected_digest=software_digest)
    if incumbent is not None:
        return _deploy_release(
            args, target, incumbent, binding, push_node, software_digest)
    _run([
        "sam", "deploy",
        "--template-file", str(BUILD / "template.yaml"),
        "--stack-name", target,
        "--capabilities", "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-fail-on-empty-changeset",
        "--parameter-overrides", *_parameters(
            args, enabled, push_node, software_digest),
        "--tags",
        f"{DEPLOYMENT_TAG}={DEPLOYMENT_MARKER}",
        f"{DEPLOYMENT_ID_TAG}={args.deployment_id}",
        *_provider_flags(args),
    ])
    deployed_stack = _owned_stack(args)
    outputs = _outputs(deployed_stack)
    _check_binding(outputs, binding)
    _version_arns(outputs, deployed_stack["StackId"])
    if outputs.get("Enabled") != ("true" if enabled else "false") \
            or outputs.get("SoftwareDigest") != software_digest:
        raise RuntimeError("deployed notification outputs are incomplete")
    _checked_queues(args, outputs)
    return outputs


def remove(args):
    """Delete an owned carrier only with explicit destructive authority."""
    if DEPLOYMENT_ID_RE.fullmatch(args.deployment_id or "") is None:
        raise ValueError("deployment ID")
    stack = _owned_stack(args)
    outputs = _outputs(stack)
    _checked_queues(args, outputs)
    if not args.destroy_carrier:
        raise RuntimeError(
            "refusing to delete the notification carrier; explicitly pass "
            "--destroy-carrier after disabling the deployment")
    if outputs.get("Enabled") != "false":
        raise RuntimeError("disable production before removal")
    flags = _provider_flags(args)
    _run([
        "aws", "cloudformation", "delete-stack",
        "--stack-name", stack["StackId"], *flags,
    ])
    _run([
        "aws", "cloudformation", "wait", "stack-delete-complete",
        "--stack-name", stack["StackId"], *flags,
    ])


def redrive(args):
    """Explicitly move bounded DLQ work back to its original source queue."""
    if not 1 <= args.max_per_second <= 500:
        raise ValueError("redrive rate")
    outputs = _outputs(_owned_stack(args))
    if outputs.get("Enabled") != "false":
        raise RuntimeError("disable notification delivery before redrive")
    _checked_queues(args, outputs)
    result = _run([
        "aws", "sqs", "start-message-move-task",
        "--source-arn", outputs["NotificationDeadLetterQueueArn"],
        "--destination-arn", outputs["NotificationQueueArn"],
        "--max-number-of-messages-per-second", str(args.max_per_second),
        "--output", "json",
        *_provider_flags(args),
    ], capture=True)
    try:
        handle = json.loads(result.stdout)["TaskHandle"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed SQS redrive response") from error
    if not isinstance(handle, str) or not handle:
        raise RuntimeError("malformed SQS redrive response")
    return handle


def _invoke(args, function, payload):
    with tempfile.TemporaryDirectory(prefix="poc16-notification-invoke-") \
            as directory:
        source = Path(directory) / "request.json"
        target = Path(directory) / "response.json"
        source.write_bytes(json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8"))
        result = _run([
            "aws", "lambda", "invoke",
            "--function-name", function,
            "--invocation-type", "RequestResponse",
            "--cli-binary-format", "raw-in-base64-out",
            "--payload", "fileb://" + str(source),
            str(target),
            "--output", "json",
            *_provider_flags(args),
        ], capture=True)
        try:
            metadata = json.loads(result.stdout)
            response = json.loads(target.read_bytes())
        except (OSError, TypeError, json.JSONDecodeError) as error:
            raise RuntimeError("malformed Lambda invocation response") \
                from error
    if metadata.get("StatusCode") != 200 \
            or "FunctionError" in metadata:
        raise RuntimeError("Lambda invocation failed")
    return response


def _check_initialized(args, outputs, stack_id=None):
    if not isinstance(outputs, dict):
        raise RuntimeError("bootstrap notification state before enabling")
    try:
        versions = _version_arns(outputs, stack_id)
        response = _invoke(
            args,
            versions["scanner_version_arn"],
            {
                "schema": SCAN_WAKE_SCHEMA,
                "workspace": outputs["WorkspaceId"],
            },
        )
    except (KeyError, RuntimeError):
        raise RuntimeError(
            "bootstrap notification state before enabling") from None
    if not isinstance(response, dict) or set(response) != {
            "schema", "status"} \
            or response.get("schema") != SCAN_RESULT_SCHEMA \
            or response.get("status") not in {
                "advanced", "idle", "published", "raced", "republished"}:
        raise RuntimeError("notification initialization check failed")


def bootstrap(args):
    """Initialize absent notification state while production is disabled."""
    stack = _owned_stack(args)
    outputs = _outputs(stack)
    if outputs.get("Enabled") != "false":
        raise RuntimeError("disable notification production before bootstrap")
    versions = _version_arns(outputs, stack["StackId"])
    response = _invoke(
        args,
        versions["scanner_version_arn"],
        {
            "mode": args.bootstrap_mode,
            "schema": BOOTSTRAP_SCHEMA,
            "workspace": outputs["WorkspaceId"],
        },
    )
    if response != {
            "mode": args.bootstrap_mode,
            "schema": BOOTSTRAP_RESULT_SCHEMA,
            "status": "initialized"}:
        raise RuntimeError("notification bootstrap was not confirmed")
    return response


def launch_binding(args):
    """Return the exact disabled deployment binding for device harnesses."""
    stack = _owned_stack(args)
    outputs = _outputs(stack)
    if outputs.get("Enabled") != "false":
        raise RuntimeError("disable notification production before launch test")
    return _launch_binding(stack["StackId"], outputs)


def direct_smoke(args):
    """Directly prove current authority plus at least one FCM acceptance."""
    if not args.confirm_live_fcm:
        raise RuntimeError("explicitly confirm live FCM invocation")
    stack = _owned_stack(args)
    outputs = _outputs(stack)
    if outputs.get("Enabled") != "false":
        raise RuntimeError("disable notification production before smoke")
    versions = _version_arns(outputs, stack["StackId"])
    raw = Path(args.hint_file).read_bytes()
    hint = decode_hint(raw)
    if hint.workspace != outputs.get("WorkspaceId"):
        raise ValueError("direct-smoke hint workspace")
    response = _invoke(
        args,
        versions["delivery_version_arn"],
        {
            "body": base64.b64encode(raw).decode("ascii"),
            "schema": DIRECT_SMOKE_SCHEMA,
        },
    )
    if not isinstance(response, dict) or set(response) != {
            "accepted_count", "retry_count", "schema", "terminal_count"} \
            or response.get("schema") != DIRECT_SMOKE_RESULT_SCHEMA \
            or any(type(response.get(name)) is not int
                   or response[name] < 0 for name in (
                       "accepted_count", "retry_count", "terminal_count")) \
            or response["accepted_count"] < 1 \
            or response["retry_count"] != 0 \
            or response["terminal_count"] != 0:
        raise RuntimeError(
            "direct Firebase smoke proved no clean provider acceptance")
    return response


def _identity_arguments(command):
    command.add_argument("--stack-name", required=True)
    command.add_argument("--deployment-id", required=True)
    command.add_argument("--region")
    command.add_argument("--profile")


def parser():
    result = argparse.ArgumentParser(
        description="POC-16 AWS notification deployment")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("build")
    test = commands.add_parser("test")
    test.add_argument("pytest_args", nargs="*")
    deploy_command = commands.add_parser("deploy")
    _identity_arguments(deploy_command)
    deploy_command.add_argument("--workspace")
    deploy_command.add_argument("--canonical-bucket")
    deploy_command.add_argument("--canonical-prefix")
    deploy_command.add_argument("--state-bucket")
    deploy_command.add_argument("--state-prefix")
    deploy_command.add_argument("--expected-owner")
    deploy_command.add_argument("--notification-secret-arn")
    deploy_command.add_argument("--notification-secret-version-id")
    deploy_command.add_argument("--repository-kms-key-arn")
    deploy_command.add_argument("--state-kms-key-arn")
    deploy_command.add_argument("--secret-kms-key-arn")
    deploy_command.add_argument("--alarm-action-arn")
    deploy_command.add_argument("--schedule", default="rate(1 minute)")
    deploy_command.add_argument("--scanner-concurrency", type=int, default=2)
    deploy_command.add_argument("--delivery-concurrency", type=int, default=10)
    deploy_command.add_argument(
        "--max-receive-count", type=int, default=MAX_RECEIVE_COUNT)
    deploy_command.add_argument("--ios-launch-record")
    deploy_command.add_argument("--android-launch-record")
    traffic = deploy_command.add_mutually_exclusive_group()
    traffic.add_argument(
        "--enable", dest="enable", action="store_const", const=True)
    traffic.add_argument(
        "--disable", dest="enable", action="store_const", const=False)
    deploy_command.set_defaults(enable=None)
    mode = deploy_command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--create", action="store_true")
    mode.add_argument("--update", action="store_true")
    remove_command = commands.add_parser("remove")
    _identity_arguments(remove_command)
    remove_command.add_argument("--destroy-carrier", action="store_true")
    redrive_command = commands.add_parser("redrive")
    _identity_arguments(redrive_command)
    redrive_command.add_argument("--max-per-second", type=int, default=10)
    bootstrap_command = commands.add_parser("bootstrap")
    _identity_arguments(bootstrap_command)
    bootstrap_mode = bootstrap_command.add_mutually_exclusive_group(
        required=True)
    bootstrap_mode.add_argument(
        "--current", dest="bootstrap_mode", action="store_const",
        const="current")
    bootstrap_mode.add_argument(
        "--backfill", dest="bootstrap_mode", action="store_const",
        const="backfill")
    launch_command = commands.add_parser("launch-binding")
    _identity_arguments(launch_command)
    smoke_command = commands.add_parser("direct-smoke")
    _identity_arguments(smoke_command)
    smoke_command.add_argument("--hint-file", required=True)
    smoke_command.add_argument("--confirm-live-fcm", action="store_true")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "build":
        build(args)
    elif args.command == "test":
        _run([
            sys.executable, "-m", "pytest", "-q",
            "tests/test_aws_notification_sqs.py",
            "tests/test_aws_notifications.py",
            "tests/test_aws_notifications_deploy.py",
            *args.pytest_args,
        ])
    elif args.command == "deploy":
        print(json.dumps(deploy(args), sort_keys=True))
    elif args.command == "remove":
        remove(args)
    elif args.command == "redrive":
        print(redrive(args))
    elif args.command == "bootstrap":
        print(json.dumps(bootstrap(args), sort_keys=True))
    elif args.command == "launch-binding":
        print(json.dumps(launch_binding(args), sort_keys=True))
    else:
        print(json.dumps(direct_smoke(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
