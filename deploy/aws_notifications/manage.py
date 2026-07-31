#!/usr/bin/env python3
"""Build, deploy, inspect, redrive, and remove AWS notifications safely."""
import argparse
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from adapters.aws import queue_binding
from adapters.s3 import S3Config
from core.object_store import validate_store_prefix
from core.shape import valid_fid
from notifications.hints import decode_hint

from .config import (
    ALARM_ACTION_ARN_RE,
    DEPLOYMENT_ID_RE,
    DEPLOYMENT_ID_TAG,
    DEPLOYMENT_MARKER,
    DEPLOYMENT_TAG,
    KMS_KEY_ARN_RE,
    MAX_RECEIVE_COUNT,
    MIN_STATE_RETENTION_DAYS,
    OWNER_RE,
    SCAN_WAKE_SCHEMA,
    SECRET_ARN_RE,
)


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
STAGE = HERE / "stage"
BUILD = HERE / ".aws-sam"
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
    "deploy/aws_notifications/__init__.py",
    "deploy/aws_notifications/app.py",
    "deploy/aws_notifications/config.py",
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


def build(_args=None):
    stage()
    _run([
        "sam", "build",
        "--template-file", str(HERE / "template.yaml"),
        "--build-dir", str(BUILD),
        "--use-container",
    ])


def _provider_flags(args):
    flags = []
    if getattr(args, "region", None):
        flags += ["--region", args.region]
    if getattr(args, "profile", None):
        flags += ["--profile", args.profile]
    return flags


def _prefixes_overlap(left, right):
    left, right = left.rstrip("/"), right.rstrip("/")
    return left == right or left.startswith(right + "/") \
        or right.startswith(left + "/")


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
    if args.canonical_bucket == args.state_bucket \
            and _prefixes_overlap(args.canonical_prefix, args.state_prefix):
        raise ValueError("canonical and notification-state prefixes overlap")
    if SECRET_ARN_RE.fullmatch(args.notification_secret_arn or "") is None:
        raise ValueError("notification secret ARN")
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
    if type(args.state_retention_days) is not int \
            or args.state_retention_days < MIN_STATE_RETENTION_DAYS:
        raise ValueError("notification-state retention")
    if not isinstance(args.schedule, str) or len(args.schedule) > 256 \
            or not args.schedule.startswith(("rate(", "cron(")) \
            or not args.schedule.endswith(")"):
        raise ValueError("notification schedule")
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


def _outputs(stack):
    return {
        row.get("OutputKey"): row.get("OutputValue")
        for row in stack.get("Outputs", ()) if isinstance(row, dict)
    }


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
    status = stack.get("StackStatus")
    if not isinstance(status, str) or status.startswith("DELETE_"):
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
        return args.stack_name, bool(args.enable)
    if incumbent is None:
        raise RuntimeError("update requires an existing owned stack")
    owned = _owned_stack(args, incumbent)
    enabled = _outputs(owned).get("Enabled")
    if enabled not in {"true", "false"}:
        raise RuntimeError("notification stack has no enabled state")
    return owned["StackId"], (
        enabled == "true" if args.enable is None else args.enable)


def _parameters(args, enabled=None):
    enabled = bool(args.enable) if enabled is None else enabled
    if type(enabled) is not bool:
        raise TypeError("notification enabled state")
    return (
        f"Enabled={'true' if enabled else 'false'}",
        f"DeploymentId={args.deployment_id}",
        f"WorkspaceId={args.workspace}",
        f"CanonicalBucketName={args.canonical_bucket}",
        f"CanonicalPrefix={args.canonical_prefix}",
        f"NotificationStateBucketName={args.state_bucket}",
        f"NotificationStatePrefix={args.state_prefix}",
        f"NotificationStateMinimumRetentionDays={args.state_retention_days}",
        f"ExpectedBucketOwner={args.expected_owner}",
        f"NotificationSecretArn={args.notification_secret_arn}",
        f"RepositoryKmsKeyArn={args.repository_kms_key_arn or ''}",
        f"NotificationStateKmsKeyArn={args.state_kms_key_arn or ''}",
        f"NotificationSecretKmsKeyArn={args.secret_kms_key_arn or ''}",
        f"ScheduleExpression={args.schedule}",
        f"ScannerReservedConcurrency={args.scanner_concurrency}",
        f"DeliveryReservedConcurrency={args.delivery_concurrency}",
        f"MaxReceiveCount={args.max_receive_count}",
        f"AlarmActionArn={args.alarm_action_arn or ''}",
    )


def deploy(args):
    """Create disabled; updates preserve state without an explicit switch."""
    args = _validated(args)
    target, enabled = _stack_for_deploy(args)
    build(args)
    _run([
        "sam", "deploy",
        "--template-file", str(BUILD / "template.yaml"),
        "--stack-name", target,
        "--capabilities", "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-fail-on-empty-changeset",
        "--parameter-overrides", *_parameters(args, enabled),
        "--tags",
        f"{DEPLOYMENT_TAG}={DEPLOYMENT_MARKER}",
        f"{DEPLOYMENT_ID_TAG}={args.deployment_id}",
        *_provider_flags(args),
    ])
    outputs = _outputs(_owned_stack(args))
    if outputs.get("WorkspaceId") != args.workspace \
            or outputs.get("Enabled") != ("true" if enabled else "false") \
            or outputs.get("NotificationStateMinimumRetentionDays") \
            != str(args.state_retention_days):
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
    if not args.discard_pending:
        raise RuntimeError(
            "refusing to delete the durable notification carrier; first "
            "disable or redrive it, then explicitly pass --discard-pending")
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
    if outputs.get("Enabled") != "true":
        raise RuntimeError("notification deployment is disabled")
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
    with tempfile.TemporaryDirectory(prefix="poc16-notification-smoke-") \
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
            raise RuntimeError("malformed Lambda smoke response") from error
    if metadata.get("StatusCode") != 200 \
            or "FunctionError" in metadata:
        raise RuntimeError("Lambda smoke invocation failed")
    return response


def live_smoke(args):
    """Opt-in scanner plus real Firebase attempt for an operator-owned hint."""
    outputs = _outputs(_owned_stack(args))
    if outputs.get("Enabled") != "true":
        raise RuntimeError("notification deployment is disabled")
    _checked_queues(args, outputs)
    raw = Path(args.hint_file).read_bytes()
    hint = decode_hint(raw)
    if hint.workspace != outputs.get("WorkspaceId"):
        raise ValueError("live-smoke hint workspace")
    scan = _invoke(
        args,
        outputs["NotificationScannerFunctionArn"],
        {"schema": SCAN_WAKE_SCHEMA, "workspace": hint.workspace},
    )
    arn = outputs["NotificationQueueArn"]
    delivery = _invoke(
        args,
        outputs["NotificationDeliveryFunctionArn"],
        {"Records": [{
            "attributes": {"ApproximateReceiveCount": "1"},
            "body": base64.b64encode(raw).decode("ascii"),
            "eventSource": "aws:sqs",
            "eventSourceARN": arn,
            "messageId": "operator-live-smoke",
        }]},
    )
    if delivery != {"batchItemFailures": []}:
        raise RuntimeError("live Firebase smoke was not accepted")
    return {"scanner": scan, "delivery": delivery}


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
    deploy_command.add_argument("--workspace", required=True)
    deploy_command.add_argument("--canonical-bucket", required=True)
    deploy_command.add_argument("--canonical-prefix", required=True)
    deploy_command.add_argument("--state-bucket", required=True)
    deploy_command.add_argument("--state-prefix", required=True)
    deploy_command.add_argument(
        "--state-retention-days", type=int, default=30,
        help=("assert the external state lifecycle preserves objects through "
              "queue, DLQ, alert, and one redrive (minimum 30 days)"),
    )
    deploy_command.add_argument("--expected-owner", required=True)
    deploy_command.add_argument("--notification-secret-arn", required=True)
    deploy_command.add_argument("--repository-kms-key-arn")
    deploy_command.add_argument("--state-kms-key-arn")
    deploy_command.add_argument("--secret-kms-key-arn")
    deploy_command.add_argument("--alarm-action-arn")
    deploy_command.add_argument("--schedule", default="rate(1 minute)")
    deploy_command.add_argument("--scanner-concurrency", type=int, default=2)
    deploy_command.add_argument("--delivery-concurrency", type=int, default=10)
    deploy_command.add_argument(
        "--max-receive-count", type=int, default=MAX_RECEIVE_COUNT)
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
    remove_command.add_argument("--discard-pending", action="store_true")
    redrive_command = commands.add_parser("redrive")
    _identity_arguments(redrive_command)
    redrive_command.add_argument("--max-per-second", type=int, default=10)
    smoke_command = commands.add_parser("live-smoke")
    _identity_arguments(smoke_command)
    smoke_command.add_argument("--hint-file", required=True)
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
    else:
        print(json.dumps(live_smoke(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
