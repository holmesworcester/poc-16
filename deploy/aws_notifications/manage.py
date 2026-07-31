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
    DIRECT_SMOKE_RESULT_SCHEMA,
    DIRECT_SMOKE_SCHEMA,
    DLQ_RETENTION_SECONDS,
    KMS_KEY_ARN_RE,
    MAX_RECEIVE_COUNT,
    OWNER_RE,
    QUEUE_RETENTION_SECONDS,
    SECRET_ARN_RE,
    SECRET_VERSION_RE,
)
from .secret import decode_secret, push_node_id


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
        return (
            args.stack_name,
            bool(args.enable),
            bool(args.direct_smoke),
            None,
        )
    if incumbent is None:
        raise RuntimeError("update requires an existing owned stack")
    owned = _owned_stack(args, incumbent)
    outputs = _outputs(owned)
    switches = []
    for output, selected in (
            ("Enabled", args.enable),
            ("DirectSmokeEnabled", args.direct_smoke)):
        incumbent = outputs.get(output)
        if incumbent not in {"true", "false"}:
            raise RuntimeError("notification stack has no traffic state")
        switches.append(
            incumbent == "true" if selected is None else selected)
    return owned["StackId"], *switches, outputs


def _parameters(args, enabled, direct_smoke, push_node):
    if type(enabled) is not bool or type(direct_smoke) is not bool \
            or not valid_fid(push_node):
        raise TypeError("notification deployment state")
    return (
        f"Enabled={'true' if enabled else 'false'}",
        f"DirectSmokeEnabled={'true' if direct_smoke else 'false'}",
        f"DeploymentId={args.deployment_id}",
        f"WorkspaceId={args.workspace}",
        f"CanonicalBucketName={args.canonical_bucket}",
        f"CanonicalPrefix={args.canonical_prefix}",
        f"NotificationStateBucketName={args.state_bucket}",
        f"NotificationStatePrefix={args.state_prefix}",
        f"ExpectedBucketOwner={args.expected_owner}",
        f"NotificationSecretArn={args.notification_secret_arn}",
        f"NotificationSecretVersionId={args.notification_secret_version_id}",
        f"PushNodeId={push_node}",
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
    target, enabled, direct_smoke_enabled, incumbent = _stack_for_deploy(args)
    push_node = _secret_binding(args)
    binding = _binding(args, push_node)
    if incumbent is not None:
        _check_binding(incumbent, binding)
    _verify_state_lifecycle(args)
    build(args)
    _run([
        "sam", "deploy",
        "--template-file", str(BUILD / "template.yaml"),
        "--stack-name", target,
        "--capabilities", "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-fail-on-empty-changeset",
        "--parameter-overrides", *_parameters(
            args, enabled, direct_smoke_enabled, push_node),
        "--tags",
        f"{DEPLOYMENT_TAG}={DEPLOYMENT_MARKER}",
        f"{DEPLOYMENT_ID_TAG}={args.deployment_id}",
        *_provider_flags(args),
    ])
    outputs = _outputs(_owned_stack(args))
    _check_binding(outputs, binding)
    if outputs.get("Enabled") != ("true" if enabled else "false") \
            or outputs.get("DirectSmokeEnabled") \
            != ("true" if direct_smoke_enabled else "false"):
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
    if outputs.get("Enabled") != "false" \
            or outputs.get("DirectSmokeEnabled") != "false":
        raise RuntimeError(
            "disable production and direct-smoke invocation before removal")
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


def direct_smoke(args):
    """Directly prove current authority plus at least one FCM acceptance."""
    outputs = _outputs(_owned_stack(args))
    if outputs.get("DirectSmokeEnabled") != "true":
        raise RuntimeError("notification direct smoke is disabled")
    raw = Path(args.hint_file).read_bytes()
    hint = decode_hint(raw)
    if hint.workspace != outputs.get("WorkspaceId"):
        raise ValueError("direct-smoke hint workspace")
    response = _invoke(
        args,
        outputs["NotificationDeliveryFunctionArn"],
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
    deploy_command.add_argument("--workspace", required=True)
    deploy_command.add_argument("--canonical-bucket", required=True)
    deploy_command.add_argument("--canonical-prefix", required=True)
    deploy_command.add_argument("--state-bucket", required=True)
    deploy_command.add_argument("--state-prefix", required=True)
    deploy_command.add_argument("--expected-owner", required=True)
    deploy_command.add_argument("--notification-secret-arn", required=True)
    deploy_command.add_argument(
        "--notification-secret-version-id", required=True)
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
    smoke = deploy_command.add_mutually_exclusive_group()
    smoke.add_argument(
        "--enable-smoke", dest="direct_smoke",
        action="store_const", const=True)
    smoke.add_argument(
        "--disable-smoke", dest="direct_smoke",
        action="store_const", const=False)
    deploy_command.set_defaults(direct_smoke=None)
    mode = deploy_command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--create", action="store_true")
    mode.add_argument("--update", action="store_true")
    remove_command = commands.add_parser("remove")
    _identity_arguments(remove_command)
    remove_command.add_argument("--destroy-carrier", action="store_true")
    redrive_command = commands.add_parser("redrive")
    _identity_arguments(redrive_command)
    redrive_command.add_argument("--max-per-second", type=int, default=10)
    smoke_command = commands.add_parser("direct-smoke")
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
        print(json.dumps(direct_smoke(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
