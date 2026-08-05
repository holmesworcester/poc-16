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
from notifications.delivery import delivery_domain_id
from notifications.hints import decode_hint

from .config import (
    ALARM_ACTION_ARN_RE,
    BOOTSTRAP_RESULT_SCHEMA,
    BOOTSTRAP_SCHEMA,
    CODE_SHA256_RE,
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
PACKAGED = BUILD / "packaged.json"
LOG_RETENTION_DAYS = 14
MAX_PACKAGED_TEMPLATE_BYTES = 1_048_576
MAX_LAMBDA_ZIP_BYTES = 256 * 1024 * 1024
SYNCHRONOUS_STORAGE_CLASSES = frozenset({
    "STANDARD_IA", "ONEZONE_IA", "GLACIER_IR",
})
OPERABLE_STACK_STATUSES = frozenset({
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
})
TEMPLATE_PARAMETERS = (
    "Enabled",
    "DeploymentId",
    "SoftwareDigest",
    "ScannerCodeSha256",
    "DeliveryCodeSha256",
    "DeliveryDomainId",
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
CODE_HASH_PARAMETERS = {
    "NotificationScannerFunction": "ScannerCodeSha256",
    "NotificationDeliveryFunction": "DeliveryCodeSha256",
}
SOURCE_PACKAGES = ("facts", "notifications")
SOURCE_TREES = ("adapters/aws", "adapters/gcp", "adapters/s3")
NOTIFICATION_CORE_MODULES = (
    "__init__.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "fact_index.py",
    "http_body.py",
    "kernel.py",
    "limits.py",
    "merkle_map.py",
    "object_store.py",
    "removal_path.py",
    "shape.py",
    "suppression.py",
    "removal_tree.py",
    "writer_head.py",
    "writer_repository.py",
    "writer_tree.py",
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
        "core/writer_repository.py",
        "deploy/aws_notifications/app.py",
        "deploy/aws_notifications/secret.py",
        "facts/auth/push_endpoint.py",
        "notifications/discovery.py",
        "notifications/forest.py",
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


def _lifecycle_prefix(rule, label):
    def malformed():
        raise RuntimeError(f"malformed {label} bucket lifecycle filter")

    def valid_tag(value):
        return isinstance(value, dict) and set(value) == {"Key", "Value"} \
            and all(isinstance(item, str) for item in value.values())

    if "Prefix" in rule and "Filter" in rule:
        malformed()
    if "Prefix" in rule:
        prefix = rule["Prefix"]
        if not isinstance(prefix, str):
            malformed()
        return prefix
    if "Filter" not in rule:
        return ""
    value = rule["Filter"]
    if not isinstance(value, dict):
        malformed()
    if not value:
        return ""
    direct = {
        "Prefix", "Tag", "ObjectSizeGreaterThan", "ObjectSizeLessThan",
    }
    if len(value) != 1 or not set(value) <= direct | {"And"}:
        malformed()
    if "And" in value:
        value = value["And"]
        allowed = {
            "Prefix", "Tags", "ObjectSizeGreaterThan", "ObjectSizeLessThan",
        }
        if not isinstance(value, dict) or not value \
                or not set(value) <= allowed \
                or "Tags" in value and (
                    not isinstance(value["Tags"], list)
                    or not value["Tags"]
                    or not all(valid_tag(tag) for tag in value["Tags"])):
            malformed()
    elif "Tag" in value and not valid_tag(value["Tag"]):
        malformed()
    for size in ("ObjectSizeGreaterThan", "ObjectSizeLessThan"):
        if size in value and (type(value[size]) is not int or value[size] < 0):
            malformed()
    prefix = value.get("Prefix", "")
    if not isinstance(prefix, str):
        malformed()
    return prefix


def _prefixes_overlap(rule_prefix, authoritative_prefix):
    targets = (
        authoritative_prefix + "/cursor",
        authoritative_prefix + "/obj/",
    )
    return any(target.startswith(rule_prefix) or rule_prefix.startswith(target)
               for target in targets)


def _verify_state_lifecycle(args):
    """Require every authoritative object to remain synchronously readable."""
    for bucket, prefix, label in (
            (args.canonical_bucket, args.canonical_prefix, "canonical"),
            (args.state_bucket, args.state_prefix, "notification-state")):
        try:
            result = _run([
                "aws", "s3api", "get-bucket-lifecycle-configuration",
                "--bucket", bucket,
                "--expected-bucket-owner", args.expected_owner,
                "--output", "json",
                *_provider_flags(args),
            ], capture=True)
        except subprocess.CalledProcessError as error:
            detail = " ".join(value for value in (
                error.stdout, error.stderr) if isinstance(value, str))
            if "NoSuchLifecycleConfiguration" in detail:
                continue
            raise RuntimeError(
                f"cannot verify {label} bucket lifecycle") from error
        try:
            rules = json.loads(result.stdout)["Rules"]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"malformed {label} bucket lifecycle") from error
        if not isinstance(rules, list) or not all(
                isinstance(rule, dict) for rule in rules):
            raise RuntimeError(f"malformed {label} bucket lifecycle")
        for rule in rules:
            if rule.get("Status") not in {"Enabled", "Disabled"}:
                raise RuntimeError(f"malformed {label} bucket lifecycle")
            if rule["Status"] != "Enabled":
                continue
            rule_prefix = _lifecycle_prefix(rule, label)
            if not _prefixes_overlap(rule_prefix, prefix):
                continue
            if any(name in rule for name in (
                    "Expiration", "NoncurrentVersionExpiration")):
                raise RuntimeError(
                    f"{label} authoritative objects may expire")
            for name in ("Transitions", "NoncurrentVersionTransitions"):
                if name not in rule:
                    continue
                transitions = rule.get(name, ())
                if not isinstance(transitions, list) or not transitions or any(
                        not isinstance(row, dict)
                        or row.get("StorageClass")
                        not in SYNCHRONOUS_STORAGE_CLASSES
                        for row in transitions):
                    raise RuntimeError(
                        f"{label} authoritative objects may require restore")


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
        secret, rows = decode_secret(response.get("SecretString"))
        push_node = push_node_id(secret)
        routes = tuple(sorted(
            (row["application"], row["environment"],
             row["credential"]["project_id"])
            for row in rows))
        return push_node, delivery_domain_id(push_node, routes)
    except (AttributeError, RuntimeError, TypeError, ValueError,
            json.JSONDecodeError):
        raise RuntimeError("invalid pinned notification secret") from None


def _outputs(stack):
    return {
        row.get("OutputKey"): row.get("OutputValue")
        for row in stack.get("Outputs", ()) if isinstance(row, dict)
    }


def _binding(args, push_node, delivery_domain):
    return {
        "WorkspaceId": args.workspace,
        "CanonicalBucketName": args.canonical_bucket,
        "CanonicalPrefix": args.canonical_prefix,
        "NotificationStateBucketName": args.state_bucket,
        "NotificationStatePrefix": args.state_prefix,
        "ExpectedBucketOwner": args.expected_owner,
        "NotificationSecretArn": args.notification_secret_arn,
        "PushNodeId": push_node,
        "DeliveryDomainId": delivery_domain,
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


def _check_requested_release(args, outputs):
    expected = {
        "NotificationSecretVersionId": args.notification_secret_version_id,
        "NotificationScanScheduleExpression": args.schedule,
        "NotificationScannerReservedConcurrency": str(
            args.scanner_concurrency),
        "NotificationDeliveryReservedConcurrency": str(
            args.delivery_concurrency),
        "NotificationMaxReceiveCount": str(args.max_receive_count),
        "NotificationLogRetentionDays": str(LOG_RETENTION_DAYS),
        "NotificationAlarmActionArn": args.alarm_action_arn or "",
    }
    changed = sorted(
        name for name, value in expected.items()
        if outputs.get(name) != value)
    if changed:
        raise RuntimeError(
            "requested notification release differs: " + ", ".join(changed))


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


def _checked_code_hashes(code_hashes):
    if not isinstance(code_hashes, dict) \
            or set(code_hashes) != set(CODE_HASH_PARAMETERS.values()) \
            or any(CODE_SHA256_RE.fullmatch(value or "") is None
                   for value in code_hashes.values()):
        raise TypeError("notification packaged code hashes")
    return code_hashes


def _output_code_hashes(outputs):
    return _checked_code_hashes({
        name: outputs.get(name) for name in CODE_HASH_PARAMETERS.values()
    })


def _parameter_values(
        args, enabled, push_node, delivery_domain, software_digest,
        code_hashes):
    if type(enabled) is not bool or not valid_fid(push_node) \
            or not valid_fid(delivery_domain) \
            or not valid_fid(software_digest):
        raise TypeError("notification deployment state")
    code_hashes = _checked_code_hashes(code_hashes)
    values = {
        "Enabled": "true" if enabled else "false",
        "DeploymentId": args.deployment_id,
        "SoftwareDigest": software_digest,
        "ScannerCodeSha256": code_hashes["ScannerCodeSha256"],
        "DeliveryCodeSha256": code_hashes["DeliveryCodeSha256"],
        "DeliveryDomainId": delivery_domain,
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


def _parameters(
        args, enabled, push_node, delivery_domain, software_digest,
        code_hashes):
    return tuple(
        f"{name}={value}" for name, value in _parameter_values(
            args, enabled, push_node, delivery_domain, software_digest,
            code_hashes).items())


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
        resource = parts[5].split("/", 2) if len(parts) == 6 else ()
        if len(resource) != 3 or resource[0] != "stack" or not resource[1]:
            raise RuntimeError("notification stack identity ARN")
        if outputs.get("AwsPartition") != parts[1] \
                or outputs.get("StackAccountId") != parts[4]:
            raise RuntimeError("notification stack partition/account mismatch")
        for role in ("delivery", "scanner"):
            value = values[f"{role}_version_arn"].split(":", 6)
            function = value[6].rsplit(":", 1)[0] if len(value) == 7 else ""
            if len(value) != 7 or value[1] != parts[1] \
                    or value[3:5] != parts[3:5] \
                    or function != f"{resource[1]}-notification-{role}":
                raise RuntimeError(
                    "notification immutable versions cross stack boundary")
    return values


def _launch_binding(stack_id, outputs):
    result = {
        "aws_partition": outputs.get("AwsPartition"),
        "canonical_bucket": outputs.get("CanonicalBucketName"),
        "canonical_prefix": outputs.get("CanonicalPrefix"),
        "deployment_id": outputs.get("DeploymentId"),
        "delivery_domain_id": outputs.get("DeliveryDomainId"),
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
        "stack_account_id": outputs.get("StackAccountId"),
        "stack_id": stack_id,
        "workspace": outputs.get("WorkspaceId"),
    }
    if not all(isinstance(value, str) and value for value in result.values()) \
            or not all(valid_fid(result[name]) for name in (
                "delivery_domain_id", "push_node_id", "software_digest",
                "workspace")):
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


def _expected_version_environment(outputs, role):
    common = {
        "TINYP2P_NOTIFICATION_AWS_PARTITION": outputs.get("AwsPartition"),
        "TINYP2P_NOTIFICATION_DEPLOYMENT_ID": outputs.get("DeploymentId"),
        "TINYP2P_NOTIFICATION_WORKSPACE_ID": outputs.get("WorkspaceId"),
        "TINYP2P_NOTIFICATION_CANONICAL_BUCKET": outputs.get(
            "CanonicalBucketName"),
        "TINYP2P_NOTIFICATION_CANONICAL_PREFIX": outputs.get(
            "CanonicalPrefix"),
        "TINYP2P_NOTIFICATION_STATE_BUCKET": outputs.get(
            "NotificationStateBucketName"),
        "TINYP2P_NOTIFICATION_STATE_PREFIX": outputs.get(
            "NotificationStatePrefix"),
        "TINYP2P_NOTIFICATION_EXPECTED_BUCKET_OWNER": outputs.get(
            "ExpectedBucketOwner"),
        "TINYP2P_NOTIFICATION_QUEUE_ARN": outputs.get(
            "NotificationQueueArn"),
        "TINYP2P_NOTIFICATION_DELIVERY_DOMAIN_ID": outputs.get(
            "DeliveryDomainId"),
        "TINYP2P_NOTIFICATION_SOFTWARE_DIGEST": outputs.get(
            "SoftwareDigest"),
    }
    if role == "scanner":
        common.update({
            "TINYP2P_NOTIFICATION_AWS_ACCOUNT_ID": outputs.get(
                "StackAccountId"),
            "TINYP2P_NOTIFICATION_QUEUE_URL": outputs.get(
                "NotificationQueueUrl"),
        })
    elif role == "delivery":
        common.update({
            "TINYP2P_NOTIFICATION_SECRET_ARN": outputs.get(
                "NotificationSecretArn"),
            "TINYP2P_NOTIFICATION_SECRET_VERSION_ID": outputs.get(
                "NotificationSecretVersionId"),
            "TINYP2P_NOTIFICATION_PUSH_NODE_ID": outputs.get("PushNodeId"),
        })
    else:
        raise ValueError("notification Lambda role")
    if any(not isinstance(value, str) or not value for value in common.values()):
        raise RuntimeError("notification version environment binding")
    return common


def _version_extensions_are_default(configured, function_name):
    # GetFunctionConfiguration grows as Lambda gains capabilities.  Exact
    # release verification must classify every returned field: either the
    # caller checks it as authority, it is inert observation metadata, or it
    # is an extension whose execution semantics we require to be the default.
    # Unknown fields fail closed until they have been classified here.
    known = {
        "Architectures", "CapacityProviderConfig", "CodeSha256", "CodeSize",
        "ConfigSha256", "DeadLetterConfig", "Description", "DurableConfig",
        "Environment", "EphemeralStorage", "FileSystemConfigs", "FunctionArn",
        "FunctionName", "Handler", "ImageConfigResponse", "KMSKeyArn",
        "LastModified", "LastUpdateStatus", "LastUpdateStatusReason",
        "LastUpdateStatusReasonCode", "Layers", "LoggingConfig", "MasterArn",
        "MemorySize", "PackageType", "RevisionId", "Role", "Runtime",
        "RuntimeVersionConfig", "SigningJobArn", "SigningProfileVersionArn",
        "SnapStart", "State", "StateReason", "StateReasonCode",
        "TenancyConfig", "Timeout", "TracingConfig", "Version", "VpcConfig",
    }
    if set(configured) - known:
        return False
    vpc = configured.get("VpcConfig")
    vpc_ok = vpc in (None, {}) or (
        isinstance(vpc, dict)
        and set(vpc) <= {
            "SubnetIds", "SecurityGroupIds", "VpcId",
            "Ipv6AllowedForDualStack",
        }
        and vpc.get("SubnetIds", []) == []
        and vpc.get("SecurityGroupIds", []) == []
        and vpc.get("VpcId", "") == ""
        and vpc.get("Ipv6AllowedForDualStack", False) is False)
    logging = configured.get("LoggingConfig")
    logging_ok = logging is None or (
        isinstance(logging, dict)
        and set(logging) <= {
            "ApplicationLogLevel", "LogFormat", "LogGroup",
            "SystemLogLevel",
        }
        and logging.get("LogFormat", "Text") == "Text"
        and logging.get("LogGroup", f"/aws/lambda/{function_name}")
        == f"/aws/lambda/{function_name}"
        and logging.get("ApplicationLogLevel") is None
        and logging.get("SystemLogLevel") is None)
    config_hash = configured.get("ConfigSha256")
    return vpc_ok \
        and logging_ok \
        and (config_hash is None
             or CODE_SHA256_RE.fullmatch(config_hash or "") is not None) \
        and configured.get("Layers") in (None, []) \
        and configured.get("FileSystemConfigs") in (None, []) \
        and configured.get("DeadLetterConfig") in (None, {}) \
        and configured.get("TracingConfig") in (
            None, {"Mode": "PassThrough"}) \
        and configured.get("KMSKeyArn") in (None, "") \
        and configured.get("ImageConfigResponse") in (None, {}) \
        and configured.get("EphemeralStorage") in (None, {"Size": 512}) \
        and configured.get("SnapStart") in (
            None, {"ApplyOn": "None", "OptimizationStatus": "Off"}) \
        and configured.get("CapacityProviderConfig") in (None, {}) \
        and configured.get("DurableConfig") in (None, {}) \
        and configured.get("TenancyConfig") in (None, {}) \
        and configured.get("MasterArn") in (None, "")


def _schedule_rule_is_exact(rule, outputs, versions, name, schedule, enabled):
    known = {
        "Arn", "CreatedBy", "Description", "EventBusName", "EventPattern",
        "ManagedBy", "Name", "RoleArn", "ScheduleExpression", "State",
    }
    scanner = versions.get("scanner_version_arn", "").split(":", 6)
    partition = outputs.get("AwsPartition")
    account = outputs.get("StackAccountId")
    if len(scanner) != 7 or scanner[0] != "arn" \
            or scanner[1] != partition or scanner[2] != "lambda" \
            or scanner[4] != account:
        return False
    expected_arn = f"arn:{partition}:events:{scanner[3]}:{account}:rule/{name}"
    return set(rule) <= known \
        and rule.get("Name") == name \
        and rule.get("Arn") == expected_arn \
        and rule.get("CreatedBy") == account \
        and rule.get("EventBusName") == "default" \
        and rule.get("ScheduleExpression") == schedule \
        and rule.get("State") == ("ENABLED" if enabled else "DISABLED") \
        and rule.get("Description") in (None, "") \
        and rule.get("EventPattern") is None \
        and rule.get("RoleArn") is None \
        and rule.get("ManagedBy") is None


def _mapping_extensions_are_default(mapping):
    known = {
        "AmazonManagedKafkaEventSourceConfig", "BatchSize",
        "BisectBatchOnFunctionError", "DestinationConfig",
        "DocumentDBEventSourceConfig", "EventSourceArn",
        "EventSourceMappingArn", "FilterCriteria", "FilterCriteriaError",
        "FunctionArn", "FunctionResponseTypes", "KMSKeyArn", "KmsKeyArn",
        "LastModified", "LastProcessingResult",
        "MaximumBatchingWindowInSeconds", "MaximumRecordAgeInSeconds",
        "MaximumRetryAttempts", "MetricsConfig", "ParallelizationFactor",
        "ProvisionedPollerConfig", "Queues", "ScalingConfig",
        "SelfManagedEventSource", "SelfManagedKafkaEventSourceConfig",
        "SourceAccessConfigurations", "StartingPosition",
        "StartingPositionTimestamp", "State", "StateTransitionReason",
        "Tags", "Topics", "TumblingWindowInSeconds", "UUID",
    }
    return set(mapping) <= known \
        and mapping.get("MaximumBatchingWindowInSeconds", 0) == 0 \
        and mapping.get("ParallelizationFactor") in (None, 1) \
        and mapping.get("TumblingWindowInSeconds", 0) == 0 \
        and mapping.get("BisectBatchOnFunctionError") in (None, False) \
        and mapping.get("MaximumRecordAgeInSeconds") is None \
        and mapping.get("MaximumRetryAttempts") is None \
        and mapping.get("StartingPosition") is None \
        and mapping.get("StartingPositionTimestamp") is None \
        and mapping.get("FilterCriteria") in (None, {}) \
        and mapping.get("FilterCriteriaError") in (None, {}) \
        and mapping.get("DestinationConfig") in (None, {}) \
        and mapping.get("ScalingConfig") in (None, {}) \
        and mapping.get("ProvisionedPollerConfig") in (None, {}) \
        and mapping.get("MetricsConfig") in (None, {}, {"Metrics": []}) \
        and mapping.get("KMSKeyArn") in (None, "") \
        and mapping.get("KmsKeyArn") in (None, "") \
        and mapping.get("SourceAccessConfigurations") in (None, []) \
        and mapping.get("Topics") in (None, []) \
        and mapping.get("Queues") in (None, []) \
        and all(mapping.get(name) in (None, {}) for name in (
            "AmazonManagedKafkaEventSourceConfig",
            "DocumentDBEventSourceConfig", "SelfManagedEventSource",
            "SelfManagedKafkaEventSourceConfig")) \
        and (mapping.get("Tags") is None
             or isinstance(mapping["Tags"], dict))


def _live_traffic(args, outputs, versions, enabled):
    """Verify the provider's actual traffic targets, not stack intentions."""
    if type(enabled) is not bool:
        raise TypeError("notification traffic state")
    mapping_id = outputs.get("NotificationDeliveryMappingUuid")
    rule_name = outputs.get("NotificationScanScheduleName")
    schedule = outputs.get("NotificationScanScheduleExpression")
    queue_arn = outputs.get("NotificationQueueArn")
    if any(not isinstance(value, str) or not value or len(value) > 1024
           for value in (mapping_id, rule_name, schedule, queue_arn)):
        raise RuntimeError("notification live traffic identity")

    code_hashes = _output_code_hashes(outputs)
    for role, handler in (
            ("scanner", "deploy.aws_notifications.app.scanner_handler"),
            ("delivery", "deploy.aws_notifications.app.delivery_handler")):
        arn = versions[f"{role}_version_arn"]
        arn_parts = arn.split(":")
        name, version = arn_parts[-2:]
        configured = _change_set_document(_run([
            "aws", "lambda", "get-function-configuration",
            "--function-name", arn,
            "--output", "json",
            *_provider_flags(args),
        ], capture=True), f"live {role} version")
        runtime = configured.get("RuntimeVersionConfig")
        runtime_ok = runtime is None or (
            isinstance(runtime, dict)
            and isinstance(runtime.get("RuntimeVersionArn"), str)
            and bool(runtime["RuntimeVersionArn"])
            and runtime.get("Error") is None)
        description = outputs.get("SoftwareDigest") if role == "scanner" \
            else f'{outputs.get("SoftwareDigest")}:' \
            f'{outputs.get("NotificationSecretVersionId")}'
        if configured.get("FunctionArn") != arn \
                or configured.get("FunctionName") != name \
                or configured.get("Version") != version \
                or configured.get("CodeSha256") \
                != code_hashes[f"{role.title()}CodeSha256"] \
                or configured.get("Handler") != handler \
                or configured.get("Runtime") != "python3.13" \
                or configured.get("State") != "Active" \
                or configured.get("Role") \
                != outputs.get(f"Notification{role.title()}RoleArn") \
                or configured.get("MemorySize") != 1024 \
                or configured.get("Timeout") != 60 \
                or configured.get("Architectures") != ["x86_64"] \
                or configured.get("PackageType") != "Zip" \
                or configured.get("Description") != description \
                or configured.get("Environment") != {
                    "Variables": _expected_version_environment(
                        outputs, role)} \
                or configured.get("LastUpdateStatus", "Successful") \
                != "Successful" \
                or not runtime_ok \
                or not _version_extensions_are_default(configured, name):
            raise RuntimeError(
                f"notification live {role} version drift")
        function_arn = arn.rsplit(":", 1)[0]
        concurrency = _change_set_document(_run([
            "aws", "lambda", "get-function-concurrency",
            "--function-name", function_arn,
            "--output", "json",
            *_provider_flags(args),
        ], capture=True), f"live {role} reserved concurrency")
        try:
            expected_concurrency = int(outputs.get(
                f"Notification{role.title()}ReservedConcurrency"))
        except (TypeError, ValueError):
            raise RuntimeError(
                f"notification live {role} reserved concurrency binding") \
                from None
        if set(concurrency) != {"ReservedConcurrentExecutions"} \
                or concurrency.get("ReservedConcurrentExecutions") \
                != expected_concurrency:
            raise RuntimeError(
                f"notification live {role} reserved concurrency drift")
        runtime_management = _change_set_document(_run([
            "aws", "lambda", "get-runtime-management-config",
            "--function-name", function_arn,
            "--qualifier", version,
            "--output", "json",
            *_provider_flags(args),
        ], capture=True), f"live {role} runtime management")
        managed_runtime = runtime_management.get("RuntimeVersionArn")
        configured_runtime = runtime.get("RuntimeVersionArn") \
            if isinstance(runtime, dict) else None
        if runtime_management.get("FunctionArn") != arn \
                or runtime_management.get("UpdateRuntimeOn") \
                != "FunctionUpdate" \
                or managed_runtime not in (
                    None, configured_runtime):
            raise RuntimeError(
                f"notification live {role} runtime management drift")

    mapping = _change_set_document(_run([
        "aws", "lambda", "get-event-source-mapping",
        "--uuid", mapping_id,
        "--output", "json",
        *_provider_flags(args),
    ], capture=True), "live event source mapping")
    if mapping.get("UUID") != mapping_id \
            or mapping.get("FunctionArn") \
            != versions["delivery_version_arn"] \
            or mapping.get("EventSourceArn") != queue_arn \
            or mapping.get("State") != ("Enabled" if enabled else "Disabled") \
            or mapping.get("BatchSize") != 10 \
            or mapping.get("FunctionResponseTypes") \
            != ["ReportBatchItemFailures"] \
            or not _mapping_extensions_are_default(mapping):
        raise RuntimeError("notification live event source mapping drift")

    rule = _change_set_document(_run([
        "aws", "events", "describe-rule",
        "--name", rule_name,
        "--event-bus-name", "default",
        "--output", "json",
        *_provider_flags(args),
    ], capture=True), "live schedule")
    if not _schedule_rule_is_exact(
            rule, outputs, versions, rule_name, schedule, enabled):
        raise RuntimeError("notification live schedule drift")

    targets = _change_set_document(_run([
        "aws", "events", "list-targets-by-rule",
        "--rule", rule_name,
        "--no-paginate",
        "--output", "json",
        *_provider_flags(args),
    ], capture=True), "live schedule targets")
    rows = targets.get("Targets")
    if targets.get("NextToken") is not None \
            or not isinstance(rows, list) or len(rows) != 1 \
            or not isinstance(rows[0], dict) \
            or set(rows[0]) != {"Arn", "Id"} \
            or rows[0].get("Id") != "notification-scanner" \
            or rows[0].get("Arn") != versions["scanner_version_arn"]:
        raise RuntimeError("notification live schedule target drift")


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


def _release_parameters(
        args, push_node, delivery_domain, software_digest, code_hashes):
    return tuple(
        f"ParameterKey={name},ParameterValue={value}"
        for name, value in _parameter_values(
            args, False, push_node, delivery_domain, software_digest,
            code_hashes).items())


def _package_release(args):
    _run([
        "sam", "package",
        "--template-file", str(BUILD / "template.yaml"),
        "--output-template-file", str(PACKAGED),
        "--resolve-s3",
        "--use-json",
        *_provider_flags(args),
    ])
    return _packaged_code_hashes(args, _caller_account(args))


def _packaged_document():
    try:
        raw = PACKAGED.read_bytes()
        if not 0 < len(raw) <= MAX_PACKAGED_TEMPLATE_BYTES:
            raise ValueError
        document = json.loads(raw)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        raise RuntimeError("malformed packaged notification template") \
            from None
    if not isinstance(document, dict):
        raise RuntimeError("malformed packaged notification template")
    return document


def _packaged_location(document, logical):
    try:
        value = document["Resources"][logical]["Properties"]["CodeUri"]
    except (KeyError, TypeError):
        raise RuntimeError("packaged notification code location") from None
    version = None
    if isinstance(value, str) and value.startswith("s3://"):
        bucket, separator, key = value[5:].partition("/")
        if not separator:
            bucket = key = ""
    elif isinstance(value, dict) and set(value) in (
            {"Bucket", "Key"}, {"Bucket", "Key", "Version"}):
        bucket, key = value.get("Bucket"), value.get("Key")
        version = value.get("Version")
    else:
        bucket = key = ""
    if not isinstance(bucket, str) or not bucket \
            or not isinstance(key, str) or not key \
            or version is not None \
            and (not isinstance(version, str) or not version):
        raise RuntimeError("packaged notification code location")
    return bucket, key, version


def _downloaded_code_hash(args, location, target, expected_owner):
    bucket, key, version = location
    command = [
        "aws", "s3api", "get-object",
        "--bucket", bucket,
        "--key", key,
        "--expected-bucket-owner", expected_owner,
    ]
    if version is not None:
        command += ["--version-id", version]
    _run([
        *command, "--output", "json", *_provider_flags(args), str(target),
    ])
    try:
        digest = hashlib.sha256()
        size = 0
        with target.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_LAMBDA_ZIP_BYTES:
                    raise ValueError
                digest.update(chunk)
        if size == 0:
            raise ValueError
    except (OSError, ValueError):
        raise RuntimeError("invalid packaged notification code") from None
    return base64.b64encode(digest.digest()).decode("ascii")


def _packaged_code_hashes(args, expected_owner):
    document = _packaged_document()
    cached = {}
    result = {}
    with tempfile.TemporaryDirectory(
            prefix="poc16-notification-package-") as directory:
        for logical, parameter in CODE_HASH_PARAMETERS.items():
            location = _packaged_location(document, logical)
            if location not in cached:
                target = Path(directory) / f"artifact-{len(cached)}.zip"
                cached[location] = _downloaded_code_hash(
                    args, location, target, expected_owner)
            result[parameter] = cached[location]
    return _checked_code_hashes(result)


def _release_publication(args, incumbent, software_digest, code_hashes):
    previous_digest = incumbent.get("SoftwareDigest")
    previous_code_hashes = _output_code_hashes(incumbent)
    shared = software_digest != previous_digest
    return {
        "scanner": shared or code_hashes["ScannerCodeSha256"]
        != previous_code_hashes["ScannerCodeSha256"],
        "delivery": shared or code_hashes["DeliveryCodeSha256"]
        != previous_code_hashes["DeliveryCodeSha256"]
        or args.notification_secret_version_id
        != incumbent.get("NotificationSecretVersionId"),
    }


def _create_release_change_set(
        args, stack_id, push_node, delivery_domain, software_digest,
        incumbent, code_hashes):
    """Create but do not execute one exact packaged release update."""
    publish = _release_publication(
        args, incumbent, software_digest, code_hashes)
    expected = _parameter_values(
        args, False, push_node, delivery_domain, software_digest,
        code_hashes)
    change_set = _start_change_set(args, stack_id, "release", [
        "--template-body", "file://" + str(PACKAGED),
        "--capabilities", "CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND",
        "--parameters", *_release_parameters(
            args, push_node, delivery_domain, software_digest, code_hashes),
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
        logical = {}
        for row in changes:
            change = row.get("ResourceChange") \
                if isinstance(row, dict) and row.get("Type") == "Resource" \
                else None
            name = change.get("LogicalResourceId") \
                if isinstance(change, dict) else None
            if not isinstance(name, str) or not name or name in logical:
                raise RuntimeError("release change set resource scope")
            logical[name] = change
        for role in ("scanner", "delivery"):
            function = f"Notification{role.title()}Function"
            version = f"Notification{role.title()}Version"
            if publish[role] and not {function, version}.issubset(logical):
                raise RuntimeError(
                    "release did not publish exact Lambda versions")
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
        _check_requested_release(args, incumbent)
        _check_launch_gate(args, stack_id, incumbent)
        _check_initialized(args, incumbent, stack_id)
        _live_traffic(args, incumbent, versions, False)
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
    _live_traffic(args, outputs, versions, enabled)
    return outputs


def _deploy_release(
        args, stack_id, incumbent, binding, push_node, delivery_domain,
        software_digest, code_hashes):
    """Execute a built release only against the same disabled predecessor."""
    previous_digest = incumbent.get("SoftwareDigest")
    if not valid_fid(previous_digest):
        raise RuntimeError("notification deployment has no software digest")
    previous_versions = _version_arns(incumbent, stack_id)
    publish = _release_publication(
        args, incumbent, software_digest, code_hashes)
    change_set = _create_release_change_set(
        args, stack_id, push_node, delivery_domain, software_digest,
        incumbent, code_hashes)
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
        _live_traffic(args, current, previous_versions, False)
    except Exception:
        _discard_change_set(args, change_set)
        raise
    _execute_change_set(args, stack_id, change_set)
    final_stack = _owned_stack(args)
    outputs = _outputs(final_stack)
    versions = _version_arns(outputs, stack_id)
    final_code_hashes = _output_code_hashes(outputs)
    if final_stack.get("StackId") != stack_id \
            or outputs.get("Enabled") != "false" \
            or outputs.get("SoftwareDigest") != software_digest \
            or final_code_hashes != code_hashes \
            or any(
                (versions[f"{role}_version_arn"]
                 != previous_versions[f"{role}_version_arn"])
                != publish[role]
                for role in ("scanner", "delivery")
            ):
        raise RuntimeError("notification release postcondition failed")
    _check_binding(outputs, binding)
    _check_requested_release(args, outputs)
    _checked_queues(args, outputs)
    _live_traffic(args, outputs, versions, False)
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
    push_node, delivery_domain = _secret_binding(args)
    binding = _binding(args, push_node, delivery_domain)
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
    code_hashes = _package_release(args)
    if incumbent is not None:
        return _deploy_release(
            args, target, incumbent, binding, push_node, delivery_domain,
            software_digest, code_hashes)
    _run([
        "sam", "deploy",
        "--template-file", str(PACKAGED),
        "--stack-name", target,
        "--capabilities", "CAPABILITY_IAM",
        "--no-fail-on-empty-changeset",
        "--parameter-overrides", *_parameters(
            args, enabled, push_node, delivery_domain, software_digest,
            code_hashes),
        "--tags",
        f"{DEPLOYMENT_TAG}={DEPLOYMENT_MARKER}",
        f"{DEPLOYMENT_ID_TAG}={args.deployment_id}",
        *_provider_flags(args),
    ])
    deployed_stack = _owned_stack(args)
    outputs = _outputs(deployed_stack)
    _check_binding(outputs, binding)
    _check_requested_release(args, outputs)
    versions = _version_arns(outputs, deployed_stack["StackId"])
    if outputs.get("Enabled") != ("true" if enabled else "false") \
            or outputs.get("SoftwareDigest") != software_digest \
            or _output_code_hashes(outputs) != code_hashes:
        raise RuntimeError("deployed notification outputs are incomplete")
    _checked_queues(args, outputs)
    _live_traffic(args, outputs, versions, enabled)
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
