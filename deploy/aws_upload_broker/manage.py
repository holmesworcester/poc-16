#!/usr/bin/env python3
"""Build and operate the isolated AWS upload-broker stack.

The external key-ring secret and both buckets are inputs, never stack-owned
resources.  Removing this stack therefore removes compute, role, alarms, and
logs without deleting upload authority or data.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from adapters.s3 import S3Config  # noqa: E402
from deploy.aws_upload_broker.config import (  # noqa: E402
    ALARM_ACTION_ARN_RE,
    DEPLOYMENT_ID_RE,
    DEPLOYMENT_ID_TAG,
    DEPLOYMENT_MARKER,
    DEPLOYMENT_TAG,
    ISSUER_RE,
    KEYRING_VERSION_RE,
    KMS_KEY_ARN_RE,
    LAMBDA_ARN_RE,
    MAX_STORE_PREFIX_LENGTH,
    PREFIX_RE,
    SECRET_ARN_RE,
    WORKSPACE_RE,
)
from deploy.aws_upload_broker.signer import (  # noqa: E402
    S3UploadConfig,
    s3_provider_binding,
)
from deploy.upload_keyring import UploadKeyring, encode_keyring  # noqa: E402
from deploy.upload_session import (  # noqa: E402
    MAX_SESSION_BYTES,
    MAX_SESSION_CLOCK_SKEW_MS,
    MAX_SESSION_TTL_MS,
    SessionKey,
    UploadSessionPolicy,
)
from deploy.python_role_modules import (  # noqa: E402
    UPLOAD_BROKER_CORE_MODULES,
)


STAGE = HERE / "stage"
BUILD = HERE / ".aws-sam"
DIRECTORIES = ("facts",)
FILES = (
    "adapters/__init__.py",
    "adapters/s3/__init__.py",
    "adapters/s3/store.py",
    "deploy/__init__.py",
    "deploy/upload_broker.py",
    "deploy/upload_broker_http.py",
    "deploy/upload_keyring.py",
    "deploy/upload_session.py",
    "deploy/upload_wire.py",
    "deploy/repository_apply_wire.py",
    "deploy/aws_upload_broker/__init__.py",
    "deploy/aws_upload_broker/app.py",
    "deploy/aws_upload_broker/config.py",
    "deploy/aws_upload_broker/signer.py",
)
MUTATION_TIMEOUT_SECONDS = 30 * 60
METADATA_TIMEOUT_SECONDS = 30
READINESS_TIMEOUT_SECONDS = 15
DEFAULT_SESSION_TTL_SECONDS = 15 * 60
DEFAULT_KEY_LIFETIME_DAYS = 90
SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9/_+=.@-]{1,512}$")


class StackAbsent(RuntimeError):
    """The exact CloudFormation stack name is definitively absent."""


def _run(command, *, timeout=MUTATION_TIMEOUT_SECONDS):
    return subprocess.run(
        command,
        cwd=REPOSITORY,
        check=True,
        timeout=timeout,
    )


def _json_command(command):
    result = subprocess.run(
        command,
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
        timeout=METADATA_TIMEOUT_SECONDS,
    )
    try:
        value = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise RuntimeError("AWS CLI returned invalid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("AWS CLI returned invalid JSON")
    return value


def _provider_flags(args):
    flags = []
    if getattr(args, "region", None):
        flags += ["--region", args.region]
    if getattr(args, "profile", None):
        flags += ["--profile", args.profile]
    return flags


def stage(destination=STAGE):
    """Create a clean source tree from one explicit authority allowlist."""
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name in UPLOAD_BROKER_CORE_MODULES:
        target = destination / "core" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPOSITORY / "core" / name, target)
    for relative in DIRECTORIES:
        shutil.copytree(
            REPOSITORY / relative,
            destination / relative,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for relative in FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPOSITORY / relative, target)
    shutil.copy2(
        HERE / "requirements.txt",
        destination / "requirements.txt",
    )
    return destination


def build(_args=None):
    stage()
    _run([
        "sam",
        "build",
        "--template-file",
        str(HERE / "template.yaml"),
        "--build-dir",
        str(BUILD),
        "--use-container",
    ])


def _deployment_id(args):
    value = getattr(args, "deployment_id", None)
    if not isinstance(value, str) or not DEPLOYMENT_ID_RE.fullmatch(value):
        raise ValueError("deployment ID")
    return value


def _validate_deploy_args(args):
    _deployment_id(args)
    if not isinstance(args.workspace, str) \
            or not WORKSPACE_RE.fullmatch(args.workspace):
        raise ValueError("workspace must be 64 lowercase hex characters")
    if not isinstance(args.prefix, str) \
            or len(args.prefix) > MAX_STORE_PREFIX_LENGTH \
            or not PREFIX_RE.fullmatch(args.prefix):
        raise ValueError("canonical prefix")
    owner = getattr(args, "expected_owner", None)
    if not isinstance(owner, str) \
            or len(owner) != 12 or not owner.isdigit():
        raise ValueError("expected bucket owner must be a 12 digit account")
    S3Config(
        bucket=args.canonical_bucket,
        prefix=args.prefix,
        expected_bucket_owner=owner,
    )
    S3UploadConfig(
        args.ingress_bucket,
        args.region,
        expected_bucket_owner=owner,
    )
    if args.canonical_bucket == args.ingress_bucket:
        raise ValueError("canonical and ingress buckets must differ")
    applier = getattr(args, "applier_function_arn", None)
    if not isinstance(applier, str) or LAMBDA_ARN_RE.fullmatch(applier) is None:
        raise ValueError("repository Applier function ARN")
    arn = applier.split(":", 7)
    if arn[3] != args.region or arn[4] != owner:
        raise ValueError("repository Applier function scope")
    if not isinstance(args.issuer, str) \
            or not ISSUER_RE.fullmatch(args.issuer):
        raise ValueError("upload issuer")
    if not isinstance(args.keyring_secret_arn, str) \
            or not SECRET_ARN_RE.fullmatch(args.keyring_secret_arn):
        raise ValueError("upload keyring secret ARN")
    if not isinstance(args.keyring_version_id, str) \
            or not KEYRING_VERSION_RE.fullmatch(
                args.keyring_version_id):
        raise ValueError("upload keyring version ID")
    if type(args.presign_ttl_seconds) is not int \
            or not 1 <= args.presign_ttl_seconds <= 15 * 60:
        raise ValueError("presigned PUT TTL")
    kms = getattr(args, "kms_key_arn", None)
    if kms is not None and (
            not isinstance(kms, str) or not KMS_KEY_ARN_RE.fullmatch(kms)):
        raise ValueError("KMS key ARN")
    alarm = getattr(args, "alarm_action_arn", None)
    if alarm is not None and (
            not isinstance(alarm, str)
            or not ALARM_ACTION_ARN_RE.fullmatch(alarm)):
        raise ValueError("alarm action ARN")


def _validate_keyring_create_args(args):
    _deployment_id(args)
    if not isinstance(args.name, str) \
            or not SECRET_NAME_RE.fullmatch(args.name):
        raise ValueError("upload keyring secret name")
    if not isinstance(args.issuer, str) \
            or not ISSUER_RE.fullmatch(args.issuer):
        raise ValueError("upload issuer")
    owner = getattr(args, "expected_owner", None)
    if not isinstance(owner, str) \
            or len(owner) != 12 or not owner.isdigit():
        raise ValueError("expected bucket owner must be a 12 digit account")
    S3UploadConfig(
        args.ingress_bucket,
        args.region,
        expected_bucket_owner=owner,
    )
    if type(args.session_ttl_seconds) is not int \
            or not 1 <= args.session_ttl_seconds \
            <= MAX_SESSION_TTL_MS // 1000:
        raise ValueError("upload session TTL")
    if type(args.key_lifetime_days) is not int \
            or not 1 <= args.key_lifetime_days <= 3650:
        raise ValueError("upload key lifetime")
    if args.session_ttl_seconds * 1000 \
            + MAX_SESSION_CLOCK_SKEW_MS \
            >= args.key_lifetime_days * 24 * 60 * 60 * 1000:
        raise ValueError("upload key lifetime must cover session TTL and skew")
    kms = getattr(args, "kms_key_arn", None)
    if kms is not None and (
            not isinstance(kms, str) or not KMS_KEY_ARN_RE.fullmatch(kms)):
        raise ValueError("KMS key ARN")


def keyring_create(args, *, now_ms=None, random_bytes=None):
    """Create one external provider-bound Secrets Manager key ring.

    The secret is supplied to the AWS CLI through a mode-0600 temporary file;
    it never appears in argv, stdout, rendered templates, or stack state.
    """
    _validate_keyring_create_args(args)
    now_ms = time.time_ns() // 1_000_000 \
        if now_ms is None else now_ms
    random_bytes = secrets.token_bytes \
        if random_bytes is None else random_bytes
    if type(now_ms) is not int or now_ms < 0 \
            or not callable(random_bytes):
        raise ValueError("upload keyring creation input")
    try:
        key_id = base64.urlsafe_b64encode(
            random_bytes(6)).decode("ascii")
        secret = random_bytes(32)
        version_id = random_bytes(16).hex()
    except Exception as error:
        raise RuntimeError("upload key generation failed") from error
    if len(key_id) != 8 or not isinstance(secret, bytes) \
            or len(secret) != 32 or len(version_id) != 32:
        raise RuntimeError("upload key generation failed")
    ttl_ms = args.session_ttl_seconds * 1000
    verify_until_ms = (
        now_ms + args.key_lifetime_days * 24 * 60 * 60 * 1000)
    config = S3UploadConfig(
        args.ingress_bucket,
        args.region,
        expected_bucket_owner=args.expected_owner,
    )
    key = SessionKey(
        key_id,
        secret,
        now_ms,
        verify_until_ms,
    )
    raw = encode_keyring(UploadKeyring(
        s3_provider_binding(config),
        UploadSessionPolicy(
            args.issuer,
            key_id,
            (key,),
            ttl_ms=ttl_ms,
            max_ttl_ms=MAX_SESSION_TTL_MS,
            clock_skew_ms=MAX_SESSION_CLOCK_SKEW_MS,
            max_bytes=MAX_SESSION_BYTES,
        ),
    ))
    command = [
        "aws",
        "secretsmanager",
        "create-secret",
        "--name",
        args.name,
        "--description",
        "POC-16 provider-bound stateless upload session key ring",
        "--client-request-token",
        version_id,
        "--tags",
        f"Key={DEPLOYMENT_TAG},Value={DEPLOYMENT_MARKER}",
        f"Key={DEPLOYMENT_ID_TAG},Value={args.deployment_id}",
        "--output",
        "json",
    ]
    if args.kms_key_arn:
        command += ["--kms-key-id", args.kms_key_arn]
    with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix="poc16-upload-keyring-",
            suffix=".json") as secret_file:
        secret_file.write(raw)
        secret_file.flush()
        command += [
            "--secret-string",
            "file://" + secret_file.name,
            *_provider_flags(args),
        ]
        response = _json_command(command)
    arn = response.get("ARN")
    observed_version = response.get("VersionId")
    if not isinstance(arn, str) or not SECRET_ARN_RE.fullmatch(arn) \
            or observed_version != version_id:
        raise RuntimeError(
            "Secrets Manager returned an unexpected keyring identity")
    return {
        "keyring_secret_arn": arn,
        "keyring_version_id": version_id,
    }


def _describe_stack(args):
    try:
        value = _json_command([
            "aws",
            "cloudformation",
            "describe-stacks",
            "--stack-name",
            args.stack,
            "--output",
            "json",
            *_provider_flags(args),
        ])
    except subprocess.CalledProcessError as error:
        detail = error.stderr if isinstance(error.stderr, str) else ""
        if "ValidationError" in detail and "does not exist" in detail:
            raise StackAbsent(args.stack) from error
        raise
    stacks = value.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 \
            or not isinstance(stacks[0], dict):
        raise RuntimeError("expected exactly one CloudFormation stack")
    return stacks[0]


def _caller_account(args):
    value = _json_command([
        "aws",
        "sts",
        "get-caller-identity",
        "--output",
        "json",
        *_provider_flags(args),
    ])
    account = value.get("Account")
    if not isinstance(account, str) or len(account) != 12 \
            or not account.isdigit():
        raise RuntimeError("AWS caller identity has no account")
    return account


def _validate_owned_stack(args, stack):
    deployment_id = _deployment_id(args)
    if stack.get("StackName") != args.stack:
        raise RuntimeError("CloudFormation returned a different stack")
    stack_id = stack.get("StackId")
    if not isinstance(stack_id, str):
        raise RuntimeError("stack has no identity ARN")
    parts = stack_id.split(":", 5)
    if len(parts) != 6 or parts[2] != "cloudformation" \
            or not parts[3] or len(parts[4]) != 12:
        raise RuntimeError("stack identity ARN")
    region, account = parts[3], parts[4]
    if getattr(args, "region", None) and args.region != region:
        raise RuntimeError("stack region does not match requested region")
    if account != _caller_account(args):
        raise RuntimeError("stack account does not match AWS caller")
    tags = {
        item.get("Key"): item.get("Value")
        for item in stack.get("Tags", [])
        if isinstance(item, dict)
    }
    if tags.get(DEPLOYMENT_TAG) != DEPLOYMENT_MARKER \
            or tags.get(DEPLOYMENT_ID_TAG) != deployment_id:
        raise RuntimeError("refusing to operate on an unowned stack")
    outputs = {
        item.get("OutputKey"): item.get("OutputValue")
        for item in stack.get("Outputs", [])
        if isinstance(item, dict)
    }
    if (
            outputs.get("DeploymentMarker") != DEPLOYMENT_MARKER
            or outputs.get("DeploymentId") != deployment_id):
        raise RuntimeError("stack deployment marker is absent")
    status = stack.get("StackStatus")
    if not isinstance(status, str) or status.startswith("DELETE_"):
        raise RuntimeError("stack is not in an operable state")
    return stack


def _stack_or_none(args):
    try:
        return _describe_stack(args)
    except StackAbsent:
        return None


def _stack_for_deploy(args):
    create = getattr(args, "create", False) is True
    update = getattr(args, "update", False) is True
    if create == update:
        raise ValueError("choose exactly one of create or update")
    stack = _stack_or_none(args)
    if create:
        if stack is not None:
            raise RuntimeError("create requires an absent stack name")
        return args.stack
    if stack is None:
        raise RuntimeError("update requires an existing owned stack")
    return _validate_owned_stack(args, stack)["StackId"]


def _deploy_stack(args, target=None):
    _validate_deploy_args(args)
    target = _stack_for_deploy(args) if target is None else target
    parameters = [
        f"DeploymentId={args.deployment_id}",
        f"WorkspaceId={args.workspace}",
        f"CanonicalBucketName={args.canonical_bucket}",
        f"CanonicalPrefix={args.prefix}",
        f"IngressBucketName={args.ingress_bucket}",
        f"RepositoryApplierFunctionArn={args.applier_function_arn}",
        f"UploadIssuer={args.issuer}",
        f"UploadKeyringSecretArn={args.keyring_secret_arn}",
        f"UploadKeyringVersionId={args.keyring_version_id}",
        f"PresignTtlSeconds={args.presign_ttl_seconds}",
    ]
    parameters.append(
        f"ExpectedBucketOwner={args.expected_owner}")
    if args.kms_key_arn:
        parameters.append(f"KmsKeyArn={args.kms_key_arn}")
    if args.alarm_action_arn:
        parameters.append(
            f"AlarmActionArn={args.alarm_action_arn}")
    _run([
        "sam",
        "deploy",
        "--template-file",
        str(BUILD / "template.yaml"),
        "--stack-name",
        target,
        "--capabilities",
        "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-confirm-changeset",
        "--tags",
        f"{DEPLOYMENT_TAG}={DEPLOYMENT_MARKER}",
        f"{DEPLOYMENT_ID_TAG}={args.deployment_id}",
        "--parameter-overrides",
        *parameters,
        *_provider_flags(args),
    ])


def _owned_stack(args):
    stack = _stack_or_none(args)
    if stack is None:
        raise StackAbsent(args.stack)
    return _validate_owned_stack(args, stack)


def _stack_url(args):
    stack = _owned_stack(args)
    outputs = {
        item.get("OutputKey"): item.get("OutputValue")
        for item in stack.get("Outputs", [])
        if isinstance(item, dict)
    }
    url = outputs.get("UploadBrokerUrl")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise RuntimeError("stack has no HTTPS UploadBrokerUrl")
    if outputs.get("UploadKeyringSecretArn") != args.keyring_secret_arn:
        raise RuntimeError("stack keyring identity does not match")
    if outputs.get("UploadKeyringVersionId") != args.keyring_version_id:
        raise RuntimeError("stack keyring version does not match")
    return url.rstrip("/")


def _readiness(url):
    request = urllib.request.Request(
        f"{url}/upload/finalize",
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(
            request, timeout=READINESS_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        if error.code == 400:
            return
        raise RuntimeError(
            f"upload broker readiness returned HTTP {error.code}") from error
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError("upload broker readiness failed") from error
    raise RuntimeError("invalid FINALIZE readiness probe was accepted")


def deploy(args):
    _validate_deploy_args(args)
    target = _stack_for_deploy(args)
    build(args)
    _deploy_stack(args, target)
    _readiness(_stack_url(args))


def remove(args):
    stack = _stack_or_none(args)
    if stack is None:
        raise StackAbsent(args.stack)
    stack = _validate_owned_stack(args, stack)
    _run([
        "sam",
        "delete",
        "--stack-name",
        stack["StackId"],
        "--no-prompts",
        *_provider_flags(args),
    ])


def test(_args=None):
    _run([
        "python3",
        "-m",
        "pytest",
        "-q",
        "tests/test_aws_upload_broker_app.py",
        "tests/test_aws_upload_signer.py",
        "tests/test_upload_broker_http.py",
        "tests/test_upload_keyring.py",
    ])


def _deployment_arguments(command):
    command.add_argument("--stack", required=True)
    command.add_argument("--deployment-id", required=True)
    command.add_argument("--workspace", required=True)
    command.add_argument("--canonical-bucket", required=True)
    command.add_argument("--prefix", required=True)
    command.add_argument("--ingress-bucket", required=True)
    command.add_argument("--applier-function-arn", required=True)
    command.add_argument("--issuer", required=True)
    command.add_argument("--keyring-secret-arn", required=True)
    command.add_argument("--keyring-version-id", required=True)
    command.add_argument(
        "--presign-ttl-seconds", type=int, default=60)
    command.add_argument("--expected-owner", required=True)
    command.add_argument("--kms-key-arn")
    command.add_argument("--alarm-action-arn")
    command.add_argument("--region", required=True)
    command.add_argument("--profile")


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    build_command = commands.add_parser(
        "build", help="stage and SAM-container build")
    build_command.set_defaults(run=build)
    test_command = commands.add_parser(
        "test", help="run broker, signer, and deployment tests")
    test_command.set_defaults(run=test)
    keyring_command = commands.add_parser(
        "keyring-create",
        help="create an external provider-bound session key ring",
    )
    keyring_command.add_argument("--name", required=True)
    keyring_command.add_argument("--deployment-id", required=True)
    keyring_command.add_argument("--issuer", required=True)
    keyring_command.add_argument("--ingress-bucket", required=True)
    keyring_command.add_argument("--region", required=True)
    keyring_command.add_argument("--expected-owner", required=True)
    keyring_command.add_argument("--kms-key-arn")
    keyring_command.add_argument("--profile")
    keyring_command.add_argument(
        "--session-ttl-seconds",
        type=int,
        default=DEFAULT_SESSION_TTL_SECONDS,
    )
    keyring_command.add_argument(
        "--key-lifetime-days",
        type=int,
        default=DEFAULT_KEY_LIFETIME_DAYS,
    )
    keyring_command.set_defaults(run=keyring_create)
    deploy_command = commands.add_parser(
        "deploy", help="build and deploy the upload broker")
    _deployment_arguments(deploy_command)
    mode = deploy_command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--create", action="store_true")
    mode.add_argument("--update", action="store_true")
    deploy_command.set_defaults(run=deploy)
    remove_command = commands.add_parser(
        "remove",
        help="remove compute while preserving secret and buckets",
    )
    remove_command.add_argument("--stack", required=True)
    remove_command.add_argument("--deployment-id", required=True)
    remove_command.add_argument("--region")
    remove_command.add_argument("--profile")
    remove_command.set_defaults(run=remove)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    result = args.run(args)
    if isinstance(result, dict):
        print(json.dumps(
            result, sort_keys=True, separators=(",", ":")))
        return 0
    return 0 if result is None else result


if __name__ == "__main__":
    raise SystemExit(main())
