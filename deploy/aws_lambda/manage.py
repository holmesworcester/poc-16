#!/usr/bin/env python3
"""Build and operate the isolated AWS Lambda package.

Examples:
  python3 deploy/aws_lambda/manage.py build
  python3 deploy/aws_lambda/manage.py deploy --create --stack poc16-edge \
      --deployment-id edge-west-2 --workspace <64-hex> \
      --bucket <bucket> --prefix <prefix>
  python3 deploy/aws_lambda/manage.py remove --stack poc16-edge \
      --deployment-id edge-west-2
"""
import argparse
import base64
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from adapters.s3 import S3Config  # noqa: E402
from deploy.aws_lambda.config import (  # noqa: E402
    ALARM_ACTION_ARN_RE,
    DEPLOYMENT_ID_RE,
    DEPLOYMENT_ID_TAG,
    DEPLOYMENT_MARKER,
    DEPLOYMENT_TAG,
    KMS_KEY_ARN_RE,
    MAX_READINESS_RESPONSE_BYTES,
    MAX_STORE_PREFIX_LENGTH,
    WORKSPACE_RE,
)
from deploy.python_role_modules import (  # noqa: E402
    HOSTED_GATE_CORE_MODULES,
)
STAGE = HERE / "stage"
BUILD = HERE / ".aws-sam"
DIRECTORIES = ("facts",)
FILES = (
    "adapters/__init__.py",
    "adapters/s3/__init__.py",
    "adapters/s3/store.py",
    "deploy/__init__.py",
    "deploy/aws_lambda/__init__.py",
    "deploy/aws_lambda/app.py",
    "deploy/aws_lambda/config.py",
    "deploy/aws_lambda/pack_issuer.py",
    "deploy/aws_lambda/sdk_smoke.py",
    "deploy/aws_lambda/s3_bucket_policy.py",
)
ARTIFACT = BUILD / "GatewayFunction"
LAMBDA_RUNTIME_IMAGE = "public.ecr.aws/lambda/python:3.13"
MUTATION_TIMEOUT_SECONDS = 30 * 60
METADATA_TIMEOUT_SECONDS = 30


class StackAbsent(RuntimeError):
    """The exact CloudFormation stack name is definitively absent."""


def _run(command, *, timeout=MUTATION_TIMEOUT_SECONDS):
    return subprocess.run(
        command, cwd=REPO, check=True, timeout=timeout)


def _json_command(command):
    result = subprocess.run(
        command, cwd=REPO, check=True,
        capture_output=True, text=True,
        timeout=METADATA_TIMEOUT_SECONDS)
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
    """Create a clean Lambda source tree from the explicit allowlist."""
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name in HOSTED_GATE_CORE_MODULES:
        target = destination / "core" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / "core" / name, target)
    for relative in DIRECTORIES:
        shutil.copytree(
            REPO / relative, destination / relative,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for relative in FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / relative, target)
    shutil.copy2(HERE / "requirements.txt", destination / "requirements.txt")
    return destination


def build(_args):
    stage()
    _run([
        "sam", "build",
        "--template-file", str(HERE / "template.yaml"),
        "--build-dir", str(BUILD),
        "--use-container",
    ])


def _validate_deploy_args(args):
    _deployment_id(args)
    if not isinstance(args.workspace, str) \
            or not WORKSPACE_RE.fullmatch(args.workspace):
        raise ValueError("workspace must be 64 lowercase hex characters")
    if not isinstance(args.prefix, str) \
            or len(args.prefix) > MAX_STORE_PREFIX_LENGTH:
        raise ValueError("store prefix exceeds Lambda key budget")
    owner = getattr(args, "expected_owner", None)
    if owner is not None and (
            not isinstance(owner, str)
            or len(owner) != 12 or not owner.isdigit()):
        raise ValueError("expected bucket owner must be a 12 digit account")
    S3Config(
        bucket=args.bucket,
        prefix=args.prefix,
        expected_bucket_owner=owner)
    kms = getattr(args, "kms_key_arn", None)
    if kms is not None and (
            not isinstance(kms, str) or not KMS_KEY_ARN_RE.fullmatch(kms)):
        raise ValueError("KMS key ARN")
    alarm = getattr(args, "alarm_action_arn", None)
    if alarm is not None and (
            not isinstance(alarm, str)
            or not ALARM_ACTION_ARN_RE.fullmatch(alarm)):
        raise ValueError("alarm action ARN")


def _deployment_id(args):
    value = getattr(args, "deployment_id", None)
    if not isinstance(value, str) or not DEPLOYMENT_ID_RE.fullmatch(value):
        raise ValueError("deployment ID")
    return value


def _deploy_stack(args, target=None):
    _validate_deploy_args(args)
    target = _stack_for_deploy(args) if target is None else target
    if not isinstance(target, str) or not target:
        raise RuntimeError("deployment has no stack identity")
    parameters = [
        f"DeploymentId={args.deployment_id}",
        f"WorkspaceId={args.workspace}",
        f"BucketName={args.bucket}",
        f"StorePrefix={args.prefix}",
    ]
    if args.expected_owner:
        parameters.append(f"ExpectedBucketOwner={args.expected_owner}")
    if getattr(args, "kms_key_arn", None):
        parameters.append(f"KmsKeyArn={args.kms_key_arn}")
    if getattr(args, "alarm_action_arn", None):
        parameters.append(f"AlarmActionArn={args.alarm_action_arn}")
    _run([
        "sam", "deploy",
        "--template-file", str(BUILD / "template.yaml"),
        "--stack-name", target,
        "--capabilities", "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-confirm-changeset",
        "--tags",
        f"{DEPLOYMENT_TAG}={DEPLOYMENT_MARKER}",
        f"{DEPLOYMENT_ID_TAG}={args.deployment_id}",
        "--parameter-overrides", *parameters,
        *_provider_flags(args),
    ])


def deploy(args):
    _validate_deploy_args(args)
    build(args)
    _deploy_stack(args)
    _readiness(_stack_url(args))


def _describe_stack(args):
    try:
        value = _json_command([
            "aws", "cloudformation", "describe-stacks",
            "--stack-name", args.stack,
            "--output", "json",
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
        "aws", "sts", "get-caller-identity", "--output", "json",
        *_provider_flags(args),
    ])
    account = value.get("Account")
    if not isinstance(account, str) or len(account) != 12 \
            or not account.isdigit():
        raise RuntimeError("AWS caller identity has no account")
    return account


def _validate_owned_stack(args, stack, *, allow_incomplete=False):
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
    if tags.get(DEPLOYMENT_TAG) != DEPLOYMENT_MARKER:
        raise RuntimeError("refusing to operate on an unowned stack")
    if tags.get(DEPLOYMENT_ID_TAG) != deployment_id:
        raise RuntimeError("stack deployment ID does not match")
    outputs = {
        item.get("OutputKey"): item.get("OutputValue")
        for item in stack.get("Outputs", [])
        if isinstance(item, dict)
    }
    if not allow_incomplete \
            and outputs.get("DeploymentMarker") != DEPLOYMENT_MARKER:
        raise RuntimeError("stack deployment marker is absent")
    if not allow_incomplete \
            and outputs.get("DeploymentId") != deployment_id:
        raise RuntimeError("stack deployment ID output does not match")
    status = stack.get("StackStatus")
    if not isinstance(status, str) or status.startswith("DELETE_"):
        raise RuntimeError("stack is not in a removable state")
    return stack


def _stack_or_none(args):
    try:
        return _describe_stack(args)
    except StackAbsent:
        return None


def _owned_stack(args, *, allow_incomplete=False):
    stack = _stack_or_none(args)
    if stack is None:
        raise StackAbsent(args.stack)
    return _validate_owned_stack(
        args, stack, allow_incomplete=allow_incomplete)


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


def remove(args):
    stack = _stack_or_none(args)
    generated = getattr(args, "generated_smoke", False)
    if stack is None:
        if generated:
            return False
        raise StackAbsent(args.stack)
    stack = _validate_owned_stack(
        args, stack, allow_incomplete=generated)
    _run([
        "sam", "delete", "--stack-name", stack["StackId"], "--no-prompts",
        *_provider_flags(args),
    ])
    return True


def bucket_policy(args):
    from deploy.aws_lambda.s3_bucket_policy import main as render

    render([
        "--bucket", args.bucket,
        "--prefix", args.prefix,
        "--profile", args.policy_profile,
        "--partition", args.partition,
        *(
            ["--gateway-principal", args.gateway_principal]
            if args.gateway_principal else []
        ),
    ])


def test(_args):
    _run([
        "python3", "-m", "pytest", "-q",
        "tests/test_aws_pack_issuer.py",
        "tests/test_lambda_deploy.py",
        "tests/test_authority_http.py",
        "tests/test_s3_adapter.py",
        "tests/test_writer_repository.py",
    ])


def package_smoke(_args):
    """Build and execute the exact artifact in the Lambda target runtime."""
    build(_args)
    if not ARTIFACT.is_dir():
        raise RuntimeError("SAM build produced no GatewayFunction artifact")
    _run([
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "--entrypoint", "/var/lang/bin/python3.13",
        "--volume", f"{ARTIFACT}:/var/task:ro",
        "--workdir", "/var/task",
        LAMBDA_RUNTIME_IMAGE,
        "-m", "deploy.aws_lambda.sdk_smoke",
    ])


def _stack_url(args):
    stack = _owned_stack(args)
    outputs = {
        item.get("OutputKey"): item.get("OutputValue")
        for item in stack.get("Outputs", [])
        if isinstance(item, dict)
    }
    url = outputs.get("GatewayUrl")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise RuntimeError("stack has no HTTPS GatewayUrl")
    return url.rstrip("/")


def _readiness(url):
    request = urllib.request.Request(
        f"{url.rstrip('/')}/readyz", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(MAX_READINESS_RESPONSE_BYTES + 1)
            status = response.status
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError("Lambda readiness request failed") from error
    if status != 200 or len(raw) > MAX_READINESS_RESPONSE_BYTES:
        raise RuntimeError("Lambda readiness request failed")
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise RuntimeError("Lambda readiness response is invalid") from error
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise RuntimeError("Lambda is not ready")
    return value


def _smoke_endpoint(url, state, workspace):
    """Publish one owner log and read its head through the live gateway."""
    from core.crypto import h
    from core.limits import MAX_REPOSITORY_OBJECT_BYTES
    from core.writer_head import decode_slot, head_slot_key
    from full_peer.node import FullPeer, now_ms
    from full_peer.sync import sync
    from full_peer.walk import Peer

    state = Path(state).resolve()
    if not state.is_dir():
        raise ValueError("smoke client state directory does not exist")
    node = FullPeer(str(state))
    if workspace not in node.workspaces():
        raise ValueError("smoke workspace is not present in client state")
    sync(node, workspace, url)
    peer = Peer(node, workspace, url)
    peer.mint()
    if peer.accepts_push or not peer.accepts_owner_publish:
        raise RuntimeError("serverless peer advertised the wrong capability")
    device = node.identity_id(workspace)
    got = peer.head(device)
    if got is None:
        raise RuntimeError("serverless peer returned no owner head")
    raw_slot, _token = got
    slot = decode_slot(raw_slot, workspace=workspace, device=device)
    raw = peer.obj(
        slot.head, response_limit=MAX_REPOSITORY_OBJECT_BYTES)
    if raw is None or h(raw) != slot.head:
        raise RuntimeError("serverless writer-head read failed")

    bad = json.dumps({
        "pile": base64.b64encode(b"not a valid pile").decode(),
        "ws": workspace,
    }, separators=(",", ":")).encode()
    denied = urllib.request.Request(
        f"{url}/mint?ws={workspace}", data=bad, method="POST")
    try:
        urllib.request.urlopen(denied, timeout=15)
    except urllib.error.HTTPError as error:
        if error.code != 403:
            raise RuntimeError(
                f"invalid proof returned HTTP {error.code}") from error
    else:
        raise RuntimeError("invalid proof was accepted")
    return {
        "head": slot.head,
        "slot": head_slot_key(workspace, device),
        "tested_at": now_ms(),
    }


def live_smoke(args):
    """Deploy a generated owner-gateway stack, test it, and remove it."""
    random_id = secrets.token_hex(16)
    args.stack = "poc16-smoke-" + random_id
    args.deployment_id = "smoke-" + random_id
    args.generated_smoke = True
    args.create, args.update = True, False
    _validate_deploy_args(args)
    build(args)
    primary_error = None
    cleanup_error = None
    deployment_attempted = False
    try:
        target = _stack_for_deploy(args)
        deployment_attempted = True
        _deploy_stack(args, target)
        result = _smoke_endpoint(
            _stack_url(args), args.state, args.workspace)
        print(json.dumps(
            {"stack": args.stack, **result},
            sort_keys=True, separators=(",", ":")))
    except BaseException as error:
        primary_error = error
    if deployment_attempted:
        try:
            remove(args)
        except BaseException as error:
            cleanup_error = error
    if primary_error is not None and cleanup_error is not None:
        group = ExceptionGroup \
            if isinstance(primary_error, Exception) \
            and isinstance(cleanup_error, Exception) \
            else BaseExceptionGroup
        raise group(
            "Lambda live-smoke and cleanup both failed",
            [primary_error, cleanup_error])
    if primary_error is not None:
        raise primary_error.with_traceback(primary_error.__traceback__)
    if cleanup_error is not None:
        raise cleanup_error.with_traceback(cleanup_error.__traceback__)


def parser():
    command = argparse.ArgumentParser(description=__doc__)
    sub = command.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build", help="stage and SAM-container build")
    build_cmd.set_defaults(run=build)
    test_cmd = sub.add_parser("test", help="run Lambda and adapter tests")
    test_cmd.set_defaults(run=test)
    smoke_cmd = sub.add_parser(
        "package-smoke",
        help="build and execute the artifact in Lambda Python 3.13")
    smoke_cmd.set_defaults(run=package_smoke)
    deploy_cmd = sub.add_parser(
        "deploy", help="build and deploy the owner-gateway Function URL")
    deploy_cmd.add_argument("--stack", required=True)
    deploy_cmd.add_argument("--deployment-id", required=True)
    deploy_cmd.add_argument("--workspace", required=True)
    deploy_cmd.add_argument("--bucket", required=True)
    deploy_cmd.add_argument("--prefix", required=True)
    deploy_cmd.add_argument("--expected-owner")
    deploy_cmd.add_argument("--kms-key-arn")
    deploy_cmd.add_argument("--alarm-action-arn")
    deploy_cmd.add_argument("--region")
    deploy_cmd.add_argument("--profile")
    deploy_mode = deploy_cmd.add_mutually_exclusive_group(required=True)
    deploy_mode.add_argument(
        "--create", action="store_true",
        help="require the stack name to be absent")
    deploy_mode.add_argument(
        "--update", action="store_true",
        help="require an existing owned stack and target its exact ID")
    deploy_cmd.set_defaults(run=deploy)
    remove_cmd = sub.add_parser(
        "remove", help="delete compute, logs, alarms, role, and grant secret")
    remove_cmd.add_argument("--stack", required=True)
    remove_cmd.add_argument("--deployment-id", required=True)
    remove_cmd.add_argument("--region")
    remove_cmd.add_argument("--profile")
    remove_cmd.set_defaults(run=remove)
    live_cmd = sub.add_parser(
        "live-smoke",
        help=(
            "deploy a generated stack, test mint/read/deny, then remove it"))
    live_cmd.add_argument("--state", required=True)
    live_cmd.add_argument("--workspace", required=True)
    live_cmd.add_argument("--bucket", required=True)
    live_cmd.add_argument("--prefix", required=True)
    live_cmd.add_argument("--expected-owner")
    live_cmd.add_argument("--kms-key-arn")
    live_cmd.add_argument("--alarm-action-arn")
    live_cmd.add_argument("--region")
    live_cmd.add_argument("--profile")
    live_cmd.set_defaults(run=live_smoke)
    policy_cmd = sub.add_parser(
        "bucket-policy",
        help="print deny guards to merge into an existing bucket policy")
    policy_cmd.add_argument("--bucket", required=True)
    policy_cmd.add_argument("--prefix", required=True)
    policy_cmd.add_argument(
        "--profile", dest="policy_profile",
        choices=("bucket-wide", "single-gateway"),
        default="bucket-wide")
    policy_cmd.add_argument("--gateway-principal")
    policy_cmd.add_argument(
        "--partition", choices=("aws", "aws-us-gov", "aws-cn"),
        default="aws")
    policy_cmd.set_defaults(run=bucket_policy)
    return command


def main(argv=None):
    args = parser().parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    main()
