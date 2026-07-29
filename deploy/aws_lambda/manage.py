#!/usr/bin/env python3
"""Build and operate the isolated AWS Lambda package.

Examples:
  python3 deploy/aws_lambda/manage.py build
  python3 deploy/aws_lambda/manage.py deploy --stack poc16-edge \
      --workspace <64-hex> --bucket <bucket> --prefix <prefix>
  python3 deploy/aws_lambda/manage.py remove --stack poc16-edge
"""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
STAGE = HERE / "stage"
BUILD = HERE / ".aws-sam"
DIRECTORIES = ("core", "facts", "adapters")
FILES = (
    "deploy/__init__.py",
    "deploy/gateway.py",
    "deploy/aws_lambda/__init__.py",
    "deploy/aws_lambda/app.py",
    "deploy/aws_lambda/sdk_smoke.py",
    "deploy/aws_lambda/s3_bucket_policy.py",
)


def _run(command):
    return subprocess.run(command, cwd=REPO, check=True)


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


def _deploy_stack(args):
    parameters = [
        f"WorkspaceId={args.workspace}",
        f"BucketName={args.bucket}",
        f"StorePrefix={args.prefix}",
    ]
    if args.expected_owner:
        parameters.append(f"ExpectedBucketOwner={args.expected_owner}")
    _run([
        "sam", "deploy",
        "--template-file", str(BUILD / "template.yaml"),
        "--stack-name", args.stack,
        "--capabilities", "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-confirm-changeset",
        "--parameter-overrides", *parameters,
        *_provider_flags(args),
    ])


def deploy(args):
    build(args)
    _deploy_stack(args)


def remove(args):
    _run([
        "sam", "delete", "--stack-name", args.stack, "--no-prompts",
        *_provider_flags(args),
    ])


def bucket_policy(args):
    from deploy.aws_lambda.s3_bucket_policy import main as render

    render([
        "--bucket", args.bucket,
        "--prefix", args.prefix,
        "--publisher-principal", args.publisher_principal,
    ])


def test(_args):
    _run([
        "python3", "-m", "pytest", "-q",
        "tests/test_lambda_deploy.py",
        "tests/test_gateway.py",
        "tests/test_s3_adapter.py",
    ])


def package_smoke(_args):
    """Install the pins in isolation and exercise their exact runtime APIs."""
    with tempfile.TemporaryDirectory(prefix="poc16-lambda-smoke-") as tmp:
        root = Path(tmp)
        source, packages = stage(root / "stage"), root / "packages"
        _run([
            sys.executable, "-m", "pip", "install",
            "--disable-pip-version-check",
            "--target", str(packages),
            "-r", str(HERE / "requirements.txt"),
        ])
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            (str(packages), str(source)))
        subprocess.run(
            [
                sys.executable, "-m",
                "deploy.aws_lambda.sdk_smoke",
            ],
            cwd=source, env=environment, check=True)


def _stack_url(args):
    command = [
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", args.stack,
        "--query",
        "Stacks[0].Outputs[?OutputKey==`GatewayUrl`].OutputValue|[0]",
        "--output", "text",
        *_provider_flags(args),
    ]
    result = subprocess.run(
        command, cwd=REPO, check=True, capture_output=True, text=True)
    url = result.stdout.strip()
    if not url.startswith("https://"):
        raise RuntimeError("stack has no HTTPS GatewayUrl")
    return url.rstrip("/")


def _smoke_endpoint(url, state, workspace):
    """Exercise the deployed database-free gate using a client identity."""
    from core import manifest
    from core.crypto import h
    from core.node import Node, now_ms
    from core.walk import Peer

    state = Path(state).resolve()
    if not state.is_dir():
        raise ValueError("smoke client state directory does not exist")
    node = Node(str(state))
    if workspace not in node.workspaces():
        raise ValueError("smoke workspace is not present in client state")
    peer = Peer(node, workspace, url)
    peer.mint()
    if peer.accepts_push:
        raise RuntimeError("serverless peer advertised write acceptance")
    got = peer.root()
    if got is None or not got[0]:
        raise RuntimeError("serverless peer returned no root")
    root, etag = got
    snapshot = manifest.decode_root(root)
    if snapshot.anchor != workspace or etag != h(root):
        raise RuntimeError("serverless root identity mismatch")
    oid = snapshot.manifest or next(
        (tree["root"] for tree in snapshot.trees.values()
         if tree["root"]),
        "",
    )
    raw = peer.obj(oid) if oid else None
    if raw is None or h(raw) != oid:
        raise RuntimeError("serverless immutable-object read failed")

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
        "object": oid,
        "root": h(root),
        "tested_at": now_ms(),
    }


def live_smoke(args):
    """Deploy a generated read-only stack, test it, and always remove it."""
    args.stack = "poc16-smoke-" + uuid.uuid4().hex[:12]
    build(args)
    primary_error = None
    try:
        _deploy_stack(args)
        result = _smoke_endpoint(
            _stack_url(args), args.state, args.workspace)
        print(json.dumps(
            {"stack": args.stack, **result},
            sort_keys=True, separators=(",", ":")))
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            remove(args)
        except Exception as cleanup_error:
            if primary_error is None:
                raise
            print(
                f"warning: generated stack cleanup failed: {cleanup_error}",
                file=sys.stderr)


def parser():
    command = argparse.ArgumentParser(description=__doc__)
    sub = command.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build", help="stage and SAM-container build")
    build_cmd.set_defaults(run=build)
    test_cmd = sub.add_parser("test", help="run Lambda and adapter tests")
    test_cmd.set_defaults(run=test)
    smoke_cmd = sub.add_parser(
        "package-smoke",
        help="install pinned wheels and verify SDK/crypto runtime APIs")
    smoke_cmd.set_defaults(run=package_smoke)
    deploy_cmd = sub.add_parser(
        "deploy", help="build and deploy the read-only Function URL")
    deploy_cmd.add_argument("--stack", required=True)
    deploy_cmd.add_argument("--workspace", required=True)
    deploy_cmd.add_argument("--bucket", required=True)
    deploy_cmd.add_argument("--prefix", required=True)
    deploy_cmd.add_argument("--expected-owner")
    deploy_cmd.add_argument("--region")
    deploy_cmd.add_argument("--profile")
    deploy_cmd.set_defaults(run=deploy)
    remove_cmd = sub.add_parser(
        "remove", help="delete compute, logs, alarms, role, and grant secret")
    remove_cmd.add_argument("--stack", required=True)
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
    live_cmd.add_argument("--region")
    live_cmd.add_argument("--profile")
    live_cmd.set_defaults(run=live_smoke)
    policy_cmd = sub.add_parser(
        "bucket-policy",
        help="print deny guards to merge into an existing bucket policy")
    policy_cmd.add_argument("--bucket", required=True)
    policy_cmd.add_argument("--prefix", required=True)
    policy_cmd.add_argument("--publisher-principal", required=True)
    policy_cmd.set_defaults(run=bucket_policy)
    return command


def main(argv=None):
    args = parser().parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    main()
