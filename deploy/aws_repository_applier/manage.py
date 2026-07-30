#!/usr/bin/env python3
"""Build, deploy, and safely remove the AWS RepositoryApplier stack."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from adapters.s3 import S3Config
from core.shape import valid_fid


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
STAGE = HERE / "stage"
BUILD = HERE / ".aws-sam"
MARKER = "poc16-aws-repository-applier-v1"
CORE_MODULES = (
    "__init__.py",
    "admission_proof.py",
    "bao.py",
    "candidate_archive.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "fact_index.py",
    "indexes.py",
    "ingress.py",
    "kernel.py",
    "limits.py",
    "merkle_map.py",
    "object_store.py",
    "repository_applier.py",
    "repository_snapshot.py",
    "settlement.py",
    "shape.py",
    "snapshot.py",
    "staged_intent.py",
    "suppression.py",
)
DEPLOYMENT = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
OWNER = re.compile(r"^[0-9]{12}$")
PREFIX = re.compile(
    r"^[a-z0-9:_-][a-z0-9:._-]*"
    r"(?:/[a-z0-9:_-][a-z0-9:._-]*)*$")


def _copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def stage(destination=STAGE):
    """Create the exact DB-free Lambda artifact; no host/SQL code is copied."""
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name in CORE_MODULES:
        _copy(
            REPOSITORY / "core" / name,
            destination / "core" / name,
        )
    shutil.copytree(
        REPOSITORY / "facts",
        destination / "facts",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    _copy(
        REPOSITORY / "adapters" / "__init__.py",
        destination / "adapters" / "__init__.py",
    )
    shutil.copytree(
        REPOSITORY / "adapters" / "s3",
        destination / "adapters" / "s3",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    for relative in (
            "deploy/__init__.py",
            "deploy/aws_repository_applier/__init__.py",
            "deploy/aws_repository_applier/app.py"):
        _copy(REPOSITORY / relative, destination / relative)
    _copy(
        REPOSITORY / "deploy" / "aws_upload_broker" / "requirements.txt",
        destination / "requirements.txt",
    )
    verify_stage(destination)
    return destination


def verify_stage(directory):
    paths = {
        path.relative_to(directory).as_posix()
        for path in Path(directory).rglob("*") if path.is_file()
    }
    required = {
        "core/repository_applier.py",
        "core/repository_snapshot.py",
        "deploy/aws_repository_applier/app.py",
        "adapters/s3/store.py",
        "facts/auth/workspace.py",
        "requirements.txt",
    }
    missing = required - paths
    if missing:
        raise RuntimeError(f"applier stage omitted {sorted(missing)}")
    forbidden = {
        "core/admission.py",
        "core/catalog.py",
        "core/client_projection.py",
        "core/daemon.py",
        "core/node.py",
        "core/pile_sender.py",
        "core/publication.py",
        "core/runtime.py",
    } & paths
    if forbidden:
        raise RuntimeError(
            f"applier stage contains forbidden authority: "
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
        "sam",
        "build",
        "--template-file", str(HERE / "template.yaml"),
        "--build-dir", str(BUILD),
        "--use-container",
    ])


def _validated(args):
    if not DEPLOYMENT.fullmatch(args.deployment_id or ""):
        raise ValueError("deployment ID")
    if not valid_fid(args.workspace):
        raise ValueError("workspace")
    if not PREFIX.fullmatch(args.canonical_prefix or ""):
        raise ValueError("canonical prefix")
    if not OWNER.fullmatch(args.expected_owner or ""):
        raise ValueError("expected bucket owner")
    S3Config(
        bucket=args.canonical_bucket,
        prefix=args.canonical_prefix,
        expected_bucket_owner=args.expected_owner,
    )
    S3Config(
        bucket=args.ingress_bucket,
        expected_bucket_owner=args.expected_owner,
    )
    if args.canonical_bucket == args.ingress_bucket:
        raise ValueError("canonical and ingress buckets must differ")
    if type(args.reserved_concurrency) is not int \
            or not 1 <= args.reserved_concurrency <= 1000:
        raise ValueError("reserved concurrency")
    return args


def _provider_flags(args):
    flags = []
    if args.region:
        flags += ["--region", args.region]
    if args.profile:
        flags += ["--profile", args.profile]
    return flags


def deploy(args):
    """Build and idempotently deploy one externally owned bucket pair."""
    args = _validated(args)
    build(args)
    parameters = (
        f"DeploymentId={args.deployment_id}",
        f"WorkspaceId={args.workspace}",
        f"CanonicalBucketName={args.canonical_bucket}",
        f"CanonicalPrefix={args.canonical_prefix}",
        f"IngressBucketName={args.ingress_bucket}",
        f"ExpectedBucketOwner={args.expected_owner}",
        f"ReservedConcurrency={args.reserved_concurrency}",
    )
    _run([
        "sam", "deploy",
        "--template-file", str(BUILD / "template.yaml"),
        "--stack-name", args.stack_name,
        "--capabilities", "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-fail-on-empty-changeset",
        "--parameter-overrides", *parameters,
        "--tags",
        f"poc16:deployment={args.deployment_id}",
        f"poc16:marker={MARKER}",
        *_provider_flags(args),
    ])


def _stack_outputs(args):
    result = _run([
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", args.stack_name,
        "--output", "json",
        *_provider_flags(args),
    ], capture=True)
    try:
        document = json.loads(result.stdout)
        stacks = document["Stacks"]
        if not isinstance(stacks, list) or len(stacks) != 1:
            raise ValueError
        return {
            row["OutputKey"]: row["OutputValue"]
            for row in stacks[0].get("Outputs", [])
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed CloudFormation stack") from error


def remove(args):
    """Delete only an exactly identified stack; buckets are never resources."""
    if not DEPLOYMENT.fullmatch(args.deployment_id or ""):
        raise ValueError("deployment ID")
    outputs = _stack_outputs(args)
    if outputs.get("DeploymentMarker") != MARKER \
            or outputs.get("DeploymentId") != args.deployment_id:
        raise RuntimeError("refusing to remove an unowned stack")
    flags = _provider_flags(args)
    _run([
        "aws", "cloudformation", "delete-stack",
        "--stack-name", args.stack_name,
        *flags,
    ])
    _run([
        "aws", "cloudformation", "wait", "stack-delete-complete",
        "--stack-name", args.stack_name,
        *flags,
    ])


def parser():
    result = argparse.ArgumentParser(
        description="POC-16 AWS RepositoryApplier deployment")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("build")
    for name in ("deploy", "remove"):
        command = commands.add_parser(name)
        command.add_argument("--stack-name", required=True)
        command.add_argument("--deployment-id", required=True)
        command.add_argument("--region")
        command.add_argument("--profile")
        if name == "deploy":
            command.add_argument("--workspace", required=True)
            command.add_argument("--canonical-bucket", required=True)
            command.add_argument("--canonical-prefix", required=True)
            command.add_argument("--ingress-bucket", required=True)
            command.add_argument("--expected-owner", required=True)
            command.add_argument(
                "--reserved-concurrency", type=int, default=10)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "build":
        build(args)
    elif args.command == "deploy":
        deploy(args)
    else:
        remove(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
