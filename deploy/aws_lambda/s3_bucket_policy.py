"""Render the deny guard to merge into a publisher bucket policy."""
import argparse
import json
import re
import sys

from adapters.s3 import S3Config
from core.object_store import validate_key

ARN_RE = re.compile(r"^arn:[^:]+:iam::[0-9]{12}:(?:role|user)/.+$")


def policy(
        bucket, prefix, publisher_principal=None, *,
        profile="bucket-wide", partition="aws"):
    """Return explicit denies for one declared publisher threat profile.

    ``bucket-wide`` protects the configured authoritative keys from every
    principal while the policy remains attached and freezes lifecycle-policy
    mutation for the whole bucket. AWS account administrators who can replace
    the bucket policy, and lifecycle rules that predate the guard, remain
    outside what an S3 bucket policy can prove. Pre-existing object ACLs,
    tags, annotations, and annotation replication also need an operator audit
    before the guard is attached.

    ``single-publisher`` is intentionally narrower. It is useful only when the
    named principal is the complete writer set and all other bucket writers
    and administrators are trusted.
    """
    S3Config(bucket=bucket, prefix=prefix)
    validate_key(prefix)
    if profile not in {"bucket-wide", "single-publisher"}:
        raise ValueError("bucket policy profile")
    if partition not in {"aws", "aws-us-gov", "aws-cn"}:
        raise ValueError("AWS partition")
    if profile == "single-publisher":
        if not isinstance(publisher_principal, str) \
                or not ARN_RE.fullmatch(publisher_principal):
            raise ValueError("publisher principal ARN")
        principal_partition = publisher_principal.split(":", 2)[1]
        if partition != principal_partition:
            raise ValueError("publisher principal partition")
        principal = {"AWS": publisher_principal}
        lifecycle_sid = "DenyPublisherLifecycleMutation"
    else:
        if publisher_principal is not None:
            raise ValueError(
                "bucket-wide profile does not accept one publisher")
        principal = "*"
        lifecycle_sid = "DenyLifecycleMutation"
    bucket_arn = f"arn:{partition}:s3:::{bucket}"
    root = f"{bucket_arn}/{prefix}/root"
    objects = f"{bucket_arn}/{prefix}/obj/*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyAuthoritativeDeletion",
                "Effect": "Deny",
                "Principal": principal,
                "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                "Resource": [root, objects],
            },
            {
                "Sid": "DenyAuthoritativeMetadataMutation",
                "Effect": "Deny",
                "Principal": principal,
                "Action": [
                    "s3:DeleteObjectAnnotation",
                    "s3:DeleteObjectTagging",
                    "s3:DeleteObjectVersionTagging",
                    "s3:PutObjectAcl",
                    "s3:PutObjectAnnotation",
                    "s3:PutObjectTagging",
                    "s3:PutObjectVersionTagging",
                ],
                "Resource": [root, objects],
            },
            {
                "Sid": lifecycle_sid,
                "Effect": "Deny",
                "Principal": principal,
                "Action": "s3:PutLifecycleConfiguration",
                "Resource": bucket_arn,
            },
            {
                "Sid": "RequireImmutableObjectCreate",
                "Effect": "Deny",
                "Principal": principal,
                "Action": "s3:PutObject",
                "Resource": objects,
                "Condition": {"Null": {"s3:if-none-match": "true"}},
            },
            {
                "Sid": "RequireRootCompareAndSwap",
                "Effect": "Deny",
                "Principal": principal,
                "Action": "s3:PutObject",
                "Resource": root,
                "Condition": {
                    "Null": {
                        "s3:if-match": "true",
                        "s3:if-none-match": "true",
                    },
                },
            },
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Print a deny-only statement set to merge with the bucket's "
            "existing policy; this command never replaces a live policy."))
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument(
        "--profile", choices=("bucket-wide", "single-publisher"),
        default="bucket-wide")
    parser.add_argument("--publisher-principal")
    parser.add_argument(
        "--partition", choices=("aws", "aws-us-gov", "aws-cn"),
        default="aws")
    args = parser.parse_args(argv)
    if args.profile == "bucket-wide":
        note = (
            "bucket-wide profile: audit existing lifecycle rules, object "
            "ACLs, tags, annotations, and annotation replication before "
            "attaching; prefer BucketOwnerEnforced; policy and replication "
            "administrators remain trusted")
    else:
        note = (
            "single-publisher profile: all other writers and bucket-policy "
            "administrators remain trusted")
    print(note, file=sys.stderr)
    print(json.dumps(
        policy(
            args.bucket, args.prefix, args.publisher_principal,
            profile=args.profile, partition=args.partition),
        indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
