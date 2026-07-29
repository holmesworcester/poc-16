"""Render the deny guard to merge into a publisher bucket policy."""
import argparse
import json
import re

from adapters.s3 import S3Config
from core.object_store import validate_key

ARN_RE = re.compile(r"^arn:[^:]+:iam::[0-9]{12}:(?:role|user)/.+$")


def policy(bucket, prefix, publisher_principal):
    """Return explicit denies that preserve the root/object storage laws."""
    S3Config(bucket=bucket, prefix=prefix)
    validate_key(prefix)
    if not isinstance(publisher_principal, str) \
            or not ARN_RE.fullmatch(publisher_principal):
        raise ValueError("publisher principal ARN")
    partition = publisher_principal.split(":", 2)[1]
    bucket_arn = f"arn:{partition}:s3:::{bucket}"
    root = f"{bucket_arn}/{prefix}/root"
    objects = f"{bucket_arn}/{prefix}/obj/*"
    principal = {"AWS": publisher_principal}
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
                "Sid": "DenyPublisherLifecycleMutation",
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
    parser.add_argument("--publisher-principal", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(
        policy(args.bucket, args.prefix, args.publisher_principal),
        indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
