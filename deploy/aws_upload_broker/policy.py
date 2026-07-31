"""Least-authority AWS policy and browser CORS shapes for ingress uploads."""
from urllib.parse import urlsplit

from core.shape import valid_fid
from core.staged_intent import staging_prefix
from deploy.aws_upload_broker.signer import S3UploadConfig


_PARTITIONS = frozenset({"aws", "aws-cn", "aws-us-gov"})


def presigner_policy(config, workspace, *, partition="aws"):
    """Allow only short-lived query-signed conditional PUTs for one workspace."""
    if not isinstance(config, S3UploadConfig):
        raise TypeError("S3 upload config")
    if not valid_fid(workspace):
        raise ValueError("workspace")
    if partition not in _PARTITIONS:
        raise ValueError("AWS partition")
    resource = (
        f"arn:{partition}:s3:::{config.bucket}/"
        f"{staging_prefix(workspace, 'pile')}*"
    )
    string_equals = {
        "s3:authType": "REST-QUERY-STRING",
        "s3:signatureversion": "AWS4-HMAC-SHA256",
    }
    if config.expected_bucket_owner is not None:
        string_equals["s3:ResourceAccount"] = (
            config.expected_bucket_owner)
    return {
        "Statement": [{
            "Action": "s3:PutObject",
            "Condition": {
                "Null": {"s3:if-none-match": "false"},
                "NumericLessThanEquals": {
                    "s3:signatureAge": (
                        config.ttl_seconds * 1000),
                },
                "StringEquals": string_equals,
            },
            "Effect": "Allow",
            "Resource": resource,
            "Sid": "PresignOneWorkspaceIngressPut",
        }],
        "Version": "2012-10-17",
    }


def ingress_cors(origins, *, max_age_seconds=300):
    """Return the exact S3 CORS document needed by browser PUT clients.

    ``Content-Length`` and ``Host`` are signed but browser-controlled headers,
    so they are intentionally absent from ``AllowedHeaders``.  A real-browser
    conformance check must prove that its generated Content-Length matches the
    signed exact length before browser support can be claimed.
    """
    try:
        origins = tuple(origins)
    except TypeError as error:
        raise ValueError("CORS origins") from error
    if not origins or len(origins) > 32 or type(max_age_seconds) is not int \
            or not 0 <= max_age_seconds <= 3600:
        raise ValueError("S3 upload CORS")
    for origin in origins:
        parsed = urlsplit(origin) if isinstance(origin, str) else None
        if parsed is None or parsed.scheme != "https" \
                or not parsed.hostname or parsed.username is not None \
                or parsed.password is not None or parsed.query \
                or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError("CORS origin")
    return {
        "CORSRules": [{
            "AllowedHeaders": [
                "content-type",
                "if-none-match",
                "x-amz-checksum-sha256",
                "x-amz-expected-bucket-owner",
            ],
            "AllowedMethods": ["PUT"],
            "AllowedOrigins": list(origins),
            "ExposeHeaders": [
                "etag",
                "x-amz-checksum-sha256",
            ],
            "MaxAgeSeconds": max_age_seconds,
        }],
    }
