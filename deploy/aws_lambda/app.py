"""AWS Lambda Function URL adapter for the shared database-free gateway."""
import asyncio
import base64
import os
import time
from urllib.parse import parse_qs

from adapters.s3 import S3Config, S3Store
from core.limits import MAX_MINT_REQUEST_BYTES, PayloadTooLarge
from deploy.gateway import AsyncFromSyncReader, Gateway, Response

_gateway_cache = None


def _required(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing {name}")
    return value


def _positive(name, default):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"invalid {name}") from error
    if value < 1:
        raise RuntimeError(f"invalid {name}")
    return value


def _secret():
    import boto3

    response = boto3.client("secretsmanager").get_secret_value(
        SecretId=_required("TINYP2P_GRANT_SECRET_ARN"))
    if isinstance(response.get("SecretString"), str):
        value = response["SecretString"].encode()
    else:
        value = response.get("SecretBinary")
        if isinstance(value, str):
            value = base64.b64decode(value, validate=True)
    if not isinstance(value, bytes) or len(value) < 32:
        raise RuntimeError("grant secret must contain at least 32 bytes")
    return value


def _store():
    config = S3Config(
        bucket=_required("TINYP2P_S3_BUCKET"),
        prefix=_required("TINYP2P_S3_PREFIX"),
        region_name=os.environ.get("AWS_REGION"),
        expected_bucket_owner=os.environ.get(
            "TINYP2P_EXPECTED_BUCKET_OWNER"),
        server_side_encryption=os.environ.get(
            "TINYP2P_S3_SERVER_SIDE_ENCRYPTION") or None,
        sse_kms_key_id=os.environ.get("TINYP2P_S3_KMS_KEY_ID") or None,
    )
    # Gateway receives only the narrowed reader wrapper. The execution role
    # has no S3 mutation action even though S3Store also implements publishing.
    return AsyncFromSyncReader(S3Store(config))


def _gateway():
    global _gateway_cache
    if _gateway_cache is None:
        _gateway_cache = Gateway(
            _store(),
            _required("TINYP2P_WORKSPACE_ID"),
            _secret(),
            lambda: int(time.time() * 1000),
            max_request_bytes=_positive(
                "TINYP2P_MAX_REQUEST_BYTES", 512 * 1024),
            max_root_bytes=_positive(
                "TINYP2P_MAX_ROOT_BYTES", 1024 * 1024),
            max_object_bytes=_positive(
                "TINYP2P_MAX_OBJECT_BYTES", 4 * 1024 * 1024),
            max_batch_count=_positive(
                "TINYP2P_MAX_BATCH_COUNT", 256),
            max_batch_bytes=_positive(
                "TINYP2P_MAX_BATCH_BYTES", 4 * 1024 * 1024),
            max_mint_fetches=_positive(
                "TINYP2P_MINT_MAX_FETCHES", 128),
            max_mint_fetch_bytes=_positive(
                "TINYP2P_MINT_MAX_FETCH_BYTES", 4 * 1024 * 1024),
            grant_ttl_ms=_positive(
                "TINYP2P_GRANT_TTL", 60_000),
        )
    return _gateway_cache


def _event(event):
    if not isinstance(event, dict) or event.get("version") != "2.0":
        raise ValueError("Function URL payload version")
    context = event.get("requestContext")
    http = context.get("http") if isinstance(context, dict) else None
    method = http.get("method") if isinstance(http, dict) else None
    path = event.get("rawPath")
    headers = event.get("headers") or {}
    if not isinstance(method, str) or not isinstance(path, str) \
            or not isinstance(headers, dict):
        raise ValueError("Function URL request")
    encoded = event.get("body")
    if encoded is None:
        body = b""
    elif not isinstance(encoded, str):
        raise ValueError("Function URL body")
    elif event.get("isBase64Encoded") is True:
        if len(encoded) > 4 * ((MAX_MINT_REQUEST_BYTES + 2) // 3):
            raise PayloadTooLarge("Function URL body")
        body = base64.b64decode(encoded, validate=True)
    else:
        body = encoded.encode()
    if len(body) > MAX_MINT_REQUEST_BYTES:
        raise PayloadTooLarge("Function URL body")
    query = parse_qs(
        event.get("rawQueryString") or "", keep_blank_values=True)
    return method, path, query, headers, body


def _response(response):
    if not isinstance(response, Response):
        raise TypeError("gateway response")
    return {
        "statusCode": response.status,
        "headers": response.headers,
        "body": base64.b64encode(response.body).decode(),
        "isBase64Encoded": True,
    }


def handler(event, _context):
    """Normalize one Function URL v2 event and fail closed."""
    try:
        request = _event(event)
    except PayloadTooLarge:
        return _response(Response(413))
    except Exception:
        return _response(Response(400))
    try:
        return _response(asyncio.run(_gateway().handle(*request)))
    except Exception:
        return _response(Response(503))
