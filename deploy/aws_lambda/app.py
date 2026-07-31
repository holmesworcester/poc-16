"""AWS Lambda Function URL adapter for the shared database-free gateway."""
import asyncio
import base64
import json
import logging
import os
import time
from urllib.parse import parse_qs

from adapters.s3 import S3Config, S3Store
from core.limits import (
    MAX_MINT_REQUEST_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PayloadTooLarge,
)
from deploy.aws_lambda.config import (
    FUNCTION_TIMEOUT_SECONDS,
    MAX_LOG_METHOD_CHARS,
    MAX_LOG_PATH_CHARS,
    MAX_LOG_RECORD_BYTES,
    MAX_QUERY_BYTES,
    MAX_QUERY_FIELDS,
    SDK_CONNECT_TIMEOUT_SECONDS,
    SDK_READ_TIMEOUT_SECONDS,
    SDK_TOTAL_ATTEMPTS,
    validate_sdk_budget,
)
from core.http import AsyncFromSyncReader, HttpGate, Response

_gateway_cache = None
_logger = logging.getLogger(__name__)
_HEX = frozenset("0123456789abcdefABCDEF")


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


def _sdk_budget():
    values = (
        _positive(
            "TINYP2P_FUNCTION_TIMEOUT_SECONDS",
            FUNCTION_TIMEOUT_SECONDS),
        _positive(
            "TINYP2P_AWS_CONNECT_TIMEOUT_SECONDS",
            SDK_CONNECT_TIMEOUT_SECONDS),
        _positive(
            "TINYP2P_AWS_READ_TIMEOUT_SECONDS",
            SDK_READ_TIMEOUT_SECONDS),
        _positive(
            "TINYP2P_AWS_TOTAL_ATTEMPTS",
            SDK_TOTAL_ATTEMPTS),
    )
    try:
        return validate_sdk_budget(*values)
    except ValueError as error:
        raise RuntimeError("invalid AWS SDK deadline budget") from error


def _botocore_config():
    from botocore.config import Config

    connect, read, attempts = _sdk_budget()
    return Config(
        connect_timeout=connect,
        ignore_configured_endpoint_urls=True,
        read_timeout=read,
        retries={
            "mode": "standard",
            "total_max_attempts": attempts,
        },
    )


def _secret():
    import boto3

    response = boto3.client(
        "secretsmanager", config=_botocore_config()).get_secret_value(
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
    connect, read, attempts = _sdk_budget()
    config = S3Config(
        bucket=_required("TINYP2P_S3_BUCKET"),
        prefix=_required("TINYP2P_S3_PREFIX"),
        region_name=os.environ.get("AWS_REGION"),
        expected_bucket_owner=os.environ.get(
            "TINYP2P_EXPECTED_BUCKET_OWNER"),
        server_side_encryption=os.environ.get(
            "TINYP2P_S3_SERVER_SIDE_ENCRYPTION") or None,
        sse_kms_key_id=os.environ.get("TINYP2P_S3_KMS_KEY_ID") or None,
        connect_timeout=connect,
        read_timeout=read,
        read_total_max_attempts=attempts,
        probe_access_denied_missing=True,
    )
    # HttpGate receives only the narrowed reader wrapper. The execution role
    # has no S3 mutation action even though S3Store also implements publishing.
    return AsyncFromSyncReader(S3Store(config))


def _gateway():
    global _gateway_cache
    if _gateway_cache is None:
        _gateway_cache = HttpGate(
            _store(),
            _required("TINYP2P_WORKSPACE_ID"),
            _secret(),
            lambda: int(time.time() * 1000),
            max_request_bytes=_positive(
                "TINYP2P_MAX_REQUEST_BYTES", 512 * 1024),
            max_root_bytes=_positive(
                "TINYP2P_MAX_ROOT_BYTES", 1024 * 1024),
            max_object_bytes=_positive(
                "TINYP2P_MAX_OBJECT_BYTES", MAX_REPOSITORY_OBJECT_BYTES),
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
    raw_query = event.get("rawQueryString") or ""
    if not isinstance(raw_query, str):
        raise ValueError("Function URL query")
    try:
        query_bytes = raw_query.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("Function URL query encoding") from error
    if len(query_bytes) > MAX_QUERY_BYTES:
        raise PayloadTooLarge("Function URL query")
    for index, character in enumerate(raw_query):
        if character == "%" and (
                index + 2 >= len(raw_query)
                or raw_query[index + 1] not in _HEX
                or raw_query[index + 2] not in _HEX):
            raise ValueError("Function URL query percent escape")
    field_count = 0 if not raw_query else raw_query.count("&") + 1
    if field_count > MAX_QUERY_FIELDS:
        raise PayloadTooLarge("Function URL query fields")
    try:
        query = parse_qs(
            raw_query, keep_blank_values=True,
            encoding="utf-8", errors="strict",
            max_num_fields=MAX_QUERY_FIELDS)
    except ValueError as error:
        raise ValueError("Function URL query encoding") from error
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


def _log_text(value, maximum):
    if not isinstance(value, str):
        return None
    return "".join(
        character if " " <= character <= "~" else "?"
        for character in value[:maximum])


def _log_failure(kind, *, request=None, context=None, error=None, status=503):
    """Emit a fixed-shape record without request bodies, tokens, or secrets."""
    method = _log_text(
        request[0] if request is not None else None,
        MAX_LOG_METHOD_CHARS)
    path = _log_text(
        request[1] if request is not None else None,
        MAX_LOG_PATH_CHARS)
    request_id = _log_text(
        getattr(context, "aws_request_id", None), 128)
    record = {
        "error_type": _log_text(
            type(error).__name__ if error is not None else None, 64),
        "event": "poc16_gateway_failure",
        "kind": kind,
        "method": method,
        "path": path,
        "request_id": request_id,
        "status": status,
    }
    encoded = json.dumps(
        record, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > MAX_LOG_RECORD_BYTES:
        raise RuntimeError("failure telemetry exceeded fixed byte bound")
    _logger.error(encoded)


def handler(event, context):
    """Normalize one Function URL v2 event and fail closed."""
    try:
        request = _event(event)
    except PayloadTooLarge:
        return _response(Response(413))
    except Exception:
        return _response(Response(400))
    try:
        response = asyncio.run(_gateway().handle(*request))
        if response.status >= 500:
            _log_failure(
                "gateway_response", request=request,
                context=context, status=response.status)
        return _response(response)
    except Exception as error:
        _log_failure(
            "handler_exception", request=request,
            context=context, error=error)
        return _response(Response(503))
