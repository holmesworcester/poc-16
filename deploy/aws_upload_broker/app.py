"""AWS Lambda Function URL adapter for the upload-broker HTTP membrane.

The Lambda receives only OPEN/ISSUE/FINALIZE metadata.  Exact object and pile
bodies travel from the client to S3 ingress using the returned bearer PUTs.
"""
import asyncio
import base64
import json
import logging
import os
import time

from adapters.s3 import S3Config, S3Store
from core.limits import PayloadTooLarge
from deploy.aws_upload_broker.config import (
    FUNCTION_TIMEOUT_SECONDS,
    MAX_LOG_METHOD_CHARS,
    MAX_LOG_PATH_CHARS,
    MAX_LOG_RECORD_BYTES,
    SDK_CONNECT_TIMEOUT_SECONDS,
    SDK_READ_TIMEOUT_SECONDS,
    SDK_TOTAL_ATTEMPTS,
    validate_sdk_budget,
)
from deploy.aws_upload_broker.signer import (
    S3UploadConfig,
    S3UploadSigner,
)
from deploy.gateway import AsyncFromSyncReader, Response
from deploy.upload_broker import UploadBroker
from deploy.upload_broker_http import (
    UploadBrokerEndpoint,
    upload_error_response,
    upload_request_body_limit,
)
from deploy.upload_keyring import (
    MAX_KEYRING_BYTES,
    decode_keyring,
)


_endpoint_cache = None
_logger = logging.getLogger(__name__)


def _required(name):
    value = os.environ.get(name)
    if not isinstance(value, str) or not value:
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
            "TINYP2P_UPLOAD_FUNCTION_TIMEOUT_SECONDS",
            FUNCTION_TIMEOUT_SECONDS,
        ),
        _positive(
            "TINYP2P_UPLOAD_AWS_CONNECT_TIMEOUT_SECONDS",
            SDK_CONNECT_TIMEOUT_SECONDS,
        ),
        _positive(
            "TINYP2P_UPLOAD_AWS_READ_TIMEOUT_SECONDS",
            SDK_READ_TIMEOUT_SECONDS,
        ),
        _positive(
            "TINYP2P_UPLOAD_AWS_TOTAL_ATTEMPTS",
            SDK_TOTAL_ATTEMPTS,
        ),
    )
    try:
        _function, connect, read, attempts = values
        validate_sdk_budget(*values)
    except ValueError as error:
        raise RuntimeError("invalid AWS upload SDK deadline budget")
    return connect, read, attempts


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


def _expected_owner():
    value = _required("TINYP2P_UPLOAD_EXPECTED_BUCKET_OWNER")
    if len(value) != 12 or not value.isdigit():
        raise RuntimeError("invalid expected S3 bucket owner")
    return value


def _signer():
    return S3UploadSigner(S3UploadConfig(
        _required("TINYP2P_UPLOAD_INGRESS_BUCKET"),
        _required("AWS_REGION"),
        ttl_seconds=_positive(
            "TINYP2P_UPLOAD_PRESIGN_TTL_SECONDS", 60),
        expected_bucket_owner=_expected_owner(),
    ))


def _keyring(signer):
    import boto3

    try:
        response = boto3.client(
            "secretsmanager",
            config=_botocore_config(),
        ).get_secret_value(
            SecretId=_required("TINYP2P_UPLOAD_KEYRING_SECRET_ARN"),
            VersionId=_required("TINYP2P_UPLOAD_KEYRING_VERSION_ID"),
        )
    except Exception as error:
        raise RuntimeError("upload keyring unavailable") from error
    secret = response.get("SecretString") \
        if isinstance(response, dict) else None
    if not isinstance(secret, str) or not secret \
            or len(secret) > MAX_KEYRING_BYTES:
        raise RuntimeError("upload keyring unavailable")
    try:
        loaded = decode_keyring(
            secret.encode("ascii"),
            signer.provider_binding,
        )
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("invalid upload keyring") from error
    if loaded.policy.issuer != _required("TINYP2P_UPLOAD_ISSUER"):
        raise RuntimeError("upload keyring issuer")
    return loaded.policy


def _store():
    connect, read, attempts = _sdk_budget()
    config = S3Config(
        bucket=_required("TINYP2P_UPLOAD_CANONICAL_BUCKET"),
        prefix=_required("TINYP2P_UPLOAD_CANONICAL_PREFIX"),
        region_name=_required("AWS_REGION"),
        expected_bucket_owner=_expected_owner(),
        connect_timeout=connect,
        read_timeout=read,
        read_total_max_attempts=attempts,
        probe_access_denied_missing=True,
    )
    # The broker receives only this narrowed reader, and its IAM role grants no
    # canonical mutation even though the host adapter has a wider interface.
    return AsyncFromSyncReader(S3Store(config))


def _endpoint():
    global _endpoint_cache
    if _endpoint_cache is None:
        signer = _signer()
        broker = UploadBroker(
            _store(),
            _required("TINYP2P_UPLOAD_WORKSPACE_ID"),
            signer,
            lambda: time.time_ns() // 1_000_000,
            _keyring(signer),
        )
        _endpoint_cache = UploadBrokerEndpoint(broker)
    return _endpoint_cache


def _bounded_body(event, method, path):
    limit = upload_request_body_limit(path)
    # Unknown routes and wrong methods never need to decode attacker bytes to
    # produce the membrane's 404/405 response.
    if limit is None or method != "POST":
        return b""
    encoded = event.get("body")
    is_base64 = event.get("isBase64Encoded", False)
    if type(is_base64) is not bool:
        raise ValueError("Function URL body encoding")
    if encoded is None:
        return b""
    if not isinstance(encoded, str):
        raise ValueError("Function URL body")
    if is_base64:
        if len(encoded) > 4 * ((limit + 2) // 3):
            raise PayloadTooLarge("Function URL body")
        try:
            body = base64.b64decode(encoded, validate=True)
        except (TypeError, ValueError) as error:
            raise ValueError("Function URL body") from error
    else:
        if len(encoded) > limit:
            raise PayloadTooLarge("Function URL body")
        body = encoded.encode("utf-8")
    if len(body) > limit:
        raise PayloadTooLarge("Function URL body")
    return body


def _event(event):
    if not isinstance(event, dict) or event.get("version") != "2.0":
        raise ValueError("Function URL payload version")
    context = event.get("requestContext")
    http = context.get("http") if isinstance(context, dict) else None
    method = http.get("method") if isinstance(http, dict) else None
    path = event.get("rawPath")
    headers = event.get("headers") or {}
    query = event.get("rawQueryString") or ""
    if not isinstance(method, str) or not isinstance(path, str) \
            or not isinstance(headers, dict) \
            or not isinstance(query, str) or query:
        raise ValueError("Function URL request")
    return method, path, headers, _bounded_body(event, method, path)


def _response(response):
    if not isinstance(response, Response):
        raise TypeError("upload broker response")
    return {
        "statusCode": response.status,
        "headers": response.headers,
        "body": base64.b64encode(response.body).decode("ascii"),
        "isBase64Encoded": True,
    }


def _log_text(value, maximum):
    if not isinstance(value, str):
        return None
    return "".join(
        character if " " <= character <= "~" else "?"
        for character in value[:maximum]
    )


def _log_failure(kind, *, request=None, context=None, status=503):
    """Log fixed metadata only: never proofs, cursors, URLs, or exceptions."""
    record = {
        "event": "poc16_upload_broker_failure",
        "kind": kind,
        "method": _log_text(
            request[0] if request is not None else None,
            MAX_LOG_METHOD_CHARS,
        ),
        "path": _log_text(
            request[1] if request is not None else None,
            MAX_LOG_PATH_CHARS,
        ),
        "request_id": _log_text(
            getattr(context, "aws_request_id", None), 128),
        "status": status,
    }
    encoded = json.dumps(
        record, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > MAX_LOG_RECORD_BYTES:
        raise RuntimeError("upload failure telemetry byte bound")
    _logger.error(encoded)


def handler(event, context):
    """Normalize one Function URL v2 event and fail closed."""
    try:
        request = _event(event)
    except PayloadTooLarge:
        return _response(upload_error_response(413))
    except Exception:
        return _response(upload_error_response(400))
    try:
        response = asyncio.run(_endpoint().handle(*request))
        if response.status >= 500:
            _log_failure(
                "broker_response",
                request=request,
                context=context,
                status=response.status,
            )
        return _response(response)
    except Exception:
        _log_failure(
            "handler_exception",
            request=request,
            context=context,
        )
        return _response(upload_error_response(503))


__all__ = ("handler",)
