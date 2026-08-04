"""Validated constants shared by the isolated Lambda deployment tools."""
import re

from core.object_store import MAX_STORE_PREFIX_BYTES


DEPLOYMENT_MARKER = "poc16-aws-lambda-gateway-v1"
DEPLOYMENT_TAG = "poc16:deployment"
DEPLOYMENT_ID_TAG = "poc16:deployment-id"

FUNCTION_TIMEOUT_SECONDS = 15
SDK_CONNECT_TIMEOUT_SECONDS = 2
SDK_READ_TIMEOUT_SECONDS = 5
SDK_TOTAL_ATTEMPTS = 1
SDK_CLEANUP_MARGIN_SECONDS = 3

# Function URL v2 places a base64 body inside Lambda's 6 MiB buffered
# invocation envelope. Four raw MiB leaves room for that expansion and the
# fixed event metadata; core deliberately permits providers to choose a lower
# control-pile ceiling than its portable 5 MiB maximum.
MAX_CONTROL_REQUEST_BYTES = 4 * 1024 * 1024

MAX_QUERY_BYTES = 4096
MAX_QUERY_FIELDS = 8
MAX_READINESS_RESPONSE_BYTES = 4 * 1024
MAX_LOG_METHOD_CHARS = 16
MAX_LOG_PATH_CHARS = 256
MAX_LOG_RECORD_BYTES = 1280
MAX_STORE_PREFIX_LENGTH = MAX_STORE_PREFIX_BYTES

WORKSPACE_PATTERN = r"^[0-9a-f]{64}$"
DEPLOYMENT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{2,63}$"
BUCKET_PATTERN = (
    r"^(?!xn--)(?!sthree-)(?![0-9]{1,3}(?:\.[0-9]{1,3}){3}$)"
    r"(?!.*\.\.)(?!.*(?:-s3alias|--ol-s3|\.mrap|--x-s3|--table-s3)$)"
    r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
PREFIX_PATTERN = (
    r"^[a-z0-9:_-][a-z0-9:._-]*"
    r"(?:/[a-z0-9:_-][a-z0-9:._-]*)*$")
KMS_KEY_ARN_PATTERN = (
    r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:"
    r"[0-9]{12}:key/[A-Za-z0-9-]+$")
ALARM_ACTION_ARN_PATTERN = r"^arn:[a-z0-9-]+:[a-z0-9-]+:[^:]*:[^:]*:.+$"

WORKSPACE_RE = re.compile(WORKSPACE_PATTERN)
DEPLOYMENT_ID_RE = re.compile(DEPLOYMENT_ID_PATTERN)
KMS_KEY_ARN_RE = re.compile(KMS_KEY_ARN_PATTERN)
ALARM_ACTION_ARN_RE = re.compile(ALARM_ACTION_ARN_PATTERN)


def validate_sdk_budget(
        function_timeout=FUNCTION_TIMEOUT_SECONDS,
        connect_timeout=SDK_CONNECT_TIMEOUT_SECONDS,
        read_timeout=SDK_READ_TIMEOUT_SECONDS,
        total_attempts=SDK_TOTAL_ATTEMPTS):
    """Reject SDK settings that can consume the whole invocation deadline."""
    values = (
        function_timeout, connect_timeout, read_timeout, total_attempts)
    if any(type(value) is not int or value < 1 for value in values):
        raise ValueError("Lambda SDK deadline budget")
    # Retrying SDK calls adds backoff that is not bounded by the socket
    # timeouts alone. The gateway therefore uses exactly one explicit attempt.
    if total_attempts != 1 or connect_timeout + read_timeout \
            > function_timeout - SDK_CLEANUP_MARGIN_SECONDS:
        raise ValueError("Lambda SDK deadline budget")
    return connect_timeout, read_timeout, total_attempts
