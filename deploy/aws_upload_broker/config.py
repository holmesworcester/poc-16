"""Validated constants for the isolated AWS upload-broker deployment."""
import re


DEPLOYMENT_MARKER = "poc16-aws-upload-broker-v1"
DEPLOYMENT_TAG = "poc16:deployment"
DEPLOYMENT_ID_TAG = "poc16:deployment-id"

FUNCTION_TIMEOUT_SECONDS = 15
SDK_CONNECT_TIMEOUT_SECONDS = 2
SDK_READ_TIMEOUT_SECONDS = 5
SDK_TOTAL_ATTEMPTS = 1
SDK_CLEANUP_MARGIN_SECONDS = 3

MAX_LOG_RECORD_BYTES = 1_280
MAX_LOG_METHOD_CHARS = 16
MAX_LOG_PATH_CHARS = 128
MAX_STORE_PREFIX_LENGTH = 760

WORKSPACE_PATTERN = r"^[0-9a-f]{64}$"
DEPLOYMENT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{2,63}$"
BUCKET_PATTERN = (
    r"^(?!xn--)(?!sthree-)(?![0-9]{1,3}(?:\.[0-9]{1,3}){3}$)"
    r"(?!.*\.\.)(?!.*(?:-s3alias|--ol-s3|\.mrap|--x-s3|--table-s3)$)"
    r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
PREFIX_PATTERN = (
    r"^[a-z0-9:_-][a-z0-9:._-]*"
    r"(?:/[a-z0-9:_-][a-z0-9:._-]*)*$")
ISSUER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$"
SECRET_ARN_PATTERN = (
    r"^arn:(?:aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:"
    r"[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$")
KMS_KEY_ARN_PATTERN = (
    r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:"
    r"[0-9]{12}:key/[A-Za-z0-9-]+$")
ALARM_ACTION_ARN_PATTERN = (
    r"^arn:[a-z0-9-]+:[a-z0-9-]+:[^:]*:[^:]*:.+$")

WORKSPACE_RE = re.compile(WORKSPACE_PATTERN)
DEPLOYMENT_ID_RE = re.compile(DEPLOYMENT_ID_PATTERN)
BUCKET_RE = re.compile(BUCKET_PATTERN)
PREFIX_RE = re.compile(PREFIX_PATTERN)
ISSUER_RE = re.compile(ISSUER_PATTERN)
SECRET_ARN_RE = re.compile(SECRET_ARN_PATTERN)
KEYRING_VERSION_RE = re.compile(r"^[A-Za-z0-9-]{32,64}$")
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
    if any(type(value) is not int or value < 1 for value in values) \
            or total_attempts != 1 \
            or connect_timeout + read_timeout \
            > function_timeout - SDK_CLEANUP_MARGIN_SECONDS:
        raise ValueError("Lambda upload SDK deadline budget")
    return connect_timeout, read_timeout, total_attempts
