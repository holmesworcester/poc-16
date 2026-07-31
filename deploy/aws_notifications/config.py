"""Validated constants for the isolated AWS notification roles."""
import re


DEPLOYMENT_MARKER = "poc16-aws-notifications-v1"
DEPLOYMENT_TAG = "poc16:deployment"
DEPLOYMENT_ID_TAG = "poc16:deployment-id"
SCAN_WAKE_SCHEMA = "poc16-notification-scan-wake-v1"
SCAN_RESULT_SCHEMA = "poc16-notification-scan-result-v1"
DIRECT_SMOKE_SCHEMA = "poc16-notification-direct-smoke-v1"
DIRECT_SMOKE_RESULT_SCHEMA = "poc16-notification-direct-smoke-result-v1"

SCANNER_TIMEOUT_SECONDS = 60
DELIVERY_TIMEOUT_SECONDS = 60
QUEUE_VISIBILITY_SECONDS = 360
QUEUE_RETENTION_SECONDS = 4 * 24 * 60 * 60
DLQ_RETENTION_SECONDS = 14 * 24 * 60 * 60
MAX_RECEIVE_COUNT = 5
MAX_SECRET_BYTES = 65_536
MAX_FIREBASE_APPS = 32
SDK_CONNECT_TIMEOUT_SECONDS = 2
SDK_READ_TIMEOUT_SECONDS = 15
SDK_TOTAL_ATTEMPTS = 2

DEPLOYMENT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{2,63}$"
WORKSPACE_PATTERN = r"^[0-9a-f]{64}$"
OWNER_PATTERN = r"^[0-9]{12}$"
BUCKET_PATTERN = (
    r"^(?!xn--)(?!sthree-)(?![0-9]{1,3}(?:\.[0-9]{1,3}){3}$)"
    r"(?!.*\.\.)(?!.*(?:-s3alias|--ol-s3|\.mrap|--x-s3|--table-s3)$)"
    r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
PREFIX_PATTERN = (
    r"^[a-z0-9:_-][a-z0-9:._-]*"
    r"(?:/[a-z0-9:_-][a-z0-9:._-]*)*$")
SECRET_ARN_PATTERN = (
    r"^arn:(?:aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:"
    r"[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$")
SECRET_VERSION_PATTERN = r"^[A-Za-z0-9-]{32,64}$"
KMS_KEY_ARN_PATTERN = (
    r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:"
    r"[0-9]{12}:key/[A-Za-z0-9-]+$")
ALARM_ACTION_ARN_PATTERN = r"^arn:[a-z0-9-]+:[a-z0-9-]+:[^:]*:[^:]*:.+$"

DEPLOYMENT_ID_RE = re.compile(DEPLOYMENT_ID_PATTERN)
OWNER_RE = re.compile(OWNER_PATTERN)
SECRET_ARN_RE = re.compile(SECRET_ARN_PATTERN)
SECRET_VERSION_RE = re.compile(SECRET_VERSION_PATTERN)
KMS_KEY_ARN_RE = re.compile(KMS_KEY_ARN_PATTERN)
ALARM_ACTION_ARN_RE = re.compile(ALARM_ACTION_ARN_PATTERN)


__all__ = tuple(
    name for name in globals()
    if name.isupper() and not name.startswith("_")
)
