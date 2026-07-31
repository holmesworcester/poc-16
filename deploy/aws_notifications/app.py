"""Two small AWS Lambda adapters around shared notification code.

The scheduled scanner owns only an operational cursor and SQS publication.
The SQS consumer is read-only over repository/state objects and maps the
shared worker's typed result to Lambda's partial-batch response.  Neither
function is a repository publication hook or an alternate fact processor.
"""
import asyncio
import json
import os
import time

from adapters.aws import SqsCarrier, consume_sqs_batch, queue_binding
from adapters.gcp.firebase import FirebaseAdminFcm
from adapters.s3 import S3Config, S3Store
from core.crypto import load_sk
from core.limits import MAX_REPOSITORY_OBJECT_BYTES, MAX_ROOT_BYTES
from core.shape import valid_fid
from notifications.discovery import NotificationDiscovery
from notifications.worker import (
    NotificationWorker,
    handle_carrier_delivery,
)

from .config import (
    MAX_FIREBASE_APPS,
    MAX_SECRET_BYTES,
    SCAN_RESULT_SCHEMA,
    SCAN_WAKE_SCHEMA,
    SDK_CONNECT_TIMEOUT_SECONDS,
    SDK_READ_TIMEOUT_SECONDS,
    SDK_TOTAL_ATTEMPTS,
)


_scanner_cache = None
_delivery_cache = None


def _required(name):
    value = os.environ.get(name)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"missing {name}")
    return value


def _workspace():
    value = _required("TINYP2P_NOTIFICATION_WORKSPACE_ID")
    if not valid_fid(value):
        raise RuntimeError("invalid notification workspace")
    return value


def _owner():
    value = _required("TINYP2P_NOTIFICATION_EXPECTED_BUCKET_OWNER")
    if len(value) != 12 or not value.isdigit():
        raise RuntimeError("invalid expected S3 bucket owner")
    return value


def _sdk_config(*, attempts=SDK_TOTAL_ATTEMPTS):
    from botocore.config import Config

    return Config(
        connect_timeout=SDK_CONNECT_TIMEOUT_SECONDS,
        ignore_configured_endpoint_urls=True,
        read_timeout=SDK_READ_TIMEOUT_SECONDS,
        retries={"mode": "standard", "total_max_attempts": attempts},
    )


def _store(bucket_name, prefix_name, *, state):
    return S3Store(S3Config(
        bucket=_required(bucket_name),
        prefix=_required(prefix_name),
        region_name=_required("AWS_REGION"),
        expected_bucket_owner=_owner(),
        connect_timeout=SDK_CONNECT_TIMEOUT_SECONDS,
        read_timeout=SDK_READ_TIMEOUT_SECONDS,
        read_total_max_attempts=SDK_TOTAL_ATTEMPTS,
        # State writes are exclusively immutable create or root CAS.  A 403
        # for a missing key may be treated as absent without permitting an
        # overwrite; canonical read-only storage must fail closed instead.
        conditional_write_403_is_absent=state,
    ))


def _scanner_dependencies():
    global _scanner_cache
    if _scanner_cache is None:
        import boto3

        workspace = _workspace()
        region = _required("AWS_REGION")
        account = _required("TINYP2P_NOTIFICATION_AWS_ACCOUNT_ID")
        queue_url = _required("TINYP2P_NOTIFICATION_QUEUE_URL")
        queue_arn = _required("TINYP2P_NOTIFICATION_QUEUE_ARN")
        queue_binding(
            queue_arn, queue_url, region=region, account=account)
        _scanner_cache = (
            _store(
                "TINYP2P_NOTIFICATION_CANONICAL_BUCKET",
                "TINYP2P_NOTIFICATION_CANONICAL_PREFIX",
                state=False,
            ),
            _store(
                "TINYP2P_NOTIFICATION_STATE_BUCKET",
                "TINYP2P_NOTIFICATION_STATE_PREFIX",
                state=True,
            ),
            workspace,
            SqsCarrier(
                boto3.client("sqs", config=_sdk_config()),
                queue_url,
                queue_arn,
                region=region,
                account=account,
            ),
        )
    return _scanner_cache


async def scan_once(*, repository=None, state=None, workspace=None,
                    carrier=None):
    """Advance at most one shared bounded discovery page."""
    if any(value is None for value in (repository, state, workspace, carrier)):
        configured = _scanner_dependencies()
        repository = configured[0] if repository is None else repository
        state = configured[1] if state is None else state
        workspace = configured[2] if workspace is None else workspace
        carrier = configured[3] if carrier is None else carrier
    return await NotificationDiscovery(
        repository, state, workspace, carrier).run_once()


def _scan_event(event, workspace):
    scheduled = isinstance(event, dict) \
        and event.get("source") == "aws.events" \
        and event.get("detail-type") == "Scheduled Event"
    wake = isinstance(event, dict) and event == {
        "schema": SCAN_WAKE_SCHEMA,
        "workspace": workspace,
    }
    if not scheduled and not wake:
        raise ValueError("notification scan invocation")


def scanner_handler(event, _context):
    """Handle one schedule or explicit non-authoritative wake."""
    workspace = _workspace()
    _scan_event(event, workspace)
    result = asyncio.run(scan_once(workspace=workspace))
    return {"schema": SCAN_RESULT_SCHEMA, "status": result.status}


def _secret_document(client):
    response = client.get_secret_value(
        SecretId=_required("TINYP2P_NOTIFICATION_SECRET_ARN"))
    value = response.get("SecretString") \
        if isinstance(response, dict) else None
    if not isinstance(value, str):
        raise RuntimeError("notification secret has no SecretString")
    raw = value.encode("utf-8")
    if not 0 < len(raw) <= MAX_SECRET_BYTES:
        raise RuntimeError("notification secret size")
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("notification secret JSON") from error
    if not isinstance(document, dict) or set(document) != {
            "firebase_apps", "push_node_seed"}:
        raise RuntimeError("notification secret shape")
    rows = document["firebase_apps"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FIREBASE_APPS:
        raise RuntimeError("notification Firebase applications")
    return document


def _push_provider():
    import firebase_admin
    from firebase_admin import credentials
    import boto3

    document = _secret_document(
        boto3.client("secretsmanager", config=_sdk_config()))
    try:
        secret = load_sk(document["push_node_seed"])
    except (TypeError, ValueError) as error:
        raise RuntimeError("notification push-node seed") from error
    configured, keys, apps, created = [], set(), {}, []
    try:
        for index, row in enumerate(document["firebase_apps"]):
            if not isinstance(row, dict) or set(row) != {
                    "application", "credential", "environment"} \
                    or not isinstance(row["application"], str) \
                    or not row["application"] \
                    or not isinstance(row["environment"], str) \
                    or not row["environment"] \
                    or not isinstance(row["credential"], dict):
                raise ValueError
            key = row["application"], row["environment"]
            if key in keys:
                raise ValueError
            keys.add(key)
            configured.append((
                key,
                credentials.Certificate(row["credential"]),
                f"poc16-notification-{index}",
            ))
        for key, credential, name in configured:
            item = firebase_admin.initialize_app(credential, name=name)
            apps[key] = item
            created.append(item)
    except Exception:
        for item in created:
            try:
                firebase_admin.delete_app(item)
            except Exception:
                pass
        raise RuntimeError("notification Firebase initialization") from None
    return secret, FirebaseAdminFcm(apps)


def _delivery_dependencies():
    global _delivery_cache
    if _delivery_cache is None:
        workspace = _workspace()
        canonical = _store(
            "TINYP2P_NOTIFICATION_CANONICAL_BUCKET",
            "TINYP2P_NOTIFICATION_CANONICAL_PREFIX",
            state=False,
        )
        state = _store(
            "TINYP2P_NOTIFICATION_STATE_BUCKET",
            "TINYP2P_NOTIFICATION_STATE_PREFIX",
            state=False,
        )
        secret, provider = _push_provider()

        def current_root(requested):
            if requested != workspace:
                raise ValueError("notification workspace")
            raw = canonical.get_bounded("root", MAX_ROOT_BYTES)
            if raw is None:
                raise OSError("notification repository has no root")
            return raw

        def fetch(requested, oid):
            if requested != workspace:
                raise ValueError("notification workspace")
            return canonical.get_bounded(
                "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES)

        worker = NotificationWorker(
            current_root,
            fetch,
            secret,
            provider,
            lambda: int(time.time() * 1000),
        )
        _delivery_cache = workspace, state, worker
    return _delivery_cache


async def deliver_batch(event, *, state=None, worker=None, workspace=None,
                        queue_arn=None):
    """Decode hints, bind historical roots, and consume one SQS batch."""
    if any(value is None for value in (state, worker, workspace, queue_arn)):
        configured = _delivery_dependencies()
        state = configured[1] if state is None else state
        worker = configured[2] if worker is None else worker
        workspace = configured[0] if workspace is None else workspace
        queue_arn = _required("TINYP2P_NOTIFICATION_QUEUE_ARN") \
            if queue_arn is None else queue_arn

    async def handle(delivery):
        return await handle_carrier_delivery(
            delivery, workspace, state, worker)

    return await consume_sqs_batch(
        event, handle, expected_queue_arn=queue_arn)


def delivery_handler(event, _context):
    """Return only Lambda's documented partial-batch failure shape."""
    return asyncio.run(deliver_batch(event))


__all__ = (
    "deliver_batch",
    "delivery_handler",
    "scan_once",
    "scanner_handler",
)
