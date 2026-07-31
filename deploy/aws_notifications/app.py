"""Two small AWS Lambda adapters around shared notification code.

The scheduled scanner owns only an operational cursor and SQS publication.
The SQS consumer is read-only over repository/state objects and maps the
shared worker's typed result to Lambda's partial-batch response.  Neither
function is a repository publication hook or an alternate fact processor.
"""
import asyncio
import base64
import binascii
import os
import time

from adapters.aws import SqsCarrier, consume_sqs_batch, queue_binding
from adapters.gcp.firebase import FirebaseAdminFcm
from adapters.s3 import S3Config, S3Store
from core.crypto import h
from core.fact import canon
from core.limits import MAX_REPOSITORY_OBJECT_BYTES, MAX_ROOT_BYTES
from core.shape import valid_fid
from notifications.carrier import CarrierDelivery
from notifications.discovery import NotificationDiscovery
from notifications.worker import (
    RETRY,
    TERMINAL,
    NotificationWorker,
    handle_carrier_delivery,
    process_carrier_delivery,
)

from .config import (
    DIRECT_SMOKE_RESULT_SCHEMA,
    DIRECT_SMOKE_SCHEMA,
    SCAN_RESULT_SCHEMA,
    SCAN_WAKE_SCHEMA,
    SDK_CONNECT_TIMEOUT_SECONDS,
    SDK_READ_TIMEOUT_SECONDS,
    SDK_TOTAL_ATTEMPTS,
)
from .secret import decode_secret, push_node_id


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


def _notification_owner():
    return h(canon([
        "aws-notification-owner-v2",
        _required("TINYP2P_NOTIFICATION_DEPLOYMENT_ID"),
        _workspace(),
        _required("TINYP2P_NOTIFICATION_CANONICAL_BUCKET"),
        _required("TINYP2P_NOTIFICATION_CANONICAL_PREFIX"),
        _required("TINYP2P_NOTIFICATION_STATE_BUCKET"),
        _required("TINYP2P_NOTIFICATION_STATE_PREFIX"),
        _owner(),
        _required("TINYP2P_NOTIFICATION_SECRET_ARN"),
        _required("TINYP2P_NOTIFICATION_SECRET_VERSION_ID"),
        _required("TINYP2P_NOTIFICATION_PUSH_NODE_ID"),
    ]))


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
                    carrier=None, owner=None):
    """Advance at most one shared bounded discovery page."""
    if any(value is None for value in (repository, state, workspace, carrier)):
        configured = _scanner_dependencies()
        repository = configured[0] if repository is None else repository
        state = configured[1] if state is None else state
        workspace = configured[2] if workspace is None else workspace
        carrier = configured[3] if carrier is None else carrier
    owner = _notification_owner() if owner is None else owner
    return await NotificationDiscovery(
        repository, state, workspace, carrier,
        owner=owner).run_once()


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


def _secret(client):
    arn = _required("TINYP2P_NOTIFICATION_SECRET_ARN")
    version = _required("TINYP2P_NOTIFICATION_SECRET_VERSION_ID")
    response = client.get_secret_value(
        SecretId=arn, VersionId=version)
    if not isinstance(response, dict) \
            or response.get("ARN") != arn \
            or response.get("VersionId") != version:
        raise RuntimeError("notification secret binding")
    return decode_secret(response.get("SecretString"))


def _push_provider():
    import firebase_admin
    from firebase_admin import credentials
    import boto3

    secret, rows = _secret(
        boto3.client("secretsmanager", config=_sdk_config()))
    if push_node_id(secret) != _required(
            "TINYP2P_NOTIFICATION_PUSH_NODE_ID"):
        raise RuntimeError("notification push-node identity")
    configured, apps, created = [], {}, []
    try:
        for index, row in enumerate(rows):
            key = row["application"], row["environment"]
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


def _smoke_body(value):
    if not isinstance(value, str):
        raise ValueError("notification direct-smoke body")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("notification direct-smoke body") from error
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("notification direct-smoke body")
    return raw


async def direct_smoke(event, *, state=None, worker=None, workspace=None):
    """Attempt one hint directly and return only aggregate acceptance facts."""
    if not isinstance(event, dict) or set(event) != {"body", "schema"} \
            or event.get("schema") != DIRECT_SMOKE_SCHEMA:
        raise ValueError("notification direct-smoke invocation")
    if any(value is None for value in (state, worker, workspace)):
        configured = _delivery_dependencies()
        workspace = configured[0] if workspace is None else workspace
        state = configured[1] if state is None else state
        worker = configured[2] if worker is None else worker
    result = await process_carrier_delivery(
        CarrierDelivery(_smoke_body(event["body"]), "direct-smoke", 1),
        workspace,
        state,
        worker,
    )
    statuses = tuple(row.status for row in result.deliveries)
    retry_count = statuses.count("retry")
    terminal_count = sum(status in {
        "invalid-endpoint", "unregistered"} for status in statuses)
    if result.action is RETRY and retry_count == 0:
        retry_count = 1
    if result.action is TERMINAL:
        terminal_count += 1
    return {
        "accepted_count": statuses.count("accepted"),
        "retry_count": retry_count,
        "schema": DIRECT_SMOKE_RESULT_SCHEMA,
        "terminal_count": terminal_count,
    }


def delivery_handler(event, _context):
    """Handle SQS normally or an independently enabled direct launch test."""
    if isinstance(event, dict) and event.get("schema") == DIRECT_SMOKE_SCHEMA:
        if os.environ.get("TINYP2P_NOTIFICATION_DIRECT_SMOKE_ENABLED") \
                != "true":
            raise RuntimeError("notification direct smoke is disabled")
        return asyncio.run(direct_smoke(event))
    return asyncio.run(deliver_batch(event))


__all__ = (
    "deliver_batch",
    "delivery_handler",
    "direct_smoke",
    "scan_once",
    "scanner_handler",
)
