"""SQS translation for the provider-neutral notification carrier.

SQS carries only opaque bounded hint bytes.  A successful ``SendMessage`` is
carrier acceptance; a Lambda batch acknowledges every item except an explicit
``RETRY``.  Queue metadata never enters repository or notification authority.
"""
import base64
import binascii
import hashlib
import re
from urllib.parse import urlsplit

from notifications.carrier import (
    ACK,
    CarrierAccepted,
    CarrierDelivery,
    PublishOutcomeUnknown,
    checked_body,
    delivery_disposition,
)


MAX_SQS_BATCH = 10
MAX_QUEUE_ADDRESS_BYTES = 4_096
_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):sqs:"
    r"([a-z0-9-]+):([0-9]{12}):([A-Za-z0-9_-]{1,80})$")
_SUFFIX = {
    "aws": "amazonaws.com",
    "aws-us-gov": "amazonaws.com",
    "aws-cn": "amazonaws.com.cn",
}


def queue_binding(arn, url, *, region=None, account=None):
    """Validate that one queue ARN and URL name the exact same SQS queue."""
    match = _ARN.fullmatch(arn) if isinstance(arn, str) else None
    if match is None or not isinstance(url, str) \
            or len(url.encode("utf-8")) > MAX_QUEUE_ADDRESS_BYTES:
        raise ValueError("AWS SQS queue")
    partition, queue_region, queue_account, name = match.groups()
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise ValueError("AWS SQS queue") from error
    if parsed.scheme != "https" \
            or parsed.hostname != (
                f"sqs.{queue_region}.{_SUFFIX[partition]}") \
            or port is not None \
            or parsed.username is not None \
            or parsed.password is not None \
            or parsed.path != f"/{queue_account}/{name}" \
            or parsed.query or parsed.fragment \
            or region is not None and queue_region != region \
            or account is not None and queue_account != account:
        raise ValueError("AWS SQS queue")
    return partition, queue_region, queue_account, name


def _wire(body):
    return base64.b64encode(checked_body(body)).decode("ascii")


def _body(value):
    if not isinstance(value, str):
        raise ValueError("SQS notification body")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("SQS notification body") from error
    if _wire(raw) != value:
        raise ValueError("SQS notification body")
    return raw


class SqsCarrier:
    """Awaitable carrier backed by one exact standard SQS queue."""

    def __init__(self, client, queue_url, queue_arn, *, region=None,
                 account=None):
        if not callable(getattr(client, "send_message", None)):
            raise TypeError("SQS client")
        queue_binding(
            queue_arn, queue_url, region=region, account=account)
        self.client = client
        self.queue_url = queue_url

    async def publish(self, body):
        encoded = _wire(body)
        try:
            response = self.client.send_message(
                QueueUrl=self.queue_url,
                MessageBody=encoded,
            )
        except Exception as error:
            # SQS may have persisted the message before a response was lost.
            # The discovery cursor therefore must remain behind and retry.
            raise PublishOutcomeUnknown(
                "SQS notification acceptance is unknown") from error
        digest = hashlib.md5(
            encoded.encode("ascii"), usedforsecurity=False).hexdigest()
        if not isinstance(response, dict) \
                or response.get("MD5OfMessageBody") != digest:
            raise PublishOutcomeUnknown(
                "SQS did not confirm the exact notification body")
        try:
            return CarrierAccepted(response.get("MessageId"))
        except (TypeError, ValueError) as error:
            raise PublishOutcomeUnknown(
                "SQS returned no bounded notification message id") from error


def _message_id(record):
    value = record.get("messageId") if isinstance(record, dict) else None
    try:
        # Let CarrierDelivery enforce the shared provider-ID byte bound.
        CarrierDelivery(b"x", value, 1)
    except (TypeError, ValueError) as error:
        raise ValueError("SQS notification message id") from error
    return value


def _delivery(record, expected_queue_arn):
    message_id = _message_id(record)
    if record.get("eventSource") != "aws:sqs" \
            or expected_queue_arn is not None \
            and record.get("eventSourceARN") != expected_queue_arn:
        raise ValueError("SQS notification source")
    attributes = record.get("attributes")
    value = attributes.get("ApproximateReceiveCount") \
        if isinstance(attributes, dict) else None
    try:
        attempt = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("SQS notification receive count") from error
    if str(attempt) != value:
        raise ValueError("SQS notification receive count")
    return CarrierDelivery(_body(record.get("body")), message_id, attempt)


async def consume_sqs_batch(event, handler, *, expected_queue_arn=None):
    """Return AWS's partial-batch response for one bounded SQS invocation.

    A malformed item with a usable provider ID is retried into the configured
    DLQ.  If AWS does not supply such an ID, the invocation fails so Lambda
    retries the complete batch rather than accidentally acknowledging it.
    """
    records = event.get("Records") if isinstance(event, dict) else None
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_SQS_BATCH:
        raise ValueError("SQS notification batch")
    failures = set()
    for record in records:
        message_id = _message_id(record)
        try:
            delivery = _delivery(record, expected_queue_arn)
        except ValueError:
            failures.add(message_id)
            continue
        if await delivery_disposition(delivery, handler) is not ACK:
            failures.add(message_id)
    return {
        "batchItemFailures": [
            {"itemIdentifier": item} for item in sorted(failures)
        ],
    }


__all__ = (
    "MAX_SQS_BATCH",
    "SqsCarrier",
    "consume_sqs_batch",
    "queue_binding",
)
