"""SQS preserves opaque hints and maps only retryable items to Lambda retry."""
import asyncio
import base64
import hashlib

import pytest

from adapters.aws.sqs import SqsCarrier, consume_sqs_batch, queue_binding
from notifications.carrier import ACK, RETRY, PublishOutcomeUnknown


ARN = "arn:aws:sqs:us-west-2:123456789012:poc16-notifications"
URL = (
    "https://sqs.us-west-2.amazonaws.com/"
    "123456789012/poc16-notifications"
)


class Sqs:
    def __init__(self):
        self.requests = []
        self.fail = None

    def send_message(self, **request):
        self.requests.append(request)
        if self.fail is not None:
            raise self.fail
        body = request["MessageBody"]
        return {
            "MD5OfMessageBody": hashlib.md5(
                body.encode("ascii"), usedforsecurity=False).hexdigest(),
            "MessageId": f"message-{len(self.requests)}",
        }


def record(message_id, body, *, attempt=1, arn=ARN):
    return {
        "attributes": {"ApproximateReceiveCount": str(attempt)},
        "body": base64.b64encode(body).decode("ascii"),
        "eventSource": "aws:sqs",
        "eventSourceARN": arn,
        "messageId": message_id,
    }


def test_queue_url_and_arn_are_one_exact_aws_identity():
    assert queue_binding(
        ARN, URL, region="us-west-2", account="123456789012"
    ) == ("aws", "us-west-2", "123456789012", "poc16-notifications")
    for arn, url in (
            (ARN.replace("123456789012", "999999999999"), URL),
            (ARN, URL.replace("us-west-2", "us-east-1")),
            (ARN, URL + "?redirect=yes"),
            (ARN, "http" + URL[5:])):
        with pytest.raises(ValueError, match="SQS queue"):
            queue_binding(arn, url)


def test_sqs_acceptance_round_trips_exact_opaque_bytes():
    client = Sqs()
    carrier = SqsCarrier(
        client, URL, ARN, region="us-west-2", account="123456789012")

    accepted = asyncio.run(carrier.publish(b"\x00canonical\xff"))

    assert accepted.message_id == "message-1"
    assert base64.b64decode(
        client.requests[0]["MessageBody"], validate=True
    ) == b"\x00canonical\xff"
    assert set(client.requests[0]) == {"QueueUrl", "MessageBody"}


def test_lost_send_response_keeps_discovery_side_retryable():
    client = Sqs()
    client.fail = TimeoutError("response lost after persistence")
    carrier = SqsCarrier(client, URL, ARN)

    with pytest.raises(PublishOutcomeUnknown):
        asyncio.run(carrier.publish(b"hint"))
    assert len(client.requests) == 1


def test_partial_batch_retries_only_explicit_retry_and_preserves_attempt():
    seen = []

    async def handle(delivery):
        seen.append((delivery.message_id, delivery.body, delivery.attempt))
        return RETRY if delivery.body == b"later" else ACK

    result = asyncio.run(consume_sqs_batch({"Records": [
        record("accepted", b"now", attempt=2),
        record("retry", b"later", attempt=4),
    ]}, handle, expected_queue_arn=ARN))

    assert seen == [
        ("accepted", b"now", 2),
        ("retry", b"later", 4),
    ]
    assert result == {
        "batchItemFailures": [{"itemIdentifier": "retry"}],
    }


def test_duplicate_delivery_is_safe_and_a_retry_wins_for_same_message_id():
    calls = 0

    async def handle(_delivery):
        nonlocal calls
        calls += 1
        return ACK if calls == 1 else RETRY

    result = asyncio.run(consume_sqs_batch({"Records": [
        record("duplicate", b"same"),
        record("duplicate", b"same", attempt=2),
    ]}, handle, expected_queue_arn=ARN))

    assert calls == 2
    assert result == {
        "batchItemFailures": [{"itemIdentifier": "duplicate"}],
    }


def test_handler_crash_and_malformed_item_are_routed_toward_dlq():
    async def crash(_delivery):
        raise RuntimeError("worker crashed")

    bad = record("bad-wire", b"ignored")
    bad["body"] = "***"
    result = asyncio.run(consume_sqs_batch({"Records": [
        record("crashed", b"valid"), bad,
    ]}, crash, expected_queue_arn=ARN))

    assert result == {"batchItemFailures": [
        {"itemIdentifier": "bad-wire"},
        {"itemIdentifier": "crashed"},
    ]}


def test_cross_queue_batch_cannot_reach_notification_worker():
    called = False

    async def handle(_delivery):
        nonlocal called
        called = True
        return ACK

    result = asyncio.run(consume_sqs_batch({"Records": [
        record("foreign", b"hint", arn=ARN.replace(
            "poc16-notifications", "other")),
    ]}, handle, expected_queue_arn=ARN))

    assert called is False
    assert result == {
        "batchItemFailures": [{"itemIdentifier": "foreign"}],
    }
