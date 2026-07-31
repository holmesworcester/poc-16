"""Injected Google Pub/Sub conformance and fault translation."""
import pytest

from adapters.gcp import PubSubQueue, PubSubQueueConfig
from core.delivery_queue import (
    MAX_QUEUE_MESSAGE_BYTES,
    PublishOutcomeUnknown,
    QueueError,
    QueueProtocolError,
    RetryableQueueError,
)
from .queue_conformance import QueueConformanceRun, exercise_delivery_queue
from .queue_fakes import (
    FakePubSubMessage,
    FakePubSubService,
    FakePullResponse,
    FakeReceivedMessage,
)


def _config(**changes):
    values = {
        "project_id": "poc16-test",
        "topic_id": "poc16-push-delivery",
        "subscription_id": "poc16-push-worker",
        "publish_timeout": 7,
        "pull_timeout": 3,
        "rpc_timeout": 5,
    }
    values.update(changes)
    return PubSubQueueConfig(**values)


def _queue(service, config):
    producer, subscriber = service.clients()
    return PubSubQueue(
        config, producer=producer, subscriber=subscriber)


def test_injected_pubsub_runs_shared_conformance():
    config = _config()
    service = FakePubSubService(config)
    result = exercise_delivery_queue(
        lambda: _queue(service, config),
        QueueConformanceRun("fake-google-pubsub", seed=0x60061E),
    )
    assert result["redelivered"] in result["published"]
    operations = [
        event[0]
        for subscriber in service.subscribers
        for event in subscriber.history
    ]
    assert {"modify_ack_deadline", "acknowledge"} <= set(operations)


def test_pubsub_uses_exact_paths_timeouts_and_receipts():
    config = _config()
    service = FakePubSubService(config)
    producer, subscriber = service.clients()
    queue = PubSubQueue(
        config, producer=producer, subscriber=subscriber)

    receipt = queue.publish(b"resolved notification")
    delivery, = queue.pull(max_messages=1, lease_seconds=30)
    queue.defer((delivery.lease,), delay_seconds=10)
    queue.ack((delivery.lease,))

    assert producer.history == [(
        config.topic_path, b"resolved notification", {})]
    assert producer.last_future.timeouts == [7.0]
    assert delivery.message_id == receipt.message_id
    assert subscriber.history[0] == (
        "pull",
        {
            "subscription": config.subscription_path,
            "max_messages": 1,
        },
        3.0,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("project_id", "UPPERCASE"),
        ("project_id", "x"),
        ("topic_id", "googo-reserved"),
        ("topic_id", "has space"),
        ("subscription_id", "../escape"),
        ("publish_timeout", True),
        ("pull_timeout", 0),
        ("rpc_timeout", 301),
    ],
)
def test_config_rejects_ambiguous_resources(field, value):
    with pytest.raises(ValueError):
        _config(**{field: value})


def test_ambiguous_publish_is_explicit_and_retry_may_duplicate():
    config = _config()
    service = FakePubSubService(config)
    producer, subscriber = service.clients()
    queue = PubSubQueue(
        config, producer=producer, subscriber=subscriber)
    ServiceUnavailable = type("ServiceUnavailable", (Exception,), {})
    producer.result_error = ServiceUnavailable("response lost")

    with pytest.raises(PublishOutcomeUnknown):
        queue.publish(b"deterministic job")

    assert len(service.queue.records) == 1
    producer.result_error = None
    queue.publish(b"deterministic job")
    assert len(service.queue.records) == 2


def test_permanent_and_transient_errors_remain_distinct():
    config = _config()
    service = FakePubSubService(config)
    producer, subscriber = service.clients()
    queue = PubSubQueue(
        config, producer=producer, subscriber=subscriber)
    PermissionDenied = type("PermissionDenied", (Exception,), {})
    producer.call_error = PermissionDenied("secret detail")
    with pytest.raises(QueueError) as caught:
        queue.publish(b"job")
    assert type(caught.value) is QueueError
    assert "secret detail" not in str(caught.value)

    producer.call_error = None
    ResourceExhausted = type("ResourceExhausted", (Exception,), {})
    subscriber.pull_error = ResourceExhausted("quota")
    with pytest.raises(RetryableQueueError):
        queue.pull()


def test_provider_response_cardinality_and_body_are_hostile_boundaries():
    config = _config()
    service = FakePubSubService(config)
    producer, subscriber = service.clients()
    queue = PubSubQueue(
        config, producer=producer, subscriber=subscriber)
    subscriber.response_override = object()
    with pytest.raises(QueueProtocolError, match="sequence"):
        queue.pull()

    subscriber.response_override = FakePullResponse((
        FakeReceivedMessage(
            "ack",
            FakePubSubMessage(
                b"x" * (MAX_QUEUE_MESSAGE_BYTES + 1), "message"),
        ),
    ))
    with pytest.raises(QueueProtocolError, match="invalid delivery"):
        queue.pull()

    subscriber.response_override = FakePullResponse((
        FakeReceivedMessage("ack-1", FakePubSubMessage(b"a", "one")),
        FakeReceivedMessage("ack-2", FakePubSubMessage(b"b", "two")),
    ))
    with pytest.raises(QueueProtocolError, match="exceeded"):
        queue.pull(max_messages=1)
