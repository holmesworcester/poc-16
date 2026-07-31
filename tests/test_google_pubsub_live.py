"""Official Pub/Sub emulator and explicit live conformance entrypoints."""
from contextlib import contextmanager
import os
import re
import secrets

import pytest

from adapters.gcp import PubSubQueue, PubSubQueueConfig
from .queue_conformance import QueueConformanceRun, exercise_delivery_queue


_RUN_ID_RE = re.compile(r"^poc16-conformance-[0-9a-f]{32}$")


def _sdk():
    try:
        from google.cloud import pubsub_v1
    except ImportError:
        pytest.skip("google-cloud-pubsub is required")
    return pubsub_v1


@contextmanager
def _isolated_queue(project_id):
    pubsub = _sdk()
    resource = "poc16-conformance-" + secrets.token_hex(16)
    if _RUN_ID_RE.fullmatch(resource) is None:
        raise AssertionError("unsafe Pub/Sub conformance resource id")
    config = PubSubQueueConfig(project_id, resource, resource)
    producer = pubsub.PublisherClient()
    subscriber = pubsub.SubscriberClient()
    queues, cleanup_errors = [], []
    try:
        producer.create_topic(
            request={"name": config.topic_path}, timeout=30)
        subscriber.create_subscription(
            request={
                "name": config.subscription_path,
                "topic": config.topic_path,
                "ack_deadline_seconds": 10,
            },
            timeout=30,
        )

        def make_queue():
            queue = PubSubQueue(config)
            queues.append(queue)
            return queue

        yield make_queue, resource
    finally:
        for queue in queues:
            try:
                queue.close()
            except Exception as error:
                cleanup_errors.append(error)
        for operation, request in (
            (
                subscriber.delete_subscription,
                {"subscription": config.subscription_path},
            ),
            (producer.delete_topic, {"topic": config.topic_path}),
        ):
            try:
                operation(request=request, timeout=30)
            except Exception as error:
                if type(error).__name__ != "NotFound":
                    cleanup_errors.append(error)
        for client in (subscriber, producer):
            close = getattr(client, "close", None)
            if callable(close):
                close()
        if cleanup_errors:
            raise RuntimeError(
                "Pub/Sub conformance cleanup failed") from cleanup_errors[0]


@pytest.mark.emulator
def test_official_pubsub_emulator_runs_shared_queue_conformance():
    if not os.environ.get("PUBSUB_EMULATOR_HOST"):
        pytest.skip("set PUBSUB_EMULATOR_HOST for emulator evidence")
    project = os.environ.get(
        "POC16_PUBSUB_EMULATOR_PROJECT", "poc16-emulator")
    with _isolated_queue(project) as (make_queue, resource):
        exercise_delivery_queue(
            make_queue,
            QueueConformanceRun(
                f"google-pubsub-emulator:{resource}", seed=0xE111),
            timeout_seconds=30,
        )


@pytest.mark.live
@pytest.mark.live_pubsub
def test_live_google_pubsub_runs_shared_queue_conformance():
    if os.environ.get("POC16_LIVE_PUBSUB") != "1":
        pytest.skip("set POC16_LIVE_PUBSUB=1 for live evidence")
    project = os.environ.get("POC16_GCP_PROJECT")
    if not project:
        pytest.skip("set POC16_GCP_PROJECT for live evidence")
    if os.environ.get("PUBSUB_EMULATOR_HOST"):
        pytest.fail("emulator wiring is not live evidence")
    try:
        import google.auth
        from google.auth.exceptions import DefaultCredentialsError
        google.auth.default()
    except ImportError:
        pytest.skip("google-cloud-pubsub is required")
    except DefaultCredentialsError:
        pytest.skip("Google Application Default Credentials are absent")
    with _isolated_queue(project) as (make_queue, resource):
        exercise_delivery_queue(
            make_queue,
            QueueConformanceRun(
                f"live-google-pubsub:{resource}", seed=0x11AE),
            timeout_seconds=60,
        )
