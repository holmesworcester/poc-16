"""Provider-neutral queue value and reference-service tests."""
import pytest

from core.delivery_queue import (
    MAX_LEASE_BATCH,
    MAX_QUEUE_MESSAGE_BYTES,
    LeasedMessage,
    Published,
    QueueLease,
    validate_defer_seconds,
    validate_leases,
    validate_message_body,
    validate_pull,
)
from .queue_conformance import QueueConformanceRun, exercise_delivery_queue
from .queue_fakes import MemoryQueueService


def test_memory_queue_runs_shared_conformance():
    service = MemoryQueueService()
    result = exercise_delivery_queue(
        service.handle, QueueConformanceRun("memory", seed=0x5151))
    assert result["redelivered"] in result["published"]


@pytest.mark.parametrize("value", [None, "", " ", "\n", "snowman-☃"])
def test_opaque_receipt_values_fail_closed(value):
    with pytest.raises((TypeError, ValueError)):
        Published(value)
    with pytest.raises((TypeError, ValueError)):
        QueueLease("binding", value)


def test_queue_message_and_operation_bounds():
    assert validate_message_body(b"x" * MAX_QUEUE_MESSAGE_BYTES)
    with pytest.raises(ValueError):
        validate_message_body(b"")
    with pytest.raises(ValueError):
        validate_message_body(b"x" * (MAX_QUEUE_MESSAGE_BYTES + 1))
    with pytest.raises(TypeError):
        validate_message_body("bytes required")
    for values in ((0, 60), (11, 60), (1, 9), (1, 601)):
        with pytest.raises(ValueError):
            validate_pull(*values)
    for delay in (-1, 1, 9, 601):
        with pytest.raises(ValueError):
            validate_defer_seconds(delay)


def test_leases_are_bound_bounded_and_duplicate_free():
    leases = tuple(
        QueueLease("binding", f"token-{index}")
        for index in range(MAX_LEASE_BATCH)
    )
    assert validate_leases(leases, "binding") == leases
    with pytest.raises(ValueError, match="batch"):
        validate_leases(
            leases + (QueueLease("binding", "extra"),), "binding")
    with pytest.raises(ValueError, match="duplicate"):
        validate_leases((leases[0], leases[0]), "binding")
    with pytest.raises(ValueError, match="binding"):
        validate_leases((QueueLease("other", "token"),), "binding")


def test_delivery_attempt_is_positive_or_unknown():
    lease = QueueLease("binding", "token")
    for attempt in (False, 0, -1):
        with pytest.raises(ValueError):
            LeasedMessage(b"body", "message", lease, attempt)
    assert LeasedMessage(b"body", "message", lease, 1).delivery_attempt == 1
