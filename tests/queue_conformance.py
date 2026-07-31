"""One behavioral schedule reusable by every managed queue adapter."""
from contextlib import contextmanager
from dataclasses import dataclass, field
import random
import time


@dataclass
class QueueConformanceRun:
    provider: str
    seed: int = 0xC0F01651
    history: list[str] = field(default_factory=list)
    message_bodies: dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self):
        self.random = random.Random(self.seed)

    def body(self, label):
        return f"{label}:{self.random.getrandbits(256):064x}".encode()

    def record(self, operation, result):
        self.history.append(f"{operation} -> {result}")

    def observe(self, message_id, body):
        incumbent = self.message_bodies.setdefault(message_id, body)
        assert incumbent == body, self.diagnostic()

    def diagnostic(self):
        history = "\n".join(
            f"  {index + 1}. {event}"
            for index, event in enumerate(self.history)
        ) or "  <empty>"
        return (
            "delivery queue conformance failure\n"
            f"provider={self.provider}\nseed={self.seed:#x}\n"
            f"history:\n{history}"
        )

    @contextmanager
    def capture(self):
        try:
            yield self
        except BaseException as error:
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note(self.diagnostic())
            raise


def _pull_until(
        queue, wanted, run, *, timeout_seconds, allowed_extras=None):
    allowed_extras = {} if allowed_extras is None else allowed_extras
    deadline = time.monotonic() + timeout_seconds
    found = {}
    while set(found) != set(wanted):
        if time.monotonic() >= deadline:
            raise AssertionError(run.diagnostic())
        deliveries = queue.pull(
            max_messages=min(10, max(1, len(wanted))), lease_seconds=60)
        if not deliveries:
            time.sleep(0.01)
            continue
        run.record("pull", tuple(item.message_id for item in deliveries))
        duplicates = []
        for item in deliveries:
            run.observe(item.message_id, item.body)
            if item.message_id not in wanted:
                queue.ack((item.lease,))
                if item.message_id in allowed_extras \
                        and item.body == allowed_extras[item.message_id]:
                    continue
                raise AssertionError(run.diagnostic())
            if item.message_id in found:
                assert found[item.message_id].body == item.body
                duplicates.append(item.lease)
            else:
                found[item.message_id] = item
        if duplicates:
            queue.ack(tuple(duplicates))
    return found


def exercise_delivery_queue(make_queue, run, *, timeout_seconds=10.0):
    """Prove publish, competing leases, ack, defer, and redelivery."""
    with run.capture():
        producer, consumer, rival = make_queue(), make_queue(), make_queue()
        assert consumer.pull(max_messages=1, lease_seconds=10) == ()

        bodies = (run.body("first"), run.body("second"))
        receipts = tuple(producer.publish(body) for body in bodies)
        assert receipts[0].message_id != receipts[1].message_id
        expected = {
            receipt.message_id: body
            for receipt, body in zip(receipts, bodies)
        }
        for message_id, body in expected.items():
            run.observe(message_id, body)
        received = _pull_until(
            consumer, expected, run, timeout_seconds=timeout_seconds)
        assert rival.pull(max_messages=1, lease_seconds=10) == ()

        consumer.ack((received[receipts[0].message_id].lease,))
        released = received[receipts[1].message_id]
        consumer.defer((released.lease,), delay_seconds=0)
        redelivered = _pull_until(
            rival,
            {receipts[1].message_id: bodies[1]},
            run,
            timeout_seconds=timeout_seconds,
            allowed_extras=expected,
        )[receipts[1].message_id]
        assert redelivered.lease != released.lease
        rival.ack((redelivered.lease,))

        duplicate_body = run.body("duplicate")
        duplicate_receipts = (
            producer.publish(duplicate_body),
            producer.publish(duplicate_body),
        )
        duplicate_ids = {
            receipt.message_id for receipt in duplicate_receipts}
        assert len(duplicate_ids) == 2
        duplicates = _pull_until(
            consumer,
            {message_id: duplicate_body for message_id in duplicate_ids},
            run,
            timeout_seconds=timeout_seconds,
            allowed_extras=expected,
        )
        consumer.ack(tuple(item.lease for item in duplicates.values()))
        return {
            "published": tuple(receipt.message_id for receipt in receipts),
            "redelivered": redelivered.message_id,
        }


__all__ = ("QueueConformanceRun", "exercise_delivery_queue")
