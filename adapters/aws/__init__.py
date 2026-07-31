"""Amazon Web Services adapters outside repository authority."""

from .sqs import (
    SqsCarrier,
    consume_sqs_batch,
    queue_binding,
)

__all__ = ("SqsCarrier", "consume_sqs_batch", "queue_binding")
