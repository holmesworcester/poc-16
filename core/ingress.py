"""The two exact authority doors for destructive ingress retirement.

Accepted bytes require a typed exact-root publication receipt. Permanently
rejected bytes require exact durable payload and metadata evidence. Provider,
publication, root, CAS, and programming failures grant neither authority, so
their exact source pile remains retryable.
"""
import secrets
from typing import NamedTuple

from .crypto import h
from .fact import canon
from .limits import PayloadTooLarge
from .object_store import (
    CREATED,
    EXISTS,
    OutcomeUnknown,
    retire_exact,
)

GENERATION_BYTES = 16
GENERATION_HEX_CHARS = 2 * GENERATION_BYTES


class PermanentIngressRejection(ValueError):
    """The exact ingress bytes can never pass the immutable input door."""


class InvalidPile(PermanentIngressRejection, PayloadTooLarge):
    """Pile bytes fail the bounded canonical ingress codec."""


class InvalidStagedIntent(PermanentIngressRejection):
    """A direct-upload key and pile bytes cannot describe one exact intent."""


class KernelRejected(PermanentIngressRejection):
    """Decoded facts fail the immutable database-free kernel."""


class RejectionReceipt(NamedTuple):
    """Exact durable quarantine evidence for one hash-bound source value."""

    source: str
    payload: str
    record: bytes
    generation: str


class IngressSource(NamedTuple):
    """Parsed identity of one never-reused ingress object generation."""

    member: str
    generation: str
    payload: str


def pile_source(member, raw, generation):
    """Name exact bytes under one caller-proven fresh generation.

    Only trusted host/worker code may call this constructor. Direct uploaders
    can address their separate session-scoped staging namespace, never this
    canonical work queue. Host/peer ingress must call :func:`stage_pile`,
    which mints its generation internally.
    """
    if not isinstance(raw, bytes):
        raise TypeError("exact ingress bytes required")
    if not isinstance(member, str) or not member \
            or "/" in member or member != member.lower():
        raise ValueError("ingress member")
    if not isinstance(generation, str) \
            or len(generation) != GENERATION_HEX_CHARS \
            or any(char not in "0123456789abcdef" for char in generation):
        raise ValueError("ingress generation")
    return f"pile/{member}/{generation}/{h(raw)}"


def stage_pile(store, member, raw):
    """Create one immediate, internally generated host/peer ingress value."""
    unknown = None
    for _ in range(2):
        source = pile_source(
            member, raw, secrets.token_hex(GENERATION_BYTES))
        try:
            result = store.put_if_absent(source, raw)
        except OutcomeUnknown as error:
            unknown = error
            if store.get(source) == raw:
                return source
            continue
        if result is CREATED:
            return source
        if result is not EXISTS:
            raise TypeError("conditional-create result")
        # A collision never authorizes reuse of an old generation, even when
        # its bytes happen to be identical.
    if unknown is not None:
        raise unknown
    raise OSError("could not mint a fresh ingress generation")


def check_source(source, raw):
    """Parse a full generation key and bind it to these exact bytes."""
    if not isinstance(raw, bytes):
        raise TypeError("exact ingress bytes required")
    parts = source.split("/") if isinstance(source, str) else ()
    if len(parts) != 4 \
            or parts[0] != "pile" \
            or not parts[1] \
            or parts[1] != parts[1].lower() \
            or len(parts[2]) != GENERATION_HEX_CHARS \
            or any(char not in "0123456789abcdef" for char in parts[2]) \
            or parts[3] != h(raw):
        raise ValueError("ingress source is not bound to exact bytes")
    return IngressSource(parts[1], parts[2], parts[3])


def _rejection_record(source, raw, error):
    if not isinstance(error, PermanentIngressRejection):
        raise TypeError("typed permanent ingress rejection required")
    return canon({
        "error": f"{type(error).__name__}: {error}",
        "id": h(raw),
        "source": source,
    })


def _retire_published(
        store, workspace, source, raw, receipt, issuer):
    """Retire accepted bytes only under their exact committed-root result."""
    from .publication import PublicationReceipt

    binding = check_source(source, raw)
    if not isinstance(receipt, PublicationReceipt) \
            or receipt.issuer is not issuer \
            or receipt.workspace != workspace \
            or receipt.source != source \
            or receipt.payload != h(raw) \
            or receipt.generation != binding.generation \
            or receipt.outcome not in {"applied", "confirmed", "noop"} \
            or not isinstance(receipt.root, bytes):
        raise ValueError("published ingress receipt")
    return retire_exact(store, source, raw)


def preserve_rejection(store, source, raw, error):
    """Preserve exact permanent-rejection evidence before retirement."""
    binding = check_source(source, raw)
    failure_id = h(raw)
    payload_key = "failed/pile/" + failure_id
    store.put_if_absent(payload_key, raw)
    if store.get(payload_key) != raw:
        raise OSError("rejection payload was not preserved exactly")
    record = _rejection_record(source, raw, error)
    meta_key = "failed/meta/" + h(record)
    store.put_if_absent(meta_key, record)
    if store.get(meta_key) != record:
        raise OSError("rejection metadata was not preserved exactly")
    return RejectionReceipt(
        source,
        failure_id,
        record,
        binding.generation,
    )


def retire_rejected(store, source, raw, receipt):
    """Retire rejected bytes only under their exact durable evidence token."""
    binding = check_source(source, raw)
    if not isinstance(receipt, RejectionReceipt) \
            or receipt.source != source \
            or receipt.payload != h(raw) \
            or receipt.generation != binding.generation \
            or store.get("failed/pile/" + receipt.payload) != raw \
            or store.get("failed/meta/" + h(receipt.record)) \
            != receipt.record:
        raise ValueError("durable rejection witness")
    return retire_exact(store, source, raw)

__all__ = (
    "InvalidPile",
    "InvalidStagedIntent",
    "KernelRejected",
    "PermanentIngressRejection",
    "RejectionReceipt",
    "check_source",
    "pile_source",
    "preserve_rejection",
    "retire_rejected",
    "stage_pile",
)
