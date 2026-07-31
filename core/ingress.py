"""Exact internal-pile identity and typed input verdicts.

This module is vocabulary only.  ``RepositoryApplier`` is the sole component
that may create an internal generation, preserve rejection evidence, or retire
work.  Client-writable staging keys use a separate grammar and are never
retired under an internal receipt.
"""

from typing import NamedTuple

from .crypto import h
from .fact import canon
from .limits import (
    MAX_REJECTION_DIAGNOSTIC_BYTES,
    MAX_REJECTION_RECORD_BYTES,
    PayloadTooLarge,
    decode_json,
    valid_bounded_text,
)
from .shape import valid_fid

GENERATION_BYTES = 32
GENERATION_HEX_CHARS = 2 * GENERATION_BYTES


class PermanentIngressRejection(ValueError):
    """The exact ingress bytes can never pass the immutable input door."""


class InvalidPile(PermanentIngressRejection, PayloadTooLarge):
    """Pile bytes fail the bounded canonical ingress codec."""


class InvalidStagedIntent(PermanentIngressRejection):
    """A direct-upload key and pile bytes cannot describe one exact intent."""


class KernelRejected(PermanentIngressRejection):
    """Decoded facts fail the immutable database-free kernel."""


class IngressSource(NamedTuple):
    """Parsed identity of one never-reused internal pile generation."""

    member: str
    generation: str
    payload: str


def pile_source(member, raw, generation):
    """Bind exact pile bytes to one durable reservation identity."""
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


def check_source(source, raw=None):
    """Parse one internal key and optionally bind its exact bytes."""
    if raw is not None and not isinstance(raw, bytes):
        raise TypeError("exact ingress bytes required")
    parts = source.split("/") if isinstance(source, str) else ()
    if len(parts) != 4 \
            or parts[0] != "pile" \
            or not parts[1] \
            or parts[1] != parts[1].lower() \
            or len(parts[2]) != GENERATION_HEX_CHARS \
            or any(char not in "0123456789abcdef" for char in parts[2]) \
            or len(parts[3]) != 64 \
            or any(char not in "0123456789abcdef" for char in parts[3]) \
            or raw is not None and parts[3] != h(raw):
        raise ValueError("ingress source is not bound to exact bytes")
    return IngressSource(parts[1], parts[2], parts[3])


_REJECTION_TYPES = (InvalidPile, InvalidStagedIntent, KernelRejected)
_REJECTION_CLASSES = frozenset(
    rejection.__name__ for rejection in _REJECTION_TYPES)
_REJECTION_FIELDS = {
    "classification", "diagnostic", "generation", "kind",
    "payload", "pile", "source", "workspace",
}


def _bounded_diagnostic(error):
    encoded = str(error).encode("utf-8", errors="replace")
    if len(encoded) <= MAX_REJECTION_DIAGNOSTIC_BYTES:
        return encoded.decode("utf-8")
    return encoded[
        :MAX_REJECTION_DIAGNOSTIC_BYTES - 3
    ].decode("utf-8", errors="ignore") + "..."


def encode_rejection_record(error, workspace, source, raw):
    """Encode one exact, bounded verdict before any evidence is mutated."""
    if type(error) not in _REJECTION_TYPES or not valid_fid(workspace):
        raise TypeError("typed permanent ingress rejection required")
    binding = check_source(source, raw)
    record = canon({
        "classification": type(error).__name__,
        "diagnostic": _bounded_diagnostic(error),
        "generation": binding.generation,
        "kind": "permanent-rejection-v1",
        "payload": binding.payload,
        "pile": "failed/pile/" + binding.payload,
        "source": source,
        "workspace": workspace,
    })
    if len(record) > MAX_REJECTION_RECORD_BYTES:
        raise PayloadTooLarge("permanent rejection record too large")
    return record


def decode_rejection_record(
        raw, *, workspace=None, source=None, payload=None, generation=None):
    """Validate one permanent verdict and every exact retirement binding."""
    value = decode_json(
        raw, MAX_REJECTION_RECORD_BYTES, "permanent rejection record")
    if not isinstance(value, dict) or set(value) != _REJECTION_FIELDS \
            or canon(value) != raw \
            or not all(
                isinstance(value[field], str)
                for field in _REJECTION_FIELDS):
        raise ValueError("permanent rejection record")
    try:
        binding = check_source(value["source"])
    except ValueError as error:
        raise ValueError("permanent rejection record") from error
    expected = {
        "kind": "permanent-rejection-v1",
        "pile": "failed/pile/" + value["payload"],
    }
    expected.update(
        (name, candidate)
        for name, candidate in (
            ("workspace", workspace),
            ("source", source),
            ("payload", payload),
            ("generation", generation),
        )
        if candidate is not None
    )
    if value["classification"] not in _REJECTION_CLASSES \
            or not valid_bounded_text(
                value["diagnostic"],
                MAX_REJECTION_DIAGNOSTIC_BYTES,
                allow_empty=True,
            ) \
            or not all(map(valid_fid, (
                value["workspace"], value["payload"], value["generation"]))) \
            or binding.payload != value["payload"] \
            or binding.generation != value["generation"] \
            or any(value[name] != candidate
                   for name, candidate in expected.items()):
        raise ValueError("permanent rejection record")
    return value


__all__ = (
    "InvalidPile",
    "InvalidStagedIntent",
    "KernelRejected",
    "PermanentIngressRejection",
    "check_source",
    "decode_rejection_record",
    "encode_rejection_record",
    "pile_source",
)
