"""Exact internal-pile identity and typed input verdicts.

This module is vocabulary only.  ``RepositoryApplier`` is the sole component
that may create an internal generation, preserve rejection evidence, or retire
work.  Client-writable staging keys use a separate grammar and are never
retired under an internal receipt.
"""

from typing import NamedTuple

from .crypto import h
from .limits import PayloadTooLarge

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


__all__ = (
    "InvalidPile",
    "InvalidStagedIntent",
    "KernelRejected",
    "PermanentIngressRejection",
    "check_source",
    "pile_source",
)
