"""Typed permanent-rejection vocabulary for one ingress unit.

Only these input-local verdicts may justify destructive quarantine. Provider,
publication, root, CAS, and programming failures deliberately do not inherit
from this type: their exact source pile remains retryable.
"""
from .limits import PayloadTooLarge


class PermanentIngressRejection(ValueError):
    """The exact ingress bytes can never pass the immutable input door."""


class InvalidPile(PermanentIngressRejection, PayloadTooLarge):
    """Pile bytes fail the bounded canonical ingress codec."""


class InvalidStagedIntent(PermanentIngressRejection):
    """A direct-upload key and pile bytes cannot describe one exact intent."""


class KernelRejected(PermanentIngressRejection):
    """Decoded facts fail the immutable database-free kernel."""


__all__ = (
    "InvalidPile",
    "InvalidStagedIntent",
    "KernelRejected",
    "PermanentIngressRejection",
)
