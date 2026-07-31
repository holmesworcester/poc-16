"""Exact retained-pile address and typed input verdicts."""
from dataclasses import dataclass

from .crypto import h
from .limits import PayloadTooLarge
from .shape import valid_fid

INGRESS_PREFIX = "ingress/v1"
SESSION_HEX_CHARS = 32
MEMBER_HEX_CHARS = 64


class PermanentIngressRejection(ValueError):
    """The exact ingress bytes can never pass the immutable input door."""


class InvalidPile(PermanentIngressRejection, PayloadTooLarge):
    """Pile bytes fail the bounded canonical ingress codec."""


class InvalidIngressAddress(PermanentIngressRejection):
    """A caller-supplied source key is not one canonical exact address."""


class KernelRejected(PermanentIngressRejection):
    """Decoded facts fail the immutable database-free kernel."""


@dataclass(frozen=True, slots=True)
class IngressAddress:
    """One strictly parsed pile address in isolated untrusted ingress."""

    workspace: str
    session: str
    member: str
    digest: str


def _lower_hex(value, length):
    return isinstance(value, str) \
        and len(value) == length \
        and all(character in "0123456789abcdef" for character in value)


def ingress_key(workspace, session, member, digest):
    """Build the sole provider-independent exact-pile address."""
    if not valid_fid(workspace) \
            or not _lower_hex(session, SESSION_HEX_CHARS) \
            or not _lower_hex(member, MEMBER_HEX_CHARS) \
            or not valid_fid(digest):
        raise ValueError("ingress key component")
    return (
        f"{INGRESS_PREFIX}/workspaces/{workspace}/piles/"
        f"{session}/{member}/{digest}"
    )


MAX_INGRESS_KEY_BYTES = len(ingress_key(
    "0" * 64,
    "0" * SESSION_HEX_CHARS,
    "0" * MEMBER_HEX_CHARS,
    "0" * 64,
).encode("ascii"))


def ingress_prefix(workspace):
    if not valid_fid(workspace):
        raise ValueError("ingress workspace")
    return f"{INGRESS_PREFIX}/workspaces/{workspace}/piles/"


def parse_ingress_key(key):
    """Parse one exact pile key; paths are never normalized."""
    parts = key.split("/") if isinstance(key, str) else ()
    if len(parts) != 8 or parts[:3] != [
            "ingress", "v1", "workspaces"] or parts[4] != "piles":
        raise InvalidIngressAddress("ingress key")
    address = IngressAddress(parts[3], parts[5], parts[6], parts[7])
    try:
        canonical = ingress_key(
            address.workspace, address.session,
            address.member, address.digest)
    except ValueError as error:
        raise InvalidIngressAddress("ingress key") from error
    if canonical != key:
        raise InvalidIngressAddress("ingress key")
    return address


__all__ = (
    "InvalidPile",
    "InvalidIngressAddress",
    "IngressAddress",
    "KernelRejected",
    "MAX_INGRESS_KEY_BYTES",
    "MEMBER_HEX_CHARS",
    "PermanentIngressRejection",
    "SESSION_HEX_CHARS",
    "INGRESS_PREFIX",
    "ingress_key",
    "ingress_prefix",
    "parse_ingress_key",
)
