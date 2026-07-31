"""Seal and open Firebase installation targets without exposing plaintext."""
from nacl.exceptions import CryptoError

from core.crypto import seal_to, unseal
from .provider import checked_target


class InvalidSealedTarget(ValueError):
    pass


def seal_target(push_node_public, target):
    target = checked_target(target)
    try:
        return seal_to(push_node_public, target.encode("ascii"))
    except (TypeError, ValueError) as error:
        raise ValueError("push node public key") from error


def open_target(push_node_secret, sealed):
    if not isinstance(sealed, bytes):
        raise TypeError("sealed FCM target")
    try:
        raw = unseal(push_node_secret, sealed)
        value = raw.decode("ascii")
        return checked_target(value)
    except (CryptoError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidSealedTarget("invalid sealed FCM target") from error


__all__ = ("InvalidSealedTarget", "open_target", "seal_target")
