"""Shared fact-level device-to-member authorship requirements."""

from core.fact import Need


def actor_needs(fact, device, owner, *, require_device=False):
    """Require an exact author, direct member, and optional owned device."""
    needs = (
        Need("author", "author", fact.fid, device),
        Need("member", "member", owner, owner),
    )
    if require_device or device != owner:
        needs += (Need("device", "device_key", device, owner),)
    return needs


__all__ = ("actor_needs",)
