"""Shared member/device identity claim for ephemeral gate families."""

from typing import NamedTuple

import facts

from core.limits import MAX_REMOVAL_PATH_SCOPES, PayloadTooLarge
from .._identity import actor_needs


class IdentityClaim(NamedTuple):
    device: str
    owner: str
    providers: tuple
    scopes: tuple[str, ...]


def needs(fact):
    body = fact.body
    device = body.get("device", "")
    owner = body.get("owner", "")
    return actor_needs(fact, device, owner)


def claim(valid, stream, writer):
    """Bind the outer writer to one direct member and optional owned device."""
    body = valid.fact.body
    device, owner = body.get("device"), body.get("owner")
    if writer != device:
        return None
    expected = {"author", "member"}
    if device != owner:
        expected.add("device")
    edges = {edge.role: edge.fid for edge in valid.edges}
    if set(edges) != expected:
        return None
    supplied = {fact.fid: fact for fact in stream}
    member = supplied.get(edges["member"])
    if member is None or ("member", owner, owner) not in member.offers():
        return None
    providers = [member]
    if device != owner:
        linked = supplied.get(edges["device"])
        if linked is None or (
                "device_key", device, owner) not in linked.offers():
            return None
        providers.append(linked)
    scopes = tuple(sorted({
        sid for provider in providers
        for sid in facts.current_scopes(provider)
    }))
    if len(scopes) > MAX_REMOVAL_PATH_SCOPES:
        raise PayloadTooLarge("identity has too many removal scopes")
    return IdentityClaim(device, owner, tuple(providers), scopes)
