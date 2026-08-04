"""Canonical peer profiles carried by the authenticated mint grant.

The short strings are the complete wire vocabulary. A mint response repeats
the profile embedded in its sealed, HMAC-protected bearer token; clients use
the grant only when the two copies agree exactly. Missing, unknown, or
mismatched profiles are invalid protocol, not compatibility signals.
"""
import base64
import json


FULL = "sync-v1/full"
OWNER = "sync-v1/owner"
READ_ONLY = "sync-v1/read"
_KNOWN = frozenset((FULL, OWNER, READ_ONLY))
_INVALID = object()


def known(profile):
    return isinstance(profile, str) and profile in _KNOWN


def _grant_profile(token):
    try:
        encoded, mac = token.split(".", 1)
        if not encoded or not mac:
            return _INVALID
        payload = json.loads(base64.urlsafe_b64decode(encoded))
        if not isinstance(payload, dict):
            return _INVALID
        return payload.get("cap", _INVALID)
    except (AttributeError, TypeError, ValueError):
        return _INVALID


def negotiate(token, mint_response):
    """Return the one exact profile authenticated and advertised by mint."""
    embedded = _grant_profile(token)
    advertised = mint_response.get("cap", _INVALID) \
        if isinstance(mint_response, dict) else _INVALID
    if embedded != advertised or not known(embedded):
        raise ValueError("peer capability negotiation")
    return embedded


def allows_push(profile):
    """Whether a peer accepts validate-first gossip for every writer."""
    return profile == FULL


def allows_object_put(profile):
    """Whether a peer accepts immutable bytes before a confined head write."""
    return profile in {FULL, OWNER}
