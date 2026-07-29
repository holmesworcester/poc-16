"""Canonical peer profiles carried by the authenticated mint grant.

The short strings are the complete wire vocabulary.  A mint response repeats
the profile embedded in its sealed, HMAC-protected bearer token; clients grant
push authority only when the two copies agree exactly.  Missing copies mean a
legacy full peer, while any present unknown or mismatched value is pull-only.
"""
import base64
import json


FULL = "sync-v1/full"
READ_ONLY = "sync-v1/read"
_KNOWN = frozenset((FULL, READ_ONLY))
_MISSING = object()
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
        return payload.get("cap", _MISSING)
    except (AttributeError, TypeError, ValueError):
        return _INVALID


def negotiate(token, mint_response):
    """Return the agreed profile, collapsing every bad signal to read-only."""
    embedded = _grant_profile(token)
    advertised = mint_response.get("cap", _MISSING) \
        if isinstance(mint_response, dict) else _INVALID
    if embedded is _MISSING and advertised is _MISSING:
        return None
    return embedded if embedded == advertised and known(embedded) else READ_ONLY


def allows_push(profile):
    return profile is None or profile == FULL
