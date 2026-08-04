"""Transport-independent bearer grant contracts."""
import base64
import hashlib
import hmac
import json

import pytest

from core import peer_capability
from core.grants import check_token, make_token


def test_grant_round_trip_and_expiry_are_driven_by_trusted_time():
    secret = b"s" * 32
    token = make_token(
        secret, "member", "workspace", issued_at=100, ttl_ms=50)

    assert check_token(
        secret, "Bearer " + token, "workspace", trusted_now=149
    ) == "member"
    assert check_token(
        secret, "Bearer " + token, "workspace",
        trusted_now=149, require_push=True
    ) == "member"
    assert check_token(
        secret, "Bearer " + token, "workspace", trusted_now=150
    ) is None
    assert check_token(
        secret, "Bearer " + token, "other", trusted_now=149
    ) is None


def test_read_only_grant_cannot_authorize_push():
    token = make_token(
        b"s" * 32, "member", "workspace",
        capability=peer_capability.READ_ONLY,
        issued_at=100, ttl_ms=50)

    assert check_token(
        b"s" * 32, "Bearer " + token, "workspace",
        trusted_now=101) == "member"
    assert check_token(
        b"s" * 32, "Bearer " + token, "workspace",
        trusted_now=101, require_push=True) is None


def test_owner_grant_can_establish_objects_but_cannot_gossip_slots():
    token = make_token(
        b"s" * 32,
        "member",
        "workspace",
        capability=peer_capability.OWNER,
        issued_at=100,
        ttl_ms=50,
    )
    authorization = "Bearer " + token

    assert check_token(
        b"s" * 32,
        authorization,
        "workspace",
        trusted_now=101,
        require_object_put=True,
    ) == "member"
    assert check_token(
        b"s" * 32,
        authorization,
        "workspace",
        trusted_now=101,
        require_push=True,
    ) is None


def test_grant_rejects_wrong_scheme_mac_and_shape():
    secret = b"k" * 32
    token = make_token(secret, "m", "w", issued_at=1, ttl_ms=100)
    body, mac = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body))
    payload["m"] = "attacker"
    forged = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True).encode()).decode() + "." + mac

    assert check_token(
        secret, "Basic " + token, "w", trusted_now=2) is None
    assert check_token(
        secret, "Bearer " + forged, "w", trusted_now=2) is None
    assert check_token(secret, "Bearer broken", "w", trusted_now=2) is None


def test_capability_is_required_hmac_bound_and_exactly_negotiated():
    secret = b"capability-authentication-secret"
    workspace = "a" * 64
    token = make_token(
        secret, "member", workspace,
        capability=peer_capability.READ_ONLY,
        issued_at=100,
    )
    encoded, mac = token.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(encoded))
    assert payload["cap"] == peer_capability.READ_ONLY
    assert peer_capability.negotiate(token, {
        "cap": peer_capability.READ_ONLY,
    }) == peer_capability.READ_ONLY

    payload["cap"] = peer_capability.FULL
    changed = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True).encode()).decode()
    assert check_token(
        secret, f"Bearer {changed}.{mac}", workspace,
        trusted_now=101) is None

    for invalid in (None, "sync-v2/full"):
        with pytest.raises(ValueError, match="capability"):
            make_token(
                secret, "member", workspace,
                capability=invalid, issued_at=100)

    payload.pop("cap")
    raw = json.dumps(payload, sort_keys=True).encode()
    missing = base64.urlsafe_b64encode(raw).decode() + "." + hmac.new(
        secret, raw, hashlib.sha256).hexdigest()
    assert check_token(
        secret, "Bearer " + missing, workspace,
        trusted_now=101) is None
    for advertised in ({}, {"cap": peer_capability.FULL}):
        with pytest.raises(ValueError, match="negotiation"):
            peer_capability.negotiate(missing, advertised)

    with pytest.raises(ValueError, match="negotiation"):
        peer_capability.negotiate(token, {
            "cap": peer_capability.FULL,
        })
