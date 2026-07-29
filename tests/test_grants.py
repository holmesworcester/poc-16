"""Transport-independent bearer grant contracts."""
import base64
import json

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
