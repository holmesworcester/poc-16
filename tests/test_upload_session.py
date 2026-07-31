"""Exact-pile lease codec tests."""
from dataclasses import replace
import base64

import pytest

from deploy.upload_session import (
    InvalidUploadSession,
    MAX_SESSION_TTL_MS,
    SessionKey,
    SessionState,
    SessionTokenCodec,
    UploadLeaf,
    UploadSessionPolicy,
)


NOW = 1_900_000_000_000
WORKSPACE = "a" * 64
MEMBER = "b" * 16
SESSION = "c" * 32
PILE = UploadLeaf("d" * 64, 1234)
KEY = SessionKey(
    "active01", b"k" * 32, NOW - 10_000, NOW + MAX_SESSION_TTL_MS + 10_000)
POLICY = UploadSessionPolicy(
    "test-upload", KEY.key_id, (KEY,), ttl_ms=60_000,
    max_ttl_ms=120_000, clock_skew_ms=1_000)


def state(**changes):
    value = SessionState(
        WORKSPACE, MEMBER, SESSION, PILE, NOW, NOW + 60_000, KEY.key_id)
    return replace(value, **changes)


def test_cursor_round_trip_binds_one_exact_pile_and_provider():
    codec = SessionTokenCodec(POLICY, "fake-s3:bucket")
    token = codec.encode(state())
    assert codec.decode(token, NOW + 1) == state()

    for foreign in (
            SessionTokenCodec(POLICY, "fake-s3:other"),
            SessionTokenCodec(replace(POLICY, issuer="other"), "fake-s3:bucket")):
        with pytest.raises(InvalidUploadSession):
            foreign.decode(token, NOW + 1)


def test_cursor_tampering_and_noncanonical_base64_fail_closed():
    codec = SessionTokenCodec(POLICY, "fake-s3:bucket")
    token = codec.encode(state())
    midpoint = len(token) // 2
    replacement = "A" if token[midpoint] != "A" else "B"
    with pytest.raises(InvalidUploadSession):
        codec.decode(token[:midpoint] + replacement + token[midpoint + 1:], NOW)
    with pytest.raises(InvalidUploadSession):
        codec.decode(token + "=", NOW)

    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    # A valid alphabet and length do not help a token with a forged MAC.
    forged = base64.urlsafe_b64encode(raw[:-1] + bytes([raw[-1] ^ 1])) \
        .rstrip(b"=").decode()
    with pytest.raises(InvalidUploadSession):
        codec.decode(forged, NOW)


def test_cursor_has_one_fixed_time_window():
    codec = SessionTokenCodec(POLICY, "fake-s3:bucket")
    token = codec.encode(state())
    with pytest.raises(InvalidUploadSession):
        codec.decode(token, NOW - 1)
    with pytest.raises(InvalidUploadSession):
        codec.decode(token, NOW + 60_000)

    with pytest.raises(InvalidUploadSession):
        codec.encode(state(expires_at_ms=NOW + POLICY.max_ttl_ms + 1))
    with pytest.raises(InvalidUploadSession):
        codec.encode(state(issued_at_ms=NOW + 60_000))


def test_key_rotation_verifies_old_lease_but_cannot_extend_it():
    old = SessionKey(
        "oldkey01", b"o" * 32, NOW - 20_000, NOW + 100_000)
    new = SessionKey(
        "newkey01", b"n" * 32, NOW, NOW + 200_000)
    policy = UploadSessionPolicy(
        "test-upload", new.key_id, (old, new), ttl_ms=50_000,
        max_ttl_ms=60_000, clock_skew_ms=1_000)
    codec = SessionTokenCodec(policy, "fake-r2:bucket")
    old_state = replace(
        state(), key_id=old.key_id, issued_at_ms=NOW - 10_000,
        expires_at_ms=NOW + 40_000)
    token = codec.encode(old_state)
    assert codec.decode(token, NOW) == old_state

    retired = replace(policy, keys=(new,))
    with pytest.raises(InvalidUploadSession):
        SessionTokenCodec(retired, "fake-r2:bucket").decode(token, NOW)


@pytest.mark.parametrize("change", [
    {"workspace": "x"},
    {"member": "B" * 16},
    {"session": "0" * 31},
    {"key_id": "missing1"},
])
def test_state_shape_is_exact(change):
    codec = SessionTokenCodec(POLICY, "fake-s3:bucket")
    with pytest.raises(InvalidUploadSession):
        codec.encode(state(**change))


@pytest.mark.parametrize("digest,size", [
    ("d" * 63, 1),
    ("d" * 64, -1),
])
def test_pile_identity_is_intrinsically_valid(digest, size):
    with pytest.raises(ValueError, match="upload pile"):
        UploadLeaf(digest, size)
