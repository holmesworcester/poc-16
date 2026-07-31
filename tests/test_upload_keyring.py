"""Durable upload-session key-ring and rotation tests."""
from dataclasses import replace
import json

import pytest

from deploy.upload_keyring import (
    InvalidUploadKeyring,
    MAX_KEYRING_BYTES,
    MAX_SESSION_KEYS,
    UploadKeyring,
    activate_key,
    decode_keyring,
    distribute_key,
    encode_keyring,
    retire_key,
)
from deploy.upload_session import (
    InvalidUploadSession,
    MAX_SESSION_BYTES,
    SessionKey,
    SessionState,
    SessionTokenCodec,
    UploadLeaf,
    UploadSessionPolicy,
)


NOW = 4_000_000
TTL = 120_000
SKEW = 5_000
PROVIDER = "aws-s3-v1:us-west-2:ingress:123456789012"
OTHER_PROVIDER = "cloudflare-r2-v1:account:default:ingress:parent"
OLD = SessionKey(
    "oldkey01",
    b"o" * 32,
    0,
    NOW + TTL + SKEW,
)
NEW = SessionKey(
    "newkey02",
    b"n" * 32,
    NOW + 1_000,
    NOW + 10 * TTL,
)


def policy(*, keys=(OLD,), active="oldkey01", ttl=TTL):
    return UploadSessionPolicy(
        "aws-upload-broker-production",
        active,
        keys,
        ttl_ms=ttl,
        max_ttl_ms=4 * TTL,
        clock_skew_ms=SKEW,
        max_bytes=MAX_SESSION_BYTES,
    )


def keyring(*, provider=PROVIDER, **policy_options):
    return UploadKeyring(provider, policy(**policy_options))


def state(key_id="oldkey01", *, expires_at=NOW + TTL):
    return SessionState(
        "a" * 64,
        "b" * 64,
        "c" * 32,
        UploadLeaf("e" * 64, 7),
        NOW,
        expires_at,
        key_id,
    )


def document(value):
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def test_keyring_round_trip_is_canonical_bounded_and_redacted():
    original = keyring(keys=(NEW, OLD))

    raw = encode_keyring(original)
    loaded = decode_keyring(raw)

    assert encode_keyring(loaded) == raw
    assert loaded.provider_binding == PROVIDER
    assert loaded.policy.max_bytes == MAX_SESSION_BYTES
    assert tuple(key.key_id for key in loaded.policy.keys) == (
        "newkey02", "oldkey01")
    assert len(raw) < MAX_KEYRING_BYTES
    assert b"o" * 32 not in raw
    assert b"n" * 32 not in raw
    assert "oooooooo" not in repr(loaded)
    assert "nnnnnnnn" not in repr(loaded)


def test_keyring_rejects_ambiguous_noncanonical_and_hostile_documents():
    raw = encode_keyring(keyring())
    value = json.loads(raw)
    cases = [
        b"",
        b"x" * (MAX_KEYRING_BYTES + 1),
        raw + b"\n",
        raw.replace(
            b'"issuer":"aws-upload-broker-production"',
            b'"issuer":"aws-upload-broker-production",'
            b'"issuer":"duplicate"',
        ),
        document({**value, "surplus": True}),
        document({**value, "keys": []}),
        document({
            **value,
            "keys": [{**value["keys"][0], "surplus": True}],
        }),
        document({
            **value,
            "keys": [{**value["keys"][0], "secret": "***"}],
        }),
        document({
            **value,
            "keys": list(reversed(value["keys"])),
        }).replace(b"oldkey01", b"oldkey00", 1),
    ]
    for candidate in cases:
        with pytest.raises(InvalidUploadKeyring):
            decode_keyring(candidate)
    with pytest.raises(InvalidUploadKeyring):
        decode_keyring("not bytes")


def test_rotation_survives_cold_instances_and_default_ttl_change():
    first_keyring = decode_keyring(encode_keyring(keyring()))
    first_policy = first_keyring.policy
    first = SessionTokenCodec(first_policy, PROVIDER)
    old_cursor = first.encode(state())

    distributed = distribute_key(first_keyring, NEW)
    cold_a = SessionTokenCodec(
        decode_keyring(
            encode_keyring(distributed), PROVIDER).policy,
        PROVIDER,
    )
    cold_b = SessionTokenCodec(
        decode_keyring(
            encode_keyring(distributed), PROVIDER).policy,
        PROVIDER,
    )
    assert cold_a.decode(old_cursor, NOW + 500) == state()
    assert cold_b.decode(old_cursor, NOW + 500) == state()

    # Activation may also alter the default lifetime for new sessions. The
    # old cursor carries its fixed expiry and remains valid.
    active = activate_key(
        distributed,
        "newkey02",
        NOW + 1_000,
        ttl_ms=60_000,
    )
    active_a = SessionTokenCodec(
        decode_keyring(encode_keyring(active), PROVIDER).policy,
        PROVIDER,
    )
    active_b = SessionTokenCodec(
        decode_keyring(encode_keyring(active), PROVIDER).policy,
        PROVIDER,
    )
    assert active_a.decode(old_cursor, NOW + 2_000) == state()
    assert active_b.decode(old_cursor, NOW + 2_000) == state()

    new_state = replace(
        state("newkey02", expires_at=NOW + 61_000),
        issued_at_ms=NOW + 1_000,
    )
    new_cursor = active_a.encode(new_state)
    assert active_b.decode(new_cursor, NOW + 2_000) == new_state

    # A sandbox that missed the distribute phase cannot verify the new cursor.
    with pytest.raises(InvalidUploadSession):
        first.decode(new_cursor, NOW + 2_000)
    # A provider-bound cursor cannot resume on the other provider even when
    # that deployment was accidentally given the same key bytes.
    with pytest.raises(InvalidUploadSession):
        SessionTokenCodec(active.policy, OTHER_PROVIDER).decode(
            new_cursor, NOW + 2_000)
    with pytest.raises(InvalidUploadKeyring):
        decode_keyring(encode_keyring(active), OTHER_PROVIDER)


def test_rotation_refuses_early_activation_and_retirement():
    original = keyring()
    distributed = distribute_key(original, NEW)

    with pytest.raises(InvalidUploadKeyring):
        activate_key(distributed, "newkey02", NOW)
    with pytest.raises(InvalidUploadKeyring):
        activate_key(
            distributed,
            "newkey02",
            NEW.verify_until_ms - 1,
        )
    active = activate_key(
        distributed, "newkey02", NOW + 1_000)
    with pytest.raises(InvalidUploadKeyring):
        retire_key(active, "newkey02", NEW.verify_until_ms)
    with pytest.raises(InvalidUploadKeyring):
        retire_key(active, "oldkey01", OLD.verify_until_ms - 1)

    retired = retire_key(
        active, "oldkey01", OLD.verify_until_ms)
    assert retired.policy.active_key_id == "newkey02"
    assert tuple(
        key.key_id for key in retired.policy.keys) == ("newkey02",)


def test_distribution_and_key_count_are_fail_closed():
    original = keyring()
    with pytest.raises(InvalidUploadKeyring):
        distribute_key(original, OLD)
    with pytest.raises(InvalidUploadKeyring):
        distribute_key(original, "not a key")

    keys = tuple(
        SessionKey(
            f"key{i:05d}",
            bytes([i]) * 32,
            0,
            NOW + 10 * TTL,
        )
        for i in range(MAX_SESSION_KEYS)
    )
    full = keyring(keys=keys, active=keys[0].key_id)
    with pytest.raises(InvalidUploadKeyring):
        distribute_key(
            full,
            SessionKey(
                "overflow",
                b"z" * 32,
                0,
                NOW + 10 * TTL,
            ),
        )
