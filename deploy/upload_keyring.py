"""Canonical durable key rings for stateless upload-session brokers.

Every cold broker instance loads the same provider-local secret document.
Rotation is deliberately three phase: distribute a verifying key, activate it
for new cursors, then retire the old key only after its declared verification
window has elapsed.  Provider secret managers store the bytes; this module
owns their one bounded, transport-independent meaning.
"""
import base64
from dataclasses import dataclass, replace
import json

from deploy.upload_session import (
    SessionKey,
    UploadSessionPolicy,
    valid_provider_binding,
)


SCHEMA = "poc16-upload-session-keyring-v1"
MAX_KEYRING_BYTES = 16 * 1024
MAX_SESSION_KEYS = 16

_POLICY_FIELDS = {
    "active_key_id",
    "clock_skew_ms",
    "issuer",
    "keys",
    "max_bytes",
    "max_ttl_ms",
    "provider_binding",
    "schema",
    "ttl_ms",
}
_KEY_FIELDS = {
    "issue_from_ms",
    "key_id",
    "secret",
    "verify_until_ms",
}


class InvalidUploadKeyring(ValueError):
    """A secret document is ambiguous, noncanonical, or unsafe to use."""


@dataclass(frozen=True)
class UploadKeyring:
    """One provider-bound policy stored by a provider-local secret manager."""

    provider_binding: str
    policy: UploadSessionPolicy

    def __post_init__(self):
        if not valid_provider_binding(self.provider_binding) \
                or not isinstance(self.policy, UploadSessionPolicy):
            raise ValueError("upload keyring")


def _unique_object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise InvalidUploadKeyring("duplicate upload keyring field")
        value[name] = item
    return value


def _secret_text(secret):
    return base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")


def _secret_bytes(value):
    if not isinstance(value, str) or not value.isascii():
        raise InvalidUploadKeyring("upload key secret")
    try:
        secret = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as error:
        raise InvalidUploadKeyring("upload key secret") from error
    if len(secret) != 32 or _secret_text(secret) != value:
        raise InvalidUploadKeyring("upload key secret")
    return secret


def _document(keyring):
    if not isinstance(keyring, UploadKeyring) \
            or len(keyring.policy.keys) > MAX_SESSION_KEYS:
        raise InvalidUploadKeyring("upload session policy")
    policy = keyring.policy
    keys = sorted(policy.keys, key=lambda item: item.key_id)
    return {
        "active_key_id": policy.active_key_id,
        "clock_skew_ms": policy.clock_skew_ms,
        "issuer": policy.issuer,
        "keys": [{
            "issue_from_ms": key.issue_from_ms,
            "key_id": key.key_id,
            "secret": _secret_text(key.secret),
            "verify_until_ms": key.verify_until_ms,
        } for key in keys],
        "max_bytes": policy.max_bytes,
        "max_ttl_ms": policy.max_ttl_ms,
        "provider_binding": keyring.provider_binding,
        "schema": SCHEMA,
        "ttl_ms": policy.ttl_ms,
    }


def encode_keyring(keyring):
    """Return the one canonical secret document for ``keyring``."""
    try:
        raw = json.dumps(
            _document(keyring),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise InvalidUploadKeyring("upload session policy") from error
    if not raw or len(raw) > MAX_KEYRING_BYTES:
        raise InvalidUploadKeyring("upload keyring byte limit")
    return raw


def decode_keyring(raw, expected_provider_binding=None):
    """Decode only the canonical bounded key-ring representation."""
    if not isinstance(raw, bytes) or not raw \
            or len(raw) > MAX_KEYRING_BYTES:
        raise InvalidUploadKeyring("upload keyring byte limit")
    try:
        document = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_object,
        )
    except (
            InvalidUploadKeyring,
            json.JSONDecodeError,
            UnicodeError,
            RecursionError,
    ) as error:
        raise InvalidUploadKeyring("upload keyring document") from error
    if not isinstance(document, dict) \
            or set(document) != _POLICY_FIELDS \
            or document.get("schema") != SCHEMA \
            or not isinstance(document.get("keys"), list) \
            or not 1 <= len(document["keys"]) <= MAX_SESSION_KEYS:
        raise InvalidUploadKeyring("upload keyring shape")
    keys = []
    try:
        for item in document["keys"]:
            if not isinstance(item, dict) or set(item) != _KEY_FIELDS:
                raise InvalidUploadKeyring("upload key shape")
            keys.append(SessionKey(
                item["key_id"],
                _secret_bytes(item["secret"]),
                item["issue_from_ms"],
                item["verify_until_ms"],
            ))
        policy = UploadSessionPolicy(
            document["issuer"],
            document["active_key_id"],
            tuple(keys),
            ttl_ms=document["ttl_ms"],
            max_ttl_ms=document["max_ttl_ms"],
            clock_skew_ms=document["clock_skew_ms"],
            max_bytes=document["max_bytes"],
        )
        keyring = UploadKeyring(
            document["provider_binding"],
            policy,
        )
    except (InvalidUploadKeyring, TypeError, ValueError) as error:
        raise InvalidUploadKeyring("upload keyring shape") from error
    if expected_provider_binding is not None \
            and (
                not valid_provider_binding(expected_provider_binding)
                or keyring.provider_binding != expected_provider_binding
            ):
        raise InvalidUploadKeyring("upload keyring provider")
    if encode_keyring(keyring) != raw:
        raise InvalidUploadKeyring("noncanonical upload keyring")
    return keyring


def distribute_key(keyring, key):
    """Add one inactive verification key without changing issuance."""
    if not isinstance(keyring, UploadKeyring) \
            or not isinstance(key, SessionKey) \
            or len(keyring.policy.keys) >= MAX_SESSION_KEYS \
            or key.key_id in {
                item.key_id for item in keyring.policy.keys}:
        raise InvalidUploadKeyring("upload key distribution")
    answer = replace(
        keyring,
        policy=replace(
            keyring.policy,
            keys=tuple(sorted(
                (*keyring.policy.keys, key),
                key=lambda item: item.key_id,
            )),
        ),
    )
    encode_keyring(answer)
    return answer


def activate_key(keyring, key_id, now_ms, *, ttl_ms=None):
    """Switch new cursor issuance after every instance has the new key."""
    if not isinstance(keyring, UploadKeyring) \
            or type(now_ms) is not int or now_ms < 0:
        raise InvalidUploadKeyring("upload key activation")
    policy = keyring.policy
    try:
        key = policy.key(key_id)
    except ValueError as error:
        raise InvalidUploadKeyring("upload key activation") from error
    lifetime = policy.ttl_ms if ttl_ms is None else ttl_ms
    if type(lifetime) is not int \
            or not 0 < lifetime <= policy.max_ttl_ms \
            or now_ms < key.issue_from_ms \
            or now_ms + lifetime + policy.clock_skew_ms \
            > key.verify_until_ms:
        raise InvalidUploadKeyring("upload key activation")
    try:
        answer = replace(
            keyring,
            policy=replace(
                policy,
                active_key_id=key_id,
                ttl_ms=lifetime,
            ),
        )
    except ValueError as error:
        raise InvalidUploadKeyring("upload key activation") from error
    encode_keyring(answer)
    return answer


def retire_key(keyring, key_id, now_ms):
    """Remove an inactive key only after every cursor it covers has expired."""
    if not isinstance(keyring, UploadKeyring) \
            or type(now_ms) is not int or now_ms < 0 \
            or key_id == keyring.policy.active_key_id:
        raise InvalidUploadKeyring("upload key retirement")
    policy = keyring.policy
    try:
        key = policy.key(key_id)
    except ValueError as error:
        raise InvalidUploadKeyring("upload key retirement") from error
    if now_ms < key.verify_until_ms:
        raise InvalidUploadKeyring("upload key retirement")
    try:
        answer = replace(
            keyring,
            policy=replace(
                policy,
                keys=tuple(
                    item for item in policy.keys
                    if item.key_id != key_id
                ),
            ),
        )
    except ValueError as error:
        raise InvalidUploadKeyring("upload key retirement") from error
    encode_keyring(answer)
    return answer


__all__ = (
    "InvalidUploadKeyring",
    "MAX_KEYRING_BYTES",
    "MAX_SESSION_KEYS",
    "SCHEMA",
    "UploadKeyring",
    "activate_key",
    "decode_keyring",
    "distribute_key",
    "encode_keyring",
    "retire_key",
)
