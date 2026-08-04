"""Self-contained exact capabilities for control-bearing writer heads.

Issuance is the sole closed-pile semantic evaluation. The HMAC authenticates
the resulting canonical ACI rows; commit therefore needs only these bounded
permit bytes and remains stable across ordinary application-projection replay.
The permit key is separate from short-lived bearer-grant material.
"""

from dataclasses import dataclass
import hashlib
import hmac

from .crypto import h
from .fact import canon
from .limits import MAX_HEAD_PERMIT_BYTES, decode_json
from .removal_state import checked_updates
from .shape import valid_fid


FORMAT = "poc16-control-head-permit-v3"
MAC_DOMAIN = "poc16-control-head-permit-mac-v3"


@dataclass(frozen=True, slots=True)
class ControlHeadPermit:
    """One exact issue-time authorization and its bounded removal rows."""

    workspace: str
    device: str
    base_head: str | None
    head: str
    removal_root: str
    updates: tuple[tuple[str, dict], ...]

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.device, self.head,
                self.removal_root)) \
                or self.base_head is not None \
                and not valid_fid(self.base_head) \
                or checked_updates(self.updates) != self.updates \
                or not self.updates:
            raise ValueError("control head permit identity")


def _claims(permit):
    if not isinstance(permit, ControlHeadPermit):
        raise TypeError("control head permit")
    return {
        "base_head": "" if permit.base_head is None else permit.base_head,
        "device": permit.device,
        "head": permit.head,
        "removal_root": permit.removal_root,
        "updates": [
            [sid, value] for sid, value in permit.updates
        ],
        "workspace": permit.workspace,
    }


def _secret(secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("control head permit secret")
    return secret


def key_id(secret):
    """Name verifier material without disclosing it."""
    return h(_secret(secret))


def _mac(secret, kid, claims):
    return hmac.new(
        _secret(secret),
        canon([MAC_DOMAIN, kid, claims]),
        hashlib.sha256,
    ).hexdigest()


def encode(permit, secret):
    """Authenticate one permit as bounded canonical bytes."""
    claims = _claims(permit)
    kid = key_id(secret)
    raw = canon({
        "claims": claims,
        "format": FORMAT,
        "kid": kid,
        "mac": _mac(secret, kid, claims),
    })
    if len(raw) > MAX_HEAD_PERMIT_BYTES:
        raise ValueError("control head permit too large")
    return raw


def decode(raw, secret):
    """Open and fully canonicalize one authenticated permit."""
    value = decode_json(raw, MAX_HEAD_PERMIT_BYTES, "control head permit")
    kid = key_id(secret)
    if not isinstance(value, dict) or set(value) != {
            "claims", "format", "kid", "mac"} \
            or value.get("format") != FORMAT \
            or value.get("kid") != kid \
            or not isinstance(value.get("claims"), dict) \
            or not isinstance(value.get("mac"), str) \
            or not hmac.compare_digest(
                value["mac"], _mac(secret, kid, value["claims"])):
        raise ValueError("control head permit")
    claims = value["claims"]
    if set(claims) != {
            "base_head", "device", "head", "updates",
            "removal_root", "workspace"} \
            or not isinstance(claims["updates"], list):
        raise ValueError("control head permit claims")
    try:
        updates = tuple(
            tuple(row) if isinstance(row, list) else row
            for row in claims["updates"]
        )
        permit = ControlHeadPermit(
            claims["workspace"],
            claims["device"],
            claims["base_head"] or None,
            claims["head"],
            claims["removal_root"],
            checked_updates(updates),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("control head permit claims") from error
    if _claims(permit) != claims or encode(permit, secret) != raw:
        raise ValueError("control head permit encoding")
    return permit


__all__ = (
    "ControlHeadPermit",
    "decode",
    "encode",
    "key_id",
)
