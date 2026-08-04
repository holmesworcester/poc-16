"""Stateless exact permits for control-bearing writer heads.

A permit is the recipient's durable-to-the-caller certificate that one exact
head transition was authorized against a current removal pin before any of
its control effects were applied.  The recipient stores no permit row, cursor,
or cache: an HMAC binds the exact base/head, control pile OIDs, derived effect
digest, and caller scopes.  The permit deliberately has no wall-clock expiry;
otherwise a crash after self-removal could make the one terminal head
impossible to finish.
"""

from dataclasses import dataclass
import hashlib
import hmac

from .fact import canon
from .limits import (
    MAX_HEAD_CONTROL_PILES,
    MAX_HEAD_PERMIT_BYTES,
    MAX_REMOVAL_PATH_SCOPES,
    MAX_SUPPRESSION_ID_BYTES,
    decode_json,
    valid_bounded_text,
)
from .shape import valid_fid


FORMAT = "poc16-control-head-permit-v1"
MAC_DOMAIN = "poc16-control-head-permit-mac-v1"


@dataclass(frozen=True, slots=True)
class ControlHeadPermit:
    """One exact, non-amplifying control-head authorization."""

    workspace: str
    device: str
    owner: str
    base_head: str | None
    head: str
    removal_root: str
    proof_oid: str
    control_oids: tuple[str, ...]
    effects_oid: str
    caller_scopes: tuple[str, ...]
    terminal_scopes: tuple[str, ...]

    def __post_init__(self):
        identities = (
            self.workspace,
            self.device,
            self.owner,
            self.head,
            self.removal_root,
            self.proof_oid,
            self.effects_oid,
        )
        if not all(valid_fid(value) for value in identities) \
                or self.base_head is not None \
                and not valid_fid(self.base_head) \
                or not isinstance(self.control_oids, tuple) \
                or not 0 < len(self.control_oids) \
                <= MAX_HEAD_CONTROL_PILES \
                or len(set(self.control_oids)) != len(self.control_oids) \
                or not all(valid_fid(oid) for oid in self.control_oids):
            raise ValueError("control head permit identity")
        for label, scopes in (
                ("caller", self.caller_scopes),
                ("terminal", self.terminal_scopes)):
            if not isinstance(scopes, tuple) \
                    or len(scopes) > MAX_REMOVAL_PATH_SCOPES \
                    or scopes != tuple(sorted(set(scopes))) \
                    or not all(valid_bounded_text(
                        sid, MAX_SUPPRESSION_ID_BYTES) for sid in scopes):
                raise ValueError(f"control head permit {label} scopes")
        if not self.caller_scopes \
                or not set(self.terminal_scopes) <= set(self.caller_scopes):
            raise ValueError("control head permit terminal scopes")


def _claims(permit):
    if not isinstance(permit, ControlHeadPermit):
        raise TypeError("control head permit")
    return {
        "base_head": "" if permit.base_head is None else permit.base_head,
        "caller_scopes": list(permit.caller_scopes),
        "control_oids": list(permit.control_oids),
        "device": permit.device,
        "effects_oid": permit.effects_oid,
        "head": permit.head,
        "owner": permit.owner,
        "proof_oid": permit.proof_oid,
        "removal_root": permit.removal_root,
        "terminal_scopes": list(permit.terminal_scopes),
        "workspace": permit.workspace,
    }


def _secret(secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("control head permit secret")
    return secret


def _mac(secret, claims):
    return hmac.new(
        _secret(secret),
        canon([MAC_DOMAIN, claims]),
        hashlib.sha256,
    ).hexdigest()


def encode(permit, secret):
    """Authenticate one permit as bounded canonical bytes."""
    claims = _claims(permit)
    raw = canon({
        "claims": claims,
        "format": FORMAT,
        "mac": _mac(secret, claims),
    })
    if len(raw) > MAX_HEAD_PERMIT_BYTES:
        raise ValueError("control head permit too large")
    return raw


def decode(raw, secret):
    """Open and fully canonicalize one authenticated permit."""
    value = decode_json(raw, MAX_HEAD_PERMIT_BYTES, "control head permit")
    if not isinstance(value, dict) or set(value) != {
            "claims", "format", "mac"} \
            or value.get("format") != FORMAT \
            or not isinstance(value.get("claims"), dict) \
            or not isinstance(value.get("mac"), str) \
            or not hmac.compare_digest(
                value["mac"], _mac(secret, value["claims"])):
        raise ValueError("control head permit")
    claims = value["claims"]
    if set(claims) != {
            "base_head", "caller_scopes", "control_oids", "device",
            "effects_oid", "head", "owner", "proof_oid", "removal_root",
            "terminal_scopes", "workspace"} \
            or not isinstance(claims["control_oids"], list) \
            or not isinstance(claims["caller_scopes"], list) \
            or not isinstance(claims["terminal_scopes"], list):
        raise ValueError("control head permit claims")
    permit = ControlHeadPermit(
        claims["workspace"],
        claims["device"],
        claims["owner"],
        claims["base_head"] or None,
        claims["head"],
        claims["removal_root"],
        claims["proof_oid"],
        tuple(claims["control_oids"]),
        claims["effects_oid"],
        tuple(claims["caller_scopes"]),
        tuple(claims["terminal_scopes"]),
    )
    if _claims(permit) != claims or encode(permit, secret) != raw:
        raise ValueError("control head permit encoding")
    return permit


__all__ = (
    "ControlHeadPermit",
    "decode",
    "encode",
)
