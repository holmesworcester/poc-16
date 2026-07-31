"""Pure binding from one direct-upload marker to one exact fact-only pile.

Provider adapters supply the configured workspace, exact staging key, and
bounded marker bytes. Inline file slices are ordinary facts, so a marker has
no secondary object-completion phase and enters ``RepositoryApplier`` once.
"""
from dataclasses import dataclass

import facts
from .close import decode_pile
from .crypto import h
from .ingress import InvalidPile, InvalidStagedIntent
from .limits import MAX_PILE_BYTES
from .shape import valid_fid


STAGING_PREFIX = "ingress/v1"
SESSION_HEX_BYTES = 32
MEMBER_HEX_BYTES = 16


def _lower_hex(value, length):
    return isinstance(value, str) \
        and len(value) == length \
        and all(character in "0123456789abcdef" for character in value)


@dataclass(frozen=True)
class StagingAddress:
    """One strictly parsed address in isolated, untrusted ingress."""

    workspace: str
    session: str
    object_class: str
    digest: str
    member: str | None = None


def staging_key(workspace, member, session, object_class, digest):
    """Build the versioned provider-independent staging grammar."""
    if not valid_fid(workspace) \
            or not _lower_hex(member, MEMBER_HEX_BYTES) \
            or not _lower_hex(session, SESSION_HEX_BYTES) \
            or not valid_fid(digest):
        raise ValueError("staging key component")
    base = f"{STAGING_PREFIX}/workspaces/{workspace}"
    if object_class == "obj":
        return f"{base}/objects/{session}/{digest}"
    if object_class == "pile":
        return f"{base}/piles/{session}/{member}/{digest}"
    raise ValueError("staging object class")


def staging_prefix(workspace, object_class):
    if not valid_fid(workspace):
        raise ValueError("staging workspace")
    base = f"{STAGING_PREFIX}/workspaces/{workspace}"
    if object_class == "obj":
        return base + "/objects/"
    if object_class == "pile":
        return base + "/piles/"
    raise ValueError("staging object class")


def parse_staging_key(key):
    """Parse an exact staging key; free-form prefixes are never normalized."""
    if not isinstance(key, str):
        raise InvalidStagedIntent("staging key")
    parts = key.split("/")
    if len(parts) == 7 and parts[4] == "objects":
        workspace, session, object_class, member, digest = (
            parts[3], parts[5], "obj", None, parts[6])
    elif len(parts) == 8 and parts[4] == "piles":
        workspace, session, object_class, member, digest = (
            parts[3], parts[5], "pile", parts[6], parts[7])
    else:
        raise InvalidStagedIntent("staging key")
    if parts[:3] != ["ingress", "v1", "workspaces"] \
            or not valid_fid(workspace) \
            or not _lower_hex(session, SESSION_HEX_BYTES) \
            or not valid_fid(digest) \
            or object_class == "pile" and not _lower_hex(
                member, MEMBER_HEX_BYTES):
        raise InvalidStagedIntent("staging key")
    address = StagingAddress(
        workspace, session, object_class, digest, member)
    try:
        canonical = staging_key(
            workspace, member or "0" * MEMBER_HEX_BYTES,
            session, object_class, digest)
    except ValueError as error:
        raise InvalidStagedIntent("staging key") from error
    if canonical != key:
        raise InvalidStagedIntent("staging key")
    return address


@dataclass(frozen=True)
class StagedPileIntent:
    """One canonical fact-only pile at its exact untrusted marker."""

    workspace: str
    session: str
    member: str
    digest: str
    key: str
    raw: bytes
    stream: tuple


def decode_staged_pile(configured_workspace, key, raw):
    """Bind one exact pile marker to canonical workspace-bound facts."""
    if not valid_fid(configured_workspace):
        raise InvalidStagedIntent("configured workspace")
    address = parse_staging_key(key)
    if address.object_class != "pile":
        raise InvalidStagedIntent("pile marker required")
    if address.workspace != configured_workspace:
        raise InvalidStagedIntent("staging workspace")
    if not isinstance(raw, bytes) or len(raw) > MAX_PILE_BYTES:
        raise InvalidStagedIntent("staged pile bytes")
    if h(raw) != address.digest:
        raise InvalidStagedIntent("staged pile digest")
    try:
        stream = decode_pile(raw, configured_workspace)
    except InvalidPile as error:
        raise InvalidStagedIntent("invalid staged pile") from error
    for fact in stream:
        if facts.family_for(fact.t) is None:
            raise InvalidStagedIntent("unknown fact family")
        if fact.ws is None and (
                fact.fid != configured_workspace
                or not facts.is_genesis(fact.t)):
            raise InvalidStagedIntent(
                "only workspace genesis may omit workspace")
    return StagedPileIntent(
        configured_workspace,
        address.session,
        address.member,
        address.digest,
        key,
        raw,
        tuple(stream),
    )


__all__ = (
    "MEMBER_HEX_BYTES",
    "SESSION_HEX_BYTES",
    "STAGING_PREFIX",
    "StagedPileIntent",
    "StagingAddress",
    "decode_staged_pile",
    "parse_staging_key",
    "staging_key",
    "staging_prefix",
)
