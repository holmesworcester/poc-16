"""Pure binding between one direct-upload pile marker and its object set.

Provider adapters hand this module only the configured workspace, an exact
staging key, and bounded bytes.  The result is the sole provider-neutral
description a publisher may advance toward kernel admission:

    exact pile marker
        -> canonical workspace-bound facts
        -> exact same-session object keys

No database, bucket listing, notification field, or client-supplied uploader
claim participates in that authority chain.
"""
from bisect import bisect_left
from dataclasses import dataclass

import facts
from .close import decode_pile, encode_pile
from .crypto import h
from .ingress import InvalidStagedIntent, stage_pile
from .limits import MAX_OBJECT_BYTES, MAX_PILE_BYTES
from .shape import valid_fid


STAGING_PREFIX = "ingress/v1"
SESSION_HEX_BYTES = 32
MEMBER_HEX_BYTES = 16
MAX_STAGED_OBJECTS = 65_536


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
    """Build the one versioned provider-independent staging grammar."""
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
    """Return the disjoint provider prefix for data or durable work markers."""
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
            address.workspace,
            address.member or "0" * MEMBER_HEX_BYTES,
            address.session,
            address.object_class,
            address.digest,
        )
    except ValueError as error:
        raise InvalidStagedIntent("staging key") from error
    if canonical != key:
        raise InvalidStagedIntent("staging key")
    return address


@dataclass(frozen=True)
class StagedPileIntent:
    """A canonical pile plus every immutable object it can demand."""

    workspace: str
    session: str
    member: str
    digest: str
    key: str
    raw: bytes
    stream: tuple
    blob_refs: tuple[str, ...]

    @property
    def object_keys(self):
        return tuple(
            staging_key(
                self.workspace,
                self.member,
                self.session,
                "obj",
                digest,
            )
            for digest in self.blob_refs
        )


class StagedObjectsPending(RuntimeError):
    """At least one exact required object is not visible yet; retry later."""


class InvalidStagedObject(ValueError):
    """One staged attachment cannot promote; it does not reject the pile."""


def promote_staged_pile(store, intent):
    """Copy one verified session intent to a fresh internal work generation.

    Upload credentials can address only ``intent.key`` in the isolated
    staging namespace.  The trusted publisher creates this distinct canonical
    key with an independent random generation and never returns it to the
    uploader.  Therefore replaying a still-valid or in-flight staging PUT
    cannot recreate a canonical generation after its receipt retires it.
    Staging-object lifecycle cleanup is deliberately a separate operation.
    """
    if not isinstance(intent, StagedPileIntent):
        raise TypeError("staged pile intent")
    return stage_pile(store, intent.member, intent.raw)


def decode_staged_pile(configured_workspace, key, raw):
    """Bind one exact pile marker to canonical facts and required objects."""
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
        stream, embedded = decode_pile(raw, configured_workspace)
        if embedded:
            raise InvalidStagedIntent(
                "direct-upload piles cannot embed objects")
        if encode_pile(
                stream, workspace=configured_workspace) != raw:
            raise InvalidStagedIntent("non-canonical staged pile")
        refs = set()
        for fact in stream:
            family = facts.family_for(fact.t)
            if family is None:
                raise InvalidStagedIntent("unknown fact family")
            if fact.ws is None and (
                    fact.fid != configured_workspace
                    or not facts.is_genesis(fact.t)):
                raise InvalidStagedIntent(
                    "only workspace genesis may omit workspace")
            for digest in facts.blob_refs(fact):
                if not valid_fid(digest):
                    raise InvalidStagedIntent("invalid object reference")
                refs.add(digest)
                if len(refs) > MAX_STAGED_OBJECTS:
                    raise InvalidStagedIntent(
                        "staged object reference count")
    except InvalidStagedIntent:
        raise
    except Exception as error:
        raise InvalidStagedIntent("invalid staged pile") from error
    return StagedPileIntent(
        configured_workspace,
        address.session,
        address.member,
        address.digest,
        key,
        raw,
        tuple(stream),
        tuple(sorted(refs)),
    )


def confirm_staged_object(intent, key, raw):
    """Verify one bounded exact GET without granting authority to bucket LIST.

    A missing body is an expected visibility/upload delay.  A foreign key,
    surplus object, oversized body, or hash mismatch is permanent poison.
    Calling this once for each derived ``object_keys`` entry keeps a Worker
    bounded to one immutable object at a time.
    """
    if not isinstance(intent, StagedPileIntent):
        raise TypeError("staged pile intent")
    try:
        address = parse_staging_key(key)
    except InvalidStagedIntent as error:
        raise InvalidStagedObject("staged object key") from error
    position = bisect_left(intent.blob_refs, address.digest)
    if address.object_class != "obj" \
            or address.workspace != intent.workspace \
            or address.session != intent.session \
            or position == len(intent.blob_refs) \
            or intent.blob_refs[position] != address.digest:
        raise InvalidStagedObject("foreign or surplus staged object")
    if raw is None:
        raise StagedObjectsPending("staged objects incomplete")
    if not isinstance(raw, bytes) or len(raw) > MAX_OBJECT_BYTES \
            or h(raw) != address.digest:
        raise InvalidStagedObject("staged object integrity")
    return raw


__all__ = (
    "MEMBER_HEX_BYTES",
    "MAX_STAGED_OBJECTS",
    "SESSION_HEX_BYTES",
    "STAGING_PREFIX",
    "InvalidStagedObject",
    "StagedObjectsPending",
    "StagedPileIntent",
    "StagingAddress",
    "promote_staged_pile",
    "confirm_staged_object",
    "decode_staged_pile",
    "parse_staging_key",
    "staging_key",
    "staging_prefix",
)
