"""Canonical signed writer heads and mutable directory-slot bytes.

Head bytes are immutable and content addressed.  Slot bytes are small mutable
values replaced with an opaque provider CAS token.  A token is deliberately
absent from every codec: it is a capability returned by the object store, not
semantic repository state.
"""
from dataclasses import dataclass

from .crypto import h, sign, verify
from .fact import canon
from .limits import PayloadTooLarge, decode_json
from .shape import valid_fid
from .writer_tree import (
    EMPTY_TREE,
    MAX_WRITER_SEQUENCE,
    WriterTree,
    tree_document,
    tree_from_document,
)

HEAD_FORMAT = "poc16-writer-head-v2"
HEAD_SIGNATURE_DOMAIN = "poc16-writer-head-signature-v2"
SLOT_FORMAT = "poc16-writer-head-slot-v2"
STORE_BINDING_DOMAIN = "poc16-writer-store-binding-v1"

HEAD_SLOT_PREFIX = "heads"

MAX_WRITER_HEAD_BYTES = 2 * 1024
MAX_HEAD_SLOT_BYTES = 1024
SIGNATURE_HEX_CHARS = 128
PUBLIC_KEY_HEX_CHARS = 64


class InvalidWriterHead(ValueError):
    """Writer-head bytes or bindings violate the canonical contract."""


class InvalidHeadSlot(ValueError):
    """Stable directory-slot bytes do not bind their exact key."""


class InvalidWriterAddress(ValueError):
    """A writer-head or directory key is not canonical."""


def _lower_hex(value, length):
    return isinstance(value, str) \
        and len(value) == length \
        and all(character in "0123456789abcdef" for character in value)


@dataclass(frozen=True, slots=True)
class WriterBinding:
    """Authority-selected identity expected by a consuming peer."""

    workspace: str
    device: str
    owner: str
    store: str

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.device, self.owner, self.store)):
            raise ValueError("writer binding")


@dataclass(frozen=True, slots=True)
class WriterHead:
    workspace: str
    device: str
    owner: str
    sequence: int
    tree: WriterTree
    control: WriterTree
    store: str
    signature: str

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.device, self.owner, self.store)) \
                or type(self.sequence) is not int \
                or not 0 <= self.sequence <= MAX_WRITER_SEQUENCE \
                or not isinstance(self.tree, WriterTree) \
                or not isinstance(self.control, WriterTree) \
                or self.control.count > self.tree.count \
                or self.tree.count != self.sequence \
                or not _lower_hex(self.signature, SIGNATURE_HEX_CHARS):
            raise ValueError("writer head")
        if (self.sequence == 0) != (self.tree == EMPTY_TREE):
            raise ValueError("writer head genesis")


@dataclass(frozen=True, slots=True)
class HeadSlot:
    workspace: str
    device: str
    head: str
    removal_root: str
    permit: str | None = None

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.device,
                self.head, self.removal_root)) \
                or self.permit is not None and not valid_fid(self.permit):
            raise ValueError("head slot")


@dataclass(frozen=True, slots=True)
class PendingHeadSlot:
    """Private reservation whose previous final value remains observable."""

    workspace: str
    device: str
    previous: HeadSlot | None
    head: str
    permit: str

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.device, self.head, self.permit)) \
                or self.previous is not None and (
                    not isinstance(self.previous, HeadSlot)
                    or (self.previous.workspace, self.previous.device) != (
                        self.workspace, self.device)
                    or self.previous.head == self.head):
            raise ValueError("pending head slot")


def _unsigned_document(
        workspace, device, owner, sequence, tree, control, store):
    return {
        "device": device,
        "format": HEAD_FORMAT,
        "owner": owner,
        "sequence": sequence,
        "store": store,
        "control": tree_document(control),
        "tree": tree_document(tree),
        "workspace": workspace,
    }


def unsigned_head_document(head):
    if not isinstance(head, WriterHead):
        raise TypeError("writer head")
    return _unsigned_document(
        head.workspace,
        head.device,
        head.owner,
        head.sequence,
        head.tree,
        head.control,
        head.store,
    )


def head_signing_message(
        workspace, device, owner, sequence, tree, control, store):
    document = _unsigned_document(
        workspace, device, owner, sequence, tree, control, store)
    return h(canon([HEAD_SIGNATURE_DOMAIN, document]))


def make_head(
        secret, workspace, device, owner, sequence, tree, store,
        control=EMPTY_TREE):
    """Construct and sign one exact immutable head."""
    message = head_signing_message(
        workspace, device, owner, sequence, tree, control, store)
    return WriterHead(
        workspace,
        device,
        owner,
        sequence,
        tree,
        control,
        store,
        sign(secret, message),
    )


def head_document(head):
    return {
        **unsigned_head_document(head),
        "signature": head.signature,
    }


def encode_head(head):
    try:
        raw = canon(head_document(head))
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterHead("writer head encoding") from error
    if len(raw) > MAX_WRITER_HEAD_BYTES:
        raise PayloadTooLarge("writer head too large")
    return raw


def decode_head(raw):
    try:
        value = decode_json(raw, MAX_WRITER_HEAD_BYTES, "writer head")
        if not isinstance(value, dict) or set(value) != {
                "control", "device", "format", "owner", "sequence",
                "signature", "store", "tree", "workspace"} \
                or value.get("format") != HEAD_FORMAT:
            raise ValueError
        head = WriterHead(
            value["workspace"],
            value["device"],
            value["owner"],
            value["sequence"],
            tree_from_document(value["tree"]),
            tree_from_document(value["control"]),
            value["store"],
            value["signature"],
        )
        if encode_head(head) != raw:
            raise ValueError
        return head
    except PayloadTooLarge:
        raise
    except (KeyError, RecursionError, TypeError, UnicodeError, ValueError) \
            as error:
        raise InvalidWriterHead("writer head encoding") from error


def head_oid(value):
    raw = encode_head(value) if isinstance(value, WriterHead) else value
    decode_head(raw)
    return h(raw)


def verify_head(head, public_key):
    if not isinstance(head, WriterHead) \
            or not _lower_hex(public_key, PUBLIC_KEY_HEX_CHARS):
        return False
    message = head_signing_message(
        head.workspace,
        head.device,
        head.owner,
        head.sequence,
        head.tree,
        head.control,
        head.store,
    )
    return verify(public_key, message, head.signature)


def require_bound_head(head, binding):
    """Reject any field not selected by the authenticated writer registry."""
    if not isinstance(head, WriterHead) \
            or not isinstance(binding, WriterBinding) \
            or (head.workspace, head.device, head.owner, head.store) != (
                binding.workspace, binding.device,
                binding.owner, binding.store) \
            or not verify_head(head, binding.device):
        raise InvalidWriterHead("writer head authority binding")
    return head


def validate_advance(accepted, current, binding):
    """Compare a candidate directly with the last locally accepted head.

    Tree-row monotonicity is proved by :func:`writer_tree.validate_extension`.
    No permanent chain of superseded head objects is part of the protocol.
    """
    require_bound_head(accepted, binding)
    require_bound_head(current, binding)
    if current.sequence < accepted.sequence:
        raise InvalidWriterHead("writer head rollback")
    if current.sequence == accepted.sequence:
        if head_oid(current) != head_oid(accepted):
            raise InvalidWriterHead("writer head fork")
        return 0
    if current.tree.root == accepted.tree.root:
        raise InvalidWriterHead("writer head advance")
    return current.sequence - accepted.sequence


def head_slot_key(workspace, device):
    if not valid_fid(workspace) or not valid_fid(device):
        raise ValueError("head slot identity")
    return f"{HEAD_SLOT_PREFIX}/{workspace}/{device}"


def writer_store_binding(workspace, device):
    """Canonical logical store binding resolved without a URL or database."""
    if not valid_fid(workspace) or not valid_fid(device):
        raise ValueError("writer store identity")
    return h(canon([STORE_BINDING_DOMAIN, workspace, device]))


def head_slot_prefix(workspace):
    if not valid_fid(workspace):
        raise ValueError("head slot workspace")
    return f"{HEAD_SLOT_PREFIX}/{workspace}/"


def parse_head_slot_key(key):
    parts = key.split("/") if isinstance(key, str) else ()
    if len(parts) != 3 or parts[0] != HEAD_SLOT_PREFIX:
        raise InvalidWriterAddress("head slot key")
    try:
        if head_slot_key(parts[1], parts[2]) != key:
            raise ValueError
    except ValueError as error:
        raise InvalidWriterAddress("head slot key") from error
    return parts[1], parts[2]


MAX_HEAD_SLOT_KEY_BYTES = len(head_slot_key(
    "0" * 64, "0" * 64).encode("ascii"))


def slot_document(slot):
    if isinstance(slot, HeadSlot):
        return {
            "device": slot.device,
            "format": SLOT_FORMAT,
            "head": slot.head,
            "permit": "" if slot.permit is None else slot.permit,
            "removal_root": slot.removal_root,
            "state": "final",
            "workspace": slot.workspace,
        }
    if isinstance(slot, PendingHeadSlot):
        previous = None if slot.previous is None else {
            "head": slot.previous.head,
            "permit": "" if slot.previous.permit is None \
                else slot.previous.permit,
            "removal_root": slot.previous.removal_root,
        }
        return {
            "device": slot.device,
            "format": SLOT_FORMAT,
            "head": slot.head,
            "permit": slot.permit,
            "previous": previous,
            "state": "pending",
            "workspace": slot.workspace,
        }
    raise TypeError("head slot")


def encode_slot(slot):
    try:
        raw = canon(slot_document(slot))
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidHeadSlot("head slot encoding") from error
    if len(raw) > MAX_HEAD_SLOT_BYTES:
        raise PayloadTooLarge("head slot too large")
    return raw


def decode_slot_state(raw, *, workspace=None, device=None):
    try:
        value = decode_json(raw, MAX_HEAD_SLOT_BYTES, "head slot")
        if not isinstance(value, dict) or value.get("format") != SLOT_FORMAT:
            raise ValueError
        if value.get("state") == "final" and set(value) == {
                "device", "format", "head", "permit", "removal_root", "state",
                "workspace"}:
            slot = HeadSlot(
                value["workspace"], value["device"],
                value["head"], value["removal_root"],
                value["permit"] or None)
        elif value.get("state") == "pending" and set(value) == {
                "device", "format", "head", "permit", "previous", "state",
                "workspace"}:
            previous = value["previous"]
            if previous is not None and (
                    not isinstance(previous, dict)
                    or set(previous) != {
                        "head", "permit", "removal_root"}):
                raise ValueError
            prior = None if previous is None else HeadSlot(
                value["workspace"], value["device"],
                previous["head"], previous["removal_root"],
                previous["permit"] or None)
            slot = PendingHeadSlot(
                value["workspace"], value["device"], prior,
                value["head"], value["permit"])
        else:
            raise ValueError
        if encode_slot(slot) != raw \
                or workspace is not None and slot.workspace != workspace \
                or device is not None and slot.device != device:
            raise ValueError
        return slot
    except PayloadTooLarge:
        raise
    except (KeyError, RecursionError, TypeError, UnicodeError, ValueError) \
            as error:
        raise InvalidHeadSlot("head slot encoding") from error


def decode_slot(raw, *, workspace=None, device=None):
    """Decode one final slot; peer-proposed pending values are invalid."""
    slot = decode_slot_state(raw, workspace=workspace, device=device)
    if not isinstance(slot, HeadSlot):
        raise InvalidHeadSlot("pending head slot is private")
    return slot


def visible_slot(raw, *, workspace=None, device=None):
    """Project the last final slot without disclosing pending metadata."""
    state = decode_slot_state(raw, workspace=workspace, device=device)
    return state if isinstance(state, HeadSlot) else state.previous


def decode_slot_at(key, raw):
    workspace, device = parse_head_slot_key(key)
    return decode_slot(raw, workspace=workspace, device=device)


def decode_slot_state_at(key, raw):
    workspace, device = parse_head_slot_key(key)
    return decode_slot_state(raw, workspace=workspace, device=device)


def visible_slot_at(key, raw):
    workspace, device = parse_head_slot_key(key)
    return visible_slot(raw, workspace=workspace, device=device)


__all__ = (
    "HEAD_FORMAT",
    "HEAD_SIGNATURE_DOMAIN",
    "HEAD_SLOT_PREFIX",
    "HeadSlot",
    "PendingHeadSlot",
    "InvalidHeadSlot",
    "InvalidWriterAddress",
    "InvalidWriterHead",
    "MAX_HEAD_SLOT_BYTES",
    "MAX_HEAD_SLOT_KEY_BYTES",
    "MAX_WRITER_HEAD_BYTES",
    "SLOT_FORMAT",
    "STORE_BINDING_DOMAIN",
    "WriterBinding",
    "WriterHead",
    "decode_head",
    "decode_slot",
    "decode_slot_at",
    "decode_slot_state",
    "decode_slot_state_at",
    "encode_head",
    "encode_slot",
    "head_document",
    "head_oid",
    "head_signing_message",
    "head_slot_key",
    "head_slot_prefix",
    "make_head",
    "parse_head_slot_key",
    "require_bound_head",
    "slot_document",
    "unsigned_head_document",
    "validate_advance",
    "verify_head",
    "visible_slot",
    "visible_slot_at",
    "writer_store_binding",
)
