"""Portable writer-bundle manifests and untrusted pack locators.

A bundle groups an ordered, contiguous publication range of independently
signed closed-pile objects.  The device-signed writer head authenticates the
bundle object's placement; each extracted pile still authenticates itself and
must pass the ordinary closed-pile evaluator.  Nothing in this module is an
admission certificate.

The pack table is deliberately only a locator.  It says which byte range is
expected to hash to each pile OID, but a consumer verifies that hash and the
signed pile's workspace/writer binding before using the bytes.  Tail versus
sealed is likewise head state, not bundle state: the same immutable bundle may
first be the current tail and later become a sealed-tree row.
"""
from dataclasses import dataclass
from itertools import islice

from .close import decode_signed_pile
from .crypto import h
from .fact import canon
from .ingress import InvalidPile
from .limits import (
    MAX_OBJECT_BYTES,
    MIB,
    PayloadTooLarge,
    decode_json,
)
from .shape import valid_fid
from .writer_tree import MAX_WRITER_SEQUENCE


BUNDLE_FORMAT = "poc16-writer-bundle-v1"

# One descriptor remains an ordinary bounded immutable repository object.
MAX_BUNDLE_DESCRIPTOR_BYTES = MAX_OBJECT_BYTES
# 95 MiB remains below a 100,000,000-byte front door while being large enough
# to amortize provider requests.  Providers may impose a stricter deployment
# limit without changing the portable format.
MAX_BUNDLE_PACK_BYTES = 95 * MIB
# At worst this produces a descriptor comfortably below four MiB, including
# 64-byte OIDs and maximum-width decimal offsets and lengths.
MAX_BUNDLE_PILES = 32_768


class InvalidWriterBundle(ValueError):
    """Bundle bytes, logical bindings, or physical locators are invalid."""


@dataclass(frozen=True, slots=True)
class PackSlice:
    """One untrusted half-open byte range in the concatenated pack body."""

    offset: int
    length: int

    def __post_init__(self):
        if type(self.offset) is not int or self.offset < 0 \
                or type(self.length) is not int or self.length <= 0 \
                or self.offset + self.length > MAX_BUNDLE_PACK_BYTES:
            raise ValueError("writer bundle slice")


@dataclass(frozen=True, slots=True)
class WriterBundle:
    """Canonical descriptor for one non-empty publication interval.

    ``piles`` is the logical authenticated order. ``slices`` is an aligned
    table of physical hints into the object named by ``pack_oid``.  Keeping
    them as separate fields makes it explicit that prefix authority never
    depends on offsets or on a provider returning the requested range.
    """

    workspace: str
    device: str
    first: int
    last: int
    piles: tuple[str, ...]
    pack_oid: str
    pack_bytes: int
    slices: tuple[PackSlice, ...]

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.device) \
                or type(self.first) is not int \
                or type(self.last) is not int \
                or not 1 <= self.first <= self.last <= MAX_WRITER_SEQUENCE \
                or not isinstance(self.piles, tuple) \
                or not 1 <= len(self.piles) <= MAX_BUNDLE_PILES \
                or self.last - self.first + 1 != len(self.piles) \
                or any(not valid_fid(oid) for oid in self.piles) \
                or len(set(self.piles)) != len(self.piles) \
                or not valid_fid(self.pack_oid) \
                or type(self.pack_bytes) is not int \
                or not 1 <= self.pack_bytes <= MAX_BUNDLE_PACK_BYTES \
                or not isinstance(self.slices, tuple) \
                or len(self.slices) != len(self.piles) \
                or any(not isinstance(item, PackSlice) for item in self.slices):
            raise ValueError("writer bundle descriptor")

        expected = 0
        for item in self.slices:
            if item.offset != expected:
                raise ValueError("writer bundle noncontiguous pack table")
            expected += item.length
        if expected != self.pack_bytes:
            raise ValueError("writer bundle pack length")


def bundle_document(bundle):
    if not isinstance(bundle, WriterBundle):
        raise TypeError("writer bundle")
    return {
        "device": bundle.device,
        "first": bundle.first,
        "format": BUNDLE_FORMAT,
        "last": bundle.last,
        "pack": {
            "bytes": bundle.pack_bytes,
            "oid": bundle.pack_oid,
            "table": [
                [item.offset, item.length] for item in bundle.slices
            ],
        },
        "piles": list(bundle.piles),
        "workspace": bundle.workspace,
    }


def encode_bundle(bundle):
    """Encode one canonical descriptor, never its possibly large pack body."""
    try:
        raw = canon(bundle_document(bundle))
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle encoding") from error
    if len(raw) > MAX_BUNDLE_DESCRIPTOR_BYTES:
        raise PayloadTooLarge("writer bundle descriptor too large")
    return raw


def _pack_from_document(value):
    if not isinstance(value, dict) or set(value) != {
            "bytes", "oid", "table"} \
            or not isinstance(value.get("table"), list) \
            or len(value["table"]) > MAX_BUNDLE_PILES:
        raise ValueError("writer bundle pack table")
    slices = []
    for item in value["table"]:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError("writer bundle pack table")
        slices.append(PackSlice(item[0], item[1]))
    return value["oid"], value["bytes"], tuple(slices)


def decode_bundle(
        raw, *, workspace=None, device=None, first=None, last=None,
        expected_oid=None):
    """Decode canonical bytes and optionally require their exact bindings."""
    try:
        value = decode_json(
            raw, MAX_BUNDLE_DESCRIPTOR_BYTES, "writer bundle")
        if not isinstance(value, dict) or set(value) != {
                "device", "first", "format", "last", "pack", "piles",
                "workspace"} \
                or value.get("format") != BUNDLE_FORMAT \
                or not isinstance(value.get("piles"), list) \
                or len(value["piles"]) > MAX_BUNDLE_PILES:
            raise ValueError("writer bundle shape")
        pack_oid, pack_bytes, slices = _pack_from_document(value["pack"])
        bundle = WriterBundle(
            value["workspace"],
            value["device"],
            value["first"],
            value["last"],
            tuple(value["piles"]),
            pack_oid,
            pack_bytes,
            slices,
        )
        if workspace is not None and bundle.workspace != workspace \
                or device is not None and bundle.device != device \
                or first is not None and bundle.first != first \
                or last is not None and bundle.last != last \
                or expected_oid is not None and (
                    not valid_fid(expected_oid) or h(raw) != expected_oid) \
                or encode_bundle(bundle) != raw:
            raise ValueError("writer bundle binding")
        return bundle
    except PayloadTooLarge:
        raise
    except (KeyError, RecursionError, TypeError, UnicodeError, ValueError) \
            as error:
        raise InvalidWriterBundle("writer bundle encoding") from error


def bundle_oid(value):
    raw = encode_bundle(value) if isinstance(value, WriterBundle) else value
    decode_bundle(raw)
    return h(raw)


def publication_rows(bundle):
    """Return the exact logical ordinal/OID rows, without locator evidence."""
    if not isinstance(bundle, WriterBundle):
        raise TypeError("writer bundle")
    return tuple(
        (bundle.first + offset, oid)
        for offset, oid in enumerate(bundle.piles)
    )


def validate_prefix_extension(accepted, candidate):
    """Prove that a replacement tail only appends logical publications.

    Physical pack OIDs, sizes, and tables intentionally do not participate.
    A writer may repack the same logical prefix; every receiver still verifies
    the candidate's physical slices before evaluating its new piles.
    """
    if not isinstance(accepted, WriterBundle) \
            or not isinstance(candidate, WriterBundle):
        raise TypeError("writer bundle")
    if (candidate.workspace, candidate.device, candidate.first) != (
            accepted.workspace, accepted.device, accepted.first):
        raise InvalidWriterBundle("writer bundle binding changed")
    if candidate.last < accepted.last:
        raise InvalidWriterBundle("writer bundle rollback")
    if candidate.piles[:len(accepted.piles)] != accepted.piles:
        raise InvalidWriterBundle("writer bundle rewrote publication")
    return publication_rows(candidate)[len(accepted.piles):]


def pack_signed_piles(workspace, device, first, raw_piles):
    """Build one descriptor and concat pack from canonical signed-pile bytes.

    This checks each portable pile's signature and workspace/device binding.
    Semantic closure remains the responsibility of the ordinary
    :class:`core.close.ClosedPileEvaluator` before publication and again after
    extraction.
    """
    if not valid_fid(workspace) or not valid_fid(device) \
            or type(first) is not int \
            or not 1 <= first <= MAX_WRITER_SEQUENCE:
        raise InvalidWriterBundle("writer bundle publication binding")
    try:
        raws = tuple(islice(raw_piles, MAX_BUNDLE_PILES + 1))
    except (TypeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pile source") from error
    if not raws:
        raise InvalidWriterBundle("writer bundle is empty")
    if len(raws) > MAX_BUNDLE_PILES:
        raise PayloadTooLarge("writer bundle has too many piles")
    if first + len(raws) - 1 > MAX_WRITER_SEQUENCE:
        raise InvalidWriterBundle("writer bundle publication range")

    piles = []
    slices = []
    seen = set()
    offset = 0
    try:
        for raw in raws:
            if not isinstance(raw, bytes) or not raw:
                raise ValueError("writer bundle pile bytes")
            decode_signed_pile(raw, workspace=workspace, writer=device)
            length = len(raw)
            if offset + length > MAX_BUNDLE_PACK_BYTES:
                raise PayloadTooLarge("writer bundle pack too large")
            oid = h(raw)
            if oid in seen:
                raise ValueError("writer bundle duplicate pile")
            seen.add(oid)
            piles.append(oid)
            slices.append(PackSlice(offset, length))
            offset += length
        pack = b"".join(raws)
        bundle = WriterBundle(
            workspace,
            device,
            first,
            first + len(piles) - 1,
            tuple(piles),
            h(pack),
            len(pack),
            tuple(slices),
        )
        encode_bundle(bundle)
        return bundle, pack
    except InvalidPile as error:
        raise InvalidWriterBundle("writer bundle pile binding") from error
    except PayloadTooLarge:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pile binding") from error


def _slice_for(bundle, publication):
    if not isinstance(bundle, WriterBundle) \
            or type(publication) is not int \
            or not bundle.first <= publication <= bundle.last:
        raise InvalidWriterBundle("writer bundle publication")
    at = publication - bundle.first
    return bundle.piles[at], bundle.slices[at]


def verify_pile_slice(bundle, publication, raw):
    """Verify one ranged response without trusting its table or provider.

    The whole pack need not be downloaded.  The expected pile OID authenticates
    the exact returned bytes; the signed-pile codec then authenticates their
    workspace and publishing device.  The caller still evaluates closure.
    """
    try:
        oid, location = _slice_for(bundle, publication)
        if not isinstance(raw, bytes) \
                or len(raw) != location.length \
                or h(raw) != oid:
            raise ValueError("writer bundle pile integrity")
        decode_signed_pile(
            raw, workspace=bundle.workspace, writer=bundle.device)
        return raw
    except InvalidWriterBundle:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pile integrity") from error


def extract_pile_bytes(bundle, pack, publication):
    """Extract and verify one pile from an already downloaded complete pack."""
    try:
        if not isinstance(pack, bytes) \
                or len(pack) != bundle.pack_bytes \
                or h(pack) != bundle.pack_oid:
            raise ValueError("writer bundle pack integrity")
        _oid, location = _slice_for(bundle, publication)
        raw = pack[location.offset:location.offset + location.length]
        return verify_pile_slice(bundle, publication, raw)
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        if isinstance(error, InvalidWriterBundle):
            raise
        raise InvalidWriterBundle("writer bundle pack integrity") from error


__all__ = (
    "BUNDLE_FORMAT",
    "InvalidWriterBundle",
    "MAX_BUNDLE_DESCRIPTOR_BYTES",
    "MAX_BUNDLE_PACK_BYTES",
    "MAX_BUNDLE_PILES",
    "PackSlice",
    "WriterBundle",
    "bundle_document",
    "bundle_oid",
    "decode_bundle",
    "encode_bundle",
    "extract_pile_bytes",
    "pack_signed_piles",
    "publication_rows",
    "validate_prefix_extension",
    "verify_pile_slice",
)
