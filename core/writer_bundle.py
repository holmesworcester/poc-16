"""Logical writer bundles and optional, untrusted physical pack locators.

``WriterBundle`` is the complete logical value authenticated by a writer head:
one contiguous publication range and its ordered signed-pile OIDs.  It says
nothing about storage layout.  A live tail can therefore prefix-extend by
publishing only a new small bundle descriptor.

``BundlePack`` is a replaceable locator bound to one bundle OID.  Multiple pack
layouts may locate the same logical bundle.  A consumer verifies that binding,
the returned range's expected pile hash, and the pile signature before passing
the pile to the ordinary closed-pile evaluator.  A locator is never admission
evidence.
"""
from dataclasses import dataclass, field
from itertools import islice

from .close import decode_signed_pile
from .crypto import h
from .fact import canon
from .ingress import InvalidPile
from .limits import MAX_OBJECT_BYTES, MIB, PayloadTooLarge, decode_json
from .shape import valid_fid
from .writer_tree import MAX_WRITER_SEQUENCE


BUNDLE_FORMAT = "poc16-writer-bundle-v1"
PACK_FORMAT = "poc16-writer-bundle-pack-v1"
MAX_BUNDLE_DESCRIPTOR_BYTES = MAX_OBJECT_BYTES
MAX_BUNDLE_PACK_TABLE_BYTES = MAX_OBJECT_BYTES
# 95 MiB is below a 100,000,000-byte front door. Deployments may be stricter.
MAX_BUNDLE_PACK_BYTES = 95 * MIB
# Both a worst-case logical descriptor and locator table fit below four MiB.
MAX_BUNDLE_PILES = 32_768


class InvalidWriterBundle(ValueError):
    """Logical bundle bytes, pack locators, or extracted bytes are invalid."""


@dataclass(frozen=True, slots=True)
class PackSlice:
    """One untrusted half-open byte range in a physical pack object."""

    offset: int
    length: int

    def __post_init__(self):
        if type(self.offset) is not int or self.offset < 0 \
                or type(self.length) is not int or self.length <= 0 \
                or self.offset + self.length > MAX_BUNDLE_PACK_BYTES:
            raise ValueError("writer bundle slice")


def _bundle_document(workspace, device, first, last, piles):
    return {
        "device": device,
        "first": first,
        "format": BUNDLE_FORMAT,
        "last": last,
        "piles": list(piles),
        "workspace": workspace,
    }


@dataclass(frozen=True, slots=True)
class WriterBundle:
    """Immutable logical publication history, independent of packing."""

    workspace: str
    device: str
    first: int
    last: int
    piles: tuple[str, ...]
    _oid: str = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.device) \
                or type(self.first) is not int \
                or type(self.last) is not int \
                or not 1 <= self.first <= self.last <= MAX_WRITER_SEQUENCE \
                or not isinstance(self.piles, tuple) \
                or not 1 <= len(self.piles) <= MAX_BUNDLE_PILES \
                or self.last - self.first + 1 != len(self.piles) \
                or any(not valid_fid(oid) for oid in self.piles) \
                or len(set(self.piles)) != len(self.piles):
            raise ValueError("writer bundle descriptor")
        raw = canon(_bundle_document(
            self.workspace, self.device, self.first, self.last, self.piles))
        if len(raw) > MAX_BUNDLE_DESCRIPTOR_BYTES:
            raise PayloadTooLarge("writer bundle descriptor too large")
        object.__setattr__(self, "_oid", h(raw))


@dataclass(frozen=True, slots=True)
class BundlePack:
    """Optional physical locator for the exact logical ``bundle_oid``."""

    bundle_oid: str
    pack_oid: str
    pack_bytes: int
    slices: tuple[PackSlice, ...]

    def __post_init__(self):
        if not valid_fid(self.bundle_oid) or not valid_fid(self.pack_oid) \
                or type(self.pack_bytes) is not int \
                or not 1 <= self.pack_bytes <= MAX_BUNDLE_PACK_BYTES \
                or not isinstance(self.slices, tuple) \
                or not 1 <= len(self.slices) <= MAX_BUNDLE_PILES \
                or any(not isinstance(item, PackSlice) for item in self.slices):
            raise ValueError("writer bundle pack")
        ordered = sorted(
            (item.offset, item.offset + item.length) for item in self.slices)
        if ordered[-1][1] > self.pack_bytes or any(
                left[1] > right[0]
                for left, right in zip(ordered, ordered[1:])):
            raise ValueError("writer bundle overlapping pack table")


def make_bundle(workspace, device, first, pile_oids):
    """Construct one bounded logical bundle from an ordered OID iterable."""
    try:
        piles = tuple(islice(pile_oids, MAX_BUNDLE_PILES + 1))
    except (TypeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pile source") from error
    if len(piles) > MAX_BUNDLE_PILES:
        raise PayloadTooLarge("writer bundle has too many piles")
    if not piles:
        raise InvalidWriterBundle("writer bundle is empty")
    try:
        return WriterBundle(
            workspace, device, first, first + len(piles) - 1, piles)
    except PayloadTooLarge:
        raise
    except (TypeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle descriptor") from error


def bundle_document(bundle):
    if not isinstance(bundle, WriterBundle):
        raise TypeError("writer bundle")
    return _bundle_document(
        bundle.workspace, bundle.device, bundle.first, bundle.last,
        bundle.piles)


def encode_bundle(bundle):
    try:
        raw = canon(bundle_document(bundle))
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle encoding") from error
    if len(raw) > MAX_BUNDLE_DESCRIPTOR_BYTES:
        raise PayloadTooLarge("writer bundle descriptor too large")
    return raw


def decode_bundle(
        raw, *, workspace=None, device=None, first=None, last=None,
        expected_oid=None):
    """Decode canonical logical bytes and optionally require exact bindings."""
    try:
        value = decode_json(
            raw, MAX_BUNDLE_DESCRIPTOR_BYTES, "writer bundle")
        if not isinstance(value, dict) or set(value) != {
                "device", "first", "format", "last", "piles", "workspace"} \
                or value.get("format") != BUNDLE_FORMAT \
                or not isinstance(value.get("piles"), list) \
                or len(value["piles"]) > MAX_BUNDLE_PILES:
            raise ValueError("writer bundle shape")
        bundle = WriterBundle(
            value["workspace"], value["device"], value["first"],
            value["last"], tuple(value["piles"]))
        if workspace is not None and bundle.workspace != workspace \
                or device is not None and bundle.device != device \
                or first is not None and bundle.first != first \
                or last is not None and bundle.last != last \
                or expected_oid is not None and (
                    not valid_fid(expected_oid) \
                    or bundle._oid != expected_oid) \
                or encode_bundle(bundle) != raw:
            raise ValueError("writer bundle binding")
        return bundle
    except PayloadTooLarge:
        raise
    except (KeyError, RecursionError, TypeError, UnicodeError, ValueError) \
            as error:
        raise InvalidWriterBundle("writer bundle encoding") from error


def bundle_oid(value):
    if isinstance(value, WriterBundle):
        return value._oid
    raw = value
    decode_bundle(raw)
    return h(raw)


def pack_document(locator):
    if not isinstance(locator, BundlePack):
        raise TypeError("writer bundle pack")
    return {
        "bundle": locator.bundle_oid,
        "format": PACK_FORMAT,
        "pack": {
            "bytes": locator.pack_bytes,
            "oid": locator.pack_oid,
        },
        "table": [[item.offset, item.length] for item in locator.slices],
    }


def encode_bundle_pack(locator):
    try:
        raw = canon(pack_document(locator))
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pack encoding") from error
    if len(raw) > MAX_BUNDLE_PACK_TABLE_BYTES:
        raise PayloadTooLarge("writer bundle pack table too large")
    return raw


def decode_bundle_pack(raw, *, expected_bundle=None, expected_oid=None):
    """Decode one canonical locator; no locator grants logical authority."""
    try:
        value = decode_json(
            raw, MAX_BUNDLE_PACK_TABLE_BYTES, "writer bundle pack")
        if not isinstance(value, dict) or set(value) != {
                "bundle", "format", "pack", "table"} \
                or value.get("format") != PACK_FORMAT \
                or not isinstance(value.get("pack"), dict) \
                or set(value["pack"]) != {"bytes", "oid"} \
                or not isinstance(value.get("table"), list) \
                or not 1 <= len(value["table"]) <= MAX_BUNDLE_PILES:
            raise ValueError("writer bundle pack shape")
        slices = []
        for item in value["table"]:
            if not isinstance(item, list) or len(item) != 2:
                raise ValueError("writer bundle pack table")
            slices.append(PackSlice(item[0], item[1]))
        locator = BundlePack(
            value["bundle"], value["pack"]["oid"],
            value["pack"]["bytes"], tuple(slices))
        if expected_bundle is not None \
                and locator.bundle_oid != expected_bundle \
                or expected_oid is not None and (
                    not valid_fid(expected_oid) or h(raw) != expected_oid) \
                or encode_bundle_pack(locator) != raw:
            raise ValueError("writer bundle pack binding")
        return locator
    except PayloadTooLarge:
        raise
    except (KeyError, RecursionError, TypeError, UnicodeError, ValueError) \
            as error:
        raise InvalidWriterBundle("writer bundle pack encoding") from error


def bundle_pack_oid(value):
    raw = encode_bundle_pack(value) if isinstance(value, BundlePack) else value
    decode_bundle_pack(raw)
    return h(raw)


def publication_rows(bundle):
    if not isinstance(bundle, WriterBundle):
        raise TypeError("writer bundle")
    return tuple(
        (bundle.first + offset, oid)
        for offset, oid in enumerate(bundle.piles))


def validate_prefix_extension(accepted, candidate):
    """Prove that a tail replacement only appends logical publications."""
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


def _bounded_raws(raw_piles):
    try:
        raws = tuple(islice(raw_piles, MAX_BUNDLE_PILES + 1))
    except (TypeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pile source") from error
    if len(raws) > MAX_BUNDLE_PILES:
        raise PayloadTooLarge("writer bundle has too many piles")
    if not raws:
        raise InvalidWriterBundle("writer bundle is empty")
    return raws


def pack_bundle(bundle, raw_piles):
    """Construct the canonical concat locator for an existing logical bundle."""
    if not isinstance(bundle, WriterBundle):
        raise TypeError("writer bundle")
    raws = _bounded_raws(raw_piles)
    if len(raws) != len(bundle.piles):
        raise InvalidWriterBundle("writer bundle pack count")
    slices = []
    offset = 0
    try:
        for expected, raw in zip(bundle.piles, raws):
            if not isinstance(raw, bytes) or not raw:
                raise ValueError("writer bundle pile bytes")
            decode_signed_pile(
                raw, workspace=bundle.workspace, writer=bundle.device)
            if h(raw) != expected:
                raise ValueError("writer bundle pile order")
            if offset + len(raw) > MAX_BUNDLE_PACK_BYTES:
                raise PayloadTooLarge("writer bundle pack too large")
            slices.append(PackSlice(offset, len(raw)))
            offset += len(raw)
        body = b"".join(raws)
        locator = BundlePack(
            bundle_oid(bundle), h(body), len(body), tuple(slices))
        encode_bundle_pack(locator)
        return locator, body
    except InvalidPile as error:
        raise InvalidWriterBundle("writer bundle pile binding") from error
    except PayloadTooLarge:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pile binding") from error


def pack_signed_piles(workspace, device, first, raw_piles):
    """Build a logical bundle and one optional concat pack in one pass."""
    raws = _bounded_raws(raw_piles)
    try:
        bundle = make_bundle(
            workspace, device, first, (h(raw) for raw in raws))
    except PayloadTooLarge:
        raise
    except (TypeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pile binding") from error
    locator, body = pack_bundle(bundle, raws)
    return bundle, locator, body


def _slice_for(bundle, locator, publication):
    if not isinstance(bundle, WriterBundle) \
            or not isinstance(locator, BundlePack) \
            or locator.bundle_oid != bundle_oid(bundle) \
            or len(locator.slices) != len(bundle.piles):
        raise InvalidWriterBundle("writer bundle pack binding")
    if type(publication) is not int \
            or not bundle.first <= publication <= bundle.last:
        raise InvalidWriterBundle("writer bundle publication")
    at = publication - bundle.first
    return bundle.piles[at], locator.slices[at]


def verify_pile_slice(bundle, locator, publication, raw):
    """Verify one ranged response without trusting its locator or provider."""
    try:
        oid, location = _slice_for(bundle, locator, publication)
        if not isinstance(raw, bytes) \
                or len(raw) != location.length or h(raw) != oid:
            raise ValueError("writer bundle pile integrity")
        decode_signed_pile(
            raw, workspace=bundle.workspace, writer=bundle.device)
        return raw
    except InvalidWriterBundle:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterBundle("writer bundle pile integrity") from error


def extract_pile_bytes(bundle, locator, pack, publication):
    """Verify a complete pack, then extract and verify one logical pile."""
    try:
        if not isinstance(pack, bytes) \
                or len(pack) != locator.pack_bytes \
                or h(pack) != locator.pack_oid:
            raise ValueError("writer bundle pack integrity")
        _oid, location = _slice_for(bundle, locator, publication)
        raw = pack[location.offset:location.offset + location.length]
        return verify_pile_slice(bundle, locator, publication, raw)
    except InvalidWriterBundle:
        raise
    except (AttributeError, RecursionError, TypeError, UnicodeError, ValueError) \
            as error:
        raise InvalidWriterBundle("writer bundle pack integrity") from error


__all__ = (
    "BUNDLE_FORMAT",
    "PACK_FORMAT",
    "BundlePack",
    "InvalidWriterBundle",
    "MAX_BUNDLE_DESCRIPTOR_BYTES",
    "MAX_BUNDLE_PACK_BYTES",
    "MAX_BUNDLE_PACK_TABLE_BYTES",
    "MAX_BUNDLE_PILES",
    "PackSlice",
    "WriterBundle",
    "bundle_document",
    "bundle_oid",
    "bundle_pack_oid",
    "decode_bundle",
    "decode_bundle_pack",
    "encode_bundle",
    "encode_bundle_pack",
    "extract_pile_bytes",
    "make_bundle",
    "pack_bundle",
    "pack_document",
    "pack_signed_piles",
    "publication_rows",
    "validate_prefix_extension",
    "verify_pile_slice",
)
