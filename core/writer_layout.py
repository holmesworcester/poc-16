"""Bounded source-local physical layout for a logical writer tree.

The writer tree remains the only history and authority.  A layout page merely
maps parts of one fixed publication window to immutable ordered concat packs.
Missing intervals are loose pile objects.  Relays may publish different pages,
and a stale or corrupt page can cause only a bounded fetch miss because every
recovered pile is checked against the tree-selected OID and its own signature.
"""
from dataclasses import dataclass, field
from itertools import islice

from .close import decode_signed_pile
from .crypto import h
from .fact import canon
from .ingress import InvalidPile
from .limits import (
    MAX_OBJECT_BYTES,
    MAX_WRITER_PACK_BYTES,
    WRITER_LAYOUT_WINDOW_PILES,
    PayloadTooLarge,
    decode_json,
)
from .object_store import (
    ABSENT,
    STALE,
    Applied,
    OutcomeUnknown,
    Versioned,
    async_store,
)
from .shape import valid_fid
from .writer_tree import MAX_WRITER_SEQUENCE, WRITER_SEQUENCE_DIGITS


LAYOUT_FORMAT = "poc16-writer-layout-page-v1"
LAYOUT_PREFIX = "layouts"
WINDOW_PILES = WRITER_LAYOUT_WINDOW_PILES
MAX_LAYOUT_PAGE_BYTES = MAX_OBJECT_BYTES
MAX_LAYOUT_PACK_BYTES = MAX_WRITER_PACK_BYTES


class InvalidWriterLayout(ValueError):
    """A page, pack, byte range, or writer binding is invalid."""


def window_start(sequence):
    if type(sequence) is not int \
            or not 1 <= sequence <= MAX_WRITER_SEQUENCE:
        raise ValueError("writer layout sequence")
    return 1 + ((sequence - 1) // WINDOW_PILES) * WINDOW_PILES


def window_end(start):
    if window_start(start) != start:
        raise ValueError("writer layout window")
    return min(MAX_WRITER_SEQUENCE, start + WINDOW_PILES - 1)


def layout_page_prefix(workspace, device):
    if not valid_fid(workspace) or not valid_fid(device):
        raise ValueError("writer layout identity")
    return f"{LAYOUT_PREFIX}/{workspace}/{device}/"


def layout_page_key(workspace, device, start):
    if window_start(start) != start:
        raise ValueError("writer layout window")
    return (
        f"{layout_page_prefix(workspace, device)}"
        f"{start:0{WRITER_SEQUENCE_DIGITS}d}"
    )


def parse_layout_page_key(key):
    parts = key.split("/") if isinstance(key, str) else ()
    if len(parts) != 4 or parts[0] != LAYOUT_PREFIX \
            or len(parts[3]) != WRITER_SEQUENCE_DIGITS \
            or not parts[3].isascii() or not parts[3].isdigit():
        raise InvalidWriterLayout("writer layout key")
    try:
        start = int(parts[3])
        if layout_page_key(parts[1], parts[2], start) != key:
            raise ValueError
    except ValueError as error:
        raise InvalidWriterLayout("writer layout key") from error
    return parts[1], parts[2], start


MAX_LAYOUT_PAGE_KEY_BYTES = len(layout_page_key(
    "0" * 64, "0" * 64, window_start(MAX_WRITER_SEQUENCE)).encode("ascii"))


@dataclass(frozen=True, slots=True)
class PackPlacement:
    """One ordered concat pack; offsets and final sequence are derived."""

    first: int
    pack_oid: str
    pack_bytes: int
    lengths: tuple[int, ...]
    _offsets: tuple[int, ...] = field(
        init=False, repr=False, compare=False)

    def __post_init__(self):
        if type(self.first) is not int \
                or not 1 <= self.first <= MAX_WRITER_SEQUENCE \
                or not valid_fid(self.pack_oid) \
                or type(self.pack_bytes) is not int \
                or not 1 <= self.pack_bytes <= MAX_LAYOUT_PACK_BYTES \
                or not isinstance(self.lengths, tuple) \
                or not 1 <= len(self.lengths) <= WINDOW_PILES \
                or any(type(length) is not int or length <= 0
                       for length in self.lengths) \
                or self.first + len(self.lengths) - 1 > MAX_WRITER_SEQUENCE:
            raise ValueError("writer pack placement")
        offsets = []
        offset = 0
        for length in self.lengths:
            offsets.append(offset)
            offset += length
            if offset > MAX_LAYOUT_PACK_BYTES:
                raise ValueError("writer pack placement")
        if offset != self.pack_bytes:
            raise ValueError("writer pack length")
        object.__setattr__(self, "_offsets", tuple(offsets))

    @property
    def last(self):
        return self.first + len(self.lengths) - 1

    def byte_range(self, sequence):
        if type(sequence) is not int \
                or not self.first <= sequence <= self.last:
            raise InvalidWriterLayout("writer pack sequence")
        index = sequence - self.first
        return self._offsets[index], self.lengths[index]


@dataclass(frozen=True, slots=True)
class LayoutPage:
    """One fixed-window flat manifest; uncovered rows remain loose."""

    workspace: str
    device: str
    window_start: int
    placements: tuple[PackPlacement, ...]

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.device) \
                or window_start(self.window_start) != self.window_start \
                or not isinstance(self.placements, tuple) \
                or len(self.placements) > WINDOW_PILES \
                or any(not isinstance(item, PackPlacement)
                       for item in self.placements):
            raise ValueError("writer layout page")
        previous = self.window_start - 1
        end = window_end(self.window_start)
        for placement in self.placements:
            if placement.first <= previous or placement.last > end:
                raise ValueError("writer layout overlap")
            previous = placement.last


def page_document(page):
    if not isinstance(page, LayoutPage):
        raise TypeError("writer layout page")
    return {
        "device": page.device,
        "format": LAYOUT_FORMAT,
        "packs": [
            [item.first, item.pack_oid, item.pack_bytes, list(item.lengths)]
            for item in page.placements
        ],
        "start": page.window_start,
        "workspace": page.workspace,
    }


def encode_layout_page(page):
    try:
        raw = canon(page_document(page))
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterLayout("writer layout encoding") from error
    if len(raw) > MAX_LAYOUT_PAGE_BYTES:
        raise PayloadTooLarge("writer layout page too large")
    return raw


def decode_layout_page(
        raw, *, workspace=None, device=None, expected_start=None):
    try:
        value = decode_json(raw, MAX_LAYOUT_PAGE_BYTES, "writer layout")
        if not isinstance(value, dict) or set(value) != {
                "device", "format", "packs", "start", "workspace"} \
                or value.get("format") != LAYOUT_FORMAT \
                or not isinstance(value.get("packs"), list) \
                or len(value["packs"]) > WINDOW_PILES:
            raise ValueError("writer layout shape")
        placements = []
        for item in value["packs"]:
            if not isinstance(item, list) or len(item) != 4 \
                    or not isinstance(item[3], list):
                raise ValueError("writer layout placement")
            placements.append(PackPlacement(
                item[0], item[1], item[2], tuple(item[3])))
        page = LayoutPage(
            value["workspace"], value["device"], value["start"],
            tuple(placements))
        if workspace is not None and page.workspace != workspace \
                or device is not None and page.device != device \
                or expected_start is not None \
                and page.window_start != expected_start \
                or encode_layout_page(page) != raw:
            raise ValueError("writer layout binding")
        return page
    except PayloadTooLarge:
        raise
    except (KeyError, RecursionError, TypeError, UnicodeError, ValueError) \
            as error:
        raise InvalidWriterLayout("writer layout encoding") from error


def decode_layout_page_at(key, raw):
    workspace, device, start = parse_layout_page_key(key)
    return decode_layout_page(
        raw, workspace=workspace, device=device, expected_start=start)


def placement_for(page, sequence):
    """Return the covering pack or ``None`` for one loose publication."""
    if not isinstance(page, LayoutPage) \
            or window_start(sequence) != page.window_start:
        raise InvalidWriterLayout("writer layout lookup")
    for placement in page.placements:
        if sequence < placement.first:
            return None
        if sequence <= placement.last:
            return placement
    return None


def add_placements(page, additions):
    """Pure CAS-rebase step that fills holes and rejects interval conflicts.

    Reapplying an identical placement is an idempotent no-op.  Any other
    overlap is explicit so a concurrent packer cannot silently replace current
    coverage while intending only to add newly packed loose rows.
    """
    if not isinstance(page, LayoutPage):
        raise TypeError("writer layout page")
    try:
        additions = tuple(islice(additions, WINDOW_PILES + 1))
    except (TypeError, ValueError) as error:
        raise InvalidWriterLayout("writer layout additions") from error
    if len(additions) > WINDOW_PILES \
            or any(not isinstance(item, PackPlacement) for item in additions):
        raise InvalidWriterLayout("writer layout additions")
    current = list(page.placements)
    for addition in additions:
        if addition in current:
            continue
        if window_start(addition.first) != page.window_start \
                or addition.last > window_end(page.window_start) \
                or any(
                    addition.first <= item.last
                    and item.first <= addition.last
                    for item in current):
            raise InvalidWriterLayout("writer layout overlap")
        current.append(addition)
    return LayoutPage(
        page.workspace, page.device, page.window_start,
        tuple(sorted(current, key=lambda item: item.first)))


async def publish_placements(
        store, workspace, device, start, additions, *, attempts=8):
    """CAS one or more established packs into their source-local page.

    Independent packers may fill disjoint holes concurrently. A stale CAS is
    rebased over the page that won. An exact placement is idempotent; an
    overlap with different physical coverage is explicit and never clobbered.
    Pack bodies must already exist before this function is called.
    """
    key = layout_page_key(workspace, device, start)
    additions = tuple(additions)
    if type(attempts) is not int or not 1 <= attempts <= 32:
        raise ValueError("writer layout attempts")
    target = async_store(store)
    unknown = None
    for _ in range(attempts):
        try:
            opened = await target.read_versioned(key)
        except PayloadTooLarge:
            raise
        if opened is ABSENT:
            token = ABSENT
            current = LayoutPage(workspace, device, start, ())
        elif isinstance(opened, Versioned):
            token = opened.token
            current = decode_layout_page_at(key, opened.value)
        else:
            raise TypeError("writer layout page read")
        updated = add_placements(current, additions)
        if updated == current:
            return current
        raw = encode_layout_page(updated)
        try:
            result = await target.cas(key, token, raw)
        except OutcomeUnknown as error:
            unknown = error
            continue
        if isinstance(result, Applied):
            return updated
        if result is not STALE:
            raise TypeError("writer layout page CAS")
    raise InvalidWriterLayout("writer layout contention") from unknown


def _bounded_piles(raw_piles):
    try:
        raws = tuple(islice(raw_piles, WINDOW_PILES + 1))
    except (TypeError, ValueError) as error:
        raise InvalidWriterLayout("writer pack source") from error
    if len(raws) > WINDOW_PILES:
        raise PayloadTooLarge("writer pack has too many piles")
    if not raws:
        raise InvalidWriterLayout("writer pack is empty")
    return raws


def build_pack(workspace, device, first, raw_piles):
    """Build one ordered concat pack from bound canonical SignedPile bytes."""
    if not valid_fid(workspace) or not valid_fid(device) \
            or type(first) is not int \
            or not 1 <= first <= MAX_WRITER_SEQUENCE:
        raise InvalidWriterLayout("writer pack binding")
    raws = _bounded_piles(raw_piles)
    if first + len(raws) - 1 > window_end(window_start(first)):
        raise InvalidWriterLayout("writer pack crosses layout window")
    lengths = []
    total = 0
    try:
        for raw in raws:
            if not isinstance(raw, bytes) or not raw:
                raise ValueError("writer pack pile bytes")
            decode_signed_pile(raw, workspace=workspace, writer=device)
            total += len(raw)
            if total > MAX_LAYOUT_PACK_BYTES:
                raise PayloadTooLarge("writer pack too large")
            lengths.append(len(raw))
        body = b"".join(raws)
        return PackPlacement(
            first, h(body), len(body), tuple(lengths)), body
    except InvalidPile as error:
        raise InvalidWriterLayout("writer pack pile binding") from error
    except PayloadTooLarge:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterLayout("writer pack pile binding") from error


def verify_pile_slice(
        placement, sequence, raw, expected_pile_oid, workspace, device):
    """Verify a sparse ranged response against one tree-selected pile OID."""
    try:
        if not isinstance(placement, PackPlacement) \
                or not valid_fid(expected_pile_oid) \
                or not valid_fid(workspace) or not valid_fid(device):
            raise ValueError("writer pack slice binding")
        _offset, length = placement.byte_range(sequence)
        if not isinstance(raw, bytes) or len(raw) != length \
                or h(raw) != expected_pile_oid:
            raise ValueError("writer pack slice integrity")
        decode_signed_pile(raw, workspace=workspace, writer=device)
        return raw
    except InvalidWriterLayout:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidWriterLayout("writer pack slice integrity") from error


def verify_whole_pack(
        placement, body, expected_pile_oids, workspace, device):
    """Hash, split, and independently verify every pile in one full GET."""
    if not isinstance(placement, PackPlacement):
        raise TypeError("writer pack placement")
    try:
        expected = tuple(islice(
            expected_pile_oids, len(placement.lengths) + 1))
    except (TypeError, ValueError) as error:
        raise InvalidWriterLayout("writer pack expected piles") from error
    if len(expected) != len(placement.lengths) \
            or not isinstance(body, bytes) \
            or len(body) != placement.pack_bytes \
            or h(body) != placement.pack_oid:
        raise InvalidWriterLayout("writer pack integrity")
    out = []
    for index, oid in enumerate(expected):
        sequence = placement.first + index
        offset, length = placement.byte_range(sequence)
        raw = body[offset:offset + length]
        out.append(verify_pile_slice(
            placement, sequence, raw, oid, workspace, device))
    return tuple(out)


__all__ = (
    "LAYOUT_FORMAT",
    "LAYOUT_PREFIX",
    "MAX_LAYOUT_PACK_BYTES",
    "MAX_LAYOUT_PAGE_BYTES",
    "MAX_LAYOUT_PAGE_KEY_BYTES",
    "WINDOW_PILES",
    "InvalidWriterLayout",
    "LayoutPage",
    "PackPlacement",
    "add_placements",
    "build_pack",
    "decode_layout_page",
    "decode_layout_page_at",
    "encode_layout_page",
    "layout_page_key",
    "layout_page_prefix",
    "page_document",
    "parse_layout_page_key",
    "placement_for",
    "publish_placements",
    "verify_pile_slice",
    "verify_whole_pack",
    "window_end",
    "window_start",
)
