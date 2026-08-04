"""Optional source-local transfer hints for authenticated writer-tree rows.

The caller supplies rows selected by the signed logical writer tree.  This
module may locate those exact piles in source-local concat packs, but a layout
page never contributes a row or an OID.  Every failed hint falls back to the
ordinary immutable pile object.

Pack bytes travel through ``copy_pack`` and large loose piles through the
source's direct object reader; neither widens buffered semantic-object reads.
The pack callback performs :func:`core.pack_access.copy_pack_get` against the
ordinary HTTP response while writing chunks into the supplied sink. The sinks
below avoid assembling a second contiguous whole-pack body; the current
consumer still retains the complete candidate suffix until its all-or-nothing
semantic commit.
"""
from collections import defaultdict
import inspect

from .crypto import h
from .limits import MAX_SEMANTIC_PILE_BYTES
from .pack_access import PackOpen
from .shape import valid_fid
from .writer_layout import (
    MAX_LAYOUT_PAGE_BYTES,
    InvalidWriterLayout,
    decode_layout_page_at,
    layout_page_key,
    placement_for,
    verify_pile_slice,
    window_start,
)
from .writer_tree import parse_leaf_key


async def _maybe_await(value):
    return await value if inspect.isawaitable(value) else value


class _ExactSink:
    """Collect one already-bounded pile range from streamed HTTP chunks."""

    def __init__(self, length):
        self.length = length
        self.value = bytearray()

    def write(self, chunk):
        if len(self.value) + len(chunk) > self.length:
            raise InvalidWriterLayout("writer pack slice length")
        self.value.extend(chunk)

    def finish(self):
        if len(self.value) != self.length:
            raise InvalidWriterLayout("writer pack slice length")
        return bytes(self.value)


class _PlacementSink:
    """Split a streamed whole pack at its declared complete-pile boundaries."""

    def __init__(self, placement):
        self.placement = placement
        self.buffers = [bytearray() for _ in placement.lengths]
        self.index = 0
        self.total = 0

    def write(self, chunk):
        self.total += len(chunk)
        if self.total > self.placement.pack_bytes:
            raise InvalidWriterLayout("writer pack length")
        view = memoryview(chunk)
        while view:
            if self.index >= len(self.buffers):
                raise InvalidWriterLayout("writer pack length")
            target = self.buffers[self.index]
            remaining = self.placement.lengths[self.index] - len(target)
            take = min(remaining, len(view))
            target.extend(view[:take])
            view = view[take:]
            if len(target) == self.placement.lengths[self.index]:
                self.index += 1

    def finish(self):
        if self.total != self.placement.pack_bytes \
                or self.index != len(self.buffers):
            raise InvalidWriterLayout("writer pack length")
        return tuple(bytes(value) for value in self.buffers)


def _rows(values, workspace, device):
    if not valid_fid(workspace) or not valid_fid(device):
        raise ValueError("writer layout fetch identity")
    try:
        rows = tuple(
            (parse_leaf_key(key), oid)
            for key, oid in values
        )
    except (TypeError, ValueError) as error:
        raise ValueError("writer layout fetch rows") from error
    sequences = tuple(sequence for sequence, _oid in rows)
    if any(not valid_fid(oid) for _sequence, oid in rows) \
            or sequences != tuple(sorted(set(sequences))):
        raise ValueError("writer layout fetch rows")
    return rows


def _verified_loose(raw, oid):
    if not isinstance(raw, bytes) \
            or len(raw) > MAX_SEMANTIC_PILE_BYTES or h(raw) != oid:
        raise ValueError("repository object integrity")
    return raw


async def fetch_layout_piles(
        workspace, device, rows, *, read_layout, copy_pack, read_loose):
    """Recover exact signed-tree rows using optional source-local layouts.

    ``read_layout(key, maximum)`` returns one directly addressed page or
    ``None``. ``copy_pack(opened, write)`` streams one exact ordinary-HTTP GET
    into ``write`` and returns its byte count. ``read_loose(oids, maximum)``
    returns the corresponding normal immutable pile bodies in order.

    Page and pack failures are recoverable hints.  Loose-object failure is not:
    the signed tree selected that OID, so the mirror must reject the candidate
    rather than accepting an incomplete suffix.
    """
    if not all(callable(callback) for callback in (
            read_layout, copy_pack, read_loose)):
        raise TypeError("writer layout fetch callbacks")
    selected = _rows(rows, workspace, device)
    if not selected:
        return ()

    by_window = defaultdict(list)
    for sequence, oid in selected:
        by_window[window_start(sequence)].append((sequence, oid))

    recovered = {}
    for start, wanted in by_window.items():
        key = layout_page_key(workspace, device, start)
        try:
            raw_page = await _maybe_await(
                read_layout(key, MAX_LAYOUT_PAGE_BYTES))
            if raw_page is None:
                continue
            if not isinstance(raw_page, bytes) \
                    or len(raw_page) > MAX_LAYOUT_PAGE_BYTES:
                raise InvalidWriterLayout("writer layout page")
            page = decode_layout_page_at(key, raw_page)
        except Exception:
            # Layout metadata is only a locator.  Even provider errors may be
            # source-path-specific, while the canonical loose object remains
            # available through the ordinary object path.
            continue

        placements = defaultdict(list)
        for sequence, oid in wanted:
            placement = placement_for(page, sequence)
            if placement is not None:
                placements[placement].append((sequence, oid))

        for placement, placement_rows in placements.items():
            sequences = tuple(sequence for sequence, _oid in placement_rows)
            whole = sequences == tuple(range(
                placement.first, placement.last + 1))
            if whole:
                opened = PackOpen(
                    "GET", placement.pack_oid, placement.pack_bytes)
                sink = _PlacementSink(placement)
                try:
                    copied = await _maybe_await(
                        copy_pack(opened, sink.write))
                    if copied != placement.pack_bytes:
                        raise InvalidWriterLayout("writer pack length")
                    values = sink.finish()
                    expected = dict(placement_rows)
                    checked = tuple(
                        verify_pile_slice(
                            placement,
                            placement.first + index,
                            value,
                            expected[placement.first + index],
                            workspace,
                            device,
                        )
                        for index, value in enumerate(values)
                    )
                except Exception:
                    continue
                recovered.update(zip(sequences, checked))
                continue

            # A partial/resumed logical difference must not download the
            # surrounding already-known piles merely to authenticate a range.
            # The signed tree supplies the expected pile OID for each slice.
            pack_failed = False
            for sequence, oid in placement_rows:
                if pack_failed:
                    break
                offset, length = placement.byte_range(sequence)
                opened = PackOpen(
                    "GET", placement.pack_oid, placement.pack_bytes,
                    offset, length)
                sink = _ExactSink(length)
                try:
                    copied = await _maybe_await(
                        copy_pack(opened, sink.write))
                    if copied != length:
                        raise InvalidWriterLayout("writer pack slice length")
                    recovered[sequence] = verify_pile_slice(
                        placement, sequence, sink.finish(), oid,
                        workspace, device)
                except Exception:
                    # Avoid repeatedly opening one known-bad pack in the same
                    # turn; all still-missing rows fall through together.
                    recovered.pop(sequence, None)
                    pack_failed = True

    missing = tuple(
        (sequence, oid) for sequence, oid in selected
        if sequence not in recovered
    )
    if missing:
        loose = await _maybe_await(read_loose(
            tuple(oid for _sequence, oid in missing),
            MAX_SEMANTIC_PILE_BYTES,
        ))
        if not isinstance(loose, (tuple, list)) \
                or len(loose) != len(missing):
            raise ValueError("repository object batch")
        for (sequence, oid), raw in zip(missing, loose):
            recovered[sequence] = _verified_loose(raw, oid)

    return tuple(recovered[sequence] for sequence, _oid in selected)


__all__ = ("fetch_layout_piles",)
