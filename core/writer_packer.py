"""Optional sender-side packing of established writer-log piles.

Packing is physical maintenance, never publication.  The caller supplies one
fixed-window snapshot of the signed logical tree and this actor fills only the
first uncovered contiguous run.  It establishes the immutable concat pack
before CAS-rebasing the source-local layout page.  Any failure leaves the
ordinary loose pile objects, writer tree, and writer head untouched.

``establish_pack`` receives ``(placement, chunks)`` and must return
``CREATED`` only after the complete create-only write succeeds, or ``EXISTS``
only after verifying that the incumbent bytes equal those chunks.  An unknown
or failed create must raise; it must never be reported as ``EXISTS``.
"""
from dataclasses import dataclass
import inspect
from itertools import islice

from .crypto import h
from .limits import MAX_PILE_BYTES, PayloadTooLarge
from .object_store import ABSENT, CREATED, EXISTS, CreateResult, Versioned
from .shape import valid_fid
from .writer_layout import (
    MAX_LAYOUT_PACK_BYTES,
    WINDOW_PILES,
    InvalidWriterLayout,
    LayoutPage,
    PackPlacement,
    build_pack,
    decode_layout_page_at,
    layout_page_key,
    placement_for,
    publish_placements,
    window_end,
    window_start,
)


DEFAULT_PROMPT_PILES = 256
DEFAULT_IDLE_MS = 1_000
DEFAULT_PUBLISH_ATTEMPTS = 8
MAX_PUBLISH_ATTEMPTS = 32


@dataclass(frozen=True, slots=True)
class LoosePile:
    """One signed-tree row whose normal immutable object already exists."""

    sequence: int
    oid: str

    def __post_init__(self):
        try:
            window_start(self.sequence)
        except ValueError as error:
            raise ValueError("writer packer row") from error
        if not valid_fid(self.oid):
            raise ValueError("writer packer row")


@dataclass(frozen=True, slots=True)
class PackingPolicy:
    """Local sealing policy; none of these thresholds is protocol state."""

    prompt_bytes: int = MAX_LAYOUT_PACK_BYTES
    prompt_piles: int = DEFAULT_PROMPT_PILES
    idle_ms: int | None = DEFAULT_IDLE_MS

    def __post_init__(self):
        if type(self.prompt_bytes) is not int \
                or not 1 <= self.prompt_bytes <= MAX_LAYOUT_PACK_BYTES \
                or type(self.prompt_piles) is not int \
                or not 1 <= self.prompt_piles <= WINDOW_PILES \
                or self.idle_ms is not None and (
                    type(self.idle_ms) is not int or self.idle_ms < 1):
            raise ValueError("writer packing policy")


@dataclass(frozen=True, slots=True)
class Packed:
    """One established placement and the page that now advertises it."""

    placement: PackPlacement
    page: LayoutPage
    pile_oids: tuple[str, ...]
    establishment: CreateResult


async def _maybe_await(value):
    return await value if inspect.isawaitable(value) else value


def _bounded_rows(rows):
    try:
        rows = tuple(islice(rows, WINDOW_PILES + 1))
    except (TypeError, ValueError) as error:
        raise InvalidWriterLayout("writer packer rows") from error
    if len(rows) > WINDOW_PILES:
        raise PayloadTooLarge("writer packer has too many rows")
    if not rows:
        return ()
    if any(not isinstance(row, LoosePile) for row in rows):
        raise InvalidWriterLayout("writer packer rows")
    start = window_start(rows[0].sequence)
    previous = rows[0].sequence - 1
    for row in rows:
        if window_start(row.sequence) != start \
                or row.sequence != previous + 1:
            raise InvalidWriterLayout(
                "writer packer rows must be one contiguous window")
        previous = row.sequence
    return rows


def _first_uncovered(page, rows):
    run = []
    bounded = False
    for row in rows:
        covered = placement_for(page, row.sequence) is not None
        if not run:
            if covered:
                continue
            run.append(row)
        elif covered:
            bounded = True
            break
        else:
            run.append(row)
    if run and run[-1].sequence == window_end(page.window_start):
        bounded = True
    return tuple(run), bounded


class WriterPacker:
    """Invocation-driven optimizer for one writer's established loose rows.

    This object has no scheduler and is intentionally not called by
    ``WriterLog``.  A FullPeer, cloud maintenance request, or test harness may
    invoke the same actor after ordinary publication has completed.
    """

    def __init__(
            self, workspace, device, layout_store, read_loose,
            establish_pack, *, policy=PackingPolicy(),
            attempts=DEFAULT_PUBLISH_ATTEMPTS):
        if not valid_fid(workspace) or not valid_fid(device) \
                or not callable(read_loose) \
                or not callable(establish_pack):
            raise ValueError("writer packer binding")
        if not isinstance(policy, PackingPolicy):
            raise TypeError("writer packing policy")
        if type(attempts) is not int \
                or not 1 <= attempts <= MAX_PUBLISH_ATTEMPTS:
            raise ValueError("writer packer attempts")
        self.workspace = workspace
        self.device = device
        self.layout_store = layout_store
        self.read_loose = read_loose
        self.establish_pack = establish_pack
        self.policy = policy
        self.attempts = attempts

    async def _page(self, start):
        key = layout_page_key(self.workspace, self.device, start)
        opened = await _maybe_await(
            self.layout_store.read_versioned(key))
        if opened is ABSENT:
            return LayoutPage(self.workspace, self.device, start, ())
        if isinstance(opened, Versioned):
            return decode_layout_page_at(key, opened.value)
        raise TypeError("writer layout page read")

    async def pack(
            self, rows, *, now_ms, last_append_ms=None, force=False):
        """Pack at most one deterministic loose run, or return ``None``.

        A small open tail waits for the count/byte threshold, an idle period,
        or an explicit ``force``.  A run bounded by an existing placement or
        the end of its fixed window seals immediately so maintenance can walk
        forward without rewriting established packs.
        """
        rows = _bounded_rows(rows)
        if not rows:
            return None
        if type(now_ms) is not int or now_ms < 0 \
                or last_append_ms is not None and (
                    type(last_append_ms) is not int
                    or last_append_ms < 0) \
                or type(force) is not bool:
            raise ValueError("writer packer time")
        start = window_start(rows[0].sequence)
        page = await self._page(start)
        candidates, bounded = _first_uncovered(page, rows)
        if not candidates:
            return None

        selected = []
        raws = []
        total = 0
        threshold = capacity = False
        for row in candidates:
            raw = await _maybe_await(self.read_loose(row.oid))
            if not isinstance(raw, bytes) or not raw:
                raise InvalidWriterLayout("writer packer loose pile integrity")
            if len(raw) > MAX_PILE_BYTES:
                raise PayloadTooLarge("writer packer loose pile too large")
            if h(raw) != row.oid:
                raise InvalidWriterLayout("writer packer loose pile integrity")
            if total + len(raw) > MAX_LAYOUT_PACK_BYTES:
                if not raws:
                    raise PayloadTooLarge("writer pack too large")
                capacity = True
                break
            selected.append(row)
            raws.append(raw)
            total += len(raw)
            if len(raws) >= self.policy.prompt_piles \
                    or total >= self.policy.prompt_bytes:
                threshold = True
                break

        bounded = bounded and len(selected) == len(candidates)
        idle = self.policy.idle_ms is not None \
            and last_append_ms is not None \
            and now_ms - last_append_ms >= self.policy.idle_ms
        if not (force or idle or threshold or capacity or bounded):
            return None

        placement, body = build_pack(
            self.workspace, self.device, selected[0].sequence, raws)
        # Establishers stream the original chunks.  The builder's concat body
        # exists only long enough to derive and cross-check the placement.
        if placement.pack_oid != h(body):
            raise AssertionError("writer pack builder integrity")
        del body
        outcome = await _maybe_await(
            self.establish_pack(placement, tuple(raws)))
        if outcome not in (CREATED, EXISTS):
            raise TypeError("writer pack establishment")
        published = await publish_placements(
            self.layout_store,
            self.workspace,
            self.device,
            start,
            (placement,),
            attempts=self.attempts,
        )
        return Packed(
            placement,
            published,
            tuple(row.oid for row in selected),
            outcome,
        )


__all__ = (
    "DEFAULT_IDLE_MS",
    "DEFAULT_PUBLISH_ATTEMPTS",
    "DEFAULT_PROMPT_PILES",
    "LoosePile",
    "Packed",
    "PackingPolicy",
    "WriterPacker",
    "MAX_PUBLISH_ATTEMPTS",
)
