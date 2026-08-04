"""Canonical per-device tree identity and closed-pile leaf keys.

The tree reuses :mod:`core.merkle_map`; this module adds only the writer-bound
seed, descriptor, and gap-free logical key discipline.  A logical value is the
OID of one complete closed pile.  Physical Merkle leaves may contain several
rows, but a row is never a fragment of a pile.
"""
from dataclasses import dataclass

from . import merkle_map
from .crypto import h
from .fact import canon
from .shape import valid_fid

TREE_FORMAT = "poc16-writer-tree-v1"
LEAF_PREFIX = "pile/"

# Exact integers survive canonical JSON and JavaScript provider wrappers.
MAX_WRITER_SEQUENCE = (1 << 53) - 1
WRITER_SEQUENCE_DIGITS = len(str(MAX_WRITER_SEQUENCE))


@dataclass(frozen=True, slots=True)
class WriterTree:
    """Authenticated Merkle-map descriptor embedded in a writer head."""

    root: str
    count: int
    depth: int

    def __post_init__(self):
        if not isinstance(self.root, str) \
                or self.root and not valid_fid(self.root) \
                or type(self.count) is not int \
                or not 0 <= self.count <= MAX_WRITER_SEQUENCE \
                or type(self.depth) is not int \
                or not 0 <= self.depth <= merkle_map.MAX_PAGE_DEPTH \
                or bool(self.root) != bool(self.count) \
                or bool(self.root) != bool(self.depth):
            raise ValueError("writer tree descriptor")


EMPTY_TREE = WriterTree("", 0, 0)


def tree_document(tree):
    if not isinstance(tree, WriterTree):
        raise TypeError("writer tree")
    return {
        "count": tree.count,
        "depth": tree.depth,
        "root": tree.root,
    }


def tree_from_document(value):
    try:
        if not isinstance(value, dict) or set(value) != {
                "count", "depth", "root"}:
            raise ValueError
        return WriterTree(value["root"], value["count"], value["depth"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("writer tree descriptor") from error


def tree_from_built(built):
    if not isinstance(built, merkle_map.Built):
        raise TypeError("writer tree build")
    return WriterTree(built.root, built.count, built.page_depth)


def writer_tree_seed(workspace, device):
    """Bind identical logical rows to one workspace/device tree."""
    if not valid_fid(workspace) or not valid_fid(device):
        raise ValueError("writer tree identity")
    return h(canon([TREE_FORMAT, workspace, device]))


def leaf_key(sequence):
    """Return the fixed-width order key for one complete pile leaf."""
    if type(sequence) is not int \
            or not 1 <= sequence <= MAX_WRITER_SEQUENCE:
        raise ValueError("writer leaf sequence")
    return f"{LEAF_PREFIX}{sequence:0{WRITER_SEQUENCE_DIGITS}d}"


def parse_leaf_key(value):
    if not isinstance(value, str) \
            or len(value) != len(LEAF_PREFIX) + WRITER_SEQUENCE_DIGITS \
            or not value.startswith(LEAF_PREFIX) \
            or not value[len(LEAF_PREFIX):].isascii() \
            or not value[len(LEAF_PREFIX):].isdigit():
        raise ValueError("writer leaf key")
    sequence = int(value[len(LEAF_PREFIX):])
    if leaf_key(sequence) != value:
        raise ValueError("writer leaf key")
    return sequence


def leaf_row(sequence, pile_oid):
    """One Merkle-map row; ``pile_oid`` names an indivisible closed pile."""
    if not valid_fid(pile_oid):
        raise ValueError("writer pile oid")
    return leaf_key(sequence), pile_oid


def build_tree(workspace, device, rows, emit):
    """Build the canonical writer tree from complete logical pile rows."""
    built = merkle_map.build(
        tuple(rows), writer_tree_seed(workspace, device), emit)
    return tree_from_built(built)


def append_piles(tree, workspace, device, pile_oids, fetch, emit):
    """Path-copy append complete pile OIDs after the current final key."""
    if not isinstance(tree, WriterTree):
        raise TypeError("writer tree")
    pile_oids = tuple(pile_oids)
    changes = tuple(
        leaf_row(tree.count + offset, pile_oid)
        for offset, pile_oid in enumerate(pile_oids, 1)
    )
    if not changes:
        return tree
    built = merkle_map.update(
        tree.root,
        writer_tree_seed(workspace, device),
        changes,
        fetch,
        emit,
        expected_count=tree.count,
        expected_depth=tree.depth,
    )
    return tree_from_built(built)


async def append_piles_awaited(
        tree, workspace, device, pile_oids, fetch, emit):
    """Awaited form of :func:`append_piles` for hosted object stores."""
    if not isinstance(tree, WriterTree):
        raise TypeError("writer tree")
    pile_oids = tuple(pile_oids)
    changes = tuple(
        leaf_row(tree.count + offset, pile_oid)
        for offset, pile_oid in enumerate(pile_oids, 1)
    )
    if not changes:
        return tree
    built = await merkle_map.update_awaited(
        tree.root,
        writer_tree_seed(workspace, device),
        changes,
        fetch,
        emit,
        expected_count=tree.count,
        expected_depth=tree.depth,
    )
    return tree_from_built(built)


def tree_reader(tree, workspace, device, fetch):
    if not isinstance(tree, WriterTree) or not callable(fetch):
        raise TypeError("writer tree reader")
    return merkle_map.Reader(
        tree.root,
        writer_tree_seed(workspace, device),
        fetch,
        max_page_depth=tree.depth,
        expected_count=tree.count,
        expected_depth=tree.depth,
    )


def reachable_staged_pages(tree, workspace, device, staged):
    """Select only newly staged pages reachable from the final descriptor."""
    if not isinstance(tree, WriterTree):
        raise TypeError("writer tree")
    return merkle_map.reachable_staged_pages(
        tree.root, writer_tree_seed(workspace, device), staged)


def diff_rows(
        remote, local, workspace, device, remote_fetch, local_fetch, *,
        limit=merkle_map.MAX_RANGE_ROWS):
    """Yield exact remote-only/different rows through resumable RBSR pages."""
    if not isinstance(remote, WriterTree) \
            or not isinstance(local, WriterTree):
        raise TypeError("writer tree")
    remote_reader = tree_reader(remote, workspace, device, remote_fetch)
    local_reader = tree_reader(local, workspace, device, local_fetch)
    after = None
    while True:
        page = remote_reader.diff_page(
            local_reader, after=after, limit=limit)
        yield from page.differing
        if page.cursor is None:
            return
        after = page.cursor


async def diff_rows_awaited(
        remote, local, workspace, device, remote_fetch, local_fetch, *,
        limit=merkle_map.MAX_RANGE_ROWS):
    """Awaited iterator over the same resumable two-root RBSR differences."""
    if not isinstance(remote, WriterTree) \
            or not isinstance(local, WriterTree):
        raise TypeError("writer tree")
    remote_reader = tree_reader(remote, workspace, device, remote_fetch)
    local_reader = tree_reader(local, workspace, device, local_fetch)
    after = None
    while True:
        page = await remote_reader.diff_page_awaited(
            local_reader, after=after, limit=limit)
        for row in page.differing:
            yield row
        if page.cursor is None:
            return
        after = page.cursor


def validate_extension(accepted, candidate, workspace, device, fetch):
    """Prove that ``candidate`` only appends contiguous immutable pile rows.

    The proof compares the two current roots directly. Superseded head objects
    are unnecessary: RBSR authenticates that all accepted rows are unchanged
    and that every difference is a new suffix key.
    """
    if not isinstance(accepted, WriterTree) \
            or not isinstance(candidate, WriterTree):
        raise TypeError("writer tree")
    if candidate.count < accepted.count:
        raise ValueError("writer tree rollback")
    if candidate == accepted:
        return ()
    if candidate.count == accepted.count:
        raise ValueError("writer tree fork")
    if any(diff_rows(
            accepted, candidate, workspace, device, fetch, fetch)):
        raise ValueError("writer tree rewrote accepted row")
    additions = tuple(diff_rows(
        candidate, accepted, workspace, device, fetch, fetch))
    expected = tuple(
        leaf_key(sequence)
        for sequence in range(accepted.count + 1, candidate.count + 1)
    )
    if tuple(key for key, _ in additions) != expected \
            or any(not valid_fid(oid) for _, oid in additions):
        raise ValueError("writer tree noncontiguous extension")
    return additions


async def validate_extension_awaited(
        accepted, candidate, workspace, device, candidate_fetch,
        accepted_fetch):
    """Awaited cross-store proof of a contiguous immutable tree extension."""
    if not isinstance(accepted, WriterTree) \
            or not isinstance(candidate, WriterTree):
        raise TypeError("writer tree")
    if candidate.count < accepted.count:
        raise ValueError("writer tree rollback")
    if candidate == accepted:
        return ()
    if candidate.count == accepted.count:
        raise ValueError("writer tree fork")
    async for _row in diff_rows_awaited(
            accepted, candidate, workspace, device,
            accepted_fetch, candidate_fetch):
        raise ValueError("writer tree rewrote accepted row")
    additions = []
    async for row in diff_rows_awaited(
            candidate, accepted, workspace, device,
            candidate_fetch, accepted_fetch):
        additions.append(row)
    expected = tuple(
        leaf_key(sequence)
        for sequence in range(accepted.count + 1, candidate.count + 1)
    )
    if tuple(key for key, _ in additions) != expected \
            or any(not valid_fid(oid) for _, oid in additions):
        raise ValueError("writer tree noncontiguous extension")
    return tuple(additions)


__all__ = (
    "EMPTY_TREE",
    "LEAF_PREFIX",
    "MAX_WRITER_SEQUENCE",
    "TREE_FORMAT",
    "WRITER_SEQUENCE_DIGITS",
    "WriterTree",
    "append_piles",
    "append_piles_awaited",
    "build_tree",
    "diff_rows",
    "diff_rows_awaited",
    "leaf_key",
    "leaf_row",
    "parse_leaf_key",
    "reachable_staged_pages",
    "tree_document",
    "tree_from_built",
    "tree_from_document",
    "tree_reader",
    "validate_extension",
    "validate_extension_awaited",
    "writer_tree_seed",
)
