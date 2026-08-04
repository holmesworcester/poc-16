"""Compact authenticated contiguous writer-sequence runs."""
import struct
from dataclasses import dataclass

from .fact import canonical, decode_slice

from .log import Head, WriterLog, decode_head, encode_head, verify_head
from .tree import _leaf, _node, inclusion


@dataclass(frozen=True)
class Run:
    writer: bytes
    lo: int
    hi: int
    facts: bytes
    head: Head
    paths: tuple[tuple[bytes, ...], ...]


def prove_run(log: WriterLog, lo: int, hi: int) -> Run:
    facts = log.slice(lo, hi)
    head = log.head()
    boundaries = (lo,) if hi - lo == 1 else (lo, hi - 1)
    paths = tuple(
        inclusion(log, seq) if log._secret is not None else log._paths[seq]
        for seq in boundaries
    )
    return Run(log.writer, lo, hi, facts, head, paths)


def _proof_nodes(run):
    if not isinstance(run, Run) or run.writer != run.head.writer \
                or type(run.lo) is not int or type(run.hi) is not int \
                or run.lo < 0 or run.hi <= run.lo or run.hi > run.head.seq + 1 \
                or not verify_head(run.head):
        raise ValueError("writer run")
    facts = decode_slice(run.facts, run.hi - run.lo)
    boundaries = (run.lo,) if len(facts) == 1 else (run.lo, run.hi - 1)
    if not isinstance(run.paths, tuple) or len(run.paths) != len(boundaries):
        raise ValueError("writer run paths")
    width = 1 << run.head.seq.bit_length()
    height = width.bit_length() - 1
    known = {
        (0, seq): _leaf(seq, canonical(fact))
        for seq, fact in zip(range(run.lo, run.hi), facts)
    }
    for boundary, path in zip(boundaries, run.paths):
        if not isinstance(path, tuple) or len(path) != height:
            raise ValueError("writer run path")
        index = boundary
        for level, sibling in enumerate(path):
            if not isinstance(sibling, bytes) or len(sibling) != 32:
                raise ValueError("writer run path")
            key = (level, index ^ 1)
            if key in known and known[key] != sibling:
                raise ValueError("writer run path collision")
            known[key] = sibling
            index //= 2
    for level in range(height):
        indexes = {index for lev, index in known if lev == level}
        for left in sorted(index & ~1 for index in indexes):
            a, b = known.get((level, left)), known.get((level, left + 1))
            if a is not None and b is not None:
                value = _node(a, b)
                key = (level + 1, left // 2)
                if key in known and known[key] != value:
                    raise ValueError("writer run proof collision")
                known[key] = value
    return facts, known, height


def verify_run(run: Run) -> bool:
    try:
        _facts, known, height = _proof_nodes(run)
        return known.get((height, 0)) == run.head.root
    except (TypeError, ValueError, UnicodeError):
        return False


def leaf_paths(run):
    """Derive reusable ordinary inclusion paths for every proved leaf."""
    facts, known, height = _proof_nodes(run)
    if known.get((height, 0)) != run.head.root:
        raise ValueError("writer run proof")
    result = {}
    for seq in range(run.lo, run.hi):
        index = seq
        path = []
        for level in range(height):
            path.append(known[(level, index ^ 1)])
            index //= 2
        result[seq] = tuple(path)
    return result


def carry(log: WriterLog, seq: int) -> Run:
    """Single-fact run, the universal carry format."""
    return prove_run(log, seq, seq + 1)


RUN_MAGIC = b"P16R2\x00"


def encode_run(run):
    if not verify_run(run):
        raise ValueError("invalid writer run")
    if run.lo >= 1 << 64 or run.hi >= 1 << 64 \
            or len(run.facts) >= 1 << 32 or len(run.paths) >= 1 << 8:
        raise ValueError("writer run bounds")
    raw = bytearray(RUN_MAGIC)
    raw.extend(run.writer)
    raw.extend(struct.pack(">QQI", run.lo, run.hi, len(run.facts)))
    raw.extend(run.facts)
    head = encode_head(run.head)
    raw.extend(struct.pack(">H", len(head)))
    raw.extend(head)
    raw.extend(struct.pack(">B", len(run.paths)))
    for path in run.paths:
        if len(path) >= 1 << 16:
            raise ValueError("writer run path")
        raw.extend(struct.pack(">H", len(path)))
        for item in path:
            raw.extend(item)
    return bytes(raw)


def decode_run(raw):
    if not isinstance(raw, bytes) or not raw.startswith(RUN_MAGIC):
        raise ValueError("writer run")
    try:
        cursor = len(RUN_MAGIC)

        def take(size):
            nonlocal cursor
            if size < 0 or cursor + size > len(raw):
                raise ValueError
            value = raw[cursor:cursor + size]
            cursor += size
            return value

        writer = take(32)
        lo, hi, facts_size = struct.unpack(">QQI", take(20))
        facts = take(facts_size)
        head_size = struct.unpack(">H", take(2))[0]
        head = decode_head(take(head_size))
        path_count = struct.unpack(">B", take(1))[0]
        paths = []
        for _path in range(path_count):
            count = struct.unpack(">H", take(2))[0]
            paths.append(tuple(take(32) for _item in range(count)))
        if cursor != len(raw):
            raise ValueError
        run = Run(
            writer, lo, hi, facts, head, tuple(paths),
        )
    except (TypeError, ValueError, UnicodeError, struct.error) as error:
        raise ValueError("writer run") from error
    if not verify_run(run) or encode_run(run) != raw:
        raise ValueError("writer run")
    return run
