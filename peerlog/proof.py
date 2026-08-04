"""Compact authenticated contiguous writer-sequence runs."""
import base64
import json
from dataclasses import dataclass

from .fact import canonical, decode_slice
from core.fact import canon

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


RUN_FORMAT = "poc16-peer-run-v1"


def encode_run(run):
    if not verify_run(run):
        raise ValueError("invalid writer run")
    return canon({
        "facts": base64.b64encode(run.facts).decode("ascii"),
        "format": RUN_FORMAT,
        "head": base64.b64encode(encode_head(run.head)).decode("ascii"),
        "hi": run.hi,
        "lo": run.lo,
        "paths": [[item.hex() for item in path] for path in run.paths],
        "writer": run.writer.hex(),
    })


def decode_run(raw):
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {
                "facts", "format", "head", "hi", "lo", "paths", "writer"} \
                or value.get("format") != RUN_FORMAT:
            raise ValueError
        run = Run(
            bytes.fromhex(value["writer"]), value["lo"], value["hi"],
            base64.b64decode(value["facts"], validate=True),
            decode_head(base64.b64decode(value["head"], validate=True)),
            tuple(tuple(bytes.fromhex(item) for item in path)
                  for path in value["paths"]),
        )
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("writer run") from error
    if not verify_run(run) or encode_run(run) != raw:
        raise ValueError("writer run")
    return run
