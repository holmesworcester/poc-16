"""Deterministic binary Merkle tree for writer sequence streams."""
import hashlib
import struct

from core.fact import canon
from core.limits import PAGE_BATCH, decode_json

EMPTY = hashlib.sha256(b"peerlog/seq/empty/v1").digest()
PAGE_FORMAT = "poc16-peer-seq-page-v1"


def _leaf(seq, raw):
    return hashlib.sha256(
        b"peerlog/seq/leaf/v1" + struct.pack(">QI", seq, len(raw)) + raw
    ).digest()


def _pad(seq):
    return hashlib.sha256(b"peerlog/seq/pad/v1" + struct.pack(">Q", seq)).digest()


def _node(left, right):
    return hashlib.sha256(b"peerlog/seq/node/v1" + left + right).digest()


def _levels(raws):
    if not raws:
        return ((EMPTY,),)
    width = 1 << (len(raws) - 1).bit_length()
    level = tuple(
        _leaf(seq, raws[seq]) if seq < len(raws) else _pad(seq)
        for seq in range(width)
    )
    levels = [level]
    while len(level) > 1:
        level = tuple(_node(level[i], level[i + 1])
                      for i in range(0, len(level), 2))
        levels.append(level)
    return tuple(levels)


def root_bytes(raws):
    return _levels(tuple(raws))[-1][0]


def _dense_raws(log):
    head = log.head()
    if head.seq < 0:
        return ()
    return tuple(log._raw(seq) for seq in range(head.seq + 1))


def root(log) -> bytes:
    raws = _dense_raws(log)
    result = root_bytes(raws)
    if result != log.head().root:
        raise ValueError("writer tree root")
    return result


def pages(log) -> tuple[bytes, ...]:
    """Deterministic bounded summaries for the current dense log."""
    head = log.head()
    result = []
    for lo in range(0, head.seq + 1, PAGE_BATCH):
        hi = min(head.seq + 1, lo + PAGE_BATCH)
        facts = tuple(log.fact(seq) for seq in range(lo, hi))
        result.append(canon([
            PAGE_FORMAT, lo, hi,
            min(fact.ts for fact in facts), max(fact.ts for fact in facts),
            root_bytes(tuple(log._raw(seq) for seq in range(lo, hi))).hex(),
        ]))
    return tuple(result)


def inclusion(log, seq: int) -> tuple[bytes, ...]:
    """Sibling-hash path proving the fact at seq against root(log)."""
    raws = _dense_raws(log)
    if type(seq) is not int or not 0 <= seq < len(raws):
        raise ValueError("writer inclusion sequence")
    levels = _levels(raws)
    index = seq
    path = []
    for level in levels[:-1]:
        path.append(level[index ^ 1])
        index //= 2
    return tuple(path)


def verify_inclusion(head, seq: int, fact_bytes: bytes,
                     path: tuple[bytes, ...]) -> bool:
    if type(seq) is not int or not 0 <= seq <= head.seq \
            or not isinstance(fact_bytes, bytes) or not isinstance(path, tuple):
        return False
    width = 1 << head.seq.bit_length()
    if len(path) != width.bit_length() - 1 \
            or any(not isinstance(item, bytes) or len(item) != 32 for item in path):
        return False
    value = _leaf(seq, fact_bytes)
    index = seq
    for sibling in path:
        value = _node(value, sibling) if index % 2 == 0 else _node(sibling, value)
        index //= 2
    return value == head.root


def ts_cut(page_bytes: tuple[bytes, ...], t0: int, t1: int) -> tuple[tuple[int, int], ...]:
    """Seq intervals whose ts summaries intersect [t0, t1)."""
    if type(t0) is not int or type(t1) is not int or t1 <= t0:
        raise ValueError("timestamp cut")
    intervals = []
    previous = 0
    for raw in page_bytes:
        value = decode_json(raw, 4096, "writer tree page")
        if not isinstance(value, list) or len(value) != 6 \
                or value[0] != PAGE_FORMAT or canon(value) != raw:
            raise ValueError("writer tree page")
        _, lo, hi, ts_min, ts_max, digest = value
        try:
            valid_digest = len(bytes.fromhex(digest)) == 32 and digest == bytes.fromhex(digest).hex()
        except (TypeError, ValueError):
            valid_digest = False
        if type(lo) is not int or type(hi) is not int or lo != previous \
                or hi <= lo or type(ts_min) is not int or type(ts_max) is not int \
                or ts_max < ts_min or not valid_digest:
            raise ValueError("writer tree page")
        previous = hi
        if ts_min < t1 and ts_max >= t0:
            intervals.append((lo, hi))
    return tuple(intervals)
