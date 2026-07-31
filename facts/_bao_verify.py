"""Small pure-Python verifier for canonical Bao 0.13 range proofs.

This is adapted from ``bao-0.13.1/tests/bao.py`` by Jack O'Connor, whose
readable reference implementation is licensed ``CC0-1.0 OR Apache-2.0``.
This adaptation keeps only the BLAKE3 compression and Bao slice-decoding
parts, replaces assertions with fail-closed exceptions, and requires the
caller to supply bounded canonical bytes. It is offered under the same
``CC0-1.0 OR Apache-2.0`` terms.

The module deliberately has no native or third-party dependency. Hosted
RepositoryAppliers import fact families and therefore run this exact verifier
when admitting a file slice; the optional Rust binding remains an authoring
and cross-test accelerator only.
"""
import hmac
from io import BytesIO


_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_SCHEDULE = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8),
    (3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1),
    (10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6),
    (12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4),
    (9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7),
    (11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13),
)
_BLOCK = 64
_CHUNK = 1024
_MASK = 2**32 - 1
_CHUNK_START = 1
_CHUNK_END = 2
_PARENT = 4
_ROOT = 8


def _rotate(value, count):
    return (value >> count | value << (32 - count)) & _MASK


def _g(state, a, b, c, d, x, y):
    state[a] = (state[a] + state[b] + x) & _MASK
    state[d] = _rotate(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotate(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + y) & _MASK
    state[d] = _rotate(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotate(state[b] ^ state[c], 7)


def _round(state, words, schedule):
    _g(state, 0, 4, 8, 12, words[schedule[0]], words[schedule[1]])
    _g(state, 1, 5, 9, 13, words[schedule[2]], words[schedule[3]])
    _g(state, 2, 6, 10, 14, words[schedule[4]], words[schedule[5]])
    _g(state, 3, 7, 11, 15, words[schedule[6]], words[schedule[7]])
    _g(state, 0, 5, 10, 15, words[schedule[8]], words[schedule[9]])
    _g(state, 1, 6, 11, 12, words[schedule[10]], words[schedule[11]])
    _g(state, 2, 7, 8, 13, words[schedule[12]], words[schedule[13]])
    _g(state, 3, 4, 9, 14, words[schedule[14]], words[schedule[15]])


def _compress(cv, block, block_len, offset, flags):
    words = [
        int.from_bytes(block[at:at + 4], "little")
        for at in range(0, _BLOCK, 4)
    ]
    state = [
        *cv, *_IV[:4], offset & _MASK, (offset >> 32) & _MASK,
        block_len, flags,
    ]
    for schedule in _SCHEDULE:
        _round(state, words, schedule)
    return tuple(state[index] ^ state[index + 8] for index in range(8))


def _cv_bytes(words):
    return b"".join(word.to_bytes(4, "little") for word in words)


def _chunk_cv(raw, index, root):
    cv, offset, flags = _IV, 0, _CHUNK_START
    while len(raw) - offset > _BLOCK:
        cv = _compress(
            cv, raw[offset:offset + _BLOCK], _BLOCK, index, flags)
        flags, offset = 0, offset + _BLOCK
    tail = raw[offset:]
    flags |= _CHUNK_END | (_ROOT if root else 0)
    return _cv_bytes(_compress(
        cv, tail + b"\0" * (_BLOCK - len(tail)), len(tail), index, flags))


def _parent_cv(raw, root):
    return _cv_bytes(_compress(
        _IV, raw, _BLOCK, 0, _PARENT | (_ROOT if root else 0)))


def _verify(expected, actual):
    if not hmac.compare_digest(expected, actual):
        raise ValueError("Bao hash mismatch")


def _read_exact(stream, count):
    raw = stream.read(count)
    if len(raw) != count:
        raise ValueError("truncated Bao proof")
    return raw


def _left_len(size):
    chunks = (size - 1) // _CHUNK
    return _CHUNK * (1 << (chunks.bit_length() - 1))


def _decode(proof, start, count, size, root):
    """Parse once; ``root=None`` trusts the earlier admission certificate."""
    if not isinstance(proof, bytes) \
            or root is not None and (
                not isinstance(root, bytes) or len(root) != 32) \
            or type(start) is not int or type(count) is not int \
            or type(size) is not int \
            or not 0 <= start < size or not 0 < count <= size - start:
        raise ValueError("Bao slice parameters")
    source, output = BytesIO(proof), BytesIO()
    encoded_size = int.from_bytes(_read_exact(source, 8), "little")
    if encoded_size != size:
        raise ValueError("Bao descriptor length mismatch")
    end = start + count

    def descend(subtree_start, subtree_len, expected, root_node):
        subtree_end = subtree_start + subtree_len
        if subtree_end <= start or end <= subtree_start:
            return
        if subtree_len <= _CHUNK:
            raw = _read_exact(source, subtree_len)
            if expected is not None:
                _verify(
                    expected,
                    _chunk_cv(raw, subtree_start // _CHUNK, root_node),
                )
            lo = max(0, start - subtree_start)
            hi = min(subtree_len, end - subtree_start)
            output.write(raw[lo:hi])
            return
        parent = _read_exact(source, 64)
        if expected is not None:
            _verify(expected, _parent_cv(parent, root_node))
        left = _left_len(subtree_len)
        descend(
            subtree_start, left,
            None if expected is None else parent[:32], False)
        descend(
            subtree_start + left, subtree_len - left,
            None if expected is None else parent[32:], False)

    descend(0, size, root, True)
    payload = output.getvalue()
    if source.tell() != len(proof) or len(payload) != count:
        raise ValueError("non-canonical or short Bao slice")
    return payload


def verify(proof, root, start, count, size):
    """Authenticate one canonical range proof and return its exact payload."""
    return _decode(proof, start, count, size, root)


def extract(proof, start, count, size):
    """Extract a canonical proof already authenticated during admission."""
    return _decode(proof, start, count, size, None)
