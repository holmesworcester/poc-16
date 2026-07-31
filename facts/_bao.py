"""Pure Bao geometry and hosted slice verification."""

from ._bao_verify import verify as _verify

WIDTH = 256 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024
MAX_SLICES = MAX_FILE_BYTES // WIDTH
BAO_CHUNK_BYTES = 1024
_DEPTH = (
    (MAX_FILE_BYTES + BAO_CHUNK_BYTES - 1) // BAO_CHUNK_BYTES - 1
).bit_length()
MAX_PROOF_BYTES = (
    (WIDTH + BAO_CHUNK_BYTES - 1) // BAO_CHUNK_BYTES + 1
) * BAO_CHUNK_BYTES + (
    WIDTH // BAO_CHUNK_BYTES + 2 * _DEPTH
) * 64 + 8
MAX_PROOF_BASE64_BYTES = ((MAX_PROOF_BYTES + 2) // 3) * 4


def geometry(size, width=WIDTH):
    """Slice count: ceil(size/width), and zero for an empty file."""
    return 0 if size == 0 else (size + width - 1) // width


def span(index, size, width=WIDTH):
    """Return this slice's unpadded ``(start, count)``."""
    if index < 0 or index >= geometry(size, width):
        raise ValueError("slice index outside the descriptor")
    start = index * width
    return start, min(width, size - start)


def verify(proof, root_hex, index, size, width=WIDTH):
    """Verify one inline proof without a native extension and return bytes."""
    if not isinstance(root_hex, str) or len(root_hex) != 64:
        raise ValueError("Bao root")
    try:
        root = bytes.fromhex(root_hex)
    except ValueError as error:
        raise ValueError("Bao root") from error
    start, count = span(index, size, width)
    return _verify(proof, root, start, count, size)
