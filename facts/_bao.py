"""Pure Bao attachment geometry shared by fact shapes and full peers."""

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


def geometry(size, width=WIDTH):
    """Slice count: ceil(size/width), and zero for an empty file."""
    return 0 if size == 0 else (size + width - 1) // width


def span(index, size, width=WIDTH):
    """Return this slice's unpadded ``(start, count)``."""
    if index < 0 or index >= geometry(size, width):
        raise ValueError("slice index outside the descriptor")
    start = index * width
    return start, min(width, size - start)
