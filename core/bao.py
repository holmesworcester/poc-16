"""The optional Bao seam for self-verifying attachment slices.

Importing fact families must not require a locally built Rust extension.
Only attachment I/O crosses this seam and loads ``tinyp2p_bao``.
"""
import importlib
from functools import lru_cache

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
BUILD_COMMAND = "python3 -m pip install ./native/bao_py"


@lru_cache(maxsize=1)
def _native():
    try:
        return importlib.import_module("tinyp2p_bao")
    except ModuleNotFoundError as error:
        if error.name != "tinyp2p_bao":
            raise
        raise RuntimeError(
            "Bao attachments require the vendored Rust extension; "
            f"from the project root run: {BUILD_COMMAND}"
        ) from error


def geometry(size, width=WIDTH):
    """Slice count: ceil(size/width), and zero for an empty file."""
    return 0 if size == 0 else (size + width - 1) // width


def span(index, size, width=WIDTH):
    """Return this slice's unpadded ``(start, count)``."""
    if index < 0 or index >= geometry(size, width):
        raise ValueError("slice index outside the descriptor")
    start = index * width
    return start, min(width, size - start)


def prepare(src_path, outboard_path):
    """Encode the tree beside a file and return its root as lowercase hex."""
    return bytes(_native().prepare_file(src_path, outboard_path)).hex()


def proof(src_path, outboard_path, index, size, width=WIDTH):
    """Return the canonical payload plus authentication path for one slice."""
    start, count = span(index, size, width)
    return bytes(
        _native().extract_slice(src_path, outboard_path, start, count))


def verify(blob, root_hex, index, size, width=WIDTH):
    """Verify and return one slice's payload."""
    start, count = span(index, size, width)
    return _native().decode_slice(
        blob, bytes.fromhex(root_hex), start, count, size)
