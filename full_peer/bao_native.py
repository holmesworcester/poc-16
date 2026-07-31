"""The optional Bao seam for self-verifying attachment slices.

Importing fact families must not require a locally built Rust extension.
Only attachment I/O crosses this seam and loads ``tinyp2p_bao``.
"""
import importlib
from functools import lru_cache

from facts._bao import (
    BAO_CHUNK_BYTES,
    MAX_FILE_BYTES,
    MAX_PROOF_BYTES,
    MAX_SLICES,
    WIDTH,
    geometry,
    span,
)

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
