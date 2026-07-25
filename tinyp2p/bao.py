"""The only bao seam: verified streaming over the official Rust crate.

A file is committed by one 32-byte BLAKE3 root. Every 256 KiB slice carries
its own authentication path, so a slice proves itself against that root with
no siblings, no ordering, and no database — which is what makes an arriving
chunk *durable download progress* rather than an unverified guess.

Swap this file to swap the verification primitive; nothing else imports
``tinyp2p_bao``.
"""
import tinyp2p_bao

WIDTH = 256 * 1024                        # POC-13 SLICE_BYTES, the wire constant
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024  # POC-13 parity
MAX_SLICES = MAX_FILE_BYTES // WIDTH
BAO_CHUNK_BYTES = 1024                    # BLAKE3's own chunk, fixed by the crate
_DEPTH = ((MAX_FILE_BYTES + BAO_CHUNK_BYTES - 1) // BAO_CHUNK_BYTES - 1).bit_length()
MAX_PROOF_BYTES = ((WIDTH + BAO_CHUNK_BYTES - 1) // BAO_CHUNK_BYTES + 1) \
    * BAO_CHUNK_BYTES + (WIDTH // BAO_CHUNK_BYTES + 2 * _DEPTH) * 64 + 8


def geometry(size, width=WIDTH):
    """Slice count: ceil(size/width), and zero for the empty file."""
    return 0 if size == 0 else (size + width - 1) // width


def span(index, size, width=WIDTH):
    """The (start, count) this index covers; the tail slice is short, never padded."""
    if index < 0 or index >= geometry(size, width):
        raise ValueError("slice index outside the descriptor")
    start = index * width
    return start, min(width, size - start)


def prepare(src_path, outboard_path):
    """Encode the tree beside the file and return its root, lowercase hex."""
    return bytes(tinyp2p_bao.prepare_file(src_path, outboard_path)).hex()


def proof(src_path, outboard_path, index, size, width=WIDTH):
    """The canonical slice encoding for one index: payload + authentication path."""
    start, count = span(index, size, width)
    return bytes(tinyp2p_bao.extract_slice(src_path, outboard_path, start, count))


def verify(blob, root_hex, index, size, width=WIDTH):
    """Return this slice's payload, or raise. The whole point: an arriving
    object is checked against the signed root alone."""
    start, count = span(index, size, width)
    return tinyp2p_bao.decode_slice(blob, bytes.fromhex(root_hex), start, count, size)
