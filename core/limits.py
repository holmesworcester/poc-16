"""One set of byte and count limits for the sync wire protocol.

Deployments may choose stricter front-door limits, but they must not silently
accept more than these core bounds.  ``PayloadTooLarge`` remains a
``ValueError`` so the pure codecs keep their total "value or ValueError"
contract while HTTP adapters can translate the condition to status 413.
"""
import json

MIB = 1024 * 1024

PAGE_BATCH = 256
MAX_ROOT_BYTES = MIB
MAX_PILE_BYTES = 64 * MIB
MAX_OBJECT_BYTES = 64 * MIB
MAX_CONTROL_BYTES = MIB
MAX_MINT_REQUEST_BYTES = 512 * 1024
MAX_MINT_FETCHES = 128
MAX_MINT_FETCH_BYTES = 4 * MIB
MAX_PAGE_REQUEST_BYTES = 64 * 1024
MAX_PAGE_BATCH_BYTES = 4 * MIB


class PayloadTooLarge(ValueError):
    """A bounded protocol value exceeded its declared byte budget."""


def decode_json(raw, limit, label):
    """Decode bounded JSON and expose every parser failure as ``ValueError``."""
    if not isinstance(raw, bytes):
        raise ValueError(f"{label} bytes")
    if len(raw) > limit:
        raise PayloadTooLarge(f"{label} too large")
    try:
        return json.loads(raw)
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError(f"{label} encoding") from error
