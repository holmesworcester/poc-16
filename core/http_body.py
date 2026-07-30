"""Small synchronous HTTP bodies, bounded before protocol decoding."""
from .limits import PayloadTooLarge


def read_bounded(response, maximum, label):
    """Read at most ``maximum + 1`` bytes from one urllib response."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError("HTTP response bound")
    headers = getattr(response, "headers", None)
    claimed = headers.get("Content-Length") \
        if headers is not None and hasattr(headers, "get") else None
    if claimed is not None:
        try:
            length = int(claimed)
        except (TypeError, ValueError) as error:
            raise ValueError(f"{label} Content-Length") from error
        if length < 0:
            raise ValueError(f"{label} Content-Length")
        if length > maximum:
            raise PayloadTooLarge(f"{label} too large")
    raw = response.read(maximum + 1)
    if not isinstance(raw, bytes):
        raise TypeError(f"{label} response bytes")
    if len(raw) > maximum:
        raise PayloadTooLarge(f"{label} too large")
    return raw
