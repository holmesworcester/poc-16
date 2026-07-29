"""SQLite-free request authorization over one authenticated composite root."""

from .crypto import h
from .worker import WorkerView


def stateless(pile_bytes, root_bytes, fetch, now, projection=None):
    """Authorize a bounded request closure using exact authenticated reads.

    A caller may cache ``WorkerView`` only while its root ETag matches. Cold
    and changed-root reads construct a lightweight view; neither path scans a
    tree or reconstructs SQLite.
    """
    if isinstance(projection, WorkerView) \
            and projection.etag == h(root_bytes):
        return projection.mint(pile_bytes, now)
    try:
        return WorkerView.from_root(root_bytes, fetch).mint(pile_bytes, now)
    except Exception:
        return None
