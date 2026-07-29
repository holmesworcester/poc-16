"""ObjectStore: the one S3-shaped trait every node stores through.

Layout: root (the CAS'd workspace/index manifest, only mutable key besides
piles/invites), obj/<hash> (manifest shards, leaf piles, closure siblings,
blobs — immutable), pile/<member>/<hash> (ingress), invite/<id> (public
reads), and quarantine/<fid> (node-local retention for a previously valid
pruned fact).
"""
import os
import re
import tempfile
import threading

from .crypto import h

KEY_RE = re.compile(r"^[a-z0-9:._/-]+$")
PAGE_BATCH = 256


class FsStore:
    def __init__(self, root):
        self.root, self.lock = root, threading.Lock()
        os.makedirs(root, exist_ok=True)

    def _p(self, key):
        if not KEY_RE.match(key) or ".." in key:
            raise ValueError(f"bad key {key!r}")
        return os.path.join(self.root, key)

    def get(self, key):
        try:
            with open(self._p(key), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def has(self, key):
        return os.path.exists(self._p(key))

    def etag(self, key):
        b = self.get(key)
        return None if b is None else h(b)

    def put(self, key, b):
        p = self._p(key)
        directory = os.path.dirname(p)
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b)
            os.replace(tmp, p)  # atomic
        except BaseException:
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass
            raise

    def put_if_absent(self, key, b):
        if not self.has(key):
            self.put(key, b)

    def cas(self, key, etag, b):
        with self.lock:
            if self.etag(key) != etag:
                return None
            self.put(key, b)
            return h(b)

    def list(self, prefix):
        out = []
        base = os.path.join(self.root, prefix)
        for dirpath, _, names in os.walk(base):
            for n in names:
                if not n.endswith(".tmp"):
                    out.append(os.path.relpath(os.path.join(dirpath, n), self.root))
        return sorted(out)

    def delete(self, key):
        try:
            os.remove(self._p(key))
        except FileNotFoundError:
            pass


# ---- remote stores through the same trait -----------------------------------


class RemoteStore:
    """Read-only ObjectStore over a walk.Peer, so a remote store is fetched
    through the same interface the local fetch(oid) driver wraps."""

    def __init__(self, peer):
        self.peer = peer

    def get(self, key):
        if key == "root":
            got = self.peer.root()
            return got[0] if got is not None else None
        if key.startswith("obj/"):
            return self.peer.obj(key[4:])
        return None

    def get_many(self, keys):
        """Fetch object keys in bounded batches; preserve order and misses."""
        keys = tuple(keys)
        if not all(key.startswith("obj/") for key in keys):
            return tuple(self.get(key) for key in keys)
        if not hasattr(self.peer, "objs"):
            return tuple(self.get(key) for key in keys)
        out = []
        for start in range(0, len(keys), PAGE_BATCH):
            out.extend(self.peer.objs(
                [key[4:] for key in keys[start:start + PAGE_BATCH]]))
        return tuple(out)

    def has(self, key):
        return self.get(key) is not None

    def etag(self, key):
        value = self.get(key)
        return h(value) if value is not None else None

    def list(self, prefix):
        raise TypeError("remote stores do not expose LIST")
