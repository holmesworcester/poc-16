"""ObjectStore: the one S3-shaped trait every node stores through.

Layout: root (the CAS'd manifest, only mutable key besides piles/invites),
obj/<hash> (leaf piles, tails, blobs — immutable, content-addressed),
pile/<member>/<hash> (ingress), invite/<id> (public reads).
"""
import os
import re
import threading

from .crypto import h

KEY_RE = re.compile(r"^[a-z0-9:._/-]+$")


class MemStore:
    def __init__(self):
        self.d, self.lock = {}, threading.Lock()

    def get(self, key):
        return self.d.get(key)

    def has(self, key):
        return key in self.d

    def etag(self, key):
        b = self.d.get(key)
        return None if b is None else h(b)

    def put(self, key, b):
        self.d[key] = b

    def put_if_absent(self, key, b):
        self.d.setdefault(key, b)

    def cas(self, key, etag, b):
        with self.lock:
            if self.etag(key) != etag:
                return None
            self.d[key] = b
            return h(b)

    def list(self, prefix):
        return sorted(k for k in self.d if k.startswith(prefix))

    def delete(self, key):
        self.d.pop(key, None)


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
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "wb") as f:
            f.write(b)
        os.replace(tmp, p)  # atomic

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
