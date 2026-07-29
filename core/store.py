"""ObjectStore: the one S3-shaped trait every node stores through.

Layout: root (the CAS'd workspace/index manifest), obj/<hash> (manifest
shards, leaf piles, closure siblings, blobs — immutable),
pile/<member>/<hash> (ingress), invite/<id> (public reads), and
failed/{pile,meta}/<hash> (node-local rejected-ingress evidence).

The public mutation contract rejects unconditional root/object replacement
and authoritative deletion. Objects use atomic put-if-absent; root uses CAS.
Kernel-valid durable receipts live in the client catalog, not object keys.
"""
import fcntl
import os
import re
import tempfile

from .crypto import h

KEY_RE = re.compile(r"^[a-z0-9:._/-]+$")
PAGE_BATCH = 256


def verified_object(oid, fetch):
    """Fetch one content-addressed object and verify its name."""
    raw = fetch(oid) if oid else None
    if raw is None or h(raw) != oid:
        raise ValueError("object integrity")
    return raw


class FsStore:
    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self._root_lock = os.path.join(root, ".root.lock")

    def _p(self, key):
        if not isinstance(key, str) or not KEY_RE.fullmatch(key):
            raise ValueError(f"bad key {key!r}")
        parts = key.split("/")
        if any(not part or part in {".", ".."} for part in parts) \
                or parts[0] == ".root.lock" \
                or key.startswith("root/"):
            raise ValueError(f"reserved key {key!r}")
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

    @staticmethod
    def _authoritative(key):
        return key == "root" or key.startswith("root/") \
            or key == "obj" or key.startswith("obj/")

    def _replace(self, key, b):
        """Atomic replacement used by CAS and deliberate fault injection."""
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

    def put(self, key, b):
        if self._authoritative(key):
            raise ValueError("authoritative keys require conditional writes")
        self._replace(key, b)

    def put_if_absent(self, key, b):
        """Atomically create one key; immutable objects verify on collision."""
        if key == "root" or key.startswith("root/"):
            raise ValueError("root requires compare-and-swap")
        if key == "obj" or (
                key.startswith("obj/") and key[4:] != h(b)):
            raise ValueError("immutable object address")
        p = self._p(key)
        directory = os.path.dirname(p)
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b)
            try:
                os.link(tmp, p)
            except FileExistsError:
                if key.startswith("obj/") and self.get(key) != b:
                    raise ValueError("immutable object conflict")
                return False
            return True
        finally:
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass

    def cas(self, key, etag, b):
        if key != "root":
            raise ValueError("only root is mutable by CAS")
        with open(self._root_lock, "a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if self.etag(key) != etag:
                return None
            self._replace(key, b)
            return h(b)

    def list(self, prefix):
        out = []
        if prefix:
            prefix = prefix[:-1] if prefix.endswith("/") else prefix
            if not prefix:
                raise ValueError("bad list prefix")
        base = self._p(prefix) if prefix else self.root
        for dirpath, _, names in os.walk(base):
            for n in names:
                if not n.endswith(".tmp") and n != ".root.lock":
                    out.append(os.path.relpath(os.path.join(dirpath, n), self.root))
        return sorted(out)

    def delete(self, key):
        if self._authoritative(key):
            raise ValueError("authoritative keys are not deletable")
        self._delete(key)

    def _delete(self, key):
        """Deletion seam for non-authoritative data and corruption tests."""
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
