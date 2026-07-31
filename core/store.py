"""ObjectStore: the one S3-shaped trait every node stores through.

Layout: root (the CAS'd composite snapshot), obj/<hash> (bounded map pages
and fact/file blobs — immutable),
pile/<member>/<reservation>/<hash> (internal ingress),
invite/<id> (public reads), and
failed/{pile,meta}/<hash> (shared immutable rejected-ingress evidence).

The public mutation contract rejects unconditional root/object replacement
and authoritative deletion. Objects use atomic put-if-absent; root uses CAS.
Never-deleted applier/generation and applier/spent records make internal
retirement one-use without treating an ETag or path segment as identity.
"""
import fcntl
import heapq
import os
import tempfile

from .crypto import h
from .object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    STALE,
    Versioned,
    VersionToken,
    ListPage,
    authoritative_key,
    validate_key,
)
from .limits import (
    MAX_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
)


class FsStore:
    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self._root_lock = os.path.join(root, ".root.lock")

    def _p(self, key):
        return os.path.join(self.root, validate_key(key))

    def get(self, key):
        try:
            with open(self._p(key), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def get_bounded(self, key, max_bytes):
        """Read at most one byte beyond the caller's explicit budget."""
        if type(max_bytes) is not int \
                or not 0 < max_bytes <= MAX_OBJECT_BYTES:
            raise ValueError("filesystem read byte limit")
        try:
            with open(self._p(key), "rb") as f:
                value = f.read(max_bytes + 1)
        except FileNotFoundError:
            return None
        if len(value) > max_bytes:
            raise PayloadTooLarge("filesystem read exceeds byte limit")
        return value

    def read_versioned(self, key):
        """Read one atomic value/token pair.

        A content digest is a valid opaque token for this local implementation
        because replacement is serialized by ``_root_lock``. Provider
        implementations return their own conditional-write token instead.
        """
        limit = MAX_ROOT_BYTES if key == "root" else MAX_OBJECT_BYTES
        value = self.get_bounded(key, limit)
        return ABSENT if value is None else Versioned(
            value, VersionToken(h(value)))

    def has(self, key):
        return os.path.exists(self._p(key))

    @staticmethod
    def _authoritative(key):
        return authoritative_key(key)

    @staticmethod
    def _temp(directory, b):
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b)
            return tmp
        except BaseException:
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass
            raise

    def _replace(self, key, b):
        """Atomic replacement used by CAS and fault injection."""
        p = self._p(key)
        directory = os.path.dirname(p)
        os.makedirs(directory, exist_ok=True)
        tmp = self._temp(directory, b)
        try:
            os.replace(tmp, p)
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
        tmp = self._temp(directory, b)
        try:
            try:
                os.link(tmp, p)
            except FileExistsError:
                return EXISTS
            return CREATED
        finally:
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass

    def cas(self, key, token, b):
        if key != "root":
            raise ValueError("only root is mutable by CAS")
        with open(self._root_lock, "a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            current = self.read_versioned(key)
            current_token = current.token \
                if isinstance(current, Versioned) else ABSENT
            if current_token != token:
                return STALE
            self._replace(key, b)
            return Applied(VersionToken(h(b)))

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

    def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        """Scan one bounded logical page using the last key as an opaque cursor."""
        if type(limit) is not int or not 0 < limit <= PAGE_BATCH:
            raise ValueError("filesystem list page limit")
        if cursor is not None:
            validate_key(cursor)
        if prefix:
            prefix = prefix[:-1] if prefix.endswith("/") else prefix
            if not prefix:
                raise ValueError("bad list prefix")
        base = self._p(prefix) if prefix else self.root

        def candidates():
            for dirpath, _, names in os.walk(base):
                for name in names:
                    if name.endswith(".tmp") or name == ".root.lock":
                        continue
                    key = os.path.relpath(
                        os.path.join(dirpath, name), self.root)
                    if cursor is None or key > cursor:
                        yield key

        selected = heapq.nsmallest(limit + 1, candidates())
        keys = tuple(selected[:limit])
        return ListPage(
            keys,
            keys[-1] if len(selected) > limit else None,
        )

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
        limit = MAX_ROOT_BYTES if key == "root" else MAX_OBJECT_BYTES
        return self.get_bounded(key, limit)

    def get_bounded(self, key, max_bytes):
        if type(max_bytes) is not int \
                or not 0 < max_bytes <= MAX_OBJECT_BYTES:
            raise ValueError("remote read byte limit")
        if key == "root":
            got = self.peer.root(response_limit=max_bytes)
            return got[0] if got is not None else None
        if key.startswith("obj/"):
            return self.peer.obj(key[4:], response_limit=max_bytes)
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

    def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        raise TypeError("remote stores do not expose LIST")
