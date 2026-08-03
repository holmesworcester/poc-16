"""Bounded ObjectStore for authenticated metadata and semantic objects.

Layout: root and authority (distinct CAS'd composite snapshots), obj/<hash>
(bounded map pages and fact/file blobs — immutable),
heads/<workspace>/<device> and layouts/<workspace>/<device>/<window>
(independent CAS registers),
ingress/v1/workspaces/<ws>/piles/<session>/<uploader>/<hash> (exact ingress),
and invite/<id> (public reads).

Large immutable pack/<hash> bodies use a separate streaming data plane.  The
namespace rules here still protect them from unconditional replacement or
deletion when the same backing directory or bucket is used.

The public mutation contract rejects unconditional root/object replacement
and authoritative deletion. Objects and retained piles use atomic
put-if-absent; repository roots use CAS.
"""
import asyncio
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
    REPOSITORY_ROOT_KEYS,
    authoritative_key,
    mutable_key,
    validate_create,
    validate_key,
)
from .limits import (
    MAX_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    MAX_STORE_READ_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
)
from .writer_head import parse_head_slot_key


class FsStore:
    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self._root_lock = os.path.join(root, ".root.lock")

    def namespace_id(self):
        return "filesystem", os.path.realpath(os.path.abspath(self.root))

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
                or not 0 < max_bytes <= MAX_STORE_READ_BYTES:
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
        limit = MAX_ROOT_BYTES \
            if key in REPOSITORY_ROOT_KEYS else MAX_OBJECT_BYTES
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
        key = validate_create(key, b)
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
        if not mutable_key(key):
            raise ValueError("key is not a CAS register")
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
    """Ordinary HTTP peer exposed as the same bounded ObjectStore contract.

    Immutable PUTs stage hash-addressed objects.  A head CAS is translated to
    the peer's mirror-finalize operation, where the receiving
    :class:`RepositoryMirror` repeats validation and owns the actual local
    compare-and-swap.
    """

    def __init__(self, peer):
        self.peer = peer

    async def get_bounded(self, key, max_bytes):
        if type(max_bytes) is not int \
                or not 0 < max_bytes <= MAX_STORE_READ_BYTES:
            raise ValueError("remote read byte limit")
        if key.startswith("heads/"):
            _workspace, device = parse_head_slot_key(key)
            got = await asyncio.to_thread(self.peer.head, device)
            return None if got is None else got[0]
        if key.startswith("obj/"):
            return await asyncio.to_thread(
                self.peer.obj, key[4:], response_limit=max_bytes)
        return None

    async def read_versioned(self, key):
        if key.startswith("heads/"):
            observed_head = getattr(self.peer, "observed_head", None)
            if callable(observed_head):
                known, opened = observed_head(key)
                if known:
                    return opened
            _workspace, device = parse_head_slot_key(key)
            try:
                got = await asyncio.to_thread(self.peer.head, device)
            except Exception as error:
                if getattr(error, "code", None) == 404:
                    return ABSENT
                raise
            return ABSENT if got is None else Versioned(*got)
        value = await self.get_bounded(key, MAX_OBJECT_BYTES)
        return ABSENT if value is None else Versioned(
            value, VersionToken(h(value)))

    async def read_many_versioned(self, keys):
        """Use the slots bundled with the latest bounded directory page."""
        keys = tuple(keys)
        if all(key.startswith("heads/") for key in keys):
            return self.peer.opened_heads(keys)
        return tuple([
            await self.read_versioned(key) for key in keys
        ])

    async def get_many(self, keys):
        """Fetch object keys in bounded batches; preserve order and misses."""
        keys = tuple(keys)
        if not all(key.startswith("obj/") for key in keys):
            return tuple([
                await self.get_bounded(key, MAX_OBJECT_BYTES)
                for key in keys
            ])
        out = []
        for start in range(0, len(keys), PAGE_BATCH):
            out.extend(await asyncio.to_thread(
                self.peer.objs,
                [key[4:] for key in keys[start:start + PAGE_BATCH]],
            ))
        return tuple(out)

    async def fetch_writer_piles(self, workspace, device, rows):
        """Use this HTTP source's optional layout without changing authority.

        ``RepositoryMirror`` has already authenticated and selected ``rows``
        from the signed writer tree.  Layout pages and pack requests merely
        locate those OIDs; the shared fetcher falls back to ``/obj`` for every
        absent or invalid hint.
        """
        from .writer_fetch import fetch_layout_piles

        async def read_layout(key, maximum):
            return await asyncio.to_thread(
                self.peer.layout, key, response_limit=maximum)

        async def copy_pack(opened, write):
            return await asyncio.to_thread(
                self.peer.copy_pack, opened, write)

        async def read_loose(oids, _maximum):
            return await self.get_many(
                tuple("obj/" + oid for oid in oids))

        return await fetch_layout_piles(
            workspace,
            device,
            rows,
            read_layout=read_layout,
            copy_pack=copy_pack,
            read_loose=read_loose,
        )

    async def put_if_absent(self, key, value):
        key = validate_create(key, value)
        if not key.startswith("obj/"):
            raise ValueError("remote create is immutable-only")
        status = await asyncio.to_thread(
            self.peer.put_obj, key[4:], value)
        if status == 201:
            return CREATED
        if status == 204:
            return EXISTS
        raise ValueError("remote immutable create")

    async def cas(self, key, token, value):
        if not mutable_key(key) or key == "root":
            raise ValueError("remote CAS is writer-slot-only")
        _workspace, device = parse_head_slot_key(key)
        applied, returned = await asyncio.to_thread(
            self.peer.accept_slot, device, value)
        if not applied:
            return STALE
        return Applied(returned or VersionToken(h(value)))

    async def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        if not prefix.startswith("heads/"):
            raise TypeError("remote LIST is writer-directory-only")
        return await asyncio.to_thread(
            self.peer.heads, cursor, limit)
