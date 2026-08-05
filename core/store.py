"""Bounded ObjectStore for authenticated metadata and semantic objects.

Layout: removal (the private authenticated access projection), cursor
(isolated operational state), obj/<hash> (map pages, fact blobs, heads, and
independently closed writer piles — immutable),
heads/<workspace>/<device> and layouts/<workspace>/<device>/<window>
(independent CAS registers),
and private control state.

Large signed-pile and pack/<hash> bodies use the direct streaming data plane.
The namespace rules here still protect them from unconditional replacement or
deletion when the same backing directory or bucket is used.

The public mutation contract rejects unconditional CAS/object replacement and
authoritative deletion. Immutable values use atomic put-if-absent; mutable
cells use CAS.
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
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    UNCHANGED,
    Versioned,
    VersionToken,
    ListPage,
    SINGLETON_CAS_KEYS,
    authoritative_key,
    mutable_key,
    validate_create,
    validate_key,
)
from .limits import (
    DIRECT_STREAM_CHUNK_BYTES,
    MAX_DIRECT_OBJECT_BYTES,
    MAX_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    MAX_STORE_READ_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
)
from .writer_head import parse_head_slot_key
from .shape import valid_fid


class FsStore:
    def __init__(self, root):
        self.root = root
        self._durable_directories = set()
        self._observed_directories = set()
        self._uncertain_keys = set()
        self._makedirs(root)
        self._cas_lock = os.path.join(root, ".cas.lock")

    @staticmethod
    def _fsync_file(fd):
        os.fsync(fd)

    @staticmethod
    def _fsync_directory(directory):
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        fd = os.open(directory, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _makedirs(self, directory):
        """Create every missing component and persist its parent entry."""
        try:
            missing = []
            current = os.path.abspath(directory)
            if current in self._durable_directories:
                return
            while not os.path.exists(current):
                missing.append(current)
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent
            for path in reversed(missing):
                try:
                    os.mkdir(path)
                except FileExistsError:
                    pass
                self._fsync_directory(os.path.dirname(path))
            if not missing:
                # A fresh process cannot inherit the previous process's
                # knowledge that this visible entry crossed a parent fsync.
                self._fsync_directory(os.path.dirname(current))
            self._durable_directories.add(os.path.abspath(directory))
        except OSError as error:
            raise RetryableStoreError(
                "filesystem directory setup did not commit") from error

    @staticmethod
    def _write_temp(stream, value):
        written = stream.write(value)
        if written != len(value):
            raise OSError("short filesystem write")

    def _after_durable_write(self, _operation, _key):
        """Response-loss seam after the namespace mutation is durable."""

    def _namespace_barrier(self, directory, key, operation):
        try:
            self._fsync_directory(directory)
        except OSError as error:
            self._uncertain_keys.add(key)
            raise OutcomeUnknown(
                f"filesystem {operation} outcome unknown") from error
        self._uncertain_keys.discard(key)
        self._observed_directories.add(os.path.abspath(directory))

    def _reconcile_read(self, key, *, force=False):
        directory = os.path.dirname(self._p(key))
        if not os.path.isdir(directory):
            return
        if force or key in self._uncertain_keys \
                or os.path.abspath(directory) not in self._observed_directories:
            self._namespace_barrier(
                directory, key, "read reconciliation")

    @staticmethod
    def _discard_temp(path):
        try:
            os.remove(path)
        except OSError:
            # The final namespace never names this inode. Cleanup failure must
            # neither mask the typed operation result nor corrupt another key.
            pass

    @staticmethod
    def _path_value(path, maximum):
        try:
            with open(path, "rb") as stream:
                value = stream.read(maximum + 1)
        except FileNotFoundError:
            return None
        return value if len(value) <= maximum else None

    def namespace_id(self):
        return "filesystem", os.path.realpath(os.path.abspath(self.root))

    def _p(self, key):
        return os.path.join(self.root, validate_key(key))

    def get(self, key):
        self._reconcile_read(key)
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
        self._reconcile_read(key)
        try:
            with open(self._p(key), "rb") as f:
                value = f.read(max_bytes + 1)
        except FileNotFoundError:
            return None
        if len(value) > max_bytes:
            raise PayloadTooLarge("filesystem read exceeds byte limit")
        return value

    def copy_pile_object(self, oid, max_bytes, write):
        """Copy one large writer pile without widening ``get_bounded``."""
        if not valid_fid(oid) or type(max_bytes) is not int \
                or not 0 < max_bytes <= MAX_DIRECT_OBJECT_BYTES \
                or not callable(write):
            raise ValueError("filesystem pile copy")
        key = "obj/" + oid
        self._reconcile_read(key)
        try:
            source = open(self._p(key), "rb")
        except FileNotFoundError:
            return None
        total = 0
        with source:
            while True:
                chunk = source.read(min(
                    DIRECT_STREAM_CHUNK_BYTES,
                    max_bytes - total + 1,
                ))
                if not chunk:
                    return total
                total += len(chunk)
                if total > max_bytes:
                    raise PayloadTooLarge(
                        "filesystem pile exceeds byte limit")
                write(chunk)

    def read_versioned(self, key):
        """Read one atomic value/token pair.

        A content digest is a valid opaque token for this local implementation
        because replacement is serialized by ``_cas_lock``. Provider
        implementations return their own conditional-write token instead.
        """
        self._reconcile_read(key, force=True)
        limit = MAX_ROOT_BYTES \
            if key in SINGLETON_CAS_KEYS else MAX_OBJECT_BYTES
        value = self.get_bounded(key, limit)
        return ABSENT if value is None else Versioned(
            value, VersionToken(h(value)))

    def read_versioned_if_changed(self, key, token):
        """Local equivalent of an If-None-Match versioned read."""
        if not isinstance(token, VersionToken):
            raise TypeError("filesystem conditional read token")
        opened = self.read_versioned(key)
        return UNCHANGED if isinstance(opened, Versioned) \
            and opened.token == token else opened

    def has(self, key):
        self._reconcile_read(key)
        return os.path.exists(self._p(key))

    @staticmethod
    def _ambiguous_readback(operation, namespace_error, readback_error):
        unknown = OutcomeUnknown(
            f"filesystem {operation} outcome unknown")
        unknown.add_note(
            f"readback also failed: {readback_error!r}")
        raise unknown from namespace_error

    @staticmethod
    def _authoritative(key):
        return authoritative_key(key)

    def _temp(self, directory, b):
        try:
            fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        except OSError as error:
            raise RetryableStoreError(
                "filesystem temporary create did not commit") from error
        try:
            with os.fdopen(fd, "wb") as f:
                self._write_temp(f, b)
                f.flush()
                self._fsync_file(f.fileno())
            return tmp
        except OSError as error:
            self._discard_temp(tmp)
            raise RetryableStoreError(
                "filesystem temporary write did not commit") from error
        except BaseException:
            self._discard_temp(tmp)
            raise

    def _replace(self, key, b):
        """Atomic replacement used by CAS and fault injection."""
        p = self._p(key)
        directory = os.path.dirname(p)
        self._makedirs(directory)
        tmp = self._temp(directory, b)
        try:
            try:
                os.replace(tmp, p)
            except OSError as error:
                try:
                    applied = self._path_value(p, len(b)) == b
                except OSError as readback_error:
                    self._ambiguous_readback(
                        "replacement", error, readback_error)
                if applied:
                    try:
                        self._namespace_barrier(directory, key, "replacement")
                    except OutcomeUnknown as unknown:
                        raise unknown from error
                    raise OutcomeUnknown(
                        "filesystem replacement outcome unknown") from error
                raise RetryableStoreError(
                    "filesystem replacement did not commit") from error
            try:
                self._namespace_barrier(directory, key, "replacement")
                self._after_durable_write("replace", key)
            except OutcomeUnknown:
                raise
            except OSError as error:
                raise OutcomeUnknown(
                    "filesystem replacement outcome unknown") from error
        except BaseException:
            self._discard_temp(tmp)
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
        self._makedirs(directory)
        tmp = self._temp(directory, b)
        try:
            try:
                os.link(tmp, p)
            except FileExistsError:
                self._namespace_barrier(directory, key, "create")
                return EXISTS
            except OSError as error:
                try:
                    applied = self._path_value(p, len(b)) == b
                except OSError as readback_error:
                    self._ambiguous_readback(
                        "create", error, readback_error)
                if applied:
                    try:
                        self._namespace_barrier(directory, key, "create")
                    except OutcomeUnknown as unknown:
                        raise unknown from error
                    raise OutcomeUnknown(
                        "filesystem create outcome unknown") from error
                raise RetryableStoreError(
                    "filesystem create did not commit") from error
            try:
                self._namespace_barrier(directory, key, "create")
                self._after_durable_write("create", key)
            except OutcomeUnknown:
                raise
            except OSError as error:
                raise OutcomeUnknown(
                    "filesystem create outcome unknown") from error
            return CREATED
        finally:
            self._discard_temp(tmp)

    def cas(self, key, token, b):
        if not mutable_key(key):
            raise ValueError("key is not a CAS register")
        try:
            lock = open(self._cas_lock, "a+b")
        except OSError as error:
            raise RetryableStoreError(
                "filesystem CAS lock did not commit") from error
        with lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX)
            except OSError as error:
                raise RetryableStoreError(
                    "filesystem CAS lock did not commit") from error
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
                if not n.endswith(".tmp") and n != ".cas.lock":
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
                    if name.endswith(".tmp") or name == ".cas.lock":
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
        if not key.startswith("heads/"):
            raise TypeError("remote versioned read is writer-head-only")
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

    async def read_many_versioned(self, keys):
        """Use the slots bundled with the latest bounded directory page."""
        keys = tuple(keys)
        if not all(key.startswith("heads/") for key in keys):
            raise TypeError("remote versioned batch is writer-head-only")
        return self.peer.opened_heads(keys)

    async def get_many(self, keys):
        """Fetch object keys in bounded batches; preserve order and misses."""
        keys = tuple(keys)
        if not all(key.startswith("obj/") for key in keys):
            raise TypeError("remote object batch is object-only")
        out = []
        for start in range(0, len(keys), PAGE_BATCH):
            out.extend(await asyncio.to_thread(
                self.peer.objs,
                [key[4:] for key in keys[start:start + PAGE_BATCH]],
            ))
        return tuple(out)

    async def copy_pile_object(self, oid, max_bytes, write):
        """Copy one tree-selected pile through ObjectOpen."""
        return await asyncio.to_thread(
            self.peer.copy_obj,
            oid,
            response_limit=max_bytes,
            write=write,
        )

    async def has(self, key):
        if not key.startswith("obj/"):
            raise TypeError("remote existence probe is object-only")
        try:
            return await self.get_bounded(key, MAX_OBJECT_BYTES) is not None
        except PayloadTooLarge:
            # Signed heads and tree pages are always buffered objects.  A
            # large value at their claimed address is not an established top.
            return False
        except Exception as error:
            if getattr(error, "code", None) == 404:
                return False
            raise

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

        async def read_loose(oids, maximum):
            out = []
            for oid in oids:
                value = bytearray()
                copied = await self.copy_pile_object(
                    oid, maximum, value.extend)
                out.append(None if copied is None else bytes(value))
            return tuple(out)

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
        if not key.startswith("heads/") or not mutable_key(key):
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
