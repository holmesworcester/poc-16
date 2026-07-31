"""Full-peer-local durable authority for a resumable direct upload.

``source.json`` and its bodies are immutable. ``session.json`` is one atomic
record whose separate cursor/cursor_index/delivered_index fields preserve the
only important crash distinction: authority issued is not a delivery receipt.
No database or provider credential is involved.
"""
from bisect import bisect_right
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import os
import shutil
import tempfile
import threading

from core.crypto import h
from core.fact import canon
from core.limits import (
    MAX_OBJECT_BYTES,
    MAX_PILE_BYTES,
    PAGE_BATCH,
    decode_json,
)
from core.shape import valid_fid
from core.staged_intent import MEMBER_HEX_BYTES, SESSION_HEX_BYTES
from deploy.upload_session import (
    MAX_SESSION_OBJECTS,
    UploadLeaf,
    UploadManifest,
    UploadVector,
)


SOURCE_SCHEMA = "poc16-upload-source-v1"
SESSION_SCHEMA = "poc16-upload-client-session-v2"
LEGACY_SESSION_SCHEMA = "poc16-upload-client-session-v1"
ABANDONED_SCHEMA = "poc16-upload-abandoned-v1"
MAX_SOURCE_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_SESSION_DOCUMENT_BYTES = 16 * 1024
MAX_ABANDONED_DOCUMENT_BYTES = 1024
MAX_UPLOAD_SOURCES = 4096
MAX_UPLOAD_DIRECTORY_ENTRIES = MAX_UPLOAD_SOURCES * 2 + 16


class UploadJournalError(ValueError):
    pass


def _hex(value, length):
    return isinstance(value, str) and len(value) == length \
        and all(c in "0123456789abcdef" for c in value)


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _lock(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _root_lock(root):
    return _lock(os.path.join(root, ".catalog.lock"))


def _source_lock(root, source_id):
    locks = os.path.join(root, ".locks")
    os.makedirs(locks, exist_ok=True)
    return _lock(os.path.join(locks, source_id[:2]))


def _new(path, raw):
    with open(path, "xb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def _replace(path, raw):
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(
        prefix="." + os.path.basename(path), dir=directory)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        _sync_dir(directory)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _read(path, maximum, label):
    try:
        if not 0 <= os.path.getsize(path) <= maximum:
            raise UploadJournalError(f"{label} exceeds limit")
        with open(path, "rb") as source:
            raw = source.read(maximum + 1)
    except OSError as error:
        raise UploadJournalError(f"{label} unavailable") from error
    if len(raw) > maximum:
        raise UploadJournalError(f"{label} exceeds limit")
    return raw


@dataclass(frozen=True)
class UploadProgress:
    source_id: str
    session: str
    cursor: str
    cursor_index: int
    delivered_index: int
    expires_at_ms: int
    issued_until_ms: int
    pile_delivered: bool = False


@dataclass(frozen=True)
class UploadStatus:
    source_id: str
    workspace: str
    member: str
    state: str
    object_count: int
    cursor_index: int
    delivered_index: int
    expires_at_ms: int | None
    collect_after_ms: int
    collectible: bool


@dataclass(frozen=True)
class UploadStatusPage:
    uploads: tuple[UploadStatus, ...]
    cursor: str | None


def _source_ids(root):
    """Return one bounded snapshot of content-addressed source names."""
    names = []
    try:
        entries = os.scandir(root)
    except FileNotFoundError:
        return ()
    with entries:
        for scanned, entry in enumerate(entries, 1):
            if scanned > MAX_UPLOAD_DIRECTORY_ENTRIES:
                raise UploadJournalError("upload directory exceeds limit")
            if valid_fid(entry.name) and entry.is_dir(follow_symlinks=False):
                names.append(entry.name)
                if len(names) > MAX_UPLOAD_SOURCES:
                    raise UploadJournalError("upload source count")
    return tuple(sorted(names))


class UploadSourceBuilder:
    """Spool present objects once, then atomically name the complete source."""

    def __init__(self, root, workspace, member):
        if not valid_fid(workspace) or not _hex(member, MEMBER_HEX_BYTES):
            raise ValueError("upload source authority")
        self.root = os.path.abspath(os.fspath(root))
        os.makedirs(self.root, exist_ok=True)
        building = os.path.join(self.root, ".building")
        os.makedirs(building, exist_ok=True)
        os.makedirs(os.path.join(self.root, ".locks"), exist_ok=True)
        self.temporary = tempfile.mkdtemp(
            prefix="source-", dir=building)
        os.mkdir(os.path.join(self.temporary, "objects"))
        self.workspace, self.member, self.sizes = workspace, member, {}
        self.done = False

    def add(self, raw):
        if self.done or not isinstance(raw, bytes) \
                or len(raw) > MAX_OBJECT_BYTES:
            raise ValueError("upload object bytes")
        digest = h(raw)
        if digest in self.sizes:
            return digest
        if len(self.sizes) >= MAX_SESSION_OBJECTS:
            raise UploadJournalError("upload object count")
        _new(os.path.join(self.temporary, "objects", digest), raw)
        self.sizes[digest] = len(raw)
        return digest

    def finish(self, pile):
        if self.done or not isinstance(pile, bytes) \
                or len(pile) > MAX_PILE_BYTES:
            raise ValueError("upload pile bytes")
        self.done = True
        try:
            leaves = tuple(
                UploadLeaf(digest, self.sizes[digest])
                for digest in sorted(self.sizes))
            vector, pile_leaf = UploadVector(leaves), UploadLeaf(
                h(pile), len(pile))
            document = {
                "manifest": asdict(vector.manifest),
                "member": self.member,
                "objects": [asdict(leaf) for leaf in leaves],
                "pile": asdict(pile_leaf),
                "schema": SOURCE_SCHEMA,
                "workspace": self.workspace,
            }
            raw = canon(document)
            source_id = h(raw)
            if len(raw) > MAX_SOURCE_DOCUMENT_BYTES:
                raise UploadJournalError("upload source document")
            _new(os.path.join(self.temporary, "pile"), pile)
            _new(os.path.join(self.temporary, "source.json"), raw)
            _sync_dir(os.path.join(self.temporary, "objects"))
            _sync_dir(self.temporary)
            target = os.path.join(self.root, source_id)
            with _root_lock(self.root):
                if os.path.isdir(target):
                    if _read(
                            os.path.join(target, "source.json"),
                            MAX_SOURCE_DOCUMENT_BYTES,
                            "upload source") != raw:
                        raise UploadJournalError("upload source collision")
                    shutil.rmtree(self.temporary)
                else:
                    if len(_source_ids(self.root)) >= MAX_UPLOAD_SOURCES:
                        raise UploadJournalError("upload source count")
                    os.rename(self.temporary, target)
                    _sync_dir(self.root)
            return UploadSource.load(target)
        except BaseException:
            if os.path.isdir(self.temporary):
                shutil.rmtree(self.temporary)
            raise

    def discard(self):
        if not self.done:
            self.done = True
            shutil.rmtree(self.temporary)


class UploadSource:
    """Validated immutable upload inputs and their atomic session journal."""

    def __init__(self, path, raw, workspace, member, vector, pile):
        self.path, self.raw = os.path.abspath(path), raw
        self.source_id, self.workspace, self.member = (
            h(raw), workspace, member)
        self.vector, self.pile = vector, pile
        self._writer = threading.local()

    @classmethod
    def _load(cls, path, *, bodies):
        path = os.path.abspath(os.fspath(path))
        raw = _read(
            os.path.join(path, "source.json"),
            MAX_SOURCE_DOCUMENT_BYTES, "upload source")
        try:
            value = decode_json(
                raw, MAX_SOURCE_DOCUMENT_BYTES, "upload source")
            if canon(value) != raw or set(value) != {
                    "manifest", "member", "objects", "pile",
                    "schema", "workspace"} \
                    or value["schema"] != SOURCE_SCHEMA \
                    or not valid_fid(value["workspace"]) \
                    or not _hex(value["member"], MEMBER_HEX_BYTES) \
                    or not isinstance(value["objects"], list) \
                    or len(value["objects"]) > MAX_SESSION_OBJECTS:
                raise ValueError
            leaves = tuple(UploadLeaf(**item) for item in value["objects"])
            vector, manifest = UploadVector(leaves), UploadManifest(
                **value["manifest"])
            pile = UploadLeaf(**value["pile"])
            if vector.manifest != manifest or not valid_fid(pile.digest) \
                    or type(pile.size) is not int \
                    or not 0 <= pile.size <= MAX_PILE_BYTES \
                    or os.path.basename(path) != h(raw):
                raise ValueError
        except (TypeError, ValueError) as error:
            raise UploadJournalError("invalid upload source") from error
        source = cls(
            path, raw, value["workspace"], value["member"], vector, pile)
        if bodies:
            source._verify(source.body_path(pile, "pile"), pile)
            for leaf in leaves:
                source._verify(source.body_path(leaf, "obj"), leaf)
        return source

    @classmethod
    def load(cls, path):
        return cls._load(path, bodies=True)

    @classmethod
    def discover(cls, root, now_ms, cursor=None, *, limit=PAGE_BATCH):
        """Read one bounded page of validated local source manifests."""
        root = os.path.abspath(os.fspath(root))
        if type(now_ms) is not int or now_ms < 0 \
                or cursor is not None and not valid_fid(cursor) \
                or type(limit) is not int or not 1 <= limit <= PAGE_BATCH:
            raise ValueError("upload status page")
        names = _source_ids(root)
        start = 0 if cursor is None else bisect_right(names, cursor)
        selected, used, uploads = names[start:start + limit], 0, []
        for source_id in selected:
            path = os.path.join(root, source_id)
            size = os.path.getsize(os.path.join(path, "source.json"))
            if size > MAX_SOURCE_DOCUMENT_BYTES \
                    or used and used + size > MAX_SOURCE_DOCUMENT_BYTES:
                break
            source = cls._load(path, bodies=False)
            used += size
            uploads.append(source.status(now_ms))
        consumed = len(uploads)
        if consumed == 0 and selected:
            raise UploadJournalError("upload status byte budget")
        end = start + consumed
        return UploadStatusPage(
            tuple(uploads), names[end - 1] if end < len(names) else None)

    @staticmethod
    def _verify(path, leaf):
        raw = _read(path, MAX_OBJECT_BYTES, "upload body")
        if len(raw) != leaf.size or h(raw) != leaf.digest:
            raise UploadJournalError("upload body integrity")

    def body_path(self, leaf, kind):
        if kind == "obj" and leaf in self.vector.leaves:
            return os.path.join(self.path, "objects", leaf.digest)
        if kind == "pile" and leaf == self.pile:
            return os.path.join(self.path, "pile")
        raise UploadJournalError("foreign upload body")

    @property
    def session_path(self):
        return os.path.join(self.path, "session.json")

    @property
    def abandoned_path(self):
        return os.path.join(self.path, "abandoned.json")

    @contextmanager
    def writer(self):
        """Serialize a whole resume transition across threads and processes."""
        depth = getattr(self._writer, "depth", 0)
        if depth:
            self._writer.depth = depth + 1
            try:
                yield
            finally:
                self._writer.depth -= 1
            return
        with _source_lock(
                os.path.dirname(self.path), self.source_id):
            if not os.path.isdir(self.path):
                raise UploadJournalError("upload source unavailable")
            self._writer.depth = 1
            try:
                yield
            finally:
                self._writer.depth = 0

    def _checked_progress(self, progress):
        count = len(self.vector.leaves)
        if not isinstance(progress, UploadProgress) \
                or progress.source_id != self.source_id \
                or not _hex(progress.session, SESSION_HEX_BYTES) \
                or not isinstance(progress.cursor, str) \
                or not progress.cursor \
                or type(progress.cursor_index) is not int \
                or type(progress.delivered_index) is not int \
                or not 0 <= progress.delivered_index \
                <= progress.cursor_index <= count \
                or type(progress.expires_at_ms) is not int \
                or type(progress.issued_until_ms) is not int \
                or not 0 <= progress.expires_at_ms \
                <= progress.issued_until_ms \
                or type(progress.pile_delivered) is not bool \
                or progress.pile_delivered \
                and progress.delivered_index != count:
            raise UploadJournalError("invalid upload session")
        return progress

    def progress(self):
        if not os.path.exists(self.session_path):
            return None
        try:
            raw = _read(
                self.session_path, MAX_SESSION_DOCUMENT_BYTES,
                "upload session")
            value = decode_json(
                raw, MAX_SESSION_DOCUMENT_BYTES, "upload session")
            if canon(value) != raw:
                raise ValueError
            schema = value.pop("schema")
            if schema == LEGACY_SESSION_SCHEMA:
                value["issued_until_ms"] = value["expires_at_ms"]
            elif schema != SESSION_SCHEMA:
                raise ValueError
            return self._checked_progress(UploadProgress(**value))
        except (KeyError, TypeError, ValueError) as error:
            raise UploadJournalError("invalid upload session") from error

    def _write_progress(self, progress):
        _replace(self.session_path, canon({
            **asdict(self._checked_progress(progress)),
            "schema": SESSION_SCHEMA,
        }))

    def save(self, progress):
        """Advance one session monotonically; never replace a newer journal."""
        with self.writer():
            current = self.progress()
            progress = self._checked_progress(progress)
            if current is not None and (
                    progress.session != current.session
                    or progress.expires_at_ms != current.expires_at_ms
                    or progress.issued_until_ms < current.issued_until_ms
                    or progress.cursor_index < current.cursor_index
                    or progress.delivered_index < current.delivered_index
                    or current.pile_delivered and not progress.pile_delivered
                    or progress.cursor_index == current.cursor_index
                    and progress.cursor != current.cursor):
                raise UploadJournalError("upload session rollback")
            self._write_progress(progress)

    def restart(self, progress):
        """Atomically replace one unusable session while retaining its expiry."""
        with self.writer():
            current = self.progress()
            progress = self._checked_progress(progress)
            if current is not None and (
                    current.pile_delivered
                    or progress.session == current.session
                    or progress.issued_until_ms < current.issued_until_ms):
                raise UploadJournalError("upload session restart")
            self._write_progress(progress)

    def abandonment(self):
        if not os.path.exists(self.abandoned_path):
            return None
        try:
            raw = _read(
                self.abandoned_path, MAX_ABANDONED_DOCUMENT_BYTES,
                "upload abandonment")
            value = decode_json(
                raw, MAX_ABANDONED_DOCUMENT_BYTES,
                "upload abandonment")
            if canon(value) != raw or set(value) != {
                    "abandoned_at_ms", "collect_after_ms",
                    "schema", "source_id"} \
                    or value["schema"] != ABANDONED_SCHEMA \
                    or value["source_id"] != self.source_id \
                    or type(value["abandoned_at_ms"]) is not int \
                    or type(value["collect_after_ms"]) is not int \
                    or not 0 <= value["abandoned_at_ms"] \
                    <= value["collect_after_ms"]:
                raise ValueError
            return value
        except (KeyError, TypeError, ValueError) as error:
            raise UploadJournalError(
                "invalid upload abandonment") from error

    def status(self, now_ms):
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("upload status clock")
        progress, abandoned = self.progress(), self.abandonment()
        completed = progress is not None and progress.pile_delivered
        if completed:
            state, collect_after = "completed", 0
        elif abandoned is not None:
            state = "abandoned"
            collect_after = abandoned["collect_after_ms"]
        elif progress is not None and progress.expires_at_ms <= now_ms:
            state, collect_after = "expired", progress.issued_until_ms
        else:
            state, collect_after = "active", (
                progress.issued_until_ms if progress is not None else 0)
        return UploadStatus(
            self.source_id, self.workspace, self.member, state,
            len(self.vector.leaves),
            progress.cursor_index if progress is not None else 0,
            progress.delivered_index if progress is not None else 0,
            progress.expires_at_ms if progress is not None else None,
            collect_after,
            completed or state == "abandoned" and now_ms >= collect_after,
        )

    def require_resumable(self):
        if self.abandonment() is not None:
            raise UploadJournalError("upload source abandoned")

    def abandon(self, now_ms):
        """Durably abandon local retries without claiming remote publication."""
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("upload abandonment clock")
        with self.writer():
            current = self.status(now_ms)
            if current.state == "completed":
                raise UploadJournalError("completed upload")
            if current.state == "abandoned":
                return current
            progress = self.progress()
            collect_after = max(
                now_ms,
                progress.issued_until_ms if progress is not None else now_ms,
            )
            _new(self.abandoned_path, canon({
                "abandoned_at_ms": now_ms,
                "collect_after_ms": collect_after,
                "schema": ABANDONED_SCHEMA,
                "source_id": self.source_id,
            }))
            _sync_dir(self.path)
            return self.status(now_ms)

    @classmethod
    def collect(cls, root, workspace, source_id, now_ms):
        """Atomically hide then remove one exact completed/abandoned source."""
        if not valid_fid(workspace) or not valid_fid(source_id) \
                or type(now_ms) is not int or now_ms < 0:
            raise ValueError("upload collection")
        root = os.path.abspath(os.fspath(root))
        target = os.path.join(root, source_id)
        tombstone = os.path.join(
            root, f".collecting-{workspace}-{source_id}")
        with _root_lock(root), _source_lock(root, source_id):
            if not os.path.isdir(target):
                if not os.path.isdir(tombstone):
                    raise UploadJournalError("upload source unavailable")
                shutil.rmtree(tombstone)
                _sync_dir(root)
                return source_id
            source = cls.load(target)
            if source.workspace != workspace:
                raise UploadJournalError("upload source workspace")
            status = source.status(now_ms)
            if not status.collectible:
                raise UploadJournalError("upload source is not collectible")
            if os.path.isdir(tombstone):
                shutil.rmtree(tombstone)
            os.rename(target, tombstone)
            _sync_dir(root)
            try:
                shutil.rmtree(tombstone)
            finally:
                _sync_dir(root)
            return source_id


__all__ = (
    "UploadJournalError",
    "UploadProgress",
    "UploadSource",
    "UploadSourceBuilder",
    "UploadStatus",
    "UploadStatusPage",
)
