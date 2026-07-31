"""Crash-safe full-peer state for one exact-pile upload.

Each source directory contains immutable ``source.json`` and ``pile`` files,
plus at most one replaceable fixed-expiry lease.  This is local retry state,
not repository authority or a server-side queue.
"""
from bisect import bisect_right
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
import shutil
import stat
import threading

from core.crypto import h
from core.fact import canon
from core.limits import MAX_PILE_BYTES, PAGE_BATCH, decode_json
from core.shape import valid_fid
from core.ingress import MEMBER_HEX_CHARS, SESSION_HEX_CHARS
from deploy.upload_session import UploadLeaf, valid_cursor
import deploy.upload_wire as wire


SOURCE_SCHEMA = "poc16-upload-source-v2"
SESSION_SCHEMA = "poc16-upload-client-session-v4"
MAX_SOURCE_DOCUMENT_BYTES = 1_024
MAX_SESSION_DOCUMENT_BYTES = 16 * 1_024
MAX_UPLOAD_SOURCES = 4_096
MAX_UPLOAD_DIRECTORY_ENTRIES = MAX_UPLOAD_SOURCES * 2 + 16
_TERMINAL = frozenset(("applied", "noop", "rejected"))


class UploadJournalError(ValueError):
    pass


def _hex(value, length):
    return isinstance(value, str) and len(value) == length \
        and all(character in "0123456789abcdef" for character in value)


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _lock(path, *, blocking=True):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    locked = False
    try:
        try:
            fcntl.flock(
                fd,
                fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB),
            )
            locked = True
        except BlockingIOError as error:
            raise UploadJournalError("upload source is active") from error
        yield
    finally:
        if locked:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _root_lock(root):
    return _lock(os.path.join(root, ".journal.lock"))


def _source_lock(root, source_id, *, blocking=True):
    locks = os.path.join(root, ".locks")
    os.makedirs(locks, exist_ok=True)
    return _lock(os.path.join(locks, source_id[:4]), blocking=blocking)


def _new(path, raw):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def _replace(path, raw):
    directory = os.path.dirname(path)
    temporary = os.path.join(
        directory, "." + os.path.basename(path) + ".next")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC \
        | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= maximum:
                raise UploadJournalError(f"{label} exceeds limit")
            raw = source.read(maximum + 1)
    except UploadJournalError:
        raise
    except OSError as error:
        raise UploadJournalError(f"{label} unavailable") from error
    if len(raw) > maximum:
        raise UploadJournalError(f"{label} exceeds limit")
    return raw


@dataclass(frozen=True, slots=True)
class UploadProgress:
    source_id: str
    session: str
    cursor: str
    expires_at_ms: int
    capability: wire.UploadCapability
    status: str | None = None


@dataclass(frozen=True, slots=True)
class UploadStatus:
    source_id: str
    workspace: str
    member: str
    state: str
    expires_at_ms: int | None
    collectible: bool


@dataclass(frozen=True, slots=True)
class UploadStatusPage:
    uploads: tuple[UploadStatus, ...]
    cursor: str | None


def _source_ids(root):
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


class UploadSource:
    """One immutable local pile and its replaceable current lease."""

    def __init__(self, path, source_id, workspace, member, pile):
        self.path = os.path.abspath(path)
        self.source_id, self.workspace, self.member = \
            source_id, workspace, member
        self.pile = pile
        self._writer = threading.local()

    @classmethod
    def create(cls, root, workspace, member, pile):
        """Atomically retain one exact pile; the call has no open builder."""
        if not valid_fid(workspace) or not _hex(member, MEMBER_HEX_CHARS):
            raise ValueError("upload source authority")
        if not isinstance(pile, bytes) or len(pile) > MAX_PILE_BYTES:
            raise ValueError("upload pile bytes")
        root = os.path.abspath(os.fspath(root))
        leaf = UploadLeaf(h(pile), len(pile))
        raw = canon({
            "member": member,
            "pile": {"digest": leaf.digest, "size": leaf.size},
            "schema": SOURCE_SCHEMA,
            "workspace": workspace,
        })
        source_id = h(raw)
        target = os.path.join(root, source_id)
        temporary = os.path.join(root, ".creating")
        os.makedirs(root, exist_ok=True)
        os.makedirs(os.path.join(root, ".locks"), exist_ok=True)
        with _root_lock(root):
            # The journal lock makes this fixed path a crash-recovery slot, not
            # an unbounded family of abandoned builder directories.
            for stale in (temporary, os.path.join(root, ".building")):
                if os.path.lexists(stale):
                    if os.path.islink(stale) or not os.path.isdir(stale):
                        raise UploadJournalError(
                            "upload creation collision")
                    shutil.rmtree(stale)
                    _sync_dir(root)
            os.mkdir(temporary, 0o700)
            try:
                _new(os.path.join(temporary, "pile"), pile)
                _new(os.path.join(temporary, "source.json"), raw)
                _sync_dir(temporary)
                if os.path.isdir(target) and not os.path.islink(target):
                    if _read(
                            os.path.join(target, "source.json"),
                            MAX_SOURCE_DOCUMENT_BYTES,
                            "upload source") != raw \
                            or _read(
                                os.path.join(target, "pile"),
                                MAX_PILE_BYTES,
                                "upload pile") != pile:
                        raise UploadJournalError(
                            "upload source collision")
                    shutil.rmtree(temporary)
                    _sync_dir(root)
                else:
                    if os.path.lexists(target):
                        raise UploadJournalError(
                            "upload source collision")
                    if len(_source_ids(root)) >= MAX_UPLOAD_SOURCES:
                        raise UploadJournalError("upload source count")
                    os.rename(temporary, target)
                    _sync_dir(root)
            except BaseException:
                if os.path.isdir(temporary) \
                        and not os.path.islink(temporary):
                    shutil.rmtree(temporary)
                    _sync_dir(root)
                raise
        return cls.load(target)

    @classmethod
    def _load(cls, path, *, body):
        path = os.path.abspath(os.fspath(path))
        if os.path.islink(path):
            raise UploadJournalError("upload source unavailable")
        raw = _read(
            os.path.join(path, "source.json"),
            MAX_SOURCE_DOCUMENT_BYTES,
            "upload source",
        )
        try:
            value = decode_json(raw, MAX_SOURCE_DOCUMENT_BYTES, "upload source")
            if canon(value) != raw or not isinstance(value, dict) \
                    or set(value) != {"member", "pile", "schema", "workspace"} \
                    or value["schema"] != SOURCE_SCHEMA \
                    or not valid_fid(value["workspace"]) \
                    or not _hex(value["member"], MEMBER_HEX_CHARS) \
                    or not isinstance(value["pile"], dict) \
                    or set(value["pile"]) != {"digest", "size"}:
                raise ValueError
            pile = UploadLeaf(
                value["pile"]["digest"], value["pile"]["size"])
            if not valid_fid(pile.digest) or type(pile.size) is not int \
                    or not 0 <= pile.size <= MAX_PILE_BYTES \
                    or os.path.basename(path) != h(raw):
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise UploadJournalError("invalid upload source") from error
        source = cls(
            path, h(raw), value["workspace"], value["member"], pile)
        if body:
            source.verify_body()
        return source

    @classmethod
    def load(cls, path):
        return cls._load(path, body=True)

    @classmethod
    def discover(cls, root, now_ms, cursor=None, *, limit=PAGE_BATCH):
        root = os.path.abspath(os.fspath(root))
        if type(now_ms) is not int or now_ms < 0 \
                or cursor is not None and not valid_fid(cursor) \
                or type(limit) is not int or not 1 <= limit <= PAGE_BATCH:
            raise ValueError("upload status page")
        names = _source_ids(root)
        start = 0 if cursor is None else bisect_right(names, cursor)
        selected = names[start:start + limit]
        uploads = tuple(
            cls._load(os.path.join(root, source_id), body=False).status(now_ms)
            for source_id in selected
        )
        end = start + len(selected)
        return UploadStatusPage(
            uploads, names[end - 1] if end < len(names) and selected else None)

    @property
    def body_path(self):
        return os.path.join(self.path, "pile")

    @property
    def session_path(self):
        return os.path.join(self.path, "session.json")

    @property
    def abandoned_path(self):
        return os.path.join(self.path, "abandoned")

    def verify_body(self):
        raw = _read(self.body_path, MAX_PILE_BYTES, "upload pile")
        if len(raw) != self.pile.size or h(raw) != self.pile.digest:
            raise UploadJournalError("upload pile integrity")
        return raw

    @contextmanager
    def writer(self):
        depth = getattr(self._writer, "depth", 0)
        if depth:
            self._writer.depth = depth + 1
            try:
                yield
            finally:
                self._writer.depth -= 1
            return
        with _source_lock(os.path.dirname(self.path), self.source_id):
            if not os.path.isdir(self.path) or os.path.islink(self.path):
                raise UploadJournalError("upload source unavailable")
            self._writer.depth = 1
            try:
                yield
            finally:
                self._writer.depth = 0

    def _checked_progress(self, value):
        capability = value.capability if isinstance(value, UploadProgress) \
            else None
        if not isinstance(value, UploadProgress) \
                or value.source_id != self.source_id \
                or not _hex(value.session, SESSION_HEX_CHARS) \
                or not valid_cursor(value.cursor) \
                or type(value.expires_at_ms) is not int \
                or value.expires_at_ms < 0 \
                or not isinstance(capability, wire.UploadCapability) \
                or not isinstance(capability.url, str) \
                or not isinstance(capability.headers, tuple) \
                or type(capability.expires_at_ms) is not int \
                or capability.expires_at_ms > value.expires_at_ms \
                or value.status is not None and value.status not in _TERMINAL:
            raise UploadJournalError("invalid upload session")
        return value

    def progress(self):
        if not os.path.exists(self.session_path):
            return None
        try:
            raw = _read(
                self.session_path,
                MAX_SESSION_DOCUMENT_BYTES,
                "upload session",
            )
            value = decode_json(raw, MAX_SESSION_DOCUMENT_BYTES, "upload session")
            if canon(value) != raw or not isinstance(value, dict) \
                    or set(value) != {
                        "capability", "cursor", "expires_at_ms", "schema",
                        "session", "source_id", "status",
                    } \
                    or value["schema"] != SESSION_SCHEMA:
                raise ValueError
            return self._checked_progress(UploadProgress(
                value["source_id"],
                value["session"],
                value["cursor"],
                value["expires_at_ms"],
                wire.decode_capability_document(value["capability"]),
                value["status"],
            ))
        except (KeyError, TypeError, ValueError) as error:
            raise UploadJournalError("invalid upload session") from error

    def _write_progress(self, value):
        value = self._checked_progress(value)
        _replace(self.session_path, canon({
            "capability": wire.capability_document(value.capability),
            "cursor": value.cursor,
            "expires_at_ms": value.expires_at_ms,
            "schema": SESSION_SCHEMA,
            "session": value.session,
            "source_id": value.source_id,
            "status": value.status,
        }))

    def advance(self, value):
        """Install a lease, replace a live lease, or make it terminal."""
        with self.writer():
            current = self.progress()
            value = self._checked_progress(value)
            if current is None and value.status is not None:
                raise UploadJournalError("upload session rollback")
            if current is not None:
                same = value.session == current.session
                if current.status is not None and value != current \
                        or same and (
                            value.cursor != current.cursor
                            or value.expires_at_ms != current.expires_at_ms
                            or value.capability != current.capability
                        ) \
                        or not same and value.status is not None:
                    raise UploadJournalError("upload session rollback")
            self._write_progress(value)

    def abandoned(self):
        if not os.path.exists(self.abandoned_path):
            return False
        if _read(self.abandoned_path, 0, "upload abandonment") != b"":
            raise UploadJournalError("invalid upload abandonment")
        return True

    def status(self, now_ms):
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("upload status clock")
        progress = self.progress()
        if self.abandoned():
            state = "abandoned"
        elif progress is not None and progress.status in {"applied", "noop"}:
            state = "completed"
        elif progress is not None and progress.status == "rejected":
            state = "rejected"
        elif progress is not None and progress.expires_at_ms <= now_ms:
            state = "expired"
        else:
            state = "active"
        return UploadStatus(
            self.source_id,
            self.workspace,
            self.member,
            state,
            progress.expires_at_ms if progress is not None else None,
            state in {"abandoned", "completed", "rejected"},
        )

    def require_resumable(self):
        if self.abandoned():
            raise UploadJournalError("upload source abandoned")

    def abandon(self, now_ms):
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("upload abandonment clock")
        with self.writer():
            current = self.status(now_ms)
            if current.state == "completed":
                raise UploadJournalError("completed upload")
            if current.state == "abandoned":
                return current
            _new(self.abandoned_path, b"")
            _sync_dir(self.path)
            return self.status(now_ms)

    @classmethod
    def collect(cls, root, workspace, source_id, now_ms):
        if not valid_fid(workspace) or not valid_fid(source_id) \
                or type(now_ms) is not int or now_ms < 0:
            raise ValueError("upload collection")
        root = os.path.abspath(os.fspath(root))
        target = os.path.join(root, source_id)
        tombstone = os.path.join(root, f".collecting-{workspace}-{source_id}")
        with _root_lock(root), _source_lock(root, source_id, blocking=False):
            if os.path.lexists(tombstone):
                if os.path.islink(tombstone):
                    raise UploadJournalError("upload collection collision")
                shutil.rmtree(tombstone)
                _sync_dir(root)
            if not os.path.isdir(target) or os.path.islink(target):
                raise UploadJournalError("upload source unavailable")
            source = cls._load(target, body=False)
            if source.workspace != workspace:
                raise UploadJournalError("upload source workspace")
            if not source.status(now_ms).collectible:
                raise UploadJournalError("upload source is not collectible")
            os.rename(target, tombstone)
            _sync_dir(root)
            shutil.rmtree(tombstone)
            _sync_dir(root)
            return source_id


__all__ = (
    "UploadJournalError",
    "UploadProgress",
    "UploadSource",
    "UploadStatus",
    "UploadStatusPage",
)
