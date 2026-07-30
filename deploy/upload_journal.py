"""Durable local authority for a resumable direct upload.

``source.json`` and its bodies are immutable. ``session.json`` is one atomic
record whose separate cursor/cursor_index/delivered_index fields preserve the
only important crash distinction: authority issued is not a delivery receipt.
No database or provider credential is involved.
"""
from dataclasses import asdict, dataclass
import os
import shutil
import tempfile

from core.crypto import h
from core.fact import canon
from core.limits import (
    MAX_OBJECT_BYTES,
    MAX_PILE_BYTES,
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
SESSION_SCHEMA = "poc16-upload-client-session-v1"
MAX_SOURCE_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_SESSION_DOCUMENT_BYTES = 16 * 1024


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
    pile_delivered: bool = False


class UploadSourceBuilder:
    """Spool present objects once, then atomically name the complete source."""

    def __init__(self, root, workspace, member):
        if not valid_fid(workspace) or not _hex(member, MEMBER_HEX_BYTES):
            raise ValueError("upload source authority")
        self.root = os.path.abspath(os.fspath(root))
        os.makedirs(self.root, exist_ok=True)
        self.temporary = tempfile.mkdtemp(
            prefix=".building-", dir=self.root)
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
            try:
                os.rename(self.temporary, target)
                _sync_dir(self.root)
            except OSError:
                if not os.path.isdir(target) \
                        or _read(
                            os.path.join(target, "source.json"),
                            MAX_SOURCE_DOCUMENT_BYTES,
                            "upload source") != raw:
                    raise
                shutil.rmtree(self.temporary)
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

    @classmethod
    def load(cls, path):
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
        source._verify(source.body_path(pile, "pile"), pile)
        for leaf in leaves:
            source._verify(source.body_path(leaf, "obj"), leaf)
        return source

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

    def progress(self):
        if not os.path.exists(self.session_path):
            return None
        try:
            raw = _read(
                self.session_path, MAX_SESSION_DOCUMENT_BYTES,
                "upload session")
            value = decode_json(
                raw, MAX_SESSION_DOCUMENT_BYTES, "upload session")
            if canon(value) != raw or value.pop("schema") != SESSION_SCHEMA:
                raise ValueError
            progress = UploadProgress(**value)
            count = len(self.vector.leaves)
            if progress.source_id != self.source_id \
                    or not _hex(progress.session, SESSION_HEX_BYTES) \
                    or not isinstance(progress.cursor, str) \
                    or not progress.cursor \
                    or type(progress.cursor_index) is not int \
                    or type(progress.delivered_index) is not int \
                    or not 0 <= progress.delivered_index \
                    <= progress.cursor_index <= count \
                    or type(progress.expires_at_ms) is not int \
                    or type(progress.pile_delivered) is not bool \
                    or progress.pile_delivered \
                    and progress.delivered_index != count:
                raise ValueError
            return progress
        except (KeyError, TypeError, ValueError) as error:
            raise UploadJournalError("invalid upload session") from error

    def save(self, progress):
        if not isinstance(progress, UploadProgress) \
                or progress.source_id != self.source_id:
            raise TypeError("upload progress")
        _replace(self.session_path, canon({
            **asdict(progress), "schema": SESSION_SCHEMA}))

    def reset(self):
        try:
            os.unlink(self.session_path)
        except FileNotFoundError:
            return
        _sync_dir(self.path)


__all__ = (
    "UploadJournalError",
    "UploadProgress",
    "UploadSource",
    "UploadSourceBuilder",
)
