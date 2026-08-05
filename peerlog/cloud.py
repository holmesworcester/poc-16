"""Owner-confined passive cloud queue for authenticated writer runs.

The cloud never interprets facts and never builds a shared content index.  It
stores immutable queue segments, one CAS slot per writer, and one derived
workspace directory used only as a conditional-GET poll target.  Segment
footers are small enough for a suffix range and summarize the sequence and
timestamp span without becoming authority.

The layout has three physical stages:

* at most ``MICRO_TAIL`` create-only publications;
* client-folded binary segments smaller than ``MULTIPART_EDGE``;
* a mono-log appended with server-side multipart copy once that edge is met.

All semantic bytes are the exact :class:`peerlog.proof.Run` codec also served
by a live peer.  Consequently a cold cloud consumer and a peer consumer make
the same signature, density, inclusion, fork, and atomic-ingest decisions.
"""
from __future__ import annotations

import base64
import hashlib
import math
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Protocol

from core.fact import canon
from core.limits import decode_json

from .fact import Ref, decode_slice, is_control
from .ingest import PeerState, ingest_batch
from .log import WriterLog, decode_head, encode_head, valid_writer
from .proof import Run, decode_run, encode_run, prove_run


MICRO_TAIL = 32
MULTIPART_EDGE = 5 * 1024 * 1024
EPOCH_CAP = 64 * 1024 * 1024
FOOTER_READ = 64 * 1024
CLOUD_GET_CONCURRENCY = 64
CLOUD_CLOSURE_MAX_DEPTH = 32
CLOUD_CLOSURE_MAX_REFS = 8 * 1024
CLOUD_CLOSURE_MAX_SEGMENTS = 2 * 1024
CLOUD_CLOSURE_MAX_BYTES = 256 * 1024 * 1024
CLOUD_DEMAND_MAX_WRITERS = 4 * 1024
CLOUD_DEMAND_MAX_INTERVALS_PER_WRITER = 64
CLOUD_DEMAND_MAX_INTERVALS = 8 * 1024
CLOUD_ANNEX_MAX_RUNS = 256
CLOUD_PUBLICATION_MAX_BYTES = 16 * 1024 * 1024
SEGMENT_MAGIC = b"P16Q1\x00"
FOOTER_MAGIC = b"P16F"
SLOT_FORMAT = "poc16-cloud-writer-slot-v1"
DIRECTORY_FORMAT = "poc16-cloud-directory-v1"
PUBLICATION_MAGIC = b"P16P1\x00"
FOOTER_FORMAT = "poc16-cloud-footer-v1"
HANDOFF_FAMILIES = frozenset({"invite", "device"})


@dataclass
class CloudMetrics:
    gets: int = 0
    conditional_gets: int = 0
    puts: int = 0
    cas: int = 0
    lists: int = 0
    multipart_creates: int = 0
    part_copies: int = 0
    multipart_completes: int = 0
    uploaded_bytes: int = 0
    object_upload_bytes: int = 0
    register_upload_bytes: int = 0
    copied_bytes: int = 0
    downloaded_bytes: int = 0

    def copy(self):
        return CloudMetrics(**vars(self))

    def delta(self, earlier):
        return CloudMetrics(**{
            name: getattr(self, name) - getattr(earlier, name)
            for name in vars(self)
        })


@dataclass(frozen=True)
class VersionedObject:
    value: bytes | None
    token: object | None


class PartCopyUnavailable(RuntimeError):
    pass


class MaintenanceRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class MicroForkEvidence:
    workspace: bytes
    writer: bytes
    lo: int
    hi: int
    key: str
    incumbent_hash: str
    proposed_hash: str


class CloudMicroFork(ValueError):
    """A divergent publication collided with a crash-orphaned micro."""

    def __init__(self, evidence):
        if not isinstance(evidence, MicroForkEvidence):
            raise ValueError("cloud micro fork evidence")
        self.evidence = evidence
        super().__init__(
            "cloud micro fork; readmit the authenticated orphan before "
            "rebasing or rotate the writer identity")


class CloudObjectStore(Protocol):
    """Provider seam implemented by MemoryCloud and the direct R2 adapter."""

    metrics: CloudMetrics

    def get(self, key, *, if_none_match=None, suffix=None): ...
    def read_versioned(self, key): ...
    def create(self, key, value): ...
    def cas(self, key, token, value): ...
    def list(self, prefix): ...
    def begin_multipart(self, key): ...
    def copy_part(self, upload, source_key, stop=None): ...
    def upload_part(self, upload, value): ...
    def complete_multipart(self, upload): ...
    def abort_multipart(self, upload): ...


class MemoryCloud:
    """Thread-safe object-store reference implementation with real CAS shape.

    Multipart uploads remain invisible until ``complete_multipart``.  Tests
    can set ``fail_next_copy`` to exercise the automatic epoch fallback at the
    same boundary used by an R2 adapter.
    """

    def __init__(self):
        self._objects = {}
        self._versions = {}
        self._uploads = {}
        self._next_upload = 0
        self._lock = threading.RLock()
        self.metrics = CloudMetrics()
        self.fail_next_copy = False

    def get(self, key, *, if_none_match=None, suffix=None):
        with self._lock:
            self.metrics.gets += 1
            if if_none_match is not None:
                self.metrics.conditional_gets += 1
            value = self._objects.get(key)
            if value is None:
                return None, None
            tag = hashlib.sha256(value).hexdigest()
            if tag == if_none_match:
                return None, tag
            result = value[-suffix:] if suffix is not None else value
            self.metrics.downloaded_bytes += len(result)
            return result, tag

    def read_versioned(self, key):
        with self._lock:
            self.metrics.gets += 1
            value = self._objects.get(key)
            if value is not None:
                self.metrics.downloaded_bytes += len(value)
            return VersionedObject(value, self._versions.get(key))

    def create(self, key, value):
        if not isinstance(value, bytes):
            raise ValueError("cloud object bytes")
        with self._lock:
            self.metrics.puts += 1
            self.metrics.uploaded_bytes += len(value)
            self.metrics.object_upload_bytes += len(value)
            incumbent = self._objects.get(key)
            if incumbent is not None and incumbent != value:
                raise ValueError("immutable object collision")
            if incumbent is None:
                self._objects[key] = value
                self._versions[key] = self._versions.get(key, 0) + 1
            return incumbent is None

    def cas(self, key, token, value):
        if not isinstance(value, bytes):
            raise ValueError("cloud CAS bytes")
        with self._lock:
            self.metrics.cas += 1
            self.metrics.uploaded_bytes += len(value)
            self.metrics.register_upload_bytes += len(value)
            if self._versions.get(key) != token:
                return False
            self._objects[key] = value
            self._versions[key] = self._versions.get(key, 0) + 1
            return True

    def list(self, prefix):
        with self._lock:
            self.metrics.lists += 1
            return tuple(sorted(key for key in self._objects
                                if key.startswith(prefix)))

    def begin_multipart(self, key):
        with self._lock:
            self.metrics.multipart_creates += 1
            self._next_upload += 1
            upload = self._next_upload
            self._uploads[upload] = [key, []]
            return upload

    def copy_part(self, upload, source_key, stop=None):
        with self._lock:
            if self.fail_next_copy:
                self.fail_next_copy = False
                self._uploads.pop(upload, None)
                raise PartCopyUnavailable("part copy unavailable")
            value = self._objects.get(source_key)
            if value is None:
                raise ValueError("multipart source")
            value = value if stop is None else value[:stop]
            if len(value) < MULTIPART_EDGE:
                raise ValueError("multipart copied part below provider edge")
            self.metrics.part_copies += 1
            self.metrics.copied_bytes += len(value)
            self._uploads[upload][1].append(value)

    def upload_part(self, upload, value):
        if not isinstance(value, bytes) or not value:
            raise ValueError("multipart upload part")
        with self._lock:
            self.metrics.puts += 1
            self.metrics.uploaded_bytes += len(value)
            self.metrics.object_upload_bytes += len(value)
            self._uploads[upload][1].append(value)

    def complete_multipart(self, upload):
        with self._lock:
            key, parts = self._uploads.pop(upload)
            if not parts:
                raise ValueError("empty multipart upload")
            value = b"".join(parts)
            self.metrics.multipart_completes += 1
            self._objects[key] = value
            self._versions[key] = self._versions.get(key, 0) + 1
            return value

    def abort_multipart(self, upload):
        with self._lock:
            self._uploads.pop(upload, None)


@dataclass(frozen=True)
class Segment:
    key: str
    lo: int
    hi: int
    size: int
    weight: int
    kind: str


@dataclass(frozen=True)
class Slot:
    workspace: bytes
    writer: bytes
    head: bytes
    segments: tuple[Segment, ...]

    @property
    def hi(self):
        return self.segments[-1].hi if self.segments else 0


@dataclass(frozen=True)
class Publication:
    main: Run
    carries: tuple[Run, ...] = ()
    handoff_targets: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class HandoffTicket:
    workspace: bytes
    writer: bytes
    lo: int
    hi: int
    key: str
    recipient: bytes


@dataclass(frozen=True)
class PublicationReceipt:
    segment: Segment
    handoffs: tuple[HandoffTicket, ...]


@dataclass
class CloudCache:
    directory_tag: str | None = None
    request_key: object | None = None
    pending: tuple[Ref, ...] = ()
    closure_exhausted: bool = False
    interactive_ready: bool = True
    state: object | None = None


@dataclass(frozen=True)
class WriterDemand:
    """One writer's tail-relative or exact sequence demand."""

    writer: bytes
    tail: int | None = None
    intervals: tuple[tuple[int, int], ...] = ()

    def __post_init__(self):
        if not valid_writer(self.writer) \
                or self.tail is not None and (
                    type(self.tail) is not int or self.tail < 0) \
                or not isinstance(self.intervals, tuple) \
                or len(self.intervals) > CLOUD_DEMAND_MAX_INTERVALS_PER_WRITER:
            raise ValueError("cloud writer demand")
        if self.tail is not None and self.intervals:
            raise ValueError("cloud writer demand mode")
        validated = []
        for interval in self.intervals:
            if not isinstance(interval, tuple) or len(interval) != 2 \
                    or any(type(item) is not int for item in interval) \
                    or interval[0] < 0 or interval[1] <= interval[0] \
                    or interval[1] >= 1 << 63:
                raise ValueError("cloud demand interval")
            validated.append(interval)
        normalized = []
        for lo, hi in sorted(validated):
            if normalized and lo <= normalized[-1][1]:
                normalized[-1] = (
                    normalized[-1][0], max(normalized[-1][1], hi))
            else:
                normalized.append((lo, hi))
        object.__setattr__(self, "intervals", tuple(normalized))
        object.__setattr__(self, "_input_interval_count", len(validated))

    def resolve(self, hi):
        if type(hi) is not int or hi < 0:
            raise ValueError("cloud writer demand head")
        if self.tail is not None:
            return () if not self.tail or not hi else ((max(0, hi - self.tail), hi),)
        return tuple((lo, min(stop, hi)) for lo, stop in self.intervals
                     if lo < hi)


@dataclass(frozen=True)
class CloudDemand:
    """Canonical bounded collection of independent writer requests."""

    writers: tuple[WriterDemand, ...]

    def __post_init__(self):
        if not isinstance(self.writers, tuple) \
                or len(self.writers) > CLOUD_DEMAND_MAX_WRITERS \
                or any(not isinstance(item, WriterDemand)
                       for item in self.writers) \
                or len({item.writer for item in self.writers}) \
                != len(self.writers) \
                or sum(item._input_interval_count for item in self.writers) \
                > CLOUD_DEMAND_MAX_INTERVALS:
            raise ValueError("cloud demand")
        object.__setattr__(
            self, "writers", tuple(sorted(
                self.writers, key=lambda item: item.writer)))

    @classmethod
    def tails(cls, writers, count):
        try:
            writers = tuple(writers)
        except TypeError as error:
            raise ValueError("cloud demand writers") from error
        return cls(tuple(WriterDemand(writer, tail=count)
                         for writer in writers))

    @classmethod
    def exact(cls, intervals_by_writer):
        if not isinstance(intervals_by_writer, dict):
            raise ValueError("cloud demand map")
        try:
            writers = tuple(
                WriterDemand(writer, intervals=tuple(intervals))
                for writer, intervals in intervals_by_writer.items())
        except TypeError as error:
            raise ValueError("cloud demand map") from error
        return cls(writers)


@dataclass(frozen=True)
class CloudClosureLimits:
    """Resource bounds for transitively closing one requested cloud view."""

    max_depth: int = CLOUD_CLOSURE_MAX_DEPTH
    max_refs: int = CLOUD_CLOSURE_MAX_REFS
    max_segments: int = CLOUD_CLOSURE_MAX_SEGMENTS
    max_bytes: int = CLOUD_CLOSURE_MAX_BYTES

    def __post_init__(self):
        if any(type(value) is not int or value < 0 for value in (
                self.max_depth, self.max_refs, self.max_segments,
                self.max_bytes)):
            raise ValueError("cloud closure limits")


@dataclass(frozen=True)
class CloudSyncReport:
    changed: bool
    rounds: int
    object_gets: int
    received_bytes: int
    facts: int
    carries: int
    pending: tuple[Ref, ...]
    directory_tag: str | None
    initial_segment_gets: int = 0
    closure_segment_gets: int = 0
    initial_bytes: int = 0
    closure_bytes: int = 0
    initial_facts: int = 0
    closure_facts: int = 0
    segment_overfetch_facts: int = 0
    closure_depth: int = 0
    closure_exhausted: bool = False
    interactive_ready: bool = True


def _segment_document(segment):
    return {
        "hi": segment.hi,
        "key": segment.key,
        "kind": segment.kind,
        "lo": segment.lo,
        "size": segment.size,
        "weight": segment.weight,
    }


def _micro_key(workspace, writer, lo, hi):
    return f"cloud/{workspace.hex()}/writers/{writer.hex()}/micro/{lo:016d}-{hi:016d}"


def _decode_segment_document(value):
    if not isinstance(value, dict) or set(value) != {
            "hi", "key", "kind", "lo", "size", "weight"}:
        raise ValueError("cloud segment descriptor")
    result = Segment(value["key"], value["lo"], value["hi"], value["size"],
                     value["weight"], value["kind"])
    if not isinstance(result.key, str) or not result.key \
            or result.kind not in {"micro", "ladder", "mono", "epoch"} \
            or any(type(item) is not int for item in (
                result.lo, result.hi, result.size, result.weight)) \
            or result.lo < 0 or result.hi <= result.lo \
            or result.size <= 0 or result.weight <= 0:
        raise ValueError("cloud segment descriptor")
    return result


def encode_slot(slot):
    stable = [item for item in slot.segments if item.kind != "micro"]
    micro = [item for item in slot.segments if item.kind == "micro"]
    if slot.segments != tuple((*stable, *micro)) \
            or any(item.key != _micro_key(
                slot.workspace, slot.writer, item.lo, item.hi)
                for item in micro):
        raise ValueError("cloud micro tail")
    return canon({
        "format": SLOT_FORMAT,
        "head": base64.b64encode(slot.head).decode("ascii"),
        "micro": [[item.lo, item.hi, item.size, item.weight]
                  for item in micro],
        "segments": [_segment_document(item) for item in stable],
        "workspace": slot.workspace.hex(),
        "writer": slot.writer.hex(),
    })


def decode_slot(raw):
    value = decode_json(raw, 2 * 1024 * 1024, "cloud writer slot")
    if not isinstance(value, dict) or set(value) != {
            "format", "head", "micro", "segments", "workspace", "writer"} \
            or value.get("format") != SLOT_FORMAT \
            or not isinstance(value.get("micro"), list) \
            or not isinstance(value.get("segments"), list):
        raise ValueError("cloud writer slot")
    try:
        workspace = bytes.fromhex(value["workspace"])
        writer = bytes.fromhex(value["writer"])
        head = base64.b64decode(value["head"], validate=True)
        decoded_head = decode_head(head)
        stable = tuple(_decode_segment_document(item)
                       for item in value["segments"])
        micro = []
        for item in value["micro"]:
            if not isinstance(item, list) or len(item) != 4 \
                    or any(type(number) is not int for number in item):
                raise ValueError
            lo, hi, size, weight = item
            micro.append(Segment(
                _micro_key(workspace, writer, lo, hi),
                lo, hi, size, weight, "micro"))
        segments = (*stable, *micro)
        slot = Slot(workspace, writer, head, segments)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("cloud writer slot") from error
    if len(workspace) != 32 or not valid_writer(writer) \
            or decoded_head.writer != writer \
            or any(left.hi != right.lo
                   for left, right in zip(segments, segments[1:])) \
            or segments and segments[0].lo != 0 \
            or segments and segments[-1].hi > decoded_head.seq + 1 \
            or sum(item.kind == "micro" for item in segments) > MICRO_TAIL \
            or len({item.key for item in segments}) != len(segments) \
            or any(item.size > EPOCH_CAP + MULTIPART_EDGE
                   or not item.key.startswith(
                       f"cloud/{workspace.hex()}/writers/{writer.hex()}/")
                   for item in segments) \
            or encode_slot(slot) != raw:
        raise ValueError("cloud writer slot")
    return slot


def _publication_bytes(publication):
    main = encode_run(publication.main)
    if len(publication.carries) > CLOUD_ANNEX_MAX_RUNS \
            or len(publication.handoff_targets) > 256:
        raise ValueError("cloud publication count")
    raw = bytearray(PUBLICATION_MAGIC)
    raw.extend(struct.pack(">I", len(main)))
    raw.extend(main)
    raw.extend(struct.pack(">H", len(publication.carries)))
    for carried in publication.carries:
        encoded = encode_run(carried)
        raw.extend(struct.pack(">I", len(encoded)))
        raw.extend(encoded)
    raw.extend(struct.pack(">H", len(publication.handoff_targets)))
    for target in publication.handoff_targets:
        if not isinstance(target, bytes) or len(target) != 32:
            raise ValueError("cloud handoff target")
        raw.extend(target)
    result = bytes(raw)
    if len(result) > CLOUD_PUBLICATION_MAX_BYTES:
        raise ValueError("cloud publication too large")
    return result


def _decode_publication(raw):
    if not isinstance(raw, bytes) or len(raw) > CLOUD_PUBLICATION_MAX_BYTES \
            or not raw.startswith(PUBLICATION_MAGIC):
        raise ValueError("cloud publication")
    try:
        cursor = len(PUBLICATION_MAGIC)

        def take(size):
            nonlocal cursor
            if cursor + size > len(raw):
                raise ValueError
            value = raw[cursor:cursor + size]
            cursor += size
            return value

        main_size = struct.unpack(">I", take(4))[0]
        main = decode_run(take(main_size))
        carry_count = struct.unpack(">H", take(2))[0]
        carries = []
        for _item in range(carry_count):
            size = struct.unpack(">I", take(4))[0]
            carries.append(decode_run(take(size)))
        target_count = struct.unpack(">H", take(2))[0]
        targets = tuple(take(32) for _item in range(target_count))
        if cursor != len(raw):
            raise ValueError
        result = Publication(main, tuple(carries), targets)
    except (TypeError, ValueError, UnicodeError, struct.error) as error:
        raise ValueError("cloud publication") from error
    if any(len(item) != 32 for item in result.handoff_targets) \
            or len(set(result.handoff_targets)) != len(result.handoff_targets) \
            or _publication_bytes(result) != raw:
        raise ValueError("cloud publication")
    return result


def _encode_segment(publications, kind):
    if not publications or kind not in {"micro", "ladder", "mono", "epoch"}:
        raise ValueError("empty cloud segment")
    records = [_publication_bytes(item) for item in publications]
    payload = bytearray(SEGMENT_MAGIC)
    for record in records:
        payload.extend(struct.pack(">I", len(record)))
        payload.extend(record)
    mains = [item.main for item in publications]
    facts = [fact for item in mains
             for fact in decode_slice(item.facts, item.hi - item.lo)]
    footer = canon({
        "count": len(publications),
        "format": FOOTER_FORMAT,
        "hash": hashlib.sha256(payload).hexdigest(),
        "hi": mains[-1].hi,
        "kind": kind,
        "lo": mains[0].lo,
        "ts_max": max(fact.ts for fact in facts),
        "ts_min": min(fact.ts for fact in facts),
        "writer": mains[0].writer.hex(),
    })
    if len(footer) + 8 > FOOTER_READ:
        raise ValueError("cloud footer too large")
    return bytes(payload) + footer + struct.pack(">I", len(footer)) + FOOTER_MAGIC


def decode_footer(suffix):
    if not isinstance(suffix, bytes) or len(suffix) < 8 \
            or suffix[-4:] != FOOTER_MAGIC:
        raise ValueError("cloud segment footer")
    size = struct.unpack(">I", suffix[-8:-4])[0]
    if size <= 0 or size + 8 > len(suffix):
        raise ValueError("cloud segment footer")
    raw = suffix[-8 - size:-8]
    value = decode_json(raw, FOOTER_READ, "cloud segment footer")
    if not isinstance(value, dict) or set(value) != {
            "count", "format", "hash", "hi", "kind", "lo", "ts_max",
            "ts_min", "writer"} or value.get("format") != FOOTER_FORMAT \
            or canon(value) != raw:
        raise ValueError("cloud segment footer")
    try:
        bytes.fromhex(value["writer"])
        bytes.fromhex(value["hash"])
    except (TypeError, ValueError) as error:
        raise ValueError("cloud segment footer") from error
    return value


def _decode_segment(raw):
    footer = decode_footer(raw[-FOOTER_READ:])
    footer_size = struct.unpack(">I", raw[-8:-4])[0]
    payload = raw[:-8 - footer_size]
    if not payload.startswith(SEGMENT_MAGIC) \
            or hashlib.sha256(payload).hexdigest() != footer["hash"]:
        raise ValueError("cloud segment payload")
    cursor = len(SEGMENT_MAGIC)
    publications = []
    while cursor < len(payload):
        if cursor + 4 > len(payload):
            raise ValueError("cloud segment frame")
        size = struct.unpack(">I", payload[cursor:cursor + 4])[0]
        cursor += 4
        if size <= 0 or cursor + size > len(payload):
            raise ValueError("cloud segment frame")
        publications.append(_decode_publication(payload[cursor:cursor + size]))
        cursor += size
    if len(publications) != footer["count"]:
        raise ValueError("cloud segment count")
    mains = [item.main for item in publications]
    if not mains or mains[0].lo != footer["lo"] \
            or mains[-1].hi != footer["hi"] \
            or any(left.hi != right.lo for left, right in zip(mains, mains[1:])) \
            or any(item.writer.hex() != footer["writer"] for item in mains):
        raise ValueError("cloud segment span")
    result = tuple(publications)
    if _encode_segment(result, footer["kind"]) != raw:
        raise ValueError("non-canonical cloud segment")
    return result


def _payload_size(raw):
    """Number of bytes before the replaceable footer/trailer."""
    decode_footer(raw[-FOOTER_READ:])
    footer_size = struct.unpack(">I", raw[-8:-4])[0]
    return len(raw) - 8 - footer_size


def _directory_bytes(workspace, slots):
    return canon({
        "format": DIRECTORY_FORMAT,
        "slots": [[writer.hex(), base64.b64encode(raw).decode("ascii")]
                  for writer, raw in sorted(slots.items())],
        "workspace": workspace.hex(),
    })


def _decode_directory(raw, workspace):
    value = decode_json(raw, 16 * 1024 * 1024, "cloud directory")
    if not isinstance(value, dict) or set(value) != {
            "format", "slots", "workspace"} \
            or value.get("format") != DIRECTORY_FORMAT \
            or value.get("workspace") != workspace.hex() \
            or not isinstance(value.get("slots"), list):
        raise ValueError("cloud directory")
    slots = {}
    try:
        for writer_hex, encoded in value["slots"]:
            writer = bytes.fromhex(writer_hex)
            slot_raw = base64.b64decode(encoded, validate=True)
            slot = decode_slot(slot_raw)
            if slot.workspace != workspace or slot.writer != writer \
                    or writer in slots:
                raise ValueError
            slots[writer] = slot
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("cloud directory") from error
    if _directory_bytes(workspace, {writer: encode_slot(slot)
                                    for writer, slot in slots.items()}) != raw:
        raise ValueError("cloud directory")
    return slots


class CloudQueue:
    def __init__(self, store, workspace):
        if not isinstance(workspace, bytes) \
                or len(workspace) != 32:
            raise ValueError("cloud queue")
        self.store = store
        self.workspace = workspace
        self._lock = threading.RLock()

    @property
    def prefix(self):
        return f"cloud/{self.workspace.hex()}/"

    @property
    def directory_key(self):
        return self.prefix + "directory"

    def _slot_key(self, writer):
        return self.prefix + f"slots/{writer.hex()}"

    def _object_key(self, writer, raw):
        return self.prefix + f"writers/{writer.hex()}/obj/" \
            + hashlib.sha256(raw).hexdigest()

    def _slot_versioned(self, writer):
        found = self.store.read_versioned(self._slot_key(writer))
        if found.value is None:
            return None, found.token
        slot = decode_slot(found.value)
        if slot.workspace != self.workspace or slot.writer != writer:
            raise ValueError("cloud slot binding")
        return slot, found.token

    def visible_heads(self):
        raw, _tag = self.store.get(self.directory_key)
        if raw is None:
            return {}
        return {writer: slot.hi
                for writer, slot in _decode_directory(raw, self.workspace).items()}

    def publish(self, log, lo=None, hi=None, *, carries=(), handoff_targets=(),
                holdings=None, announce=False):
        """Create one immutable micro publication and CAS only its owner slot.

        ``announce=False`` is the store-lag lever: a chat burst updates only
        owner-confined state, then one idle ``repair_directory`` advertises all
        writers without placing the derived digest on the publication path.
        """
        if not isinstance(log, WriterLog) or log._secret is None:
            raise ValueError("cloud publish requires owner log")
        carries = tuple(carries)
        handoff_targets = tuple(handoff_targets)
        with self._lock:
            slot, token = self._slot_versioned(log.writer)
            expected = 0 if slot is None else slot.hi
            hi = log.head().seq + 1 if hi is None else hi
            # Reconcile an exact retry after an applied slot CAS whose response
            # was lost, or after an identical same-base publisher won first.
            # The immutable micro bytes and signed head must both agree; a
            # divergent same-writer proposal still fails closed as a collision.
            if slot is not None and slot.segments and slot.hi == hi \
                    and slot.head == encode_head(log.head()):
                retry_lo = slot.segments[-1].lo if lo is None else lo
                retry_run = prove_run(log, retry_lo, hi)
                retry_key = _micro_key(
                    self.workspace, log.writer, retry_lo, hi)
                incumbent, _tag = self.store.get(retry_key)
                if incumbent is not None:
                    stored = _decode_segment(incumbent)
                    retry_descriptor = Segment(
                        retry_key, retry_lo, hi, len(incumbent), 1, "micro")
                    if len(stored) == 1 \
                            and stored[0].main == retry_run \
                            and stored[0].handoff_targets == handoff_targets \
                            and retry_descriptor == slot.segments[-1]:
                        if announce:
                            self.repair_directory()
                        return PublicationReceipt(
                            retry_descriptor,
                            tuple(HandoffTicket(
                                self.workspace, log.writer, retry_lo, hi,
                                retry_key, target)
                                for target in handoff_targets),
                        )
            if slot is not None and sum(
                    item.kind == "micro" for item in slot.segments) \
                    >= MICRO_TAIL:
                # The owner-confined slot is durable even if the shared hint
                # lagged throughout the burst. Hitting the maintenance bound
                # always advertises that durable prefix before asking the
                # caller to fold it.
                self.repair_directory()
                raise MaintenanceRequired("cloud micro tail is ready to fold")
            lo = expected if lo is None else lo
            if lo != expected or hi <= lo:
                raise ValueError("cloud writer sequence")
            run = prove_run(log, lo, hi)
            publication = self._close_publication(
                Publication(run, carries, handoff_targets), holdings)
            main_facts = decode_slice(run.facts, run.hi - run.lo)
            needs_heads = any(
                fact.refs and (
                    is_control(fact) or fact.family in HANDOFF_FAMILIES)
                for fact in main_facts)
            self._validate_publication(
                publication, self.visible_heads() if needs_heads else {})
            raw = _encode_segment((publication,), "micro")
            key = _micro_key(self.workspace, log.writer, lo, hi)
            try:
                self.store.create(key, raw)
            except ValueError as error:
                incumbent, _tag = self.store.get(key)
                if incumbent is None or incumbent == raw:
                    raise
                raise CloudMicroFork(MicroForkEvidence(
                    self.workspace, log.writer, lo, hi, key,
                    hashlib.sha256(incumbent).hexdigest(),
                    hashlib.sha256(raw).hexdigest(),
                )) from error
            descriptor = Segment(key, lo, hi, len(raw), 1, "micro")
            segments = (*(() if slot is None else slot.segments), descriptor)
            new_slot = Slot(
                self.workspace, log.writer, encode_head(log.head()), segments)
            if not self.store.cas(self._slot_key(log.writer), token,
                                  encode_slot(new_slot)):
                raise ValueError("stale cloud writer slot")
            if announce:
                self.repair_directory()
            tickets = tuple(
                HandoffTicket(self.workspace, log.writer, lo, hi, key, target)
                for target in handoff_targets
            )
            return PublicationReceipt(descriptor, tickets)

    def readmit_orphan(self, writer, lo, hi, *, announce=False):
        """Validate and install one micro created before a crashed slot CAS.

        This chooses the already signed orphan branch. A divergent restarted
        writer must then import/rebase that accepted branch or rotate identity;
        it may never overwrite the immutable range key.
        """
        if not valid_writer(writer) or any(
                type(item) is not int for item in (lo, hi)) \
                or lo < 0 or hi <= lo:
            raise ValueError("cloud orphan range")
        with self._lock:
            slot, token = self._slot_versioned(writer)
            expected = 0 if slot is None else slot.hi
            key = _micro_key(self.workspace, writer, lo, hi)
            raw, _tag = self.store.get(key)
            if raw is None:
                raise ValueError("missing cloud orphan")
            publications = _decode_segment(raw)
            if len(publications) != 1:
                raise ValueError("cloud orphan publication")
            publication = publications[0]
            run = publication.main
            if run.writer != writer or run.lo != lo or run.hi != hi:
                raise ValueError("cloud orphan binding")
            descriptor = Segment(key, lo, hi, len(raw), 1, "micro")
            if slot is not None and slot.segments \
                    and slot.segments[-1] == descriptor \
                    and slot.head == encode_head(run.head):
                return PublicationReceipt(
                    descriptor,
                    tuple(HandoffTicket(
                        self.workspace, writer, lo, hi, key, target)
                        for target in publication.handoff_targets),
                )
            if expected != lo:
                raise ValueError("stale cloud orphan")
            self._validate_publication(publication, self.visible_heads())
            segments = (*(() if slot is None else slot.segments), descriptor)
            replacement = Slot(
                self.workspace, writer, encode_head(run.head), segments)
            if not self.store.cas(
                    self._slot_key(writer), token, encode_slot(replacement)):
                raise ValueError("stale cloud orphan")
            if announce:
                self.repair_directory()
            return PublicationReceipt(
                descriptor,
                tuple(HandoffTicket(
                    self.workspace, writer, lo, hi, key, target)
                    for target in publication.handoff_targets),
            )

    def _close_publication(self, publication, holdings):
        """Carry the exact transitive cross-writer closure once per micro.

        A same-writer ref remains a sequence cite. Every cross-writer target
        is an authenticated exact Run drawn from the publisher's local
        holdings (or an explicit caller-supplied carry), recursively. Folds
        preserve these deterministic adjacent annex runs unchanged.
        """
        if holdings is not None and not isinstance(holdings, PeerState):
            raise ValueError("cloud publication holdings")
        carried_facts = {}
        for run in publication.carries:
            facts = decode_slice(run.facts, run.hi - run.lo)
            for offset, fact in enumerate(facts):
                address = (run.writer, run.lo + offset)
                incumbent = carried_facts.get(address)
                if incumbent is not None and incumbent != fact:
                    raise ValueError("cloud annex equivocation")
                carried_facts[address] = fact

        main_facts = decode_slice(
            publication.main.facts,
            publication.main.hi - publication.main.lo)
        main_addresses = {
            (publication.main.writer, publication.main.lo + offset)
            for offset in range(len(main_facts))
        }
        frontier = []

        def extend(writer, seq, fact):
            for ref in fact.refs:
                if ref.writer != writer \
                        and (ref.writer, ref.seq) not in main_addresses:
                    frontier.append(ref)

        for offset, fact in enumerate(main_facts):
            extend(publication.main.writer,
                   publication.main.lo + offset, fact)

        generated = []
        visited = set(main_addresses)
        while frontier:
            ref = frontier.pop(0)
            address = (ref.writer, ref.seq)
            if address in visited:
                continue
            visited.add(address)
            fact = carried_facts.get(address)
            if fact is None:
                target = None if holdings is None \
                    else holdings.logs.get(ref.writer)
                if target is None or ref.seq not in target._facts:
                    raise ValueError(
                        "Rule-2/cross-writer reference lacks adjacent annex")
                run = prove_run(target, ref.seq, ref.seq + 1)
                generated.append(run)
                fact = target.fact(ref.seq)
                carried_facts[address] = fact
            extend(ref.writer, ref.seq, fact)

        encoded = {}
        for run in (*publication.carries, *generated):
            raw = encode_run(run)
            encoded[raw] = run
        carries = tuple(encoded[raw] for raw in sorted(encoded))
        if len(carries) > CLOUD_ANNEX_MAX_RUNS:
            raise ValueError("cloud annex run count")
        return Publication(
            publication.main, carries, publication.handoff_targets)

    def _validate_publication(self, publication, visible):
        main_facts = decode_slice(
            publication.main.facts, publication.main.hi - publication.main.lo)
        handoff = any(fact.family in HANDOFF_FAMILIES for fact in main_facts)
        if handoff != bool(publication.handoff_targets):
            raise ValueError("handoff facts require explicit out-of-band targets")
        carried = {}
        carried_facts = []
        for run in publication.carries:
            facts = decode_slice(run.facts, run.hi - run.lo)
            for offset, seq in enumerate(range(run.lo, run.hi)):
                carried[(run.writer, seq)] = run
                carried_facts.append((run.writer, seq, facts[offset]))
        available = set(carried)
        available.update(
            (publication.main.writer, publication.main.lo + offset)
            for offset in range(len(main_facts)))
        all_facts = [
            (publication.main.writer,
             publication.main.lo + offset, fact)
            for offset, fact in enumerate(main_facts)]
        all_facts.extend(carried_facts)
        for writer, _seq, fact in all_facts:
            for ref in fact.refs:
                if ref.writer != writer \
                        and (ref.writer, ref.seq) not in available:
                    raise ValueError(
                        "Rule-2/cross-writer reference lacks adjacent annex")
        for fact in main_facts:
            if not (is_control(fact) or fact.family in HANDOFF_FAMILIES):
                continue
            for ref in fact.refs:
                if visible.get(ref.writer, 0) > ref.seq:
                    continue
                if (ref.writer, ref.seq) not in carried:
                    raise ValueError("Rule-2 reference lacks adjacent carry")

    def repair_directory(self):
        """Deterministically rebuild the sole non-writer-owned object."""
        slot_keys = self.store.list(self.prefix + "slots/")
        slots = {}
        found_slots = self._parallel(slot_keys, self.store.read_versioned)
        for key, found in zip(slot_keys, found_slots):
            if found.value is None:
                continue
            slot = decode_slot(found.value)
            if slot.workspace != self.workspace \
                    or key != self._slot_key(slot.writer):
                raise ValueError("cloud directory workspace")
            slots[slot.writer] = found.value
        desired = _directory_bytes(self.workspace, slots)
        for _attempt in range(8):
            current = self.store.read_versioned(self.directory_key)
            if current.value == desired:
                return hashlib.sha256(desired).hexdigest()
            if self.store.cas(self.directory_key, current.token, desired):
                return hashlib.sha256(desired).hexdigest()
        raise ValueError("cloud directory CAS contention")

    def footer(self, segment):
        raw, _tag = self.store.get(segment.key, suffix=FOOTER_READ)
        if raw is None:
            raise ValueError("missing cloud segment")
        return decode_footer(raw)

    def _read_segment(self, segment):
        raw, _tag = self.store.get(segment.key)
        if raw is None or len(raw) != segment.size:
            raise ValueError("missing cloud segment")
        marker = "/obj/"
        if marker in segment.key \
                and segment.key.rsplit(marker, 1)[1] \
                != hashlib.sha256(raw).hexdigest():
            raise ValueError("cloud segment address")
        return _decode_segment(raw)

    def _parallel(self, items, operation):
        items = tuple(items)
        if len(items) < 2:
            return tuple(operation(item) for item in items)
        with ThreadPoolExecutor(
                max_workers=min(CLOUD_GET_CONCURRENCY, len(items)),
                thread_name_prefix="poc16-cloud-get") as executor:
            return tuple(executor.map(operation, items))

    def _parallel_completed(self, items, operation):
        """Yield bounded GET results as they finish for ingest pipelining."""
        items = tuple(items)
        if len(items) < 2:
            for item in items:
                yield operation(item)
            return
        with ThreadPoolExecutor(
                max_workers=min(CLOUD_GET_CONCURRENCY, len(items)),
                thread_name_prefix="poc16-cloud-get") as executor:
            futures = tuple(executor.submit(operation, item) for item in items)
            for future in as_completed(futures):
                yield future.result()

    def _write_segment(self, publications, kind, weight):
        raw = _encode_segment(publications, kind)
        writer = publications[0].main.writer
        key = self._object_key(writer, raw)
        self.store.create(key, raw)
        return Segment(key, publications[0].main.lo,
                       publications[-1].main.hi, len(raw), weight, kind)

    def fold_idle(self, writer, *, announce=True):
        """Fold the micro tail, carry the binary ladder, then append mono."""
        with self._lock:
            slot, token = self._slot_versioned(writer)
            if slot is None:
                return None
            mono = [item for item in slot.segments
                    if item.kind in {"mono", "epoch"}]
            pending = [item for item in slot.segments
                       if item.kind not in {"mono", "epoch"}]
            if not pending:
                return slot

            if mono:
                additions = tuple(publication for item in pending
                                  for publication in self._read_segment(item))
                if additions:
                    appended = self._append_mono(mono[-1], additions)
                    if appended.lo == mono[-1].lo:
                        mono[-1] = appended
                    else:
                        mono.append(appended)
                stack = []
            else:
                publications = tuple(publication for item in pending
                                     for publication in self._read_segment(item))
                candidate = _encode_segment(publications, "mono")
                if _payload_size(candidate) >= MULTIPART_EDGE:
                    mono = [self._write_segment(
                        publications, "mono", sum(item.weight for item in pending))]
                    stack = []
                else:
                    ladder = [item for item in pending if item.kind == "ladder"]
                    micros = [item for item in pending if item.kind == "micro"]
                    if not micros:
                        return slot
                    current_publications = tuple(
                        publication for item in micros
                        for publication in self._read_segment(item))
                    current = self._write_segment(
                        current_publications, "ladder",
                        sum(item.weight for item in micros))
                    stack = ladder
                    while stack and stack[-1].weight == current.weight:
                        left = stack.pop()
                        current = self._write_segment(
                            (*self._read_segment(left),
                             *self._read_segment(current)),
                            "ladder", left.weight + current.weight)
                    stack.append(current)

            new_segments = tuple((*mono, *stack))
            if new_segments == slot.segments:
                return slot
            replacement = Slot(slot.workspace, slot.writer, slot.head,
                               new_segments)
            if not self.store.cas(self._slot_key(writer), token,
                                  encode_slot(replacement)):
                raise ValueError("stale cloud fold")
            if announce:
                self.repair_directory()
            return replacement

    def _append_mono(self, old, additions):
        tail = _encode_segment(additions, "mono")
        if old.size + len(tail) > EPOCH_CAP:
            return self._write_segment(additions, "epoch",
                                       sum(item.main.hi - item.main.lo
                                           for item in additions))
        raw_old, _tag = self.store.get(old.key)
        if raw_old is None or len(raw_old) != old.size:
            raise ValueError("missing mono segment")
        # A mono append is one new canonical segment.  The provider operation
        # copies the old semantic records and uploads only the new tail before
        # Complete makes the new key visible.
        old_publications = _decode_segment(raw_old)
        combined = _encode_segment((*old_publications, *additions), "mono")
        prefix_size = _payload_size(raw_old)
        if prefix_size < MULTIPART_EDGE:
            raise ValueError("mono prefix below provider edge")
        key = self._object_key(old_publications[0].main.writer, combined)
        upload = self.store.begin_multipart(key)
        try:
            # Copy the old records prefix, omitting its replaceable footer,
            # then upload only new record frames plus the new footer.
            self.store.copy_part(upload, old.key, prefix_size)
            self.store.upload_part(upload, combined[prefix_size:])
            completed = self.store.complete_multipart(upload)
            if completed is not None and completed != combined:
                raise ValueError("multipart assembly")
        except PartCopyUnavailable:
            self.store.abort_multipart(upload)
            return self._write_segment(additions, "epoch",
                                       sum(item.main.hi - item.main.lo
                                           for item in additions))
        return Segment(key, old.lo, additions[-1].main.hi, len(combined),
                       old.weight + sum(item.main.hi - item.main.lo
                                        for item in additions), "mono")

    def poll(self, if_none_match=None):
        raw, tag = self.store.get(
            self.directory_key, if_none_match=if_none_match)
        # A missing derived hint is repairable from owner-confined slots by
        # any reader. A conditional 304 has an opaque tag and remains the
        # one-GET no-change path; it is not a missing object.
        if raw is None and tag is None:
            self.repair_directory()
            raw, tag = self.store.get(self.directory_key)
        return (None if raw is None else _decode_directory(raw, self.workspace)), tag

    def read_run(self, writer, lo, hi):
        """Passive forest recipe primitive, byte-identical to a live peer."""
        slots, _tag = self.poll()
        if slots is None or writer not in slots:
            return None
        for segment in slots[writer].segments:
            if segment.lo <= lo and hi <= segment.hi:
                for publication in self._read_segment(segment):
                    run = publication.main
                    if run.lo == lo and run.hi == hi:
                        return encode_run(run)
        return None

    def sync(self, state, cache=None, *, demand=None, ts_window=None,
             closure_limits=None):
        """Fetch a requested view and its bounded transitive ref closure.

        Segment bodies remain the atomic authenticated transport unit.  Facts
        neighboring a requested fact are honest overfetch, but only logical
        window members and their exact ``(writer, seq)`` dependencies widen
        the closure traversal.
        """
        if not isinstance(state, PeerState):
            raise ValueError("cloud sync state")
        if demand is not None and ts_window is not None:
            raise ValueError("one cloud sync window")
        if demand is not None and not isinstance(demand, CloudDemand):
            raise ValueError("cloud demand")
        if ts_window is not None and (
                not isinstance(ts_window, tuple) or len(ts_window) != 2
                or any(type(item) is not int for item in ts_window)
                or ts_window[1] <= ts_window[0]):
            raise ValueError("cloud timestamp window")
        if closure_limits is None:
            closure_limits = CloudClosureLimits()
        if not isinstance(closure_limits, CloudClosureLimits):
            raise ValueError("cloud closure limits")
        cache = cache or CloudCache()
        if cache.state is not state:
            cache.directory_tag = None
            cache.request_key = None
            cache.pending = ()
            cache.closure_exhausted = False
            cache.interactive_ready = True
            cache.state = state
        request_key = (demand, ts_window, closure_limits)
        same_request = cache.request_key == request_key
        before = self.store.metrics.copy()
        conditional_tag = cache.directory_tag \
            if same_request and cache.interactive_ready else None
        slots, tag = self.poll(conditional_tag)
        if slots is None:
            return CloudSyncReport(False, 1, 0,
                                   self.store.metrics.downloaded_bytes
                                   - before.downloaded_bytes,
                                   0, 0, cache.pending, tag,
                                   closure_exhausted=cache.closure_exhausted,
                                   interactive_ready=cache.interactive_ready)
        cache.directory_tag = tag
        if not same_request:
            cache.pending = ()
            cache.closure_exhausted = False
            cache.interactive_ready = True
        cache.request_key = request_key
        selected = []
        all_segments = tuple(
            segment for slot in slots.values() for segment in slot.segments)
        footers = {}
        if ts_window is not None:
            footers = dict(zip(
                all_segments, self._parallel(all_segments, self.footer)))
        demand_by_writer = None if demand is None else {
            item.writer: item for item in demand.writers}
        resolved = {}
        for writer, slot in slots.items():
            if demand_by_writer is not None and writer not in demand_by_writer:
                continue
            resolved[writer] = ((0, slot.hi),) if demand_by_writer is None \
                else demand_by_writer[writer].resolve(slot.hi)
            held = state.logs.get(writer)
            coverage = () if held is None else held.coverage()
            missing = _subtract_coverage(resolved[writer], coverage)
            for segment in slot.segments:
                lo, hi = segment.lo, segment.hi
                if ts_window is not None:
                    footer = footers[segment]
                    if footer["ts_max"] < ts_window[0] \
                            or footer["ts_min"] >= ts_window[1]:
                        continue
                elif not _intersects(missing, lo, hi):
                    continue
                if ts_window is not None and _covered(coverage, lo, hi):
                    continue
                if ts_window is not None or missing:
                    selected.append(segment)
        # The demand pump makes a partial view useful before old history:
        # submit newest sequence ranges first while retaining per-publication
        # atomic ingest and accepting out-of-order writer islands.
        selected.sort(key=lambda segment: (segment.hi, segment.lo),
                      reverse=True)
        facts = carries = 0
        initial_addresses = set()
        initial_refs = set()
        visible = {writer: slot.hi for writer, slot in slots.items()}
        for publications in self._parallel_completed(
                selected,
                lambda segment: (segment, self._read_segment(segment))):
            segment, publications = publications
            for publication in publications:
                self._validate_publication(publication, visible)
                main_facts = decode_slice(
                    publication.main.facts,
                    publication.main.hi - publication.main.lo)
                # One adjacency-bound publication remains atomic, while later
                # writer bodies continue downloading on the bounded executor.
                ingest_batch(
                    state, (*publication.carries, publication.main))
                for carried in publication.carries:
                    carries += carried.hi - carried.lo
                facts += len(main_facts)
                for offset, fact in enumerate(main_facts):
                    seq = publication.main.lo + offset
                    requested = ts_window is None \
                        and _contains(resolved[publication.main.writer], seq)
                    if ts_window is not None:
                        requested = ts_window[0] <= fact.ts < ts_window[1]
                    if requested:
                        initial_addresses.add((publication.main.writer, seq))
                        initial_refs.update(fact.refs)

        # Close only the logical requested roots.  Downloaded neighbors are
        # filed because runs are indivisible, but following their refs would
        # turn one range request into an accidental history-wide crawl.
        # A fresh request may begin from facts obtained over P2P. Fully held
        # root segments need no cloud GET, but their refs still seed closure.
        root_addresses = set(initial_addresses)
        for writer, intervals in resolved.items():
            held = state.logs.get(writer)
            if held is None:
                continue
            for seq, fact in held._facts.items():
                requested = ts_window is None and _contains(intervals, seq)
                if ts_window is not None:
                    requested = ts_window[0] <= fact.ts < ts_window[1]
                if requested:
                    root_addresses.add((writer, seq))
                    initial_refs.update(fact.refs)
        visited = {Ref(writer, seq) for writer, seq in root_addresses}
        frontier = {ref: 1 for ref in initial_refs if ref not in visited}
        pending = set()
        exhausted_pending = set()
        closure_segments = set()
        closure_target_addresses = set()
        closure_bytes = 0
        closure_depth = 0
        closure_exhausted = False
        refs_examined = 0
        closure_rounds = 0

        def resident(ref):
            log = state.logs.get(ref.writer)
            return None if log is None else log._facts.get(ref.seq)

        while frontier:
            next_frontier = {}
            needed = {}
            for ref, depth in sorted(
                    frontier.items(), key=lambda item: (
                        item[1], item[0].writer, item[0].seq)):
                if ref in visited:
                    continue
                if refs_examined >= closure_limits.max_refs:
                    pending.add(ref)
                    exhausted_pending.add(ref)
                    closure_exhausted = True
                    continue
                refs_examined += 1
                visited.add(ref)
                if depth > closure_limits.max_depth:
                    pending.add(ref)
                    exhausted_pending.add(ref)
                    closure_exhausted = True
                    continue
                fact = resident(ref)
                if fact is not None:
                    closure_depth = max(closure_depth, depth)
                    for dependency in fact.refs:
                        if dependency not in visited:
                            next_frontier[dependency] = max(
                                next_frontier.get(dependency, 0), depth + 1)
                    continue
                slot = slots.get(ref.writer)
                if slot is None or ref.seq >= slot.hi:
                    pending.add(ref)
                    continue
                segment = next((item for item in slot.segments
                                if item.lo <= ref.seq < item.hi), None)
                if segment is None:
                    pending.add(ref)
                    continue
                if segment in closure_segments:
                    # A verified containing run must have installed the target.
                    raise ValueError("cloud dependency segment omitted target")
                needed.setdefault(segment, []).append((ref, depth))

            allowed = []
            for segment in sorted(
                    needed, key=lambda item: (item.key, item.lo, item.hi)):
                if len(closure_segments) + len(allowed) \
                        >= closure_limits.max_segments \
                        or closure_bytes + sum(item.size for item in allowed) \
                        + segment.size > closure_limits.max_bytes:
                    pending.update(ref for ref, _depth in needed[segment])
                    exhausted_pending.update(
                        ref for ref, _depth in needed[segment])
                    closure_exhausted = True
                else:
                    allowed.append(segment)
            if allowed:
                closure_rounds += math.ceil(
                    len(allowed) / CLOUD_GET_CONCURRENCY)
            for result in self._parallel_completed(
                    allowed,
                    lambda segment: (segment, self._read_segment(segment))):
                segment, publications = result
                closure_segments.add(segment)
                closure_bytes += segment.size
                for publication in publications:
                    self._validate_publication(publication, visible)
                    main_facts = decode_slice(
                        publication.main.facts,
                        publication.main.hi - publication.main.lo)
                    ingest_batch(
                        state, (*publication.carries, publication.main))
                    carries += sum(carried.hi - carried.lo
                                   for carried in publication.carries)
                    facts += len(main_facts)
                for ref, depth in needed[segment]:
                    fact = resident(ref)
                    if fact is None:
                        raise ValueError("cloud dependency segment omitted target")
                    closure_target_addresses.add((ref.writer, ref.seq))
                    closure_depth = max(closure_depth, depth)
                    for dependency in fact.refs:
                        if dependency not in visited:
                            next_frontier[dependency] = max(
                                next_frontier.get(dependency, 0), depth + 1)
            frontier = next_frontier

        pending = exhausted_pending | {
            ref for ref in pending if resident(ref) is None}
        delta = self.store.metrics.delta(before)
        # Directory, bounded footer waves, then bounded immutable-body waves.
        footer_gets = len(all_segments) if ts_window is not None else 0
        rounds = 1 + math.ceil(footer_gets / CLOUD_GET_CONCURRENCY) \
            + math.ceil(len(selected) / CLOUD_GET_CONCURRENCY) \
            + closure_rounds
        initial_facts = len(initial_addresses)
        closure_facts = len(closure_target_addresses)
        report = CloudSyncReport(True, rounds,
                               footer_gets + len(selected)
                               + len(closure_segments),
                               delta.downloaded_bytes, facts, carries,
                               tuple(sorted(pending,
                                            key=lambda ref: (ref.writer, ref.seq))),
                               tag,
                               initial_segment_gets=len(selected),
                               closure_segment_gets=len(closure_segments),
                               initial_bytes=sum(item.size for item in selected),
                               closure_bytes=closure_bytes,
                               initial_facts=initial_facts,
                               closure_facts=closure_facts,
                               segment_overfetch_facts=max(
                                   0, facts - initial_facts - closure_facts),
                               closure_depth=closure_depth,
                               closure_exhausted=closure_exhausted,
                               interactive_ready=(
                                   not pending and not closure_exhausted))
        cache.pending = report.pending
        cache.closure_exhausted = report.closure_exhausted
        cache.interactive_ready = report.interactive_ready
        return report

    def redeem_handoff(self, ticket, recipient, state):
        """Consume an explicitly delivered handoff capability out of band."""
        if not isinstance(ticket, HandoffTicket) \
                or ticket.workspace != self.workspace \
                or ticket.recipient != recipient:
            raise ValueError("handoff ticket")
        raw, _tag = self.store.get(ticket.key)
        if raw is None:
            raise ValueError("missing handoff segment")
        for publication in _decode_segment(raw):
            run = publication.main
            if run.writer == ticket.writer and run.lo == ticket.lo \
                    and run.hi == ticket.hi \
                    and recipient in publication.handoff_targets:
                ingest_batch(state, (*publication.carries, run))
                return run
        raise ValueError("handoff publication")


def _covered(coverage, lo, hi):
    return any(start <= lo and hi <= stop for start, stop in coverage)


def _contains(intervals, seq):
    return any(lo <= seq < hi for lo, hi in intervals)


def _intersects(intervals, lo, hi):
    return any(start < hi and lo < stop for start, stop in intervals)


def _subtract_coverage(intervals, coverage):
    """Return canonical parts of intervals not already held locally."""
    result = []
    for lo, hi in intervals:
        cursor = lo
        for held_lo, held_hi in coverage:
            if held_hi <= cursor:
                continue
            if held_lo >= hi:
                break
            if cursor < held_lo:
                result.append((cursor, min(held_lo, hi)))
            cursor = max(cursor, held_hi)
            if cursor >= hi:
                break
        if cursor < hi:
            result.append((cursor, hi))
    return tuple(result)


__all__ = (
    "CLOUD_ANNEX_MAX_RUNS",
    "CLOUD_CLOSURE_MAX_BYTES", "CLOUD_CLOSURE_MAX_DEPTH",
    "CLOUD_CLOSURE_MAX_REFS", "CLOUD_CLOSURE_MAX_SEGMENTS",
    "CLOUD_DEMAND_MAX_INTERVALS", "CLOUD_DEMAND_MAX_INTERVALS_PER_WRITER",
    "CLOUD_DEMAND_MAX_WRITERS", "CLOUD_GET_CONCURRENCY", "CloudCache",
    "CLOUD_PUBLICATION_MAX_BYTES",
    "CloudClosureLimits", "CloudDemand", "CloudMicroFork",
    "CloudMetrics", "CloudObjectStore", "CloudQueue", "CloudSyncReport",
    "EPOCH_CAP", "FOOTER_READ", "HANDOFF_FAMILIES", "HandoffTicket",
    "MICRO_TAIL", "MULTIPART_EDGE", "MaintenanceRequired", "MemoryCloud",
    "MicroForkEvidence",
    "PartCopyUnavailable",
    "PublicationReceipt", "Segment", "WriterDemand", "decode_footer",
    "decode_slot", "encode_slot",
)
