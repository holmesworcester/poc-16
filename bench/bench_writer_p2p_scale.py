"""Repeatable public per-writer P2P scale and RTT accounting.

The benchmark calls :meth:`RepositoryMirror.sync_from`, not a private helper.
Its source implements the same wire behavior as ``RemoteStore``: one bounded
``/heads`` response contains both directory keys and their opened slots, exact
objects use buffered ``GET /obj/<oid>``, and pile bodies use the required
bounded streaming object read.

Wall and CPU times are measured with an in-memory object store and no injected
network delay. Network time is then modeled as measured wall time plus one RTT
per exact dependency wave observed at that public source. The current mirror
serializes changed-writer traversal and projection, so only requests actually
started together share a wave.

The RTT model deliberately excludes bandwidth, auth minting, HTTP/TLS headers,
and connection setup. Exact application-body bytes are reported so those costs
can be added without hiding assumptions in this benchmark.

Large source fixtures skip the sender's redundant preflight evaluation. They
still use ``WriterLog`` to sign every pile and build every authenticated tree;
the measured receiving ``FactConsumer`` validates every pile and durable fact.
"""
import argparse
import asyncio
import base64
from collections import Counter
from dataclasses import asdict, dataclass
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto import h, load_sk
from core.close import EvaluatedPile, decode_signed_pile
from core.kernel import Judgment, Valid
from core.limits import (
    MAX_PILE_BYTES,
    MAX_PAGE_BATCH_BYTES,
    MAX_STORE_READ_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
)
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    ListPage,
    STALE,
    Versioned,
    VersionToken,
    validate_create,
)
from core.writer_head import (
    HeadSlot,
    WriterBinding,
    encode_slot,
    head_slot_key,
    parse_head_slot_key,
)
from core.writer_repository import (
    FactConsumer,
    RepositoryMirror,
    WriterLog,
)
from facts.auth.device import device as device_fact
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message as message_fact


DEFAULT_WRITERS = (100, 1_000)
DEFAULT_RTTS_MS = (25, 50, 75)
LARGE_DURABLE_FACTS = 100_000
NORMAL_MESSAGES_PER_PILE = 1
OFFLINE_PACKED_MESSAGES_PER_PILE = 125
AUTHORITY_ROOT = h(b"p2p benchmark authority")


def identity(label):
    """Return a deterministic Ed25519 identity for repeatable bytes."""
    secret = load_sk(h(("p2p-benchmark/" + label).encode()))
    return secret, secret.verify_key.encode().hex()


class MemoryStore:
    """Small awaited store used only to remove disk noise from the benchmark."""

    def __init__(self):
        self.data = {}
        self.tokens = {}
        self.generation = 0

    async def get_bounded(self, key, maximum):
        if type(maximum) is not int \
                or not 0 < maximum <= MAX_STORE_READ_BYTES:
            raise ValueError("memory-store read bound")
        value = self.data.get(key)
        if value is not None and len(value) > maximum:
            raise PayloadTooLarge("memory-store object")
        return value

    async def read_versioned(self, key):
        value = self.data.get(key)
        return ABSENT if value is None else Versioned(
            value, VersionToken(self.tokens[key]))

    async def copy_pile_object(self, oid, maximum, write):
        if type(maximum) is not int or not 0 < maximum <= MAX_PILE_BYTES:
            raise ValueError("memory-store pile bound")
        value = self.data.get("obj/" + oid)
        if value is not None and len(value) > maximum:
            raise PayloadTooLarge("memory-store pile")
        if value is None:
            return None
        write(value)
        return len(value)

    async def put_if_absent(self, key, value):
        validate_create(key, value)
        incumbent = self.data.get(key)
        if incumbent is not None:
            return EXISTS
        self._write(key, value)
        return CREATED

    async def cas(self, key, token, value):
        incumbent = await self.read_versioned(key)
        current = ABSENT if incumbent is ABSENT else incumbent.token
        if current != token:
            return STALE
        self._write(key, value)
        return Applied(VersionToken(self.tokens[key]))

    async def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        if type(limit) is not int or not 0 < limit <= PAGE_BATCH:
            raise ValueError("memory-store page limit")
        keys = sorted(
            key for key in self.data
            if key.startswith(prefix) and (cursor is None or key > cursor)
        )
        selected = tuple(keys[:limit])
        return ListPage(
            selected,
            selected[-1] if len(keys) > limit else None,
        )

    def _write(self, key, value):
        self.generation += 1
        self.data[key] = bytes(value)
        self.tokens[key] = f"memory-version-{self.generation}"


@dataclass(frozen=True, slots=True)
class DeviceSpec:
    ordinal: int
    secret: object
    public: str
    owner: str
    binding: WriterBinding
    authority: tuple


@dataclass(slots=True)
class DeviceRuntime:
    spec: DeviceSpec
    writer: WriterLog
    head: str


class ReceiverValidatedFixture:
    """Skip only unmeasured sender preflight for large valid fixtures."""

    @staticmethod
    def evaluate(raw, *, writer=None):
        pile = decode_signed_pile(raw, writer=writer)
        return EvaluatedPile(
            pile,
            Judgment(True, tuple(Valid(fact, ()) for fact in pile.facts)),
        )


@dataclass(slots=True)
class Forest:
    root: object
    founder_secret: object
    founder: str
    primary_authority: tuple
    source: MemoryStore
    bindings: dict
    devices: list
    object_owner: dict

    def binding_for(
            self, workspace, device, authority_root, candidate):
        del candidate
        if workspace != self.root.fid or authority_root != AUTHORITY_ROOT:
            return None
        return self.bindings.get(device)


def base_forest():
    founder_secret, founder = identity("founder")
    root = workspace_fact(founder_secret, founder, "workspace", 1)
    primary = device_fact(root.fid, founder, "device-0000", 2)
    primary_signature = signature_fact(
        founder_secret, founder, primary, 2)
    return Forest(
        root,
        founder_secret,
        founder,
        (root, primary_signature, primary),
        MemoryStore(),
        {},
        [],
        {},
    )


def device_spec(forest, ordinal):
    if ordinal == 0:
        secret, public = forest.founder_secret, forest.founder
        authority = forest.primary_authority
    else:
        secret, public = identity(f"device-{ordinal:04d}")
        grant = device_invite(
            forest.root.fid,
            forest.founder,
            public,
            f"device-{ordinal:04d}",
            ordinal + 2,
        )
        grant_signature = signature_fact(
            forest.founder_secret,
            forest.founder,
            grant,
            grant.ts,
        )
        authority = (
            *forest.primary_authority, grant_signature, grant)
    return DeviceSpec(
        ordinal,
        secret,
        public,
        forest.founder,
        WriterBinding(
            forest.root.fid,
            public,
            forest.founder,
            h(f"p2p-store-{ordinal:04d}".encode()),
        ),
        authority,
    )


def message_pair(forest, spec, index, *, label="history"):
    timestamp = 1_000_000 + spec.ordinal * 10_000 + index
    item = message_fact(
        forest.root.fid,
        spec.public,
        "general",
        f"{label} writer={spec.ordinal} item={index}",
        timestamp,
        owner=spec.owner,
    )
    return (
        signature_fact(spec.secret, spec.public, item, timestamp),
        item,
    )


def closures_for_messages(
        forest, spec, message_count, *, filler=None, label="history",
        messages_per_pile=NORMAL_MESSAGES_PER_PILE):
    if type(messages_per_pile) is not int or messages_per_pile < 1:
        raise ValueError("messages per pile")
    pairs = [
        message_pair(forest, spec, index, label=label)
        for index in range(message_count)
    ]
    closures = []
    for start in range(0, len(pairs), messages_per_pile):
        facts = list(spec.authority)
        if start == 0 and filler is not None:
            facts.append(filler)
        for signed, item in pairs[start:start + messages_per_pile]:
            facts.extend((signed, item))
        closures.append(tuple(facts))
    if not closures:
        closures.append((*spec.authority, *(() if filler is None else (
            filler,))))
    return tuple(closures)


def register_objects(forest, spec, prepared):
    for oid, _raw in prepared.objects:
        incumbent = forest.object_owner.setdefault(oid, spec.public)
        if incumbent != spec.public:
            raise ValueError("cross-writer object identity")


async def publish_device(
        forest, spec, closures, *, receiver_validated_fixture=False):
    writer = WriterLog(
        forest.root.fid,
        spec.public,
        spec.owner,
        spec.binding.store,
        spec.secret,
        forest.source,
    )
    if receiver_validated_fixture:
        writer.evaluator = ReceiverValidatedFixture()
    prepared = await writer.prepare(closures)
    await writer.establish(prepared)
    key = head_slot_key(forest.root.fid, spec.public)
    opened = await forest.source.read_versioned(key)
    token = ABSENT if opened is ABSENT else opened.token
    slot = encode_slot(HeadSlot(
        forest.root.fid,
        spec.public,
        prepared.head_oid,
        AUTHORITY_ROOT,
    ))
    applied = await forest.source.cas(key, token, slot)
    if not isinstance(applied, Applied):
        raise ValueError("benchmark slot publication")
    register_objects(forest, spec, prepared)
    runtime = DeviceRuntime(spec, writer, prepared.head_oid)
    forest.bindings[spec.public] = spec.binding
    if spec.ordinal == len(forest.devices):
        forest.devices.append(runtime)
    else:
        forest.devices[spec.ordinal] = runtime
    return prepared


async def build_small_forest(writer_count):
    forest = base_forest()
    for ordinal in range(writer_count):
        spec = device_spec(forest, ordinal)
        await publish_device(
            forest,
            spec,
            closures_for_messages(
                forest, spec, 1, label="initial"),
        )
    return forest


async def append_message(forest, ordinal, label):
    runtime = forest.devices[ordinal]
    pair = message_pair(
        forest, runtime.spec, 9_000 + len(label), label=label)
    prepared = await runtime.writer.prepare((
        (*runtime.spec.authority, *pair),))
    await runtime.writer.establish(prepared)
    key = head_slot_key(forest.root.fid, runtime.spec.public)
    opened = await forest.source.read_versioned(key)
    slot = encode_slot(HeadSlot(
        forest.root.fid,
        runtime.spec.public,
        prepared.head_oid,
        AUTHORITY_ROOT,
    ))
    applied = await forest.source.cas(key, opened.token, slot)
    if not isinstance(applied, Applied):
        raise ValueError("benchmark append publication")
    register_objects(forest, runtime.spec, prepared)
    runtime.head = prepared.head_oid
    return prepared


async def add_writer(forest):
    ordinal = len(forest.devices)
    spec = device_spec(forest, ordinal)
    return await publish_device(
        forest,
        spec,
        closures_for_messages(forest, spec, 1, label="new"),
    )


def large_distribution(writer_count, durable_facts):
    authority_facts = 2 * writer_count + 1
    remaining = durable_facts - authority_facts
    if writer_count < 1 or remaining < 0:
        raise ValueError("large catch-up fact target")
    messages, filler = divmod(remaining, 2)
    each, extra = divmod(messages, writer_count)
    return tuple(
        each + int(ordinal < extra)
        for ordinal in range(writer_count)
    ), filler


async def build_large_forest(
        writer_count, durable_facts=LARGE_DURABLE_FACTS, *,
        messages_per_pile=NORMAL_MESSAGES_PER_PILE):
    forest = base_forest()
    distribution, filler_count = large_distribution(
        writer_count, durable_facts)
    filler = signature_fact(
        forest.founder_secret,
        forest.founder,
        forest.root,
        9_999_999,
    ) if filler_count else None
    for ordinal, message_count in enumerate(distribution):
        spec = device_spec(forest, ordinal)
        await publish_device(
            forest,
            spec,
            closures_for_messages(
                forest,
                spec,
                message_count,
                filler=filler if ordinal == 0 else None,
                label="catchup",
                messages_per_pile=messages_per_pile,
            ),
            receiver_validated_fixture=True,
        )
    return forest


@dataclass(frozen=True, slots=True)
class RequestEvent:
    kind: str
    device: str | None
    wave: int
    request_bytes: int
    response_bytes: int


class TraceRemoteStore:
    """One established-session HTTP pull, without socket or RTT noise."""

    def __init__(self, forest):
        self.forest = forest
        self.events = []
        self._opened_head_page = None
        self._open_wave = None
        self._next_wave = 0
        self._active_requests = 0

    async def _record(
            self, kind, device, request_bytes=0, response_bytes=0):
        if self._open_wave is None:
            self._open_wave = self._next_wave
            self._next_wave += 1
        wave = self._open_wave
        self._active_requests += 1
        self.events.append(RequestEvent(
            kind, device, wave, request_bytes, response_bytes))
        # A zero-duration scheduler turn detects requests genuinely started
        # together without injecting any simulated network latency.
        await asyncio.sleep(0)
        self._active_requests -= 1
        if self._active_requests == 0:
            self._open_wave = None

    async def get_bounded(self, key, maximum):
        value = await self.forest.source.get_bounded(key, maximum)
        if not key.startswith("obj/"):
            raise ValueError("trace remote exact object")
        oid = key[4:]
        device = self.forest.object_owner[oid]
        await self._record(
            "object",
            device,
            response_bytes=0 if value is None else len(value),
        )
        return value

    async def copy_pile_object(self, oid, maximum, write):
        if type(maximum) is not int or not 0 < maximum <= MAX_PILE_BYTES:
            raise ValueError("trace remote pile bound")
        value = self.forest.source.data.get("obj/" + oid)
        if value is not None and len(value) > maximum:
            raise PayloadTooLarge("trace remote pile")
        device = self.forest.object_owner[oid]
        await self._record(
            "pile", device,
            response_bytes=0 if value is None else len(value))
        if value is None:
            return None
        write(value)
        return len(value)

    async def read_versioned(self, key):
        workspace, device = parse_head_slot_key(key)
        if workspace != self.forest.root.fid:
            raise ValueError("trace remote workspace")
        opened = await self.forest.source.read_versioned(key)
        wire = ABSENT if opened is ABSENT else Versioned(
            opened.value, VersionToken(h(opened.value)))
        await self._record(
            "head",
            device,
            response_bytes=0 if wire is ABSENT else len(wire.value),
        )
        return wire

    async def read_many_versioned(self, keys):
        """Return slots already carried by the latest ``/heads`` body."""
        keys = tuple(keys)
        if self._opened_head_page is None \
                or self._opened_head_page[0] != keys:
            raise ValueError("head directory page is no longer current")
        return self._opened_head_page[1]

    async def _object_batch(self, keys):
        """Mirror ``Peer.objs`` success, 413 split, and single-GET fallback."""
        keys = tuple(keys)
        oids = tuple(key[4:] for key in keys)
        values = tuple([
            await self.forest.source.get_bounded(
                key, MAX_STORE_READ_BYTES)
            for key in keys
        ])
        request = json.dumps(list(oids)).encode()
        response = json.dumps([
            None if value is None else base64.b64encode(value).decode()
            for value in values
        ], sort_keys=True, separators=(",", ":")).encode()
        owners = {self.forest.object_owner[oid] for oid in oids}
        if len(owners) != 1:
            raise ValueError("cross-writer object batch")
        device = next(iter(owners))
        if len(response) <= MAX_PAGE_BATCH_BYTES:
            await self._record(
                "pile-batch", device, len(request), len(response))
            return values

        await self._record(
            "pile-batch-413", device, len(request))
        if len(keys) == 1:
            value = values[0]
            await self._record(
                "object", device,
                response_bytes=0 if value is None else len(value))
            return values
        middle = len(keys) // 2
        return await self._object_batch(keys[:middle]) + \
            await self._object_batch(keys[middle:])

    async def get_many(self, keys):
        keys = tuple(keys)
        oids = tuple(key.removeprefix("obj/") for key in keys)
        if any("obj/" + oid != key for key, oid in zip(keys, oids)):
            raise ValueError("trace remote object batch")
        out = []
        for start in range(0, len(keys), PAGE_BATCH):
            out.extend(await self._object_batch(
                keys[start:start + PAGE_BATCH]))
        return tuple(out)

    async def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        page = await self.forest.source.list_page(prefix, cursor, limit)
        opened = tuple([
            await self.forest.source.read_versioned(key)
            for key in page.keys
        ])
        if any(not isinstance(value, Versioned) for value in opened):
            raise ValueError("listed writer slot disappeared")
        wire_opened = tuple(
            Versioned(value.value, VersionToken(h(value.value)))
            for value in opened
        )
        response = json.dumps({
            "cursor": page.cursor,
            "heads": [
                [
                    key,
                    base64.b64encode(value.value).decode(),
                    value.token.value,
                ]
                for key, value in zip(page.keys, wire_opened)
            ],
        }, sort_keys=True, separators=(",", ":")).encode()
        self._opened_head_page = (page.keys, wire_opened)
        await self._record(
            "heads", None, response_bytes=len(response))
        return page


@dataclass(frozen=True, slots=True)
class LatencyEstimate:
    rtt_ms: int
    modeled_wall_seconds: float
    modeled_facts_per_second: float


@dataclass(frozen=True, slots=True)
class P2PMeasurement:
    scenario: str
    writers: int
    messages_per_pile: int
    facts: int
    piles: int
    requests: int
    parallel_request_waves: int
    request_breakdown: tuple[tuple[str, int], ...]
    request_bytes: int
    response_bytes: int
    measured_wall_seconds: float
    measured_cpu_seconds: float
    measured_facts_per_second: float
    latency_estimates: tuple[LatencyEstimate, ...]

    def to_json(self):
        value = asdict(self)
        value["timing"] = {
            "entrypoint": "RepositoryMirror.sync_from",
            "measured": "zero-RTT in-memory optimized core execution",
            "modeled": "measured wall + exact waves * RTT",
            "bandwidth": "not modeled; application bytes reported",
            "session": (
                "one-way pull with an established cached grant; /heads "
                "bundles opened slots"
            ),
        }
        return value


def request_waves(events):
    """Count exact concurrent phases observed at the public source."""
    waves = tuple(sorted({event.wave for event in events}))
    if not waves or waves != tuple(range(len(waves))):
        raise ValueError("P2P trace request waves")
    return len(waves)


async def measure(
        forest, target_store, consumer, scenario, *,
        rtts_ms=DEFAULT_RTTS_MS, page_limit=PAGE_BATCH,
        messages_per_pile=NORMAL_MESSAGES_PER_PILE):
    source = TraceRemoteStore(forest)
    mirror = RepositoryMirror(
        forest.root.fid,
        target_store,
        forest.binding_for,
        consumer,
    )
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    result = await mirror.sync_from(source, page_limit=page_limit)
    cpu = time.process_time() - cpu_start
    wall = time.perf_counter() - wall_start
    if result.errors:
        raise AssertionError(f"benchmark mirror errors: {result.errors}")
    waves = request_waves(source.events)
    breakdown = tuple(sorted(Counter(
        event.kind for event in source.events).items()))
    estimates = tuple(
        LatencyEstimate(
            rtt,
            wall + waves * rtt / 1_000,
            0.0 if result.facts == 0 else result.facts / (
                wall + waves * rtt / 1_000),
        )
        for rtt in rtts_ms
    )
    return P2PMeasurement(
        scenario,
        len(forest.devices),
        messages_per_pile,
        result.facts,
        result.piles,
        len(source.events),
        waves,
        breakdown,
        sum(event.request_bytes for event in source.events),
        sum(event.response_bytes for event in source.events),
        wall,
        cpu,
        0.0 if result.facts == 0 else result.facts / wall,
        estimates,
    )


async def measure_small_scale(
        writer_count, *, rtts_ms=DEFAULT_RTTS_MS,
        page_limit=PAGE_BATCH):
    forest = await build_small_forest(writer_count)
    target = MemoryStore()
    consumer = FactConsumer(forest.root.fid)
    # Establish the receiver state outside the measured no-op turn.
    await measure(
        forest, target, consumer, "setup",
        rtts_ms=(), page_limit=page_limit)
    noop = await measure(
        forest, target, consumer, "noop",
        rtts_ms=rtts_ms, page_limit=page_limit)
    await append_message(forest, writer_count - 1, "one-changed")
    changed = await measure(
        forest, target, consumer, "one-changed",
        rtts_ms=rtts_ms, page_limit=page_limit)
    await add_writer(forest)
    new_writer = await measure(
        forest, target, consumer, "new-writer",
        rtts_ms=rtts_ms, page_limit=page_limit)
    return noop, changed, new_writer


async def measure_large_catchup(
        writer_count, *, durable_facts=LARGE_DURABLE_FACTS,
        rtts_ms=DEFAULT_RTTS_MS, page_limit=PAGE_BATCH,
        messages_per_pile=NORMAL_MESSAGES_PER_PILE):
    forest = await build_large_forest(
        writer_count,
        durable_facts,
        messages_per_pile=messages_per_pile,
    )
    target = MemoryStore()
    consumer = FactConsumer(forest.root.fid)
    result = await measure(
        forest,
        target,
        consumer,
        "large-catchup-normal" if messages_per_pile == 1 else
        f"large-catchup-offline-packed-{messages_per_pile}",
        rtts_ms=rtts_ms,
        page_limit=page_limit,
        messages_per_pile=messages_per_pile,
    )
    if result.facts != durable_facts:
        raise AssertionError(
            f"large catch-up admitted {result.facts}, expected "
            f"{durable_facts}")
    return result


async def run_suite(
        writer_counts=DEFAULT_WRITERS, *, rtts_ms=DEFAULT_RTTS_MS,
        durable_facts=LARGE_DURABLE_FACTS, include_large=True,
        messages_per_pile=NORMAL_MESSAGES_PER_PILE):
    out = []
    for writer_count in writer_counts:
        out.extend(await measure_small_scale(
            writer_count, rtts_ms=rtts_ms))
        if include_large:
            out.append(await measure_large_catchup(
                writer_count,
                durable_facts=durable_facts,
                rtts_ms=rtts_ms,
                messages_per_pile=messages_per_pile,
            ))
    return tuple(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Measure per-writer P2P sync and exact RTT waves")
    parser.add_argument(
        "--writers", type=int, nargs="+", default=DEFAULT_WRITERS)
    parser.add_argument(
        "--rtts", type=int, nargs="+", default=DEFAULT_RTTS_MS)
    parser.add_argument(
        "--large-facts", type=int, default=LARGE_DURABLE_FACTS)
    parser.add_argument(
        "--messages-per-pile", type=int,
        default=NORMAL_MESSAGES_PER_PILE,
        help=(
            "1 models accumulated normal authorship; values above 1 are "
            "explicitly labeled offline packing"
        ),
    )
    parser.add_argument("--skip-large", action="store_true")
    args = parser.parse_args(argv)
    results = asyncio.run(run_suite(
        tuple(args.writers),
        rtts_ms=tuple(args.rtts),
        durable_facts=args.large_facts,
        include_large=not args.skip_large,
        messages_per_pile=args.messages_per_pile,
    ))
    for result in results:
        print(json.dumps(result.to_json(), sort_keys=True))


if __name__ == "__main__":
    main()
