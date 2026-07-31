"""Bounded replayable schedules over the running RepositoryApplier.

This is a test harness, not a model of repository semantics.  Facts are
authored by a FullPeer and closed by its PileSender; every transition below is
performed by a fresh production RepositoryApplier.

The race precomputes two proposals at one base, then orders their CAS calls.
Atomic stores linearize every real overlap to such an order; the provider
conformance barrier separately proves that simultaneous replacements have one
winner. These tests explore deterministic interleavings, not wall-clock load.
"""
from dataclasses import dataclass
import random

import facts

from adapters.r2 import R2BindingStore
from adapters.s3 import S3Config, S3Store
from core import http, peer_capability
from core.close import decode_pile
from core.crypto import h, load_sk
from core.grants import make_token
from core.limits import (
    MAX_OBJECT_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    MAX_ROOT_BYTES,
)
from core.object_store import CREATED, Applied, OutcomeUnknown
from core.repository_applier import RepositoryApplier
from core.repository_reader import RepositoryReader
from core.repository_snapshot import compile_snapshot
from core.staged_intent import staging_key
from core.store import FsStore
from full_peer.node import FullPeer

from .adversarial_bucket import AdversarialBucket, Fault, Nonconforming
from .ingress_obligations import ObligationTrace
from .provider_fakes import FakeR2Bucket, FakeS3Bucket
from .provider_obligations import ProviderHistory
from .shared_bucket import InjectedCrash
from .util import add_member, suppression_world


FIXED_CASES = tuple(
    (workers, 0xF20000 + workers) for workers in range(2, 7))
DIRECT_LABELS = (
    "post-a",
    "post-b",
    "delete-a",
    "join",
    "remove-member",
    "post-c",
    "duplicate-b",
    "malformed",
)


@dataclass(frozen=True, slots=True)
class Corpus:
    workspace: str
    work: dict
    staged_raw: bytes
    staged_objects: dict
    expected_facts: dict
    expected_root: bytes


@dataclass(frozen=True, slots=True)
class Plan:
    workers: int
    seed: int
    race: tuple
    stages: tuple
    actors: tuple
    remaining: tuple
    retries: tuple

    def diagnostic(self, trace):
        lines = "\n".join(
            f"  {ordinal + 1}. {label}"
            for ordinal, label in enumerate(trace)) or "  <empty>"
        return (
            f"F2 replay workers={self.workers} seed={self.seed:#x}\n"
            f"first failing prefix:\n{lines}"
        )


def _pile(node, workspace, fids):
    """Close through the authenticated view and encode through PileSender."""
    unit = node.reader(workspace).validated().closure(tuple(fids))
    return node.sender(workspace).pack(unit)


def build_corpus(directory):
    """Build deterministic post/delete/join/remove/file wire closures."""
    node, workspace, posts, deletions = suppression_world(
        directory, initial_secret="11" * 32)
    raw_a = _pile(node, workspace, (posts[1],))
    raw_b = _pile(node, workspace, (posts[0],))
    raw_delete = _pile(node, workspace, (deletions[0],))
    raw_c = _pile(node, workspace, (posts[2],))

    invite_secret = load_sk(h(b"poc16-f2-invite"))
    invite_public = invite_secret.verify_key.encode().hex()
    member_secret = load_sk(h(b"poc16-f2-member"))
    member_public = member_secret.verify_key.encode().hex()
    _, _, joined = add_member(
        node, workspace, "member", ts=30,
        member_identity=(member_secret, member_public),
        invite_identity=(invite_secret, invite_public))
    raw_join = _pile(node, workspace, (joined.fid,))
    node.now_ms = lambda: 40
    removed = facts.auth.removal.evict(node, workspace, member_public)
    raw_removal = _pile(node, workspace, (removed,))

    attachment, = node.by_type(
        workspace, facts.content.file.TAG, include_suppressed=True)
    chunks = node.by_type(
        workspace, facts.content.chunk.TAG, include_suppressed=True)
    staged_raw = _pile(
        node, workspace, (attachment.fid, *(fact.fid for fact in chunks)))
    staged_refs = {
        oid
        for fact in decode_pile(staged_raw, workspace)
        for oid in facts.blob_refs(fact)
    }
    staged_objects = {
        oid: node.store(workspace).get_bounded(
            "obj/" + oid, MAX_OBJECT_BYTES)
        for oid in staged_refs
    }
    assert staged_objects and all(
        raw is not None and h(raw) == oid
        for oid, raw in staged_objects.items())

    published = (
        raw_a, raw_b, raw_delete, raw_join,
        raw_removal, raw_c, staged_raw)
    expected = {
        fact.fid: fact
        for raw in published
        for fact in decode_pile(raw, workspace)
    }
    compiled = compile_snapshot(workspace, expected)

    return Corpus(
        workspace,
        {
            "post-a": raw_a,
            "post-b": raw_b,
            "delete-a": raw_delete,
            "join": raw_join,
            "remove-member": raw_removal,
            "post-c": raw_c,
            "duplicate-b": raw_b,
            "malformed": b"{}",
        },
        staged_raw,
        staged_objects,
        expected,
        compiled.root,
    )


def build_plan(workers, seed):
    """Generate one bounded plan; seed and worker count fully identify it."""
    if workers not in range(2, 7) or type(seed) is not int:
        raise ValueError("F2 schedule")
    rng = random.Random(seed)
    staged = list(DIRECT_LABELS)
    rng.shuffle(staged)
    remaining = ["post-a", "duplicate-b", "malformed"]
    rng.shuffle(remaining)
    retries = list(DIRECT_LABELS)
    rng.shuffle(retries)
    ordinal = iter(range(10_000))

    def actor(worker=None):
        worker = rng.randrange(workers) if worker is None else worker
        return f"worker-{worker}-step-{next(ordinal)}"

    return Plan(
        workers,
        seed,
        ("post-b", "join") if seed & 1 else ("join", "post-b"),
        tuple(
            (actor(index % workers), label, f"member-{index}-{label}")
            for index, label in enumerate(staged)),
        tuple(actor() for _ in range(5)),
        tuple((actor(), label) for label in remaining),
        tuple((actor(), label) for label in retries),
    )


class _TracedApplier(RepositoryApplier):
    """Observe the real post-commit/pre-delete F10 seam."""

    def __init__(self, workspace, store, trace):
        super().__init__(workspace, store)
        self._trace = trace

    async def retire(self, source, raw, receipt):
        self._trace.observe_publication(source, raw, receipt)
        return await super().retire(source, raw, receipt)


class F1Oracle:
    """Check each actual committed root and each destructive obligation."""

    def __init__(self, corpus, bucket, trace):
        self.corpus, self.bucket, self.trace = corpus, bucket, trace
        self._checked = 0
        self._previous = frozenset()
        self.report = None

    def _acknowledged_before(self, key, raw, seq):
        return any(
            event.seq < seq
            and event.op == "put_if_absent"
            and event.key == key
            and event.value == raw
            and event.result is CREATED
            for event in self.bucket.history
        )

    def check(self, final=False):
        self.bucket.assert_valid_history()
        report = self.trace.check()
        self.report = report
        applied = [
            event for event in self.bucket.history
            if event.op == "cas" and isinstance(event.result, Applied)
        ]
        assert [commit.seq for commit in self.bucket.commits] == [
            event.seq for event in applied]
        for event in applied:
            assert event.result.token.value.startswith("opaque:")
            assert event.result.token.value != h(event.value)

        for commit in self.bucket.commits[self._checked:]:
            objects = dict(commit.objects)
            reader = RepositoryReader(
                self.corpus.workspace, commit.root, objects.get)
            validated = reader.all_facts()
            current = frozenset(validated.facts)
            assert self._previous <= current
            compiled = compile_snapshot(
                self.corpus.workspace, validated.facts)
            assert compiled.root == commit.root
            for oid, raw in compiled.outbox:
                assert objects.get(oid) == raw
                assert self._acknowledged_before(
                    "obj/" + oid, raw, commit.seq)
            worker = reader.worker()
            assert all(
                isinstance(worker.fact_active(fid), bool)
                for fid in current)
            self._previous = current
        self._checked = len(self.bucket.commits)

        if not final:
            return
        assert not report.live
        final = self.bucket.handle("oracle-final")
        assert final.get("root") == self.corpus.expected_root
        assert not final.list("pile/")
        for oid, raw in self.corpus.staged_objects.items():
            assert final.get("obj/" + oid) == raw
        assert self._previous == frozenset(self.corpus.expected_facts)
        self.bucket.assert_valid_history()


class ProviderF10Oracle:
    """Apply the same checker to normalized native-adapter operations."""

    def __init__(self, provider, bucket, history, trace):
        self.provider = provider
        self.bucket = bucket
        self.history = history
        self.trace = trace
        self.report = None

    def check(self, final=False):
        self.history.assert_valid_history()
        self.report = self.trace.check()
        if not final:
            return
        assert not self.report.live, self.history.diagnostic()
        prefix = (
            '"opaque-value-' if self.provider == "s3"
            else "opaque-r2-value-")
        assert self.history.token_values
        assert all(
            token.startswith(prefix) and token != h(raw)
            for token, raw in self.history.token_values.items()
        ), self.history.diagnostic()
        assert all(
            rule[2] >= 1 for rule in self.bucket.put_faults
        ), self.history.diagnostic()
        native = self.bucket.history
        if self.provider == "s3":
            assert any(
                operation == "delete"
                and "/pile/" in key
                for _, operation, key, _ in native
            ), self.history.diagnostic()
        else:
            assert any(
                operation == "delete"
                and "/pile/" in key
                for operation, key, *_ in native
            ), self.history.diagnostic()


@dataclass(slots=True)
class Backend:
    name: str
    applier: object
    inject: object
    oracle: object = None


def f1_backend(
        corpus, seed, *, nonconforming=Nonconforming()):
    bucket = AdversarialBucket(
        seed=seed,
        list_page_size=3,
        short_page_sizes=(1, 2, 3),
        nonconforming=nonconforming,
    )
    trace = ObligationTrace(bucket, corpus.workspace)
    oracle = F1Oracle(corpus, bucket, trace)

    def applier(actor):
        return _TracedApplier(
            corpus.workspace, bucket.handle(actor), trace)

    def inject(actor, fault):
        rules = {
            "unknown-before": (Fault.TRANSPORT, "before"),
            "unknown-after": (Fault.RESPONSE_LOST, "after"),
            "crash-after": (Fault.CRASH, "after"),
        }
        kind, when = rules[fault]
        bucket.fail(actor, "cas", "root", kind, when=when)
        return True

    return Backend("f1", applier, inject, oracle)


def provider_backend(kind, corpus, directory, seed=0):
    """Build a provider/full-peer refinement of the same logical schedule."""
    if kind == "full-peer":
        peer = FullPeer(
            str(directory / "peer"), initial_secret="22" * 32)
        store = FsStore(str(directory / "store"))
        peer._stores[corpus.workspace] = store

        def applier(_actor):
            peer._appliers.pop(corpus.workspace, None)
            return peer.applier(corpus.workspace)

    elif kind == "s3":
        bucket = FakeS3Bucket(page_size=2)
        history = ProviderHistory("s3", seed, bucket.history)
        trace = ObligationTrace(history, corpus.workspace)

        def applier(actor):
            store = S3Store(
                S3Config(
                    "f2-convergence",
                    "tenant",
                    read_total_max_attempts=1,
                    list_page_size=2,
                ),
                client=bucket.client(actor),
            )
            return _TracedApplier(
                corpus.workspace,
                history.sync_store(store, actor),
                trace,
            )
    elif kind == "r2":
        bucket = FakeR2Bucket(page_size=2)
        history = ProviderHistory("r2", seed, bucket.history)
        trace = ObligationTrace(history, corpus.workspace)

        def applier(actor):
            store = R2BindingStore(bucket, "tenant")
            return _TracedApplier(
                corpus.workspace,
                history.async_store(store, actor),
                trace,
            )
    else:
        raise AssertionError(kind)
    if kind == "full-peer":
        return Backend(kind, applier, lambda _actor, _fault: False)

    def inject(actor, fault):
        if fault == "crash-after":
            history.crash_after(actor, "cas", "root")
        else:
            bucket.fail_put(
                "tenant/root",
                when={
                    "unknown-before": "before",
                    "unknown-after": "after",
                }[fault],
            )
        return True

    return Backend(
        kind, applier, inject,
        ProviderF10Oracle(kind, bucket, history, trace))


def _put_staged(corpus, ingress, seed):
    session = h(f"f2:{seed}".encode())[:32]
    member = "d" * 16
    marker = staging_key(
        corpus.workspace, member, session,
        "pile", h(corpus.staged_raw))
    ingress.put_if_absent(marker, corpus.staged_raw)
    for oid, raw in corpus.staged_objects.items():
        ingress.put_if_absent(
            staging_key(
                corpus.workspace, member, session, "obj", oid),
            raw,
        )
    return marker


async def _verify_provider(corpus, backend):
    applier = backend.applier("provider-oracle")
    root = await applier.store.get_bounded(
        "root", MAX_ROOT_BYTES)
    compiled = compile_snapshot(
        corpus.workspace, corpus.expected_facts)
    objects = {}
    for oid, _ in compiled.outbox:
        objects[oid] = await applier.store.get_bounded(
            "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES)
    reader = RepositoryReader(corpus.workspace, root, objects.get)
    assert reader.all_facts().facts == corpus.expected_facts
    assert compiled.root == root
    for oid, raw in corpus.staged_objects.items():
        assert await applier.store.get_bounded(
            "obj/" + oid, MAX_OBJECT_BYTES) == raw


async def _race(corpus, backend, sources, order):
    first = backend.applier("worker-0-race")
    second = backend.applier("worker-1-race")
    winner, loser = order
    left = await first.propose(
        sources[winner], corpus.work[winner])
    right = await second.propose(
        sources[loser], corpus.work[loser])
    assert left.base_token == right.base_token
    won = await first.commit(
        sources[winner], corpus.work[winner], left)
    lost = await second.commit(
        sources[loser], corpus.work[loser], right)
    assert (won.status, lost.status) == ("applied", "stale")
    assert (await first.apply(sources[winner])).retired


async def _peer(corpus, backend, actor):
    member, raw = "grant-peer", corpus.work["duplicate-b"]
    receiver = backend.applier(actor)
    secret, now = b"f2-grant-gate-secret" * 2, 1_000
    gate = http.HttpGate(
        receiver.store, corpus.workspace, secret, lambda: now, receiver,
        sync_profile=peer_capability.FULL)
    token = make_token(
        secret, member, corpus.workspace,
        capability=peer_capability.FULL, issued_at=now - 1)
    response = await gate.handle(
        "PUT", f"/pile/{member}/{h(raw)}", {"ws": corpus.workspace},
        {"Authorization": "Bearer " + token}, raw)
    assert response.status == 204


async def _attempt(backend, actor, source, fault="", expected=""):
    injected = bool(fault and backend.inject(actor, fault))
    try:
        result = await backend.applier(actor).apply(source)
    except (OutcomeUnknown, InjectedCrash):
        if not injected or fault not in {"unknown-before", "crash-after"}:
            raise
    else:
        if injected and fault == "unknown-after":
            assert result.status == "confirmed"
        elif injected:
            raise AssertionError("injected failure did not escape")
        if expected:
            assert result.status == expected
        return result


async def execute(
        corpus, plan, backend, ingress_directory, *,
        stop_after=None, after_step=None):
    """Run the fixed plan; a seed plus a failing prefix replays every choice."""
    if stop_after is not None and (
            type(stop_after) is not int or stop_after < 1):
        raise ValueError("stop_after")
    sources, trace = {}, []
    ingress = FsStore(str(ingress_directory))
    marker = _put_staged(corpus, ingress, plan.seed)

    class _Stop(BaseException):
        pass

    async def take(label, action, *, final=False):
        if stop_after is not None and len(trace) >= stop_after:
            raise _Stop
        trace.append(label)
        try:
            result = await action()
            if after_step is not None:
                after_step(len(trace), backend)
            if backend.oracle is not None:
                backend.oracle.check(final=final)
            return result
        except BaseException as error:
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note(plan.diagnostic(trace))
            raise

    try:
        for actor, label, member in plan.stages:
            sources[label] = await take(
                f"stage({label}) actor={actor}",
                lambda actor=actor, label=label, member=member:
                    backend.applier(actor).stage(
                        member, corpus.work[label]))
        await take(
            f"race({','.join(plan.race)}) "
            "actors=worker-0-race,worker-1-race",
            lambda: _race(corpus, backend, sources, plan.race))
        await take(
            f"peer(duplicate-b) actor={plan.actors[0]}",
            lambda: _peer(corpus, backend, plan.actors[0]))
        for actor, label, fault in zip(
                plan.actors[1:4],
                ("delete-a", "remove-member", "post-c"),
                ("unknown-before", "unknown-after", "crash-after")):
            await take(
                f"attempt({label}) actor={actor} fault={fault}",
                lambda actor=actor, label=label, fault=fault:
                    _attempt(backend, actor, sources[label], fault))
        actor = plan.actors[4]

        async def staged():
            outcome = await backend.applier(actor).apply_staged(
                ingress, marker)
            assert outcome.result.status in {
                "applied", "confirmed", "noop", "admitted"}
            assert set(outcome.promoted) == set(corpus.staged_objects)
            assert ingress.get(marker) == corpus.staged_raw

        await take(f"staged(attachment) actor={actor}", staged)
        for actor, label in plan.remaining:
            await take(
                f"attempt({label}) actor={actor}",
                lambda actor=actor, label=label:
                    _attempt(
                        backend, actor, sources[label],
                        expected="rejected" if label == "malformed" else ""))
        for actor, label in plan.retries:
            await take(
                f"retry({label}) actor={actor}",
                lambda actor=actor, label=label:
                    backend.applier(actor).apply(sources[label]))
    except _Stop:
        return tuple(trace)

    async def finalize():
        for label, source in sources.items():
            applier = backend.applier("final-" + label)
            assert await applier.store.get_bounded(
                source, max(1, len(corpus.work[label]))) is None
        assert ingress.get(marker) == corpus.staged_raw
        if backend.name != "f1":
            await _verify_provider(corpus, backend)

    try:
        await take("finalize", finalize, final=True)
    except _Stop:
        return tuple(trace)
    return tuple(trace)


async def exercise_spent_aba(corpus, plan, backend):
    """Recreate one spent source and prove restart cannot delete it again."""
    member = next(
        member for _, label, member in plan.stages
        if label == "post-b")
    raw = corpus.work["post-b"]
    first = backend.applier("aba-create")
    source = await first.stage(member, raw)
    assert await first.store.get_bounded(source, len(raw)) is None
    assert await first.store.put_if_absent(source, raw) is CREATED

    replay = await backend.applier("aba-restart").apply(source)

    assert replay.status in {"applied", "confirmed", "noop"}
    assert replay.retired is False
    assert await first.store.get_bounded(source, len(raw)) == raw
    report = backend.oracle.trace.check()
    assert [(item.key, item.raw) for item in report.live] == [(source, raw)]
    return source
