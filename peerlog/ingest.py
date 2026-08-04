"""Atomic filing of verified runs into local foreign-writer copies."""
import threading
from dataclasses import dataclass

from .fact import canonical, decode_slice, fid
from .log import Head, WriterLog, verify_head
from .proof import Run, leaf_paths, verify_run
from .treap import Treap

TS_QUARANTINE = 24 * 60 * 60 * 1000


@dataclass(frozen=True)
class ForkEvidence:
    writer: bytes
    heads: tuple[Head, Head]


class PeerState:
    """The canonical per-writer copies plus rebuildable discovery index."""

    def __init__(self):
        self.logs = {}
        self.heads = {}
        self.forks = []
        self.session_cache = {}
        self.treap = Treap()
        self.lock = threading.RLock()

    def add_owned(self, log):
        if not isinstance(log, WriterLog) or log._secret is None:
            raise ValueError("owned writer log")
        with self.lock:
            self.logs[log.writer] = log
            self.heads[log.writer] = log.head()
            self.treap = _rebuild(self.logs)

    def entries(self):
        return self.treap.entries()


def _fork(older, newer):
    if older.writer != newer.writer:
        return None
    if older.seq == newer.seq and (
            older.root != newer.root or older.control_root != newer.control_root):
        return ForkEvidence(older.writer, (older, newer))
    return None


def ingest(state, run: Run) -> None:
    """Verify and stage every effect before changing any resident state."""
    if not isinstance(state, PeerState) or not verify_run(run):
        raise ValueError("invalid writer run")
    facts = decode_slice(run.facts, run.hi - run.lo)
    with state.lock:
        incumbent_head = state.heads.get(run.writer)
        evidence = _fork(incumbent_head, run.head) if incumbent_head else None
        if evidence is not None:
            state.forks.append(evidence)
            raise ValueError("writer fork")

        incumbent_log = state.logs.get(run.writer)
        staged_log = WriterLog(run.writer)
        if incumbent_log is not None:
            staged_log._facts = dict(incumbent_log._facts)
            staged_log._paths = dict(incumbent_log._paths)
            staged_log._head = incumbent_log._head
        staged_log._install(run.lo, facts, run.head)
        staged_log._paths.update(leaf_paths(run))

        staged_logs = dict(state.logs)
        staged_logs[run.writer] = staged_log
        staged_treap = _rebuild(staged_logs)

        state.logs[run.writer] = staged_log
        if incumbent_head is None or run.head.seq >= incumbent_head.seq:
            state.heads[run.writer] = run.head
        state.treap = staged_treap


def ingest_batch(state, runs) -> None:
    """Atomically verify and file one adjacency-bound publication."""
    runs = tuple(runs)
    if not isinstance(state, PeerState) or not runs:
        raise ValueError("writer run batch")
    with state.lock:
        staged = PeerState()
        staged.logs = dict(state.logs)
        staged.heads = dict(state.heads)
        staged.forks = list(state.forks)
        staged.session_cache = dict(state.session_cache)
        staged.treap = state.treap
        staged.coverage = getattr(state, "coverage", None)
        for run in runs:
            ingest(staged, run)
        state.logs = staged.logs
        state.heads = staged.heads
        state.forks = staged.forks
        state.treap = staged.treap


def _rebuild(logs):
    treap = Treap()
    for log in logs.values():
        high = None
        for seq in sorted(log._facts):
            fact = log.fact(seq)
            late = high is not None and fact.ts + TS_QUARANTINE < high
            treap.insert(fact.ts, fid(fact), exact=late)
            high = fact.ts if high is None else max(high, fact.ts)
    return treap


def observe_head(state, head: Head) -> ForkEvidence | None:
    if not isinstance(state, PeerState) or not verify_head(head):
        raise ValueError("invalid writer head")
    with state.lock:
        incumbent = state.heads.get(head.writer)
        evidence = _fork(incumbent, head) if incumbent else None
        if evidence is not None:
            state.forks.append(evidence)
            return evidence
        if incumbent is None or head.seq > incumbent.seq:
            state.heads[head.writer] = head
        return None
