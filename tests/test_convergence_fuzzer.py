"""F2: fixed multi-Applier convergence schedules over the running engine."""
import asyncio
from dataclasses import replace
import sqlite3

import pytest

from core import snapshot
from core.repository_applier import RepositoryApplier
from .adversarial_bucket import Nonconforming
from .convergence_fuzzer import (
    DIRECT_LABELS,
    FIXED_CASES,
    build_corpus,
    build_plan,
    execute,
    exercise_spent_aba,
    f1_backend,
    provider_backend,
)
from .ingress_obligations import ObligationViolation


pytestmark = pytest.mark.unit


def _database_forbidden(*_args, **_kwargs):
    raise AssertionError("database-free RepositoryApplier opened SQLite")


@pytest.mark.parametrize(("workers", "seed"), FIXED_CASES)
def test_fixed_schedules_converge_through_f1_full_peer_s3_and_r2(
        workers, seed, tmp_path, monkeypatch):
    corpus = build_corpus(tmp_path / "author")
    plan = build_plan(workers, seed)
    assert plan == build_plan(workers, seed)
    assert plan != build_plan(workers, seed + 0x10)
    assert plan.race == (
        ("post-b", "join") if seed & 1 else ("join", "post-b"))
    assert set(DIRECT_LABELS) == {
        label for _, label, _ in plan.stages}
    backends = [
        f1_backend(corpus, seed),
        *(provider_backend(kind, corpus, tmp_path / kind, seed)
          for kind in ("full-peer", "s3", "r2")),
    ]
    monkeypatch.setattr(sqlite3, "connect", _database_forbidden)

    # FullPeer was composed above; every receiving turn after this point is a
    # freshly requested exact core Applier, including the grant-gated PUT.
    assert type(backends[1].applier("db-free-probe")) is RepositoryApplier
    for backend in backends:
        asyncio.run(execute(
            corpus, plan, backend,
            tmp_path / f"ingress-{backend.name}"))
    checked = [
        backend for backend in backends
        if backend.name in {"f1", "s3", "r2"}
    ]
    summaries = [
        tuple(sorted(
            (item.key, item.witness)
            for item in backend.oracle.report.discharges
        ))
        for backend in checked
    ]
    assert summaries[1:] == summaries[:1] * 2
    for backend in checked:
        asyncio.run(exercise_spent_aba(corpus, plan, backend))
    used = {
        int(actor.split("-")[1])
        for actor in (
            [item[0] for item in plan.stages] + list(plan.actors)
            + [item[0] for item in plan.remaining + plan.retries])
    }
    assert used == set(range(workers))


@pytest.mark.parametrize("kind", ("s3", "r2"))
def test_provider_trace_reports_first_unsupported_aba_delete(
        kind, tmp_path):
    corpus = build_corpus(tmp_path / f"author-{kind}")
    plan = build_plan(2, 0xF10BAD)
    backend = provider_backend(
        kind, corpus, tmp_path / kind, plan.seed)
    asyncio.run(execute(
        corpus, plan, backend, tmp_path / f"ingress-{kind}"))
    source = asyncio.run(exercise_spent_aba(corpus, plan, backend))

    applier = backend.applier("unsupported-delete")
    asyncio.run(applier.store.delete(source))

    with pytest.raises(ObligationViolation) as caught:
        backend.oracle.trace.check()
    assert caught.value.event.key == source
    assert len(caught.value.prefix) == caught.value.event.seq
    assert f"provider={kind}" in str(caught.value)
    assert f"seed={plan.seed:#x}" in str(caught.value)
    assert f"unsupported DELETE {source}" in str(caught.value)


def test_actual_reachable_object_destruction_shrinks_and_replays(
        tmp_path):
    corpus = build_corpus(tmp_path / "author")
    plan = build_plan(2, 0xF2BAD)
    corrupt_at = len(plan.stages) + 1

    def corrupt(step, backend):
        if step != corrupt_at:
            return
        bucket = backend.oracle.bucket
        root = snapshot.decode_root(bucket.commits[-1].root)
        oid = root.maps[snapshot.FACT_ORDER]["root"]
        bucket.handle("worker-0-corrupt").delete("obj/" + oid)

    def run(length):
        backend = f1_backend(
            corpus,
            plan.seed,
            nonconforming=Nonconforming(destructive_objects=True),
        )
        asyncio.run(execute(
            corpus, plan, backend,
            tmp_path / f"ingress-{length}",
            stop_after=length, after_step=corrupt))

    failing = _first_failing(corrupt_at, run)

    assert failing == corrupt_at
    for _ in range(2):
        with pytest.raises(AssertionError) as caught:
            run(failing)
        assert any(
            "workers=2 seed=0xf2bad" in note
            and "race(post-b,join)" in note
            for note in caught.value.__notes__
        )


def test_final_union_divergence_is_prefix_replayable(tmp_path):
    corpus = build_corpus(tmp_path / "author")
    broken = replace(
        corpus,
        staged_raw=corpus.work["post-b"],
    )
    plan = build_plan(2, 0xF2F1A)
    final_at = len(plan.stages) + len(plan.remaining) \
        + len(plan.retries) + 7

    def run(length):
        asyncio.run(execute(
            broken, plan, f1_backend(broken, plan.seed),
            tmp_path / f"final-ingress-{length}",
            stop_after=length))

    failing = _first_failing(final_at, run)

    assert failing == final_at
    with pytest.raises(AssertionError) as caught:
        run(failing)
    assert any(
        "seed=0xf2f1a" in note and "finalize" in note
        for note in caught.value.__notes__)


def _first_failing(last, run):
    return next(
        length for length in range(1, last + 1)
        if _raises_assertion(lambda length=length: run(length)))


def _raises_assertion(action):
    try:
        action()
    except AssertionError:
        return True
    return False
