"""F3: full and path-copy repository compilation are byte-identical."""

import ast
from dataclasses import replace
from pathlib import Path

import pytest

import facts
from core import indexes
from core.repository_snapshot import extend_snapshot
from tests import repository_compiler_fuzzer as fuzzer


pytestmark = pytest.mark.unit


def _active(action):
    return indexes.suppression_slot(action)


@pytest.mark.parametrize("seed", fuzzer.FIXED_SEEDS)
def test_fixed_stateful_histories_match_after_every_transition(seed):
    corpus = fuzzer.build_corpus()
    plan = fuzzer.build_plan(corpus, seed)
    result = fuzzer.run_plan(corpus, plan)
    mark, state = corpus.landmarks, result.suppression

    assert state["single-target-before-action"][
        mark["target_first_sid"]] == indexes.suppression_slot()
    assert state["action-after-target"][
        mark["target_first_sid"]] == _active(mark["action_after"])
    assert state["action-before-target"][
        mark["target_later_sid"]] == _active(mark["action_before"])
    assert state["target-after-action"][
        mark["target_later_sid"]] == _active(mark["action_before"])
    assert state["competing-action-late"][
        mark["competing_sid"]] == _active(mark["competing_late"])
    assert state["competing-action-earlier"][
        mark["competing_sid"]] == _active(mark["competing_early"])
    assert state["removal-late"][
        mark["member_sid"]] == _active(mark["removal_late"])
    assert state["removal-earlier"][
        mark["member_sid"]] == _active(mark["removal_early"])
    assert result.roots["removal-late"] \
        == result.roots["duplicate-existing"] \
        == result.roots["empty-noop"]
    assert result.residents == frozenset(corpus.facts)


def test_seed_replays_and_covers_single_batch_duplicate_and_noop():
    corpus = fuzzer.build_corpus()
    first = fuzzer.build_plan(corpus, fuzzer.FIXED_SEEDS[0])

    assert first == fuzzer.build_plan(corpus, fuzzer.FIXED_SEEDS[0])
    assert first != fuzzer.build_plan(corpus, fuzzer.FIXED_SEEDS[1])
    assert any(len(step.fids) == 1 for step in first.steps)
    assert any(len(step.fids) > 2 for step in first.steps)
    assert any(not step.fids for step in first.steps)
    assert {
        "action-after-target",
        "action-before-target",
        "target-after-action",
        "target-action-batch",
        "multi-scope-file",
        "multi-scope-chunk",
        "competing-action-late",
        "competing-action-earlier",
        "duplicate-existing",
        "empty-noop",
        "removal-late",
        "removal-earlier",
    } <= {step.name for step in first.steps}


def test_differential_oracle_rejects_a_dropped_suppression_scope(
        monkeypatch):
    corpus = fuzzer.build_corpus()
    plan = fuzzer.build_plan(corpus, fuzzer.FIXED_SEEDS[0])
    current_scopes = facts.current_scopes

    def broken(anchor, base_root, incoming, fetch):
        with monkeypatch.context() as patch:
            patch.setattr(
                facts,
                "current_scopes",
                lambda fact: frozenset(sorted(current_scopes(fact))[:1]),
            )
            return extend_snapshot(anchor, base_root, incoming, fetch)

    with pytest.raises(AssertionError) as caught:
        fuzzer.run_plan(corpus, plan, broken)
    assert any(
        "multi-scope-chunk" in note for note in caught.value.__notes__)


def test_failure_shrinks_to_one_fact_and_reports_seed_and_prefix():
    corpus = fuzzer.build_corpus()
    plan = fuzzer.build_plan(corpus, 0xF3BAD)
    sentinel = corpus.landmarks["competing_early"]

    def broken(anchor, base_root, incoming, fetch):
        compiled = extend_snapshot(anchor, base_root, incoming, fetch)
        return replace(compiled, root=b"not-the-canonical-root") \
            if sentinel in incoming else compiled

    def fails(candidate):
        try:
            fuzzer.run_plan(corpus, candidate, broken)
        except AssertionError:
            return True
        return False

    shrunk = fuzzer.shrink_plan(plan, fails)

    assert len(shrunk.steps) == 1
    assert shrunk.steps[0].fids == (sentinel,)
    with pytest.raises(AssertionError) as caught:
        fuzzer.run_plan(corpus, shrunk, broken)
    assert any(
        "F3 compiler replay seed=0xf3bad" in note
        and shrunk.steps[0].name in note
        and sentinel[:8] in note
        for note in caught.value.__notes__
    )


def test_fuzzer_has_no_host_sql_or_provider_import_path():
    source = Path(fuzzer.__file__).read_text()
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")

    assert not any(
        name == "sqlite3"
        or name.startswith(("full_peer", "adapters", "deploy"))
        for name in imported
    )
