"""Bounded proofs for the shared-bucket object/CAS protocol."""
from .shared_bucket_model import (
    Action,
    Protocol,
    drive,
    explore,
    initial_state,
    snapshot_tokens,
    step,
    violation,
)


def apply(state, actor, verb, protocol=Protocol()):
    action = Action(actor, verb)
    successor = step(state, action, protocol)
    assert violation(state, successor, action) is None
    return successor


def test_two_writers_and_one_reader_exhaust_every_safe_interleaving():
    explored = explore()

    assert explored.counterexample is None
    assert explored.states > 100
    assert explored.terminals
    assert all(
        snapshot_tokens(state.root, state.object_map())
        == {"base", "a", "b"}
        for state in explored.terminals
    )
    # A read opened before either CAS may legally finish after both: stale,
    # but still explained completely by its one pinned root.
    assert any(
        state.reader.result == {"base"}
        and snapshot_tokens(state.root, state.object_map())
        == {"base", "a", "b"}
        for state in explored.terminals
    )


def test_breadth_first_search_reports_minimal_missing_object_schedule():
    broken = explore(Protocol(root_before_objects=True))

    assert broken.counterexample is not None
    assert "root closure" in broken.counterexample.law
    assert broken.counterexample.schedule == (
        "A.read", "A.build", "A.cas")


def test_breadth_first_search_rejects_a_split_composite_root():
    broken = explore(Protocol(split_root=True))

    assert broken.counterexample is not None
    assert "split root generation" in broken.counterexample.law
    assert broken.counterexample.schedule[-1] == "A.cas"


def test_breadth_first_search_rejects_a_reader_that_repins_mid_decision():
    broken = explore(Protocol(reader_repins=True))

    assert broken.counterexample is not None
    assert broken.counterexample.law == "reader mixed root generations"
    assert broken.counterexample.schedule[-1] == "R.index"


def test_breadth_first_search_rejects_non_atomic_check_then_swap():
    broken = explore(Protocol(non_atomic_cas=True))

    assert broken.counterexample is not None
    assert broken.counterexample.law \
        == "two root writes accepted the same CAS precondition"
    schedule = broken.counterexample.schedule
    assert schedule[-3:] == ("B.check", "A.swap", "B.swap")
    assert schedule.index("A.check") < schedule.index("B.check")
    assert "retry" not in " ".join(schedule)


def test_breadth_first_search_rejects_destructive_object_replacement():
    broken = explore(Protocol(overwrite_object=True))

    assert broken.counterexample is not None
    assert broken.counterexample.law == "object-address integrity"
    assert broken.counterexample.schedule == (
        "A.read", "A.build", "A.put", "A.put")


def test_crash_before_cas_leaves_only_harmless_immutable_objects():
    state = initial_state()
    initial_objects = state.object_map()
    state = apply(state, "A", "read")
    state = apply(state, "A", "build")
    state = apply(state, "A", "put")
    old_root = state.root
    state = apply(state, "A", "crash")

    assert state.root == old_root
    assert state.object_map().items() > initial_objects.items()

    state = apply(state, "A", "restart")
    state = drive(state, "A")
    assert snapshot_tokens(state.root, state.object_map()) == {"base", "a"}


def test_crash_after_cas_retries_as_an_idempotent_ack():
    state = initial_state()
    for verb in ("read", "build", "put", "put", "put", "put", "cas"):
        state = apply(state, "A", verb)
    committed_history = state.history
    state = apply(state, "A", "crash")
    state = apply(state, "A", "restart")
    state = drive(state, "A")

    assert state.history == committed_history
    assert snapshot_tokens(state.root, state.object_map()) == {"base", "a"}


def test_every_bounded_crash_state_is_safe_and_fairly_recoverable():
    explored = explore(crashes=True)

    assert explored.counterexample is None
    assert explored.terminals
    for terminal in explored.terminals:
        recovered = drive(drive(terminal, "A"), "B")
        assert snapshot_tokens(
            recovered.root, recovered.object_map()) == {"base", "a", "b"}
