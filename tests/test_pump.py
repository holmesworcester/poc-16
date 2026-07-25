"""PLAN SKELETON — the cursored pump and the projector contract
(SIMPLIFY.md §5/§6.3/§6.4; beads poc-16-808.5/.6/.7, stages S4–S5)."""
import pytest

pytestmark = pytest.mark.skip(
    reason="skeleton — poc-16-808.5/.6/.7 (SIMPLIFY.md §5)")


# ---- exactly-once (poc-16-808.5) ---------------------------------------------

def test_pump_twice_is_noop():
    """Second pump with no new log rows changes nothing."""
    raise NotImplementedError


def test_pump_crash_resume():
    """Kill between any two rows: rerun continues cleanly — row application
    and cursor advance share ONE transaction; no handler needs
    INSERT OR IGNORE to survive it."""
    raise NotImplementedError


def test_minus_follows_plus():
    """A deletion refs its target, so −t appears after +t in every legal
    stream node.merge appends."""
    raise NotImplementedError


# ---- the contract (poc-16-808.6) ----------------------------------------------

def test_every_projector_row_carries_src():
    """AST check (extends test_fact_contract): every INSERT a materialize
    handler issues includes the src fid column."""
    raise NotImplementedError


def test_generic_retraction_by_src():
    """pump.retract deletes a fact's rows across the family's tables; no
    per-family retraction code exists."""
    raise NotImplementedError


def test_handlers_contain_no_suppression_logic():
    """AST check: no materialize handler reads S, removals, or evicted state
    — suppression reaches app.db only as pump '−' rows."""
    raise NotImplementedError


def test_removal_join_confluence():
    """The known bug (SIMPLIFY.md §5): removal before join in delivery order
    still yields evicted=1 in the members view — insert-only removals row +
    view, not UPDATE."""
    raise NotImplementedError


# ---- THE theorem (poc-16-808.7) ------------------------------------------------

def test_fold_pm_over_d_equals_fold_over_e():
    """Live: fold± over random delivery orders of D. Rebuild: fold over E in
    canonical order. Identical app.db (dump compare), for every world in the
    suppression corpus."""
    raise NotImplementedError


def test_rebuild_fires_zero_retractions():
    """Replay computes S first (T_supp / the root), folds over E: the '−'
    path never runs; the retraction counter stays 0."""
    raise NotImplementedError
