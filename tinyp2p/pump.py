"""PLAN SKELETON (poc-16-808.5/.6, stages S4–S5) — read models as a cursored
pure fold. SIMPLIFY.md §5.

    app.db = fold(step, ∅, log)      exactly-once, resumable, order-robust
    fold±(delivery order over D) == fold(canonical order over E)   THE theorem
                                                       (tests/test_pump.py)

The λ path never touches this module: read models are a leaf-client concern.
Rebuild is the clean side of the theorem: replay computes S first (T_supp /
the root), folds over E in canonical order, and zero retractions fire.
"""

# idx.db — appended by node.merge in the same transaction as facts/offers
LOG_SCHEMA = """
CREATE TABLE IF NOT EXISTS log(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    op  TEXT NOT NULL CHECK(op IN ('+','-')),
    fid TEXT NOT NULL);
"""

# app.db — the pump applies rows and advances the cursor in ONE transaction
CURSOR_SCHEMA = """
CREATE TABLE IF NOT EXISTS cursors(
    ws TEXT NOT NULL, projector TEXT NOT NULL, seq INT NOT NULL,
    PRIMARY KEY(ws, projector));
"""


def append_admitted(idx, fids):
    """+fid for each newly admitted durable fact (node.merge calls this)."""
    raise NotImplementedError("poc-16-808.5")


def append_retracted(idx, targets):
    """−target for each target of a newly admitted deletion; 1:N victims
    stream in as yez.3's surfacing walk hands them over. A deletion refs its
    target, so −t follows +t in every legal stream."""
    raise NotImplementedError("poc-16-808.5")


def pump(node, ws, projector="app"):
    """Apply log rows past the cursor and advance it, in ONE app.db
    transaction. Exactly-once replaces idempotence as the handler obligation
    (INSERT OR IGNORE stops being load-bearing). Returns rows applied. Crash
    anywhere => rerun is a no-op or a clean continuation."""
    raise NotImplementedError("poc-16-808.5")


def retract(app, ws, fid):
    """THE generic retraction — one pump operation, zero per-family code:
    DELETE FROM <table> WHERE src=? across the family's declared tables. No
    materialize handler ever sees suppression."""
    raise NotImplementedError("poc-16-808.6")


def tables_of(family):
    """The projector tables a family writes, so retract() can sweep them.
    Contract (AST-enforced, extends tests/test_fact_contract.py): every row
    carries its producing src fid; insert-only rows keyed by src; views for
    anything aggregate-shaped. Known fix bundled here: removal's
    `UPDATE members SET evicted=1` becomes an insert-only removals row + a
    view — display data, not fact suppression; S never lives in app.db."""
    raise NotImplementedError("poc-16-808.6")
