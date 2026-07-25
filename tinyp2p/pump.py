"""PLAN SKELETON (poc-16-808.5/.6, stages S4–S5) — read models as a cursored
pure fold. SIMPLIFY.md §5.

    app.db = fold(step, ∅, log)      exactly-once, resumable, order-robust
    fold±(delivery order over D) == fold(canonical order over E)   THE theorem
                                                       (tests/test_pump.py)

The λ path never touches this module: read models are a leaf-client concern.
Rebuild is the clean side of the theorem: replay computes S first (T_supp /
the root), folds over E in canonical order, and zero retractions fire.
"""
from . import facts
from .close import close
from .kernel import Valid, resolve_deps

# idx.db — appended by node.merge in the same transaction as facts/offers
LOG_SCHEMA = """
CREATE TABLE IF NOT EXISTS log(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    op  TEXT NOT NULL CHECK(op IN ('+','-','*')),
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
    idx.executemany(
        "INSERT INTO log(op, fid) VALUES('+', ?)",
        ((fid,) for fid in fids),
    )


def append_retracted(idx, targets):
    """−target for each target of a newly admitted deletion; 1:N victims
    stream in as yez.3's surfacing walk hands them over. A deletion refs its
    target, so −t follows +t in every legal stream."""
    idx.executemany(
        "INSERT INTO log(op, fid) VALUES('-', ?)",
        ((fid,) for fid in targets),
    )


def append_received(idx, fids):
    """``*fid`` for each fact whose bulk object is now resident and proved.
    Object arrival is a second delivery channel over the same log, so a
    chunk's bytes land in the read model by exactly the same fold as its
    fact — and a duplicate delivery is a no-op, not a double count."""
    idx.executemany(
        "INSERT INTO log(op, fid) VALUES('*', ?)",
        ((fid,) for fid in fids),
    )


def pump(node, ws, projector="app"):
    """Apply log rows past the cursor and advance it, in ONE app.db
    transaction. Exactly-once replaces idempotence as the handler obligation
    (INSERT OR IGNORE stops being load-bearing). Returns rows applied. Crash
    anywhere => rerun is a no-op or a clean continuation."""
    with node.lock:
        idx, app = node.idx(ws), node.app
        row = app.execute(
            "SELECT seq FROM cursors WHERE ws=? AND projector=?",
            (ws, projector),
        ).fetchone()
        cursor = row[0] if row else 0
        rows = idx.execute(
            "SELECT seq, op, fid FROM log WHERE seq>? ORDER BY seq",
            (cursor,),
        ).fetchall()
        marker = idx.execute(
            "SELECT CAST(v AS INT) FROM meta WHERE k='reproject'"
        ).fetchone()
        rebuilding = ws in node._reproject \
            or marker is not None and marker[0] > cursor \
            or any(op == "-" for _, op, _ in rows)
        if not rows and not rebuilding:
            return 0

        valids = []
        blob_of = lambda bh: node.store(ws).get("obj/" + bh)

        def valid(fid):
            fact = node.fact_of(ws, fid)
            deps = resolve_deps(fact, idx) if fact is not None else None
            if deps is None:
                raise ValueError("projection log references an absent fact")
            return Valid(fact, tuple(deps))

        app.execute("BEGIN")
        try:
            if rebuilding:
                facts.clear(app, ws)
                active = [
                    node.fact_of(ws, fid)
                    for (fid,) in idx.execute("SELECT fid FROM facts")
                ]
                ordered = close(
                    active,
                    lambda fid: resolve_deps(node.fact_of(ws, fid), idx) or (),
                    lambda fid: node.fact_of(ws, fid),
                )
                valids = [valid(fact.fid) for fact in ordered]
                for item in valids:
                    facts.materialize(app, ws, item)
                for (fid,) in idx.execute(
                        "SELECT fid FROM log WHERE op='*' ORDER BY seq"):
                    if node.fact_of(ws, fid) is not None:
                        facts.received(app, ws, valid(fid), blob_of)
                end = idx.execute(
                    "SELECT COALESCE(MAX(seq), 0) FROM log").fetchone()[0]
            else:
                for seq, op, fid in rows:
                    if op == "+":
                        item = valid(fid)
                        facts.materialize(app, ws, item)
                        valids.append(item)
                    elif op == "*":
                        facts.received(app, ws, valid(fid), blob_of)
                    else:
                        retract(app, ws, fid)
                end = rows[-1][0]
            facts.reconcile(
                app, ws, idx, lambda fid: node.fact_of(ws, fid), valids)
            app.execute(
                "INSERT INTO cursors VALUES(?,?,?) "
                "ON CONFLICT(ws, projector) DO UPDATE SET seq=excluded.seq",
                (ws, projector, end),
            )
            app.commit()
        except Exception:
            app.rollback()
            raise
        if rebuilding:
            node._reproject.discard(ws)
        return len(rows)


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
