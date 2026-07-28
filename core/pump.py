"""Read models as a cursored pure fold (docs/SIMPLIFY.md §5).

    app.db = fold(step, ∅, log)      exactly-once, resumable, order-robust
    fold±(delivery order over D) == fold(canonical order over E)   THE theorem
                                                       (tests/test_pump.py)

The λ path never touches this module: read models are a leaf-client concern.
Rebuild is the clean side of the theorem: replay computes S through the same
exact suppression-id consult as live admission, folds over E = V∖S in
canonical order, and fires zero retractions.
"""
import facts
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
    """−target for each suppressed victim: the forward mask and
    node.apply_actions both land here. −t follows +t in every legal stream;
    an action's immutable evidence is admitted before its sid becomes active."""
    idx.executemany(
        "INSERT INTO log(op, fid) VALUES('-', ?)",
        ((fid,) for fid in targets),
    )


def append_received(idx, fids):
    """*fid when every immutable object named by a fact is resident."""
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
            or row is None
        if not rows and not rebuilding:
            return 0

        def valid(fid):
            fact = node.fact_of(ws, fid)
            deps = resolve_deps(fact, idx) if fact is not None else None
            if deps is None:
                raise ValueError("projection log references an absent fact")
            return Valid(fact, tuple(deps))

        def materialize(item):
            rank = idx.execute(
                "SELECT rank FROM proofs WHERE fid=?",
                (item.fact.fid,),
            ).fetchone()
            app.execute(
                "INSERT INTO projected VALUES(?,?,?,?)",
                (ws, item.fact.fid, item.fact.t,
                 rank[0] if rank else None),
            )
            facts.materialize(app, ws, item)

        blob_of = lambda oid: node.store(ws).get("obj/" + oid)
        app.execute("BEGIN")
        try:
            if rebuilding:
                facts.clear(app, ws)
                valid_facts = [
                    node.fact_of(ws, fid)
                    for (fid,) in idx.execute("SELECT fid FROM facts")
                ]
                suppressed = {  # E = V∖S by the one consult (CUTOVER §2.4)
                    fact.fid for fact in valid_facts
                    if node.suppressed(ws, fact)
                }
                ordered = close(
                    valid_facts,
                    lambda fid: resolve_deps(node.fact_of(ws, fid), idx) or (),
                    lambda fid: node.fact_of(ws, fid),
                )
                active = {
                    fact.fid for fact in ordered
                    if fact.fid not in suppressed
                }
                for item in (valid(fact.fid) for fact in ordered
                             if fact.fid in active):
                    materialize(item)
                for (fid,) in idx.execute(
                        "SELECT fid FROM log WHERE op='*' ORDER BY seq"):
                    if fid in active:
                        facts.received(app, ws, valid(fid), blob_of)
                end = idx.execute(
                    "SELECT COALESCE(MAX(seq), 0) FROM log").fetchone()[0]
            else:
                for seq, op, fid in rows:
                    if op == "+":
                        item = valid(fid)
                        materialize(item)
                    elif op == "*":
                        if app.execute(
                                "SELECT 1 FROM projected "
                                "WHERE ws=? AND src=?",
                                (ws, fid)).fetchone() is not None:
                            facts.received(app, ws, valid(fid), blob_of)
                    else:
                        retract(app, ws, fid)
                end = rows[-1][0]
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
    row = app.execute(
        "SELECT family FROM projected WHERE ws=? AND src=?",
        (ws, fid),
    ).fetchone()
    if row is None:
        return
    for table in tables_of(row[0]):
        app.execute(
            f"DELETE FROM {table} WHERE ws=? AND src=?",
            (ws, fid),
        )
    app.execute(
        "DELETE FROM projected WHERE ws=? AND src=?",
        (ws, fid),
    )


def tables_of(family):
    """The projector tables a family writes, so retract() can sweep them.
    Contract (AST-enforced, extends tests/test_fact_contract.py): every row
    carries its producing src fid; insert-only rows keyed by src; views for
    anything aggregate-shaped. Known fix bundled here: removal's
    `UPDATE members SET evicted=1` becomes an insert-only removals row + a
    view — display data, not fact suppression; S never lives in app.db."""
    handler = facts.handler_for(family) \
        if isinstance(family, str) else family
    if handler is None:
        raise ValueError(f"unknown fact family {family!r}")
    tables = handler.TABLES
    if not isinstance(tables, tuple) or not all(
            isinstance(table, str) and table.isidentifier()
            for table in tables):
        raise TypeError(f"bad projector tables for {handler.TAG!r}")
    return tables
