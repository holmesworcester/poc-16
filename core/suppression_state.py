"""Admitted suppression state and its local reverse index.

The authenticated state is keyed by suppression id: SuppTree answers whether
one id is CLEAR or ACTIVE and FactTree's matching action slot names the
immutable action record, whose admission pointer is the witness. Local SQLite
retains proposal ids and targets,
derives the current action frontier, and supports the reverse index used
to enumerate already-resident victims. It is never consulted by a Worker and
is not a second authority index.

``core.suppression`` defines the pure clear-envelope selector and exact-target
vocabulary. This module is the stateful half: it folds validated proposals
and answers admission and suppression queries against the derived index.
An action's selected historical witness lives once in its FactRecord.
"""
ACTION_PROPOSALS_SCHEMA = """
CREATE TABLE IF NOT EXISTS action_proposals(
    fid TEXT PRIMARY KEY,
    k TEXT NOT NULL);
"""
ACTIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS actions(
    sid TEXT PRIMARY KEY,
    fid TEXT NOT NULL);
"""
SCHEMA = ACTION_PROPOSALS_SCHEMA + """
CREATE TABLE IF NOT EXISTS action_targets(
    fid TEXT NOT NULL,
    sid TEXT NOT NULL,
    PRIMARY KEY(fid, sid));
""" + ACTIONS_SCHEMA + """
CREATE INDEX IF NOT EXISTS actions_by_fid ON actions(fid);
"""


def upgrade_schema(idx):
    """Drop legacy copied action JSON after the canonical blob cutover."""
    proposal_columns = {
        row[1] for row in idx.execute("PRAGMA table_info(action_proposals)")
    }
    action_columns = {
        row[1] for row in idx.execute("PRAGMA table_info(actions)")
    }
    rebuild_actions = action_columns != {"sid", "fid"}
    if "j" not in proposal_columns and not rebuild_actions:
        return
    idx.execute("BEGIN")
    try:
        if "j" in proposal_columns:
            idx.execute(
                "ALTER TABLE action_proposals "
                "RENAME TO action_proposals_legacy")
            idx.execute(ACTION_PROPOSALS_SCHEMA)
            idx.execute(
                "INSERT INTO action_proposals(fid,k) "
                "SELECT fid,k FROM action_proposals_legacy")
            idx.execute("DROP TABLE action_proposals_legacy")
        if rebuild_actions:
            idx.execute("ALTER TABLE actions RENAME TO actions_legacy")
            idx.execute(ACTIONS_SCHEMA)
            idx.execute(
                "INSERT INTO actions(sid,fid) "
                "SELECT sid,fid FROM actions_legacy")
            idx.execute("DROP TABLE actions_legacy")
            idx.execute(
                "CREATE INDEX IF NOT EXISTS actions_by_fid ON actions(fid)")
        idx.commit()
    except Exception:
        idx.rollback()
        raise


def archive(idx, fact):
    """Retain one action id independently of any particular proof."""
    import facts

    targets = sorted(facts.action_sids(fact))
    if not targets:
        raise ValueError("action proposal targets")
    existing = idx.execute(
        "SELECT k FROM action_proposals WHERE fid=?",
        (fact.fid,)).fetchone()
    if existing is not None and existing != (fact.key,):
        raise ValueError("action proposal conflict")
    idx.execute(
        "INSERT OR IGNORE INTO action_proposals VALUES(?,?)",
        (fact.fid, fact.key),
    )
    idx.executemany(
        "INSERT OR IGNORE INTO action_targets VALUES(?,?)",
        ((fact.fid, sid) for sid in targets),
    )


def discard(idx, fids):
    """Remove proposals whose staged catalog receipts did not commit."""
    fids = tuple(fids)
    idx.executemany(
        "DELETE FROM action_targets WHERE fid=?", ((fid,) for fid in fids))
    idx.executemany(
        "DELETE FROM action_proposals WHERE fid=?", ((fid,) for fid in fids))


def snapshot(idx):
    """Return the exact effective sid bindings at this settlement point."""
    return dict(idx.execute(
        "SELECT sid, fid FROM actions ORDER BY sid"))


def changed(before, after):
    """Return ids whose effective action binding changed."""
    return {
        sid for sid in before.keys() | after.keys()
        if before.get(sid) != after.get(sid)
    }


def settle(idx, fact_of, guards_of):
    """Derive the effective action frontier in canonical proposal-key order.

    Proposal ids are monotone. Effective actions are a deterministic fold:
    an earlier accepted proposal masks a later proposal whose declared guard
    scopes intersect its targets. This makes action-first and fact-first
    delivery converge while retaining a temporarily rejected proposal for a
    later rebuild.
    """
    before = snapshot(idx)
    idx.execute("DELETE FROM actions")
    active = set()
    for fid, key in idx.execute(
            "SELECT fid, k FROM action_proposals ORDER BY k, fid"):
        fact = fact_of(fid)
        if fact is None:
            continue
        guards = sorted(guards_of(fact))
        targets = {
            sid for (sid,) in idx.execute(
                "SELECT sid FROM action_targets WHERE fid=? ORDER BY sid",
                (fid,))
        }
        import facts
        if fact.fid != fid or fact.key != key \
                or guards != sorted(set(guards)) \
                or not all(isinstance(sid, str) for sid in guards) \
                or targets != set(facts.action_sids(fact)):
            raise ValueError("action proposal integrity")
        if active.intersection(guards):
            continue
        for sid in sorted(targets - active):
            idx.execute(
                "INSERT INTO actions VALUES(?,?)",
                (sid, fid),
            )
        active.update(targets)
    return changed(before, snapshot(idx))


def active(idx, sid):
    return idx.execute(
        "SELECT 1 FROM actions WHERE sid=?", (sid,)).fetchone() is not None


def blocks(idx, sid, candidate_key, fact_of):
    """Whether the canonical action precedes this prospective fact.

    Historical facts remain admissible under delivery permutation. Facts
    ordered after the action cannot exercise the withdrawn guard. Worker
    authorization is stricter: it always consults current ACTIVE state.
    """
    row = idx.execute(
        "SELECT fid FROM actions WHERE sid=?", (sid,)).fetchone()
    if row is None:
        return False
    action = fact_of(row[0])
    import facts
    if action is None or sid not in facts.action_sids(action):
        raise ValueError("active action integrity")
    return action.key < candidate_key


def suppresses(idx, fact):
    import facts

    return any(active(idx, sid) for sid in facts.fact_scopes(fact))
