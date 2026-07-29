"""Admitted suppression state and its local reverse projection.

The authenticated state is keyed by suppression id: SuppTree answers whether
one id is CLEAR or ACTIVE and FactTree's matching action slot names the
immutable evidence record. Local SQLite retains immutable proposal bytes,
derives the current action frontier, and supports the reverse projection used
to enumerate already-resident victims. It is never consulted by a Worker and
is not a second authority index.

``core.suppression`` defines the pure clear-envelope selector and exact-target
vocabulary. This module is the stateful half: it folds validated proposals,
binds each effective action to its current canonical proof closure, and
answers admission and projection queries against the derived index.
"""
import json

from .crypto import h
from .fact import canon, from_json

SCHEMA = """
CREATE TABLE IF NOT EXISTS action_proposals(
    fid TEXT PRIMARY KEY,
    k TEXT NOT NULL,
    j TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS action_targets(
    fid TEXT NOT NULL,
    sid TEXT NOT NULL,
    PRIMARY KEY(fid, sid));
CREATE TABLE IF NOT EXISTS actions(
    sid TEXT PRIMARY KEY,
    fid TEXT NOT NULL,
    j TEXT NOT NULL,
    evidence TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS actions_by_fid ON actions(fid);
"""


def archive(idx, fact):
    """Retain one action proposal independently of any particular proof."""
    import facts

    targets = sorted(facts.action_sids(fact))
    if not targets:
        raise ValueError("action proposal targets")
    row = (fact.key, json.dumps(fact.to_json()))
    existing = idx.execute(
        "SELECT k, j FROM action_proposals WHERE fid=?",
        (fact.fid,)).fetchone()
    if existing is not None and existing != row:
        raise ValueError("action proposal conflict")
    idx.execute(
        "INSERT OR IGNORE INTO action_proposals VALUES(?,?,?)",
        (fact.fid, *row),
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


def settle(idx, fact_of, guards_of):
    """Derive the effective action frontier in canonical proposal-key order.

    Proposal bytes are monotone. Effective actions are a deterministic fold:
    an earlier accepted proposal masks a later proposal whose declared guard
    scopes intersect its targets. This makes action-first and fact-first
    delivery converge while retaining a temporarily rejected proposal for a
    later rebuild.
    """
    before = {
        sid: (fid, evidence)
        for sid, fid, evidence in idx.execute(
            "SELECT sid, fid, evidence FROM actions")
    }
    idx.execute("DELETE FROM actions")
    active = set()
    for fid, key, raw in idx.execute(
            "SELECT fid, k, j FROM action_proposals ORDER BY k, fid"):
        fact = fact_of(fid)
        if fact is None:
            continue
        archived = from_json(json.loads(raw))
        guards = sorted(guards_of(fact))
        targets = {
            sid for (sid,) in idx.execute(
                "SELECT sid FROM action_targets WHERE fid=? ORDER BY sid",
                (fid,))
        }
        import facts
        if archived != fact or fact.fid != fid or fact.key != key \
                or guards != sorted(set(guards)) \
                or not all(isinstance(sid, str) for sid in guards) \
                or targets != set(facts.action_sids(fact)):
            raise ValueError("action proposal integrity")
        if active.intersection(guards):
            continue
        for sid in sorted(targets - active):
            previous = before.get(sid)
            evidence = previous[1] \
                if previous is not None and previous[0] == fid else ""
            idx.execute(
                "INSERT INTO actions VALUES(?,?,?,?)",
                (sid, fid, raw, evidence),
            )
        active.update(targets)
    after = {
        sid: (fid, evidence)
        for sid, fid, evidence in idx.execute(
            "SELECT sid, fid, evidence FROM actions")
    }
    return {
        sid for sid in set(before) | set(after)
        if before.get(sid) != after.get(sid)
    }


def bind_evidence(idx, fid, evidence_oid):
    """Bind one canonical current proof closure to every slot for ``fid``."""
    rows = idx.execute(
        "SELECT sid, evidence FROM actions WHERE fid=? ORDER BY sid",
        (fid,)).fetchall()
    if not rows or not isinstance(evidence_oid, str) or not evidence_oid:
        raise ValueError("action evidence binding")
    changed = {sid for sid, evidence in rows if evidence != evidence_oid}
    idx.execute(
        "UPDATE actions SET evidence=? WHERE fid=?",
        (evidence_oid, fid),
    )
    return changed


def active(idx, sid):
    return idx.execute(
        "SELECT 1 FROM actions WHERE sid=?", (sid,)).fetchone() is not None


def etag(idx):
    """Non-authoritative sync hint for the exact active action set."""
    rows = list(idx.execute(
        "SELECT sid, fid, evidence FROM actions ORDER BY sid"))
    return h(canon(["active-actions-v1", rows]))


def validate_evidence(workspace, sid, fid, evidence_oid, fetch):
    """Verify one immutable action witness through the ordinary kernel."""
    import facts
    from .close import decode_pile
    from .kernel import drain

    raw = fetch(evidence_oid) if evidence_oid else None
    if raw is None or h(raw) != evidence_oid:
        raise ValueError("action evidence object")
    stream, blobs = decode_pile(raw)
    result = drain(stream, workspace)
    matches = [
        valid for valid in result.valids
        if valid.fact.fid == fid and sid in facts.action_sids(valid.fact)
    ]
    if blobs or not result.ok or len(matches) != 1:
        raise ValueError("action evidence")
    return matches[0].fact, raw


def blocks(idx, sid, candidate_key):
    """Whether the canonical action precedes this prospective fact.

    Historical facts remain admissible under delivery permutation. Facts
    ordered after the action cannot exercise the withdrawn guard. Worker
    authorization is stricter: it always consults current ACTIVE state.
    """
    row = idx.execute(
        "SELECT j FROM actions WHERE sid=?", (sid,)).fetchone()
    if row is None:
        return False
    action = from_json(json.loads(row[0]))
    return action.key < candidate_key


def suppresses(idx, fact):
    import facts

    return any(active(idx, sid) for sid in facts.fact_scopes(fact))
