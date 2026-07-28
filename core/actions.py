"""Durable suppression actions and their local reverse projection.

The authenticated state is keyed by suppression id: SuppTree answers whether
one id is CLEAR or ACTIVE and FactTree's matching action slot names the
immutable evidence record.  This SQLite table is only the node-local,
rebuildable reverse projection used to enumerate already-resident victims.
It is never consulted by a Worker and is not a second authority index.
"""
import json

from .crypto import h
from .fact import canon, from_json
from .suppression import deathkey, is_deletion, suppkeys

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions(
    sid TEXT PRIMARY KEY,
    fid TEXT NOT NULL,
    j TEXT NOT NULL,
    evidence TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS actions_by_fid ON actions(fid);
"""


class ScreenRejected(ValueError):
    """A valid immutable fact attempted to use already-masked authority."""


def principal_sid(kind, public_key):
    if kind not in {"member", "device"} \
            or not isinstance(public_key, str) or not public_key:
        raise ValueError("principal suppression id")
    return f"{kind}:{public_key}"


def action_sids(fact):
    """The exact typed suppression ids activated by one action fact."""
    out = set()
    if is_deletion(fact):
        out.add(deathkey(fact))
    out.update(
        principal_sid("member", target)
        for name, target, _ in fact.offers()
        if name == "removed"
    )
    return frozenset(out)


def fact_scopes(fact):
    """The family-declared selectors that can suppress this fact itself."""
    return frozenset(suppkeys(fact))


def provider_scopes(fact):
    """Fact selectors plus typed principal liveness for offered authority."""
    out = set(fact_scopes(fact))
    for name, public_key, _ in fact.offers():
        if name == "member":
            out.add(principal_sid("member", public_key))
        elif name == "device_key":
            out.add(principal_sid("device", public_key))
    return frozenset(out)


def archive(idx, fact, evidence_oid):
    """Keep the canonical minimum action witness for each monotone sid."""
    for sid in sorted(action_sids(fact)):
        idx.execute(
            "INSERT INTO actions VALUES(?,?,?,?) "
            "ON CONFLICT(sid) DO UPDATE SET "
            "fid=excluded.fid,j=excluded.j,evidence=excluded.evidence "
            "WHERE (excluded.fid, excluded.evidence) "
            "< (actions.fid, actions.evidence)",
            (sid, fact.fid, json.dumps(fact.to_json()), evidence_oid),
        )


def active(idx, sid):
    return idx.execute(
        "SELECT 1 FROM actions WHERE sid=?", (sid,)).fetchone() is not None


def summary(idx):
    rows = [list(row) for row in idx.execute(
        "SELECT sid, fid, evidence FROM actions ORDER BY sid")]
    return {
        "count": len(rows),
        "digest": h(canon(["action-set-v1", rows])),
    }


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
    return any(active(idx, sid) for sid in fact_scopes(fact))
