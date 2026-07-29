"""Stable client admission catalog and derived canonical eligibility.

``facts`` and ``offers`` are immutable local receipts. ``proofs`` is the
current finite canonical DAG: a fact is publishable exactly when it has a
proof row. Winner changes replace proofs/edges; they never serialize, delete,
or reinsert a receipt.

Receipts enter as staged (``admitted=0``). Publication marks them admitted
only after the composite-root CAS. Recovery discards an uncommitted stage and
replays the still-live pile, while a post-CAS crash recovers from the new root.
"""
import json
from typing import NamedTuple

import facts

from .fact import from_json
from . import suppression_state
from .close import close
from .kernel import (
    Context,
    ResolvedEdge,
    accepts,
    extend_proofs,
    rebuild_proofs,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(
    fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT,
    admitted INT NOT NULL CHECK(admitted IN (0,1)));
CREATE TABLE IF NOT EXISTS offers(
    name TEXT, a0 TEXT, a1 TEXT, src TEXT,
    PRIMARY KEY(name, a0, a1, src));
CREATE INDEX IF NOT EXISTS offers_by_src ON offers(src, name, a0, a1);
CREATE TABLE IF NOT EXISTS proofs(fid TEXT PRIMARY KEY, rank INT NOT NULL);
CREATE TABLE IF NOT EXISTS edges(
    src TEXT NOT NULL, role TEXT NOT NULL, dst TEXT NOT NULL, kind TEXT NOT NULL,
    PRIMARY KEY(src, role));
"""


class Eligibility(NamedTuple):
    """One settlement, consumed unchanged by publication and projection."""

    received: tuple
    activated: tuple
    deactivated: tuple
    authority_changed: bool


class Catalog:
    def __init__(self, db, anchor):
        self.db = db
        self.anchor = anchor
        self.action_changes = frozenset()

    def candidate(self, fid):
        row = self.db.execute(
            "SELECT j FROM facts WHERE fid=?", (fid,)).fetchone()
        return from_json(json.loads(row[0])) if row else None

    def eligible(self, fid):
        row = self.db.execute(
            "SELECT f.j FROM facts f JOIN proofs p ON p.fid=f.fid "
            "WHERE f.fid=?", (fid,)).fetchone()
        return from_json(json.loads(row[0])) if row else None

    def eligible_ids(self):
        return {
            fid for (fid,) in self.db.execute("SELECT fid FROM proofs")
        }

    def has_eligible(self):
        return self.db.execute(
            "SELECT 1 FROM proofs LIMIT 1").fetchone() is not None

    def staged_ids(self):
        return tuple(
            fid for (fid,) in self.db.execute(
                "SELECT fid FROM facts WHERE admitted=0 ORDER BY fid")
        )

    def edges(self, fid):
        return tuple(
            ResolvedEdge(role, target, kind)
            for role, target, kind in self.db.execute(
                "SELECT role, dst, kind FROM edges "
                "WHERE src=? ORDER BY role",
                (fid,))
        )

    def stage(self, fact):
        """Store one kernel-minted durable receipt once; return whether new."""
        fresh = self.db.execute(
            "SELECT 1 FROM facts WHERE fid=?", (fact.fid,)).fetchone() is None
        self.db.execute(
            "INSERT OR IGNORE INTO facts VALUES(?,?,?,?,0)",
            (fact.fid, fact.ts, fact.t, json.dumps(fact.to_json())))
        self.db.executemany(
            "INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
            ((*offer, fact.fid) for offer in fact.offers()),
        )
        return fresh

    def commit_stage(self, fids):
        self.db.executemany(
            "UPDATE facts SET admitted=1 WHERE fid=?",
            ((fid,) for fid in fids),
        )

    def discard_stage(self):
        staged = [
            fid for (fid,) in self.db.execute(
                "SELECT fid FROM facts WHERE admitted=0")
        ]
        self.db.executemany(
            "DELETE FROM offers WHERE src=?", ((fid,) for fid in staged))
        self.db.executemany(
            "DELETE FROM facts WHERE fid=?", ((fid,) for fid in staged))
        return tuple(staged)

    def shadows(self, fids):
        """Whether these receipts can change a canonical offer winner."""
        for fid in fids:
            fact = self.candidate(fid)
            if fact is None:
                continue
            for name, a0, a1 in fact.offers():
                if self.db.execute(
                        "SELECT COUNT(*) FROM offers "
                        "WHERE name=? AND a0=?",
                        (name, a0)).fetchone()[0] > 1:
                    return True
        return False

    def _authorization_scopes(self, fact, edges=None):
        edges = edges or self.edges(fact.fid)
        direct = {edge.role: edge.fid for edge in edges}
        def edges_of(fid):
            if fid == fact.fid:
                return direct
            return {edge.role: edge.fid for edge in self.edges(fid)}
        return facts.authorization_scopes(
            fact, edges, edges_of, self.candidate)

    def _accept(self, fact, edges):
        """Canonical family validity plus deterministic action-time guards."""
        context = Context(self.db, self.anchor)
        if not accepts(fact, edges, context):
            return False
        try:
            return not any(
                suppression_state.blocks(self.db, sid, fact.key)
                for sid in self._authorization_scopes(fact, edges)
            )
        except (KeyError, TypeError, ValueError):
            return False

    def _proof_order(self, fids):
        selected = {
            fid for fid in fids if self.eligible(fid) is not None
        }
        if not selected:
            return ()
        ordered = close(
            (self.eligible(fid) for fid in selected),
            lambda fid: tuple(edge.fid for edge in self.edges(fid)),
            self.eligible,
        )
        return tuple(fact.fid for fact in ordered if fact.fid in selected)

    def settle(self, received, *, force=False, actions_dirty=False):
        """Settle once and return the exact eligibility delta."""
        self.action_changes = frozenset()
        received = tuple(dict.fromkeys(received))
        received_set = set(received)
        shadows = self.shadows(received) if received else False
        rebuild = force or shadows or not received
        before = self.eligible_ids() - received_set \
            if rebuild or actions_dirty else None
        if rebuild:
            rebuild_proofs(
                self.db, self.candidate, self.anchor, self._accept)
        else:
            unresolved = extend_proofs(
                self.db, received, self.candidate,
                self.anchor, self._accept)
            if unresolved:
                before = self.eligible_ids() - received_set
                rebuild_proofs(
                    self.db, self.candidate, self.anchor, self._accept)
                rebuild = True
            elif not actions_dirty:
                return Eligibility(
                    tuple(sorted(received)),
                    self._proof_order(received),
                    (),
                    False,
                )

        changed_actions = set()
        if rebuild or actions_dirty:
            seen = set()
            while True:
                state = tuple(self.db.execute(
                    "SELECT sid, fid, evidence FROM actions ORDER BY sid"))
                if state in seen:
                    raise ValueError("action settlement cycle")
                seen.add(state)
                changed = suppression_state.settle(
                    self.db, self.eligible, self._authorization_scopes)
                if not changed:
                    break
                changed_actions.update(changed)
                rebuild_proofs(
                    self.db, self.candidate, self.anchor, self._accept)

        after = self.eligible_ids()
        deactivated = before - after
        activated = after - before
        self.action_changes = frozenset(changed_actions)
        return Eligibility(
            tuple(sorted(received)),
            self._proof_order(activated),
            tuple(sorted(deactivated)),
            shadows or bool(changed_actions) or bool(
                deactivated or (activated - received_set)),
        )
