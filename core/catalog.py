"""Stable fact-blob catalog plus generic indexes and derived eligibility.

``facts(fid, blob)`` is the only stored fact representation. ``fact_index``
indexes every fact by type, reconciliation key, explicit reference, and
dependency-key offer; it never copies a fact body. ``proofs`` is the current
finite canonical DAG: a fact is publishable exactly when it has a proof row.
Winner changes replace proofs/edges; they never serialize, delete, or reinsert
a receipt.

Receipts enter with a row in ``staged``. Publication removes that marker only
after the composite-root CAS. Recovery retains uncommitted stages while
rebuilding derived standing from the current root, so a lost CAS never depends
on another process leaving the original ingress pile in place.
"""
from typing import NamedTuple

import facts

from .fact import decode, encode, from_json
from . import suppression_state
from .close import close
from .kernel import (
    Context,
    ResolvedEdge,
    accepts,
    extend_proofs,
    rebuild_proofs,
)

TYPE_INDEX = "fact.type"
KEY_INDEX = "fact.key"
REF_INDEX = "fact.ref"
INTERNAL_INDEXES = frozenset((TYPE_INDEX, KEY_INDEX, REF_INDEX))
INDEX_VERSION = "admission-catalog-v25"
FACTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(
    fid TEXT PRIMARY KEY, blob BLOB NOT NULL);
"""

SCHEMA = FACTS_SCHEMA + """
CREATE TABLE IF NOT EXISTS staged(
    fid TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS fact_index(
    kind TEXT, k0 TEXT, k1 TEXT, src TEXT,
    PRIMARY KEY(kind, k0, k1, src));
CREATE INDEX IF NOT EXISTS fact_index_by_src
    ON fact_index(src, kind, k0, k1);
DROP INDEX IF EXISTS fact_keys;
DROP INDEX IF EXISTS fact_boundaries;
CREATE TABLE IF NOT EXISTS proofs(fid TEXT PRIMARY KEY, rank INT NOT NULL);
CREATE TABLE IF NOT EXISTS edges(
    src TEXT NOT NULL, role TEXT NOT NULL, dst TEXT NOT NULL, kind TEXT NOT NULL,
    PRIMARY KEY(src, role));
"""


def _index_rows(fact):
    """The complete derived index contribution of one canonical fact."""
    if any(name in INTERNAL_INDEXES for name, _, _ in fact.offers()):
        raise ValueError("reserved fact index kind")
    return (
        (TYPE_INDEX, fact.t, "", fact.fid),
        (KEY_INDEX, fact.key, "", fact.fid),
        *((REF_INDEX, role, target, fact.fid)
          for role, target in fact.refs()),
        *((*offer, fact.fid) for offer in fact.offers()),
    )


def _reindex(db):
    """Replace generic rows with the exact contribution of every fact blob."""
    rows = db.execute(
        "SELECT fid, blob FROM facts ORDER BY fid").fetchall()
    db.execute("DELETE FROM fact_index")
    for fid, raw in rows:
        fact = decode(raw)
        if fact.fid != fid:
            raise ValueError("fact catalog integrity")
        db.executemany(
            "INSERT INTO fact_index VALUES(?,?,?,?)",
            _index_rows(fact),
        )


def upgrade_schema(db):
    """Preserve old local receipts while cutting over to canonical blobs."""
    columns = {
        row[1] for row in db.execute("PRAGMA table_info(facts)")
    }
    if not columns:
        return
    if "blob" in columns:
        # Derived rows must reach the running version before _sync_index can
        # republish and stamp it. This also removes early-v24 boundary markers
        # and closes a crash window where publication could look current while
        # key/reference routes were still old.
        has_meta = db.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='table' AND name='meta'").fetchone() is not None
        version = db.execute(
            "SELECT v FROM meta WHERE k='index-version'").fetchone() \
            if has_meta else None
        try:
            db.execute("BEGIN")
            if version != (INDEX_VERSION,):
                _reindex(db)
            db.execute("DROP TABLE IF EXISTS offers")
            db.execute("DROP TABLE IF EXISTS log")
            db.commit()
        except Exception:
            db.rollback()
            raise
        return
    if not {"fid", "j", "admitted"} <= columns:
        raise ValueError("unknown fact catalog schema")

    import json

    rows = db.execute(
        "SELECT fid, j, admitted FROM facts ORDER BY fid").fetchall()
    db.execute("BEGIN")
    try:
        db.execute("ALTER TABLE facts RENAME TO facts_legacy")
        db.execute(FACTS_SCHEMA)
        db.execute("DELETE FROM staged")
        db.execute("DELETE FROM fact_index")
        for fid, raw_json, admitted in rows:
            fact = from_json(json.loads(raw_json))
            if fact.fid != fid:
                raise ValueError("legacy fact catalog integrity")
            db.execute("INSERT INTO facts VALUES(?,?)", (fid, encode(fact)))
            if not admitted:
                db.execute("INSERT INTO staged VALUES(?)", (fid,))
            db.executemany(
                "INSERT INTO fact_index VALUES(?,?,?,?)",
                _index_rows(fact),
            )
        db.execute("DROP TABLE facts_legacy")
        if db.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name='offers'").fetchone():
            db.execute("DROP TABLE offers")
        db.execute("DROP TABLE IF EXISTS log")
        db.commit()
    except Exception:
        db.rollback()
        raise


class Eligibility(NamedTuple):
    """One settlement, consumed unchanged by publication."""

    received: tuple
    activated: tuple
    deactivated: tuple
    authority_changed: bool
    changed_sids: tuple


class Catalog:
    def __init__(self, db, anchor):
        self.db = db
        self.anchor = anchor

    def candidate(self, fid):
        row = self.db.execute(
            "SELECT blob FROM facts WHERE fid=?", (fid,)).fetchone()
        return decode(row[0]) if row else None

    def eligible(self, fid):
        row = self.db.execute(
            "SELECT f.blob FROM facts f JOIN proofs p ON p.fid=f.fid "
            "WHERE f.fid=?", (fid,)).fetchone()
        return decode(row[0]) if row else None

    def eligible_ids(self):
        return {
            fid for (fid,) in self.db.execute("SELECT fid FROM proofs")
        }

    def has_eligible(self):
        return self.db.execute(
            "SELECT 1 FROM proofs LIMIT 1").fetchone() is not None

    def indexed(
            self, kind, k0=None, k1=None, *,
            source_type=None, source_prefix=None):
        """Current facts at one generic index address, in canonical rank order.

        Type rows use ``kind=fact.type`` and key rows use ``kind=fact.key``.
        Reference rows use ``(fact.ref, role, target_fid)``. Every other row is
        copied mechanically from a fact's declared offers. Optional source
        filters intersect those rows with a family type or fid prefix before
        bodies are decoded.
        """
        clauses, args = ["i.kind=?"], [kind]
        if k0 is not None:
            clauses.append("i.k0=?")
            args.append(k0)
        if k1 is not None:
            clauses.append("i.k1=?")
            args.append(k1)
        if source_type is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM fact_index t "
                "WHERE t.src=i.src AND t.kind=? AND t.k0=? AND t.k1='')")
            args.extend((TYPE_INDEX, source_type))
        if source_prefix is not None:
            clauses.extend(("i.src>=?", "i.src<?"))
            args.extend((source_prefix, source_prefix + "\uffff"))
        rows = self.db.execute(
            "SELECT i.src, f.blob, p.rank "
            "FROM fact_index i "
            "JOIN proofs p ON p.fid=i.src "
            "JOIN facts f ON f.fid=i.src "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY p.rank, i.src",
            tuple(args),
        )
        seen, out = set(), []
        for fid, raw, rank in rows:
            if fid not in seen:
                fact = decode(raw)
                if fact.fid != fid:
                    raise ValueError("fact catalog integrity")
                seen.add(fid)
                out.append((rank, fact))
        return tuple(out)

    def by_type(self, tag):
        """Current facts of one type, selected through the generic index."""
        return self.indexed(TYPE_INDEX, tag)

    def staged_ids(self):
        return tuple(
            fid for (fid,) in self.db.execute(
                "SELECT fid FROM staged ORDER BY fid")
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
        """Store one durable receipt; return whether it still awaits publish."""
        raw = encode(fact)
        row = self.db.execute(
            "SELECT blob FROM facts WHERE fid=?", (fact.fid,)).fetchone()
        fresh = row is None
        if row is not None and row[0] != raw:
            raise ValueError("fact catalog conflict")
        self.db.execute("INSERT OR IGNORE INTO facts VALUES(?,?)",
                        (fact.fid, raw))
        if fresh:
            self.db.execute("INSERT INTO staged VALUES(?)", (fact.fid,))
        self.db.executemany(
            "INSERT OR IGNORE INTO fact_index VALUES(?,?,?,?)",
            _index_rows(fact),
        )
        return self.db.execute(
            "SELECT 1 FROM staged WHERE fid=?",
            (fact.fid,),
        ).fetchone() is not None

    def reindex(self):
        """Rebuild the exact generic index from every retained fact blob."""
        _reindex(self.db)

    def commit_stage(self, fids):
        self.db.executemany(
            "DELETE FROM staged WHERE fid=?",
            ((fid,) for fid in fids),
        )

    def shadows(self, fids):
        """Whether these receipts can change a canonical offer winner."""
        for fid in fids:
            fact = self.candidate(fid)
            if fact is None:
                continue
            for name, a0, a1 in fact.offers():
                if self.db.execute(
                        "SELECT COUNT(*) FROM fact_index "
                        "WHERE kind=? AND k0=?",
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
                suppression_state.blocks(
                    self.db, sid, fact.key, self.candidate)
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

    def settle(
            self, received, *, force=False, actions_dirty=False,
            allowed_staged=None):
        """Settle once and return the exact eligibility delta."""
        received = tuple(dict.fromkeys(received))
        received_set = set(received)
        shadows = self.shadows(received) if received else False
        rebuild = force or shadows or not received
        rebuild_fids = None
        if allowed_staged is not None:
            allowed_staged = set(allowed_staged)
            # A failed pile leaves its receipts staged for an exact retry.
            # Another pile must not accidentally publish them when its own
            # change triggers a full canonical rebuild.
            disallowed_staged = any(
                fid not in allowed_staged
                for (fid,) in self.db.execute("SELECT fid FROM staged"))
            rebuild = rebuild or disallowed_staged
            rebuild_fids = tuple(
                fid for fid, staged in self.db.execute(
                    "SELECT f.fid, s.fid IS NOT NULL "
                    "FROM facts f LEFT JOIN staged s ON s.fid=f.fid")
                if not staged or fid in allowed_staged
            )
        action_before = suppression_state.snapshot(self.db) \
            if rebuild or actions_dirty else None
        before = self.eligible_ids() - received_set \
            if rebuild or actions_dirty else None

        def rebuild_all():
            return rebuild_proofs(
                self.db, self.candidate, self.anchor, self._accept,
                rebuild_fids)

        if rebuild:
            rebuild_all()
        else:
            unresolved = extend_proofs(
                self.db, received, self.candidate,
                self.anchor, self._accept)
            if unresolved:
                action_before = suppression_state.snapshot(self.db)
                before = self.eligible_ids() - received_set
                rebuild_all()
                rebuild = True
            elif not actions_dirty:
                return Eligibility(
                    tuple(sorted(received)),
                    self._proof_order(received),
                    (),
                    False,
                    (),
                )

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
                rebuild_all()

        after = self.eligible_ids()
        deactivated = before - after
        activated = after - before
        changed_sids = suppression_state.changed(
            action_before, suppression_state.snapshot(self.db))
        return Eligibility(
            tuple(sorted(received)),
            self._proof_order(activated),
            tuple(sorted(deactivated)),
            shadows or bool(
                deactivated or (activated - received_set)),
            tuple(sorted(changed_sids)),
        )
