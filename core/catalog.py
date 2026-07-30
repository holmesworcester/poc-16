"""Disposable SQLite projection for full-node queries and local authorship.

The repository root and its reachable immutable objects are authoritative.
This module deliberately contains no admission, settlement, publication, CAS,
or retirement logic.  A client may delete this database and rebuild it from a
``RepositoryReader`` without changing repository state.

Facts are stored once as their canonical wire bytes.  ``fact_index`` indexes
type, reconciliation key, every explicit reference, and every family offer.
Eligibility, resolved edges, and active suppression actions are ordinary typed
rows in the same index.  There is no second family-specific schema.
"""

import facts

from .fact import bound_to, decode
from .fact_index import (
    ACTION_INDEX,
    EDGE_INDEX,
    INTERNAL_INDEXES,
    KEY_INDEX,
    REF_INDEX,
    STATE_INDEX,
    TYPE_INDEX,
    index_rows,
)
from .kernel import ResolvedEdge
from .shape import valid_fid

INDEX_VERSION = "client-projection-v2-combined-index"

SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(
    fid TEXT PRIMARY KEY,
    blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS fact_index(
    kind TEXT NOT NULL,
    k0 TEXT NOT NULL,
    k1 TEXT NOT NULL,
    src TEXT NOT NULL,
    PRIMARY KEY(kind, k0, k1, src));
CREATE INDEX IF NOT EXISTS fact_index_by_src
    ON fact_index(src, kind, k0, k1);
"""

_OBSOLETE_AUTHORITY_TABLES = (
    "action_proposals",
    "action_targets",
    "actions",
    "admission_receipts",
    "edges",
    "proofs",
    "supp",
    "staged",
    "offers",
    "log",
)


def upgrade_schema(db, anchor):
    """Make an old local database an empty current projection.

    This is an intentional format cut, not an authority migration.  Legacy
    rows without root-reachable admission proofs are never inferred into the
    repository.  When the fact-table shape differs, all projection tables are
    discarded and the normal root refresh repopulates them.
    """
    if not valid_fid(anchor):
        raise ValueError("projection workspace")
    changed = False
    columns = {
        row[1] for row in db.execute("PRAGMA table_info(facts)")
    }
    if columns and columns != {"fid", "blob"}:
        changed = True
        for table in ("fact_index", "facts"):
            db.execute(f"DROP TABLE IF EXISTS {table}")
        db.executescript(SCHEMA)
    for table in _OBSOLETE_AUTHORITY_TABLES:
        if db.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name=?", (table,)).fetchone():
            changed = True
            db.execute(f"DROP TABLE {table}")
    db.execute("DROP INDEX IF EXISTS fact_keys")
    db.execute("DROP INDEX IF EXISTS fact_boundaries")
    if changed and db.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='table' AND name='meta'").fetchone():
        db.execute(
            "DELETE FROM meta WHERE k IN "
            "('root','root-bytes','publish-base','tree-rebuild',"
            "'index-version')")
    db.commit()


class Catalog:
    """Read-only query facade over one disposable projection."""

    def __init__(self, db, anchor):
        if not valid_fid(anchor):
            raise ValueError("projection workspace")
        self.db = db
        self.anchor = anchor

    def _fact(self, row, fid):
        if row is None:
            return None
        fact = decode(row[0])
        if fact.fid != fid or not bound_to(fact, self.anchor) \
                or fact.ws is None and not facts.is_genesis(fact.t):
            raise ValueError("fact projection integrity")
        return fact

    def candidate(self, fid):
        row = self.db.execute(
            "SELECT blob FROM facts WHERE fid=?", (fid,)).fetchone()
        return self._fact(row, fid)

    def eligible(self, fid):
        row = self.db.execute(
            "SELECT f.blob FROM facts f "
            "JOIN fact_index s ON s.src=f.fid "
            "AND s.kind=? AND s.k0='eligible' "
            "WHERE f.fid=?",
            (STATE_INDEX, fid),
        ).fetchone()
        return self._fact(row, fid)

    def eligible_ids(self):
        return {
            fid for (fid,) in self.db.execute(
                "SELECT src FROM fact_index "
                "WHERE kind=? AND k0='eligible'",
                (STATE_INDEX,),
            )
        }

    def has_eligible(self):
        return self.db.execute(
            "SELECT 1 FROM fact_index "
            "WHERE kind=? AND k0='eligible' LIMIT 1",
            (STATE_INDEX,),
        ).fetchone() is not None

    def edges(self, fid):
        out = []
        for typed_role, target in self.db.execute(
                "SELECT k0, k1 FROM fact_index "
                "WHERE src=? AND kind=? ORDER BY k0",
                (fid, EDGE_INDEX)):
            kind, separator, role = typed_role.partition(":")
            if separator != ":" or kind not in {"need", "ref"} or not role:
                raise ValueError("fact projection edge")
            out.append(ResolvedEdge(role, target, kind))
        return tuple(sorted(out, key=lambda edge: edge.role))

    def indexed(
            self, kind, k0=None, k1=None, *,
            source_type=None, source_prefix=None):
        """Return current facts at one generic address in proof order."""
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
            "SELECT i.src, f.blob, CAST(s.k1 AS INTEGER) "
            "FROM fact_index i "
            "JOIN fact_index s ON s.src=i.src "
            "AND s.kind=? AND s.k0='eligible' "
            "JOIN facts f ON f.fid=i.src "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY CAST(s.k1 AS INTEGER), i.src",
            (STATE_INDEX, *args),
        )
        seen, out = set(), []
        for fid, raw, rank in rows:
            if fid in seen:
                continue
            fact = self._fact((raw,), fid)
            seen.add(fid)
            out.append((rank, fact))
        return tuple(out)

    def by_type(self, tag):
        return self.indexed(TYPE_INDEX, tag)


__all__ = (
    "Catalog",
    "ACTION_INDEX",
    "EDGE_INDEX",
    "INDEX_VERSION",
    "INTERNAL_INDEXES",
    "KEY_INDEX",
    "REF_INDEX",
    "STATE_INDEX",
    "SCHEMA",
    "TYPE_INDEX",
    "index_rows",
    "upgrade_schema",
)
