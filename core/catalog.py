"""Disposable SQLite query facade over validated canonical fact bytes.

SQLite is never a validation or publication authority.  It contains one fact
table, the generic type/key/ref/offer index, and current suppression-action
rows copied from the authenticated repository.  Deleting it changes nothing
about the validated set.
"""

import facts

from .fact import bound_to, decode
from .fact_index import (
    ACTION_INDEX,
    INTERNAL_INDEXES,
    KEY_INDEX,
    REF_INDEX,
    SCOPE_INDEX,
    TYPE_INDEX,
    index_rows,
)
from .shape import valid_fid

INDEX_VERSION = "full-peer-projection-v3-validated-facts"

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
    """Drop obsolete authority caches and reset incompatible projections."""
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
    """Read-only query facade over one disposable validated-fact projection."""

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

    def fact(self, fid):
        row = self.db.execute(
            "SELECT blob FROM facts WHERE fid=?", (fid,)).fetchone()
        return self._fact(row, fid)

    def fact_ids(self):
        return {
            fid for (fid,) in self.db.execute("SELECT fid FROM facts")
        }

    def has_facts(self):
        return self.db.execute(
            "SELECT 1 FROM facts LIMIT 1").fetchone() is not None

    def indexed(
            self, kind, k0=None, k1=None, *,
            source_type=None, source_prefix=None):
        """Return validated facts at one generic address in fid order."""
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
            "SELECT i.src, f.blob FROM fact_index i "
            "JOIN facts f ON f.fid=i.src "
            f"WHERE {' AND '.join(clauses)} ORDER BY i.src",
            args,
        )
        seen, out = set(), []
        for fid, raw in rows:
            if fid in seen:
                continue
            seen.add(fid)
            out.append(self._fact((raw,), fid))
        return tuple(out)

    def by_type(self, tag):
        return self.indexed(TYPE_INDEX, tag)


__all__ = (
    "Catalog",
    "ACTION_INDEX",
    "INDEX_VERSION",
    "INTERNAL_INDEXES",
    "KEY_INDEX",
    "REF_INDEX",
    "SCHEMA",
    "SCOPE_INDEX",
    "TYPE_INDEX",
    "index_rows",
    "upgrade_schema",
)
