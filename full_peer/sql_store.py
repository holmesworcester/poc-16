"""The full peer's disposable SQLite fact projection.

This module is the sole SQL boundary.  It stores canonical validated fact
bytes, one generic mechanical index, and a pinned-root cache stamp.  It is
never an input to closed-pile validation, repository compilation, root CAS,
or hosted reads; deleting it only makes the full peer rebuild local query
state from :class:`core.repository_reader.RepositoryReader`.
"""

import os
import sqlite3

import facts

from core.crypto import h
from core.fact import bound_to, decode, encode
from core.fact_index import ACTION_INDEX, TYPE_INDEX, index_rows
from core.repository_snapshot import action_bindings
from core.shape import valid_fid

SCHEMA_VERSION = 1

SCHEMA = """
PRAGMA user_version=1;
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
CREATE TABLE IF NOT EXISTS meta(
    k TEXT PRIMARY KEY,
    v BLOB);
"""


_COLUMNS = {
    "facts": ("fid", "blob"),
    "fact_index": ("kind", "k0", "k1", "src"),
    "meta": ("k", "v"),
}


def _tables(db):
    return {
        name for (name,) in db.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    }


def _compatible(db):
    return db.execute("PRAGMA user_version").fetchone()[0] \
        == SCHEMA_VERSION and _tables(db) == set(_COLUMNS) and all(
            tuple(
                row[1] for row in db.execute(
                    f"PRAGMA table_info({table})")
            ) == columns
            for table, columns in _COLUMNS.items()
        )


class SqlStore:
    """Query and rebuild one workspace's subordinate local SQL state."""

    @classmethod
    def open(cls, path, anchor):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        db = sqlite3.connect(path, check_same_thread=False)
        tables = _tables(db)
        if tables and not _compatible(db):
            db.close()
            for exact in (path, path + "-wal", path + "-shm"):
                try:
                    os.unlink(exact)
                except FileNotFoundError:
                    pass
            db = sqlite3.connect(path, check_same_thread=False)
        db.executescript(SCHEMA)
        return cls(db, anchor)

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

    def active(self, sid):
        return self.db.execute(
            "SELECT 1 FROM fact_index "
            "WHERE kind=? AND k0=? LIMIT 1",
            (ACTION_INDEX, sid),
        ).fetchone() is not None

    def suppresses(self, fact):
        return any(self.active(sid) for sid in facts.current_scopes(fact))

    def current_for(self, reader):
        root_digest = None if reader is None else reader.etag
        stamped = self.db.execute(
            "SELECT v FROM meta WHERE k='root'").fetchone()
        return stamped == (root_digest,)

    def refresh(self, reader):
        """Replace all rows from one pinned authenticated repository."""
        if reader is None:
            validated, root_bytes = None, None
        elif reader.workspace != self.anchor:
            raise ValueError("projection workspace")
        else:
            validated = reader.all_facts()
            root_bytes = reader.root_bytes
        self.db.execute("BEGIN")
        try:
            for table in ("fact_index", "facts"):
                self.db.execute(f"DELETE FROM {table}")
            if validated is not None:
                for fid in sorted(validated.facts):
                    fact = validated.facts[fid]
                    self.db.execute(
                        "INSERT INTO facts VALUES(?,?)",
                        (fid, encode(fact)),
                    )
                    self.db.executemany(
                        "INSERT INTO fact_index VALUES(?,?,?,?)",
                        index_rows(fact),
                    )
                self.db.executemany(
                    "INSERT INTO fact_index VALUES(?,?,?,?)",
                    (
                        (ACTION_INDEX, sid, "", fid)
                        for sid, fid in sorted(
                            action_bindings(validated.facts).items())
                    ),
                )
            self.db.execute("DELETE FROM meta")
            self.db.execute(
                "INSERT OR REPLACE INTO meta VALUES('root',?)",
                (h(root_bytes) if root_bytes is not None else None,),
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise


__all__ = ("SCHEMA", "SCHEMA_VERSION", "SqlStore")
