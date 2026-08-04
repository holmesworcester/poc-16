"""Disposable full-peer fact/index projection with per-writer checkpoints.

Core validates complete signed piles and owns accepted writer slots.  This
sole SQL boundary atomically joins the resulting canonical facts and advances
one projection checkpoint.  Deleting the file loses no protocol state: core
replays each accepted writer tree from its durable slot.
"""

import os
import sqlite3

import facts

from core.fact import bound_to, decode
from core.fact_index import (
    ACTION_INDEX,
    SCOPE_INDEX,
    TYPE_INDEX,
    index_rows,
)
from core.shape import valid_fid

SCHEMA_VERSION = 2

SCHEMA = """
PRAGMA user_version=2;
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
CREATE TABLE IF NOT EXISTS projected_heads(
    device TEXT PRIMARY KEY,
    head_oid TEXT NOT NULL);
"""


_COLUMNS = {
    "facts": ("fid", "blob"),
    "fact_index": ("kind", "k0", "k1", "src"),
    "projected_heads": ("device", "head_oid"),
}


def _tables(db):
    return {
        name for (name,) in db.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    }


def _index_filter(kind, k0, k1, source_type, source_prefix=None):
    clauses, args = ["i.kind=?"], [kind]
    for column, value in (("i.k0", k0), ("i.k1", k1)):
        if value is not None:
            clauses.append(column + "=?")
            args.append(value)
    if source_type is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM fact_index t "
            "WHERE t.src=i.src AND t.kind=? AND t.k0=? AND t.k1='')")
        args.extend((TYPE_INDEX, source_type))
    if source_prefix is not None:
        clauses.extend(("i.src>=?", "i.src<?"))
        args.extend((source_prefix, source_prefix + "\uffff"))
    return " AND ".join(clauses), args


def _current_schema(db):
    return db.execute("PRAGMA user_version").fetchone()[0] \
        == SCHEMA_VERSION and _tables(db) == set(_COLUMNS) and all(
            tuple(
                row[1] for row in db.execute(
                    f"PRAGMA table_info({table})")
            ) == columns
            for table, columns in _COLUMNS.items()
        )


class SqlStore:
    """Query and rebuild one workspace's subordinate local SQL state.

    A ``FullPeer`` owns each connection and serializes every production use
    with its one reentrant lock. ``check_same_thread=False`` permits that
    ownership to move between daemon threads; it does not permit concurrent
    entry into a connection.
    """

    @classmethod
    def open(cls, path, anchor):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        db = sqlite3.connect(path, check_same_thread=False)
        tables = _tables(db)
        if tables and not _current_schema(db):
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

    def fact_of(self, fid):
        row = self.db.execute(
            "SELECT blob FROM facts WHERE fid=?", (fid,)).fetchone()
        return self._fact(row, fid)

    def fact_bytes(self, fid):
        row = self.db.execute(
            "SELECT blob FROM facts WHERE fid=?", (fid,)).fetchone()
        return None if row is None else bytes(row[0])

    def offers_from(self, source, name):
        return self.db.execute(
            "SELECT k0, k1 FROM fact_index WHERE src=? AND kind=? "
            "ORDER BY k0, k1", (source, name),
        ).fetchall()

    def resolve_offer(self, name, a0, a1=None, source=None):
        row = self.db.execute(
            "SELECT src FROM fact_index WHERE kind=? AND k0=? "
            "AND (? IS NULL OR k1=?) AND (? IS NULL OR src=?) "
            "ORDER BY src LIMIT 1",
            (name, a0, a1, a1, source, source),
        ).fetchone()
        return None if row is None else row[0]

    def fact_ids(self):
        return {
            fid for (fid,) in self.db.execute("SELECT fid FROM facts")
        }

    def indexed(
            self, kind, k0=None, k1=None, *,
            source_type=None, source_prefix=None):
        """Return validated facts at one generic address in fid order."""
        where, args = _index_filter(
            kind, k0, k1, source_type, source_prefix)
        rows = self.db.execute(
            "SELECT i.src, f.blob FROM fact_index i "
            "JOIN facts f ON f.fid=i.src "
            f"WHERE {where} ORDER BY i.src",
            args,
        )
        seen, out = set(), []
        for fid, raw in rows:
            if fid in seen:
                continue
            seen.add(fid)
            out.append(self._fact((raw,), fid))
        return tuple(out)

    def count_indexed(
            self, kind, k0=None, k1=None, *, source_type=None):
        """Count distinct facts at one generic address without loading bodies."""
        where, args = _index_filter(kind, k0, k1, source_type)
        return self.db.execute(
            "SELECT COUNT(DISTINCT i.src) FROM fact_index i "
            f"WHERE {where}", args,
        ).fetchone()[0]

    def postings(
            self, kind, k0=None, k1=None, *, source_type=None):
        """Return only generic index values and fact IDs, never fact blobs."""
        where, args = _index_filter(kind, k0, k1, source_type)
        return tuple(self.db.execute(
            "SELECT i.k1, i.src FROM fact_index i "
            f"WHERE {where} ORDER BY i.k1, i.src",
            args,
        ))

    def active(self, sid):
        return self.db.execute(
            "SELECT 1 FROM fact_index "
            "WHERE kind=? AND k0=? LIMIT 1",
            (ACTION_INDEX, sid),
        ).fetchone() is not None

    def suppresses(self, fact):
        return any(self.active(sid) for sid in facts.current_scopes(fact))

    # The access gate consumes this small Worker-like capability.  It keeps
    # family authorization independent of SQL while letting a full peer use
    # the same query as a database-free authenticated authority view.
    def fact_known(self, fid):
        return self.fact_bytes(fid) is not None

    def fact_active(self, fid):
        fact = self.fact_of(fid)
        return fact is not None and not self.suppresses(fact)

    def suppression_known(self, sid):
        return self.db.execute(
            "SELECT 1 FROM fact_index WHERE "
            "(kind=? OR kind=?) AND k0=? LIMIT 1",
            (SCOPE_INDEX, ACTION_INDEX, sid),
        ).fetchone() is not None

    def principal_active(self, namespace, public_key):
        return not self.active(facts.principal_sid(
            namespace, public_key))

    def projected_head(self, device):
        if not valid_fid(device):
            raise ValueError("projection device")
        row = self.db.execute(
            "SELECT head_oid FROM projected_heads WHERE device=?",
            (device,),
        ).fetchone()
        return None if row is None else row[0]

    def commit(self, batch, *, device, head):
        """Atomically join one core-validated suffix and its checkpoint."""
        from core.writer_repository import ValidatedBatch

        if not isinstance(batch, ValidatedBatch) \
                or not valid_fid(device) or not valid_fid(head):
            raise ValueError("projection commit")
        additions, candidates = [], {}
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for fid, raw in batch.facts:
                fact = self._fact((raw,), fid)
                family = facts.family_for(fact.t)
                if family is None or not family.DURABLE:
                    raise ValueError("projection durable fact")
                incumbent = self.fact_bytes(fid)
                if incumbent is not None and incumbent != raw:
                    raise ValueError("fact projection conflict")
                if incumbent is None:
                    self.db.execute(
                        "INSERT INTO facts VALUES(?,?)",
                        (fid, raw),
                    )
                    self.db.executemany(
                        "INSERT INTO fact_index VALUES(?,?,?,?)",
                        index_rows(fact),
                    )
                    additions.append(fid)
                    for sid in facts.action_sids(fact):
                        candidate = (fact.key, fact.fid)
                        candidates[sid] = min(
                            candidates.get(sid, candidate), candidate)

            for sid, candidate in sorted(candidates.items()):
                row = self.db.execute(
                    "SELECT src FROM fact_index "
                    "WHERE kind=? AND k0=? AND k1=''",
                    (ACTION_INDEX, sid),
                ).fetchone()
                if row is not None:
                    incumbent = self.fact_of(row[0])
                    candidate = min(
                        candidate, (incumbent.key, incumbent.fid))
                self.db.execute(
                    "DELETE FROM fact_index "
                    "WHERE kind=? AND k0=? AND k1=''",
                    (ACTION_INDEX, sid),
                )
                self.db.execute(
                    "INSERT INTO fact_index VALUES(?,?,?,?)",
                    (ACTION_INDEX, sid, "", candidate[1]),
                )
            self.db.execute(
                "INSERT OR REPLACE INTO projected_heads VALUES(?,?)",
                (device, head),
            )
            self.db.commit()
            return tuple(additions)
        except Exception:
            self.db.rollback()
            raise

    def reset(self):
        """Discard only rebuildable projection rows."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for table in ("projected_heads", "fact_index", "facts"):
                self.db.execute(f"DELETE FROM {table}")
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise


class LockedProjection:
    """Serialize FactConsumer's synchronous SQL capability.

    Repository mirroring awaits object-store reads between projection calls.
    Lock only these four immediate calls so one FullPeer connection is never
    entered concurrently and no lock is held across network I/O.
    """

    def __init__(self, projection, lock):
        self.projection = projection
        self.lock = lock

    def fact_bytes(self, fid):
        with self.lock:
            return self.projection.fact_bytes(fid)

    def fact_ids(self):
        with self.lock:
            return self.projection.fact_ids()

    def projected_head(self, device):
        with self.lock:
            return self.projection.projected_head(device)

    def commit(self, batch, *, device, head):
        with self.lock:
            return self.projection.commit(
                batch, device=device, head=head)


__all__ = ("LockedProjection", "SCHEMA", "SCHEMA_VERSION", "SqlStore")
