"""Content fact-family table of contents."""
from . import chunk, file, message

MODULES = (message, file, chunk)

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages(fid TEXT PRIMARY KEY, ws TEXT, chan TEXT,
                                    pk TEXT, text TEXT, ts INT);
CREATE TABLE IF NOT EXISTS files(fid TEXT PRIMARY KEY, ws TEXT, chan TEXT,
                                 name TEXT, size INT, root TEXT, width INT,
                                 n INT, pk TEXT, ts INT);

-- expected: one row per admitted chunk fact, keyed by that fact
CREATE TABLE IF NOT EXISTS file_slices(src TEXT PRIMARY KEY, ws TEXT, root TEXT,
                                       idx INT, cid TEXT, ts INT);
-- verified-present: written only once the bytes arrive and prove themselves
CREATE TABLE IF NOT EXISTS file_chunks(src TEXT PRIMARY KEY, ws TEXT, root TEXT,
                                       idx INT, cid TEXT, ts INT);

CREATE INDEX IF NOT EXISTS file_slices_root ON file_slices(ws, root, idx);
CREATE INDEX IF NOT EXISTS file_chunks_root ON file_chunks(ws, root, idx);

-- progress is an aggregate, so it is a view: never a stored counter
CREATE VIEW IF NOT EXISTS file_progress AS
  SELECT f.ws AS ws, f.fid AS fid, f.chan AS chan, f.name AS name,
         f.size AS size, f.root AS root, f.n AS total, f.ts AS ts,
         (SELECT COUNT(DISTINCT c.idx) FROM file_chunks c
           WHERE c.ws = f.ws AND c.root = f.root) AS have
    FROM files f;
"""


def clear(db, workspace):
    """Clear this scope's derived rows before a canonical reprojection."""
    for table in ("messages", "files", "file_slices", "file_chunks"):
        db.execute(f"DELETE FROM {table} WHERE ws=?", (workspace,))
