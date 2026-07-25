"""Content fact-family table of contents."""
from . import file, message

MODULES = (message, file)

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages(fid TEXT PRIMARY KEY, ws TEXT, chan TEXT,
                                    pk TEXT, text TEXT, ts INT);
CREATE TABLE IF NOT EXISTS files(fid TEXT PRIMARY KEY, ws TEXT, chan TEXT,
                                 name TEXT, size INT, blob TEXT, pk TEXT, ts INT);
"""


def clear(db, workspace):
    """Clear this scope's derived rows before a canonical reprojection."""
    db.execute("DELETE FROM messages WHERE ws=?", (workspace,))
    db.execute("DELETE FROM files WHERE ws=?", (workspace,))
