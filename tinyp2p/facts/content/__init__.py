"""Content fact-family table of contents."""
from . import file, message

MODULES = (message, file)

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages(fid TEXT PRIMARY KEY, ws TEXT, chan TEXT,
                                    pk TEXT, text TEXT, ts INT);
CREATE TABLE IF NOT EXISTS files(fid TEXT PRIMARY KEY, ws TEXT, chan TEXT,
                                 name TEXT, size INT, blob TEXT, pk TEXT, ts INT);
"""
