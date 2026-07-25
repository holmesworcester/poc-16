"""Content fact-family table of contents."""
from . import file, message

MODULES = (message, file)

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS message_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, chan TEXT, pk TEXT, text TEXT, ts INT,
    PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS file_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, chan TEXT, name TEXT, size INT,
    blob TEXT, pk TEXT, ts INT, PRIMARY KEY(ws, src));
CREATE VIEW IF NOT EXISTS messages AS
    SELECT src AS fid, ws, chan, pk, text, ts, src FROM message_rows;
CREATE VIEW IF NOT EXISTS files AS
    SELECT src AS fid, ws, chan, name, size, blob, pk, ts, src FROM file_rows;
"""
