"""Content fact-family table of contents."""
from . import chunk, delete, file, legacy_file, message

MODULES = (message, legacy_file, file, chunk, delete)

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS message_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, chan TEXT, pk TEXT, text TEXT, ts INT,
    PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS file_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, chan TEXT, name TEXT, size INT,
    root TEXT, width INT, n INT, pk TEXT, ts INT, PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS legacy_file_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, chan TEXT, name TEXT, size INT,
    blob TEXT, pk TEXT, ts INT, PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS legacy_file_arrival_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, blob TEXT, ts INT,
    PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS file_slice_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, root TEXT, idx INT, cid TEXT, ts INT,
    PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS file_chunk_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, root TEXT, idx INT, cid TEXT, ts INT,
    PRIMARY KEY(ws, src));
CREATE INDEX IF NOT EXISTS file_slices_by_root
    ON file_slice_rows(ws, root, idx);
CREATE INDEX IF NOT EXISTS file_chunks_by_root
    ON file_chunk_rows(ws, root, idx);
CREATE VIEW IF NOT EXISTS messages AS
    SELECT src AS fid, ws, chan, pk, text, ts, src FROM message_rows;
CREATE VIEW IF NOT EXISTS files AS
    SELECT src AS fid, ws, chan, name, size, root, width, n, pk, ts, src,
           NULL AS blob, 'bao-v1' AS encoding
    FROM file_rows
    UNION ALL
    SELECT src AS fid, ws, chan, name, size, NULL, NULL, 1, pk, ts, src,
           blob, 'blob-v1'
    FROM legacy_file_rows;
CREATE VIEW IF NOT EXISTS file_progress AS
    SELECT f.ws, f.src AS fid, f.chan, f.name, f.size, f.root,
           f.n AS total, f.ts, NULL AS blob, 'bao-v1' AS encoding,
           (SELECT COUNT(DISTINCT c.idx) FROM file_chunk_rows c
            WHERE (c.ws, c.root) = (f.ws, f.root)) AS have
    FROM file_rows f
    UNION ALL
    SELECT f.ws, f.src, f.chan, f.name, f.size, NULL, 1, f.ts,
           f.blob, 'blob-v1',
           EXISTS(SELECT 1 FROM legacy_file_arrival_rows a
                  WHERE (a.ws, a.src) = (f.ws, f.src))
    FROM legacy_file_rows f;
"""
