"""Auth fact-family table of contents."""
from . import (
    admin,
    device,
    device_invite,
    legacy_genesis,
    legacy_invite,
    legacy_join,
    legacy_signature,
    removal,
    request,
    signature,
    user,
    user_invite,
    workspace,
)

MODULES = (
    workspace,
    signature,
    user_invite,
    user,
    legacy_genesis,
    legacy_signature,
    legacy_invite,
    legacy_join,
    admin,
    device,
    device_invite,
    removal,
    request,
)

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS member_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, pk TEXT NOT NULL,
    name TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS admin_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, pk TEXT NOT NULL,
    PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS removal_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, pk TEXT NOT NULL,
    PRIMARY KEY(ws, src));
CREATE TABLE IF NOT EXISTS device_rows(
    ws TEXT NOT NULL, src TEXT NOT NULL, user TEXT NOT NULL,
    pk TEXT NOT NULL, label TEXT NOT NULL, PRIMARY KEY(ws, src));
CREATE INDEX IF NOT EXISTS member_rows_by_key ON member_rows(ws, pk);
CREATE INDEX IF NOT EXISTS admin_rows_by_key ON admin_rows(ws, pk);
CREATE INDEX IF NOT EXISTS removal_rows_by_key ON removal_rows(ws, pk);
CREATE INDEX IF NOT EXISTS device_rows_by_key ON device_rows(ws, pk);

CREATE VIEW IF NOT EXISTS devices AS
SELECT ws, user, pk, label, src AS source, src
FROM (
    SELECT d.*, ROW_NUMBER() OVER (
        PARTITION BY d.ws, d.pk
        ORDER BY COALESCE(p.rank, 9223372036854775807), d.src) AS choice
    FROM device_rows d
    JOIN projected p ON (p.ws, p.src) = (d.ws, d.src)
)
WHERE choice=1;

CREATE VIEW IF NOT EXISTS members AS
WITH chosen AS (
    SELECT m.*, ROW_NUMBER() OVER (
        PARTITION BY m.ws, m.pk
        ORDER BY CASE m.role WHEN 'admin' THEN 0
                             WHEN 'member' THEN 1 ELSE 2 END,
                 COALESCE(p.rank, 9223372036854775807), m.src) AS choice
    FROM member_rows m
    JOIN projected p ON (p.ws, p.src) = (m.ws, m.src)
)
SELECT c.ws, c.pk,
       CASE WHEN c.role='device'
            THEN COALESCE((SELECT d.label FROM devices d
                           WHERE d.ws=c.ws AND d.pk=c.pk), c.name)
            ELSE c.name END AS name,
       CASE WHEN c.role='admin' OR EXISTS (
                    SELECT 1 FROM admin_rows a
                    WHERE a.ws=c.ws AND a.pk=c.pk)
            THEN 'admin' ELSE c.role END AS role,
       EXISTS (SELECT 1 FROM removal_rows r
               WHERE r.ws=c.ws AND r.pk=c.pk) AS evicted,
       c.src
FROM chosen c
WHERE c.choice=1;
"""
