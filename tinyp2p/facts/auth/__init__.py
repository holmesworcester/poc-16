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
CREATE TABLE IF NOT EXISTS members(ws TEXT, pk TEXT, name TEXT, role TEXT,
                                   evicted INT DEFAULT 0, PRIMARY KEY(ws, pk));
CREATE TABLE IF NOT EXISTS devices(ws TEXT, user TEXT, pk TEXT, label TEXT,
                                   source TEXT, PRIMARY KEY(ws, pk));
"""


def clear(db, workspace):
    """Clear this scope's derived rows before a canonical reprojection."""
    db.execute("DELETE FROM members WHERE ws=?", (workspace,))
    db.execute("DELETE FROM devices WHERE ws=?", (workspace,))
