"""Auth fact-family table of contents."""
from . import removal, request, signature, user, user_invite, workspace

MODULES = (workspace, signature, user_invite, user, removal, request)

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS members(ws TEXT, pk TEXT, name TEXT, role TEXT,
                                   evicted INT DEFAULT 0, PRIMARY KEY(ws, pk));
"""
