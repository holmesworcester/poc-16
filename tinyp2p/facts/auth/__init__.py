"""Auth fact-family table of contents."""
from . import genesis, invite, join, removal, request, signature

MODULES = (genesis, signature, invite, join, removal, request)

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS members(ws TEXT, pk TEXT, name TEXT, role TEXT,
                                   evicted INT DEFAULT 0, PRIMARY KEY(ws, pk));
"""
