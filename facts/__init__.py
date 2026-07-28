"""Fact-family router.

Core code dispatches through this table and contains no auth/content tags or
projection SQL.  Scope packages are deliberately just tables of contents.
"""
from . import auth, content
from ._policy import (
    ADMIN,
    CONTENT_DELETE,
    NEVER,
    OWNER,
    POLICIES,
    allows_direct_target,
    author_selectors,
    member_principal,
    policy_for,
    validate_fact_policy,
)

MODULES = auth.MODULES + content.MODULES
ROUTES = {module.TAG: module for module in MODULES}
assert len(ROUTES) == len(MODULES), "duplicate fact tag"
assert set(POLICIES) == set(ROUTES), "family policy registry must be exhaustive"
assert all(not hasattr(module, "evaluate") or not module.DURABLE for module in MODULES), \
    "only ephemeral families may inspect evaluate-mode globals"

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS projected(
    ws TEXT NOT NULL, src TEXT NOT NULL, family TEXT NOT NULL, rank INT,
    PRIMARY KEY(ws, src));
""" + auth.APP_SCHEMA + content.APP_SCHEMA


def handler_for(tag):
    return ROUTES.get(tag)


def materialize(db, workspace, valid):
    """Dispatch a kernel-minted ``Valid`` to its family's projection."""
    ROUTES[valid.fact.t].materialize(db, workspace, valid)


def clear(db, workspace):
    """Clear every family scope before rebuilding one workspace projection."""
    tables = {table for module in MODULES for table in module.TABLES}
    for table in sorted(tables):
        db.execute(f"DELETE FROM {table} WHERE ws=?", (workspace,))
    db.execute("DELETE FROM projected WHERE ws=?", (workspace,))


def blob_refs(fact):
    """Return immutable object hashes named by a fact, if that family has any."""
    return tuple(ROUTES[fact.t].blob_refs(fact))


def received(db, workspace, valid, blob_of):
    """Tell a spilling family that all objects named by one fact are local."""
    handler = ROUTES[valid.fact.t]
    if hasattr(handler, "received"):
        handler.received(db, workspace, valid, blob_of)
