"""Fact-family router.

Core code dispatches through this table and contains no auth/content tags or
projection SQL.  Scope packages are deliberately just tables of contents.
"""
from . import auth, content

MODULES = auth.MODULES + content.MODULES
ROUTES = {module.TAG: module for module in MODULES}
assert len(ROUTES) == len(MODULES), "duplicate fact tag"
assert all(not hasattr(module, "evaluate") or not module.DURABLE for module in MODULES), \
    "only ephemeral families may inspect evaluate-mode globals"

APP_SCHEMA = auth.APP_SCHEMA + content.APP_SCHEMA


def handler_for(tag):
    return ROUTES.get(tag)


def materialize(db, workspace, valid):
    """Dispatch a kernel-minted ``Valid`` to its family's projection."""
    ROUTES[valid.fact.t].materialize(db, workspace, valid)


def reconcile(db, workspace, index, fact_of, valids, changed=None):
    """Let families reconcile projections that use canonical offer winners."""
    for module in MODULES:
        if hasattr(module, "reconcile"):
            module.reconcile(
                db, workspace, index, fact_of, valids, changed=changed)


def clear(db, workspace):
    """Clear every family scope before rebuilding one workspace projection."""
    auth.clear(db, workspace)
    content.clear(db, workspace)


def blob_refs(fact):
    """Return immutable object hashes named by a fact, if that family has any."""
    return tuple(ROUTES[fact.t].blob_refs(fact))
