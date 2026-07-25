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

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS projected(
    ws TEXT NOT NULL, src TEXT NOT NULL, family TEXT NOT NULL, rank INT,
    PRIMARY KEY(ws, src));
""" + auth.APP_SCHEMA + content.APP_SCHEMA


def handler_for(tag):
    return ROUTES.get(tag)


# ---- versioning skeleton (epic poc-16-9fc; plan docs/VERSIONING.md) ---------
# Signatures only; nothing calls these yet and the suite stays green.

VERSIONS = {}
"""(FAMILY, VERSION) -> module, beside the tag-keyed ROUTES. poc-16-9fc.1 §2."""


def handler_for_version(family, version):
    """Route by (family, version) rather than by persisted wire tag."""
    raise NotImplementedError("poc-16-9fc.1 — docs/VERSIONING.md §2")


def current_version(family):
    """The version this release's COMMANDS author for ``family``."""
    raise NotImplementedError("poc-16-9fc.1 — docs/VERSIONING.md §2")


def offers(fact):
    """Emitted offers for ``fact``, normalized to the current vocabulary.

    THE seam: a fact's emitted offers are not the offer atoms in its body.  The
    atoms are what the author asserted in the vocabulary of the release that
    authored it — immutable, and still exactly what the family's own validator
    reconstructs.  This is what the release makes of that assertion, and it is
    what fills the offer table.  Every family's first implementation returns
    ``fact.offers()``, the identity, so the seam lands byte-identical.
    Needs are already handler functions, hence already current-version; that
    asymmetry is the whole of the change (docs/VERSIONING.md §3, §4).
    """
    raise NotImplementedError("poc-16-9fc.2 — docs/VERSIONING.md §3")


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
