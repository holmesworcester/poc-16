"""Fact-family router.

Core code dispatches through this table and contains no auth/content tags or
projection SQL.  Scope packages are deliberately just tables of contents.
"""
from . import auth, content
from core.suppression import deathkey, is_deletion, scoped_id, suppkeys
from ._policy import validate_fact_policy

MODULES = auth.MODULES + content.MODULES


def compile_families(modules):
    """Validate and freeze the one behavior+policy dispatch inventory."""
    modules = tuple(modules)
    families = {module.TAG: module for module in modules}
    if len(families) != len(modules):
        raise ValueError("duplicate fact tag")
    if any(not hasattr(module, "POLICY") for module in modules):
        raise ValueError("every fact family must own its policy")
    return families


FAMILIES = compile_families(MODULES)
MAX_AUTHORITY_SCOPES = 64

APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS projected(
    ws TEXT NOT NULL, src TEXT NOT NULL, family TEXT NOT NULL, rank INT,
    PRIMARY KEY(ws, src));
""" + auth.APP_SCHEMA + content.APP_SCHEMA


def family_for(tag):
    """The one checked dispatch table: behavior and policy travel together."""
    return FAMILIES.get(tag)


def _offer_sids(fact, declarations):
    by_name = {row.name: row.namespace for row in declarations}
    return {
        scoped_id(by_name[name], a0)
        for name, a0, _ in fact.offers()
        if name in by_name
    }


def fact_scopes(fact):
    """Explicit SELF/parent/ancestor ids which may suppress this fact."""
    return frozenset(suppkeys(fact))


def principal_sids(fact):
    """Family-declared typed ids for authority offered by this fact."""
    family = family_for(fact.t)
    return frozenset() if family is None else frozenset(
        _offer_sids(fact, family.POLICY.principal_offers))


def authority_scopes(fact, edges_of, fact_of):
    """Transitively expand the declared continuing liveness of authority.

    Only family-declared ``authority_liveness_guards`` are followed.  This is
    not a walk over every dependency: it is a bounded expansion of explicit
    policy edges, so a delegated admin carried by a child device inherits that
    device provider's user/device liveness without making unrelated proof
    support revocable.
    """
    out, seen, pending = set(), set(), [fact]
    while pending:
        provider = pending.pop()
        if provider.fid in seen:
            continue
        seen.add(provider.fid)
        if len(seen) > MAX_AUTHORITY_SCOPES:
            raise ValueError("authority liveness budget")
        out.update(fact_scopes(provider))
        out.update(principal_sids(provider))
        family = family_for(provider.t)
        if family is None:
            raise ValueError("authority liveness family")
        edges = edges_of(provider.fid)
        for role in family.POLICY.authority_liveness_guards:
            guarded = fact_of(edges.get(role))
            if guarded is None:
                raise ValueError("authority liveness edge")
            pending.append(guarded)
    if len(out) > MAX_AUTHORITY_SCOPES:
        raise ValueError("authority liveness scope budget")
    return frozenset(out)


def authorization_scopes(fact, edges, edges_of, fact_of):
    """Exact live scopes required to admit this irreversible effect."""
    family = family_for(fact.t)
    if family is None:
        raise ValueError("authorization family")
    by_role = {edge.role: edge.fid for edge in edges}
    out = set()
    for role in family.POLICY.authorization_guards:
        provider = fact_of(by_role.get(role))
        if provider is None:
            raise ValueError("authorization guard edge")
        out.update(authority_scopes(provider, edges_of, fact_of))
    if len(out) > MAX_AUTHORITY_SCOPES:
        raise ValueError("authorization scope budget")
    return frozenset(out)


def action_sids(fact):
    """Every typed id activated by this validated action family."""
    family = family_for(fact.t)
    out = {deathkey(fact)} if is_deletion(fact) else set()
    if family is not None:
        out.update(_offer_sids(fact, family.POLICY.action_offers))
    return frozenset(out)


def principal_sid(namespace, public_key):
    """Address one family-declared principal slot for an exact Worker read."""
    return scoped_id(namespace, public_key)


def materialize(db, workspace, valid):
    """Dispatch a kernel-minted ``Valid`` to its family's projection."""
    family = FAMILIES[valid.fact.t]
    hook = getattr(family, "materialize", None)
    if hook is not None:
        hook(db, workspace, valid)


def clear(db, workspace):
    """Clear every family scope before rebuilding one workspace projection."""
    tables = {table for module in MODULES for table in module.TABLES}
    for table in sorted(tables):
        db.execute(f"DELETE FROM {table} WHERE ws=?", (workspace,))
    db.execute("DELETE FROM projected WHERE ws=?", (workspace,))


def blob_refs(fact):
    """Return immutable object hashes named by a fact, if that family has any."""
    hook = getattr(FAMILIES[fact.t], "blob_refs", None)
    return tuple(hook(fact)) if hook is not None else ()


def received(db, workspace, valid, blob_of):
    """Tell a spilling family that all objects named by one fact are local."""
    handler = FAMILIES[valid.fact.t]
    if hasattr(handler, "received"):
        handler.received(db, workspace, valid, blob_of)
