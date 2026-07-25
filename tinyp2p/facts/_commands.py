"""Shared mechanics for family commands; no fact policy lives here."""


def offer_source(node, workspace, name, a0, a1=None):
    from ..kernel import offer_src

    with node.lock:
        return offer_src(node.idx(workspace), name, a0, a1)


def offer_source_by_value(node, workspace, name, a1):
    """Canonical source for an offer selected by its second value."""
    with node.lock:
        row = node.idx(workspace).execute(
            "SELECT src FROM offers WHERE name=? AND a1=? "
            "ORDER BY src LIMIT 1",
            (name, a1)).fetchone()
    return row and row[0]


def closer(node, workspace, newmap, deps):
    from ..close import close
    from ..kernel import resolve_deps

    fact_of = lambda fid: newmap.get(fid) or node.fact_of(workspace, fid)
    deps_of = lambda fid: deps[fid] if fid in deps else \
        (resolve_deps(fact_of(fid), node.idx(workspace)) or [])
    return close(list(newmap.values()), deps_of, fact_of)


def publish(node, workspace, fact, signature, role="member", blobs=None):
    """Close one signed fact with its local authority edge and ingest it."""
    _, public_key = node.identity(workspace)
    src = offer_source(node, workspace, role, public_key)
    if src is None:
        raise ValueError(
            f"local identity is not a workspace {role}")
    deps = {fact.fid: [r for _, r in fact.refs()] + [signature.fid]
            + [src], signature.fid: []}
    node.ingest_new(workspace, [signature, fact], deps, blobs)
    return fact.fid
