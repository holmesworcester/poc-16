"""Shared mechanics for family commands; no fact policy lives here."""


def offer_source(node, workspace, name, a0, a1=None, requires=()):
    from ..kernel import offer_src

    with node.lock:
        return offer_src(
            node.idx(workspace), name, a0, a1, requires)


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
