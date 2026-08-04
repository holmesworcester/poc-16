"""Shared mechanics for family commands; no fact policy lives here."""

def offer_source(node, workspace, name, a0, a1=None):
    """Choose one current provider through the stateful peer's SQL projection."""
    with node.lock:
        providers = node.select(workspace, name, a0, a1)
        return min(
            providers, key=lambda fact: (fact.key, fact.fid)
        ).fid if providers else None


def member_source(node, workspace, public_key, owner=None):
    """Resolve one unambiguous ``member(key, owner)`` authority address.

    Fact validation never guesses an owner from a provider winner.  Authoring
    may use the disposable local index to discover the sole live owner, or a
    caller may name the expected owner explicitly.
    """
    from . import _policy

    if owner is not None:
        source = offer_source(
            node, workspace, "member", public_key, owner)
        return (source, owner) if source is not None else (None, None)
    with node.lock:
        choices = {
            (_policy.member_principal(
                node.sql(workspace), fact.fid, public_key), fact.fid)
            for fact in node.select(workspace, "member", public_key)
        }
    choices = {(principal, fid) for principal, fid in choices if principal}
    owners = {principal for principal, _ in choices}
    if not choices:
        return None, None
    if len(owners) != 1:
        raise ValueError("publishing identity has ambiguous member ownership")
    principal = next(iter(owners))
    source = min(fid for owner_value, fid in choices
                 if owner_value == principal)
    return source, principal


def member_key(node, workspace, target):
    """Resolve a command target: exact public key first, unique name second."""
    from .auth.user import members

    roster = members(node, workspace)
    if any(row["pk"] == target for row in roster):
        return target
    named = sorted(
        row["pk"] for row in roster if row["name"] == target)
    if not named:
        raise ValueError(f"no member {target!r}")
    if len(named) != 1:
        raise ValueError(f"ambiguous member name {target!r}")
    return named[0]


def publish(node, workspace, fact, signature, role="member"):
    """Close one signed fact with its local authority edge and ingest it."""
    authors = [
        public_key
        for name, target, public_key in signature.offers()
        if name == "author" and target == fact.fid
    ]
    if len(authors) != 1:
        raise ValueError("signature does not author the published fact")
    public_key = authors[0]
    family = __import__("facts").family_for(fact.t)
    matching = [
        need for need in family.needs(fact)
        if need.name == role and need.a0 == public_key
    ] if family is not None else []
    if len(matching) > 1:
        raise ValueError(f"ambiguous {role} authority need")
    need = matching[0] if matching else None
    src = offer_source(
        node, workspace, role, public_key,
        None if need is None else need.a1)
    if src is None:
        raise ValueError(
            f"publishing identity is not a workspace {role}")
    deps = {fact.fid: [r for _, r in fact.refs()] + [signature.fid]
            + [src], signature.fid: []}
    node.ingest_new(
        workspace, [signature, fact], deps,
        owner=None if need is None else need.a1)
    return fact.fid
