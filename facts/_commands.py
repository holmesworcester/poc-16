"""Shared mechanics for family commands; no fact policy lives here."""

def offer_source(node, workspace, name, a0, a1=None):
    """Choose one current provider through the stateful peer's SQL projection."""
    with node.lock:
        providers = node.select(workspace, name, a0, a1)
        return min(
            providers, key=lambda fact: (fact.key, fact.fid)
        ).fid if providers else None


def member_source(node, workspace, public_key, owner=None):
    """Resolve a direct member plus an optional owned-device link."""
    if owner is None:
        direct = offer_source(
            node, workspace, "member", public_key, public_key)
        if direct is not None:
            return direct, public_key
        with node.lock:
            owners = {
                value_owner
                for fact in node.select(
                    workspace, "device_key", public_key)
                for name, device, value_owner in fact.offers()
                if name == "device_key" and device == public_key
            }
        if len(owners) > 1:
            raise ValueError("publishing device has ambiguous ownership")
        if not owners:
            return None, None
        owner = next(iter(owners))
    member = offer_source(node, workspace, "member", owner, owner)
    linked = public_key == owner or offer_source(
        node, workspace, "device_key", public_key, owner) is not None
    if member is None or not linked:
        return None, None
    return member, owner


def _proof_sources(node, workspace, fact, signature, public_key):
    import facts

    family = facts.family_for(fact.t)
    if family is None:
        raise ValueError("unknown fact family")
    sources = [fid for _role, fid in fact.refs()] + [signature.fid]
    declared = tuple(family.needs(fact))
    author = []
    for need in declared:
        if need.name == "author":
            author.append(need)
            continue
        source = offer_source(
            node, workspace, need.name, need.a0, need.a1)
        if source is None:
            raise ValueError(
                f"publishing identity lacks {need.role} evidence")
        sources.append(source)
    if len(author) != 1 or (
            author[0].a0, author[0].a1) != (fact.fid, public_key):
        raise ValueError("signature does not satisfy author need")
    return list(dict.fromkeys(sources)), next((
        need.a1 or need.a0
        for need in declared
        if need.role == "member"
    ), None)


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


def publish(node, workspace, fact, signature):
    """Close one signed fact over every family-declared provider."""
    authors = [
        public_key
        for name, target, public_key in signature.offers()
        if name == "author" and target == fact.fid
    ]
    if len(authors) != 1:
        raise ValueError("signature does not author the published fact")
    public_key = authors[0]
    sources, owner = _proof_sources(
        node, workspace, fact, signature, public_key)
    deps = {fact.fid: sources, signature.fid: []}
    node.ingest_new(
        workspace, [signature, fact], deps,
        owner=owner)
    return fact.fid
