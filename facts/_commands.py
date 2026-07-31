"""Shared mechanics for family commands; no fact policy lives here."""

def offer_source(node, workspace, name, a0, a1=None):
    """Return the current live provider from one pinned repository root."""
    with node.lock:
        reader = node.reader(workspace)
        return None if reader is None else reader.worker().authority_provider(
            name, a0, a1)


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
    node.ingest_new(workspace, [signature, fact], deps)
    return fact.fid


def direct_upload(
        node, workspace, source, broker_url, provider_origin):
    """Run the one provider-neutral direct uploader with a fresh auth proof."""
    import facts

    if source.workspace != workspace \
            or source.member != node.member_for(workspace):
        raise ValueError("upload source authority")

    def proof():
        now = node.now_ms()
        return node.sender(workspace).pack(facts.proof_payload(
            node, workspace, "upload", now + 120_000, now))

    result = node.run_upload(
        source, broker_url, provider_origin, proof)
    return {
        "objects": result.object_count,
        "session": result.session,
        "upload": result.source_id,
    }
