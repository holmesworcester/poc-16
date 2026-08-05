"""Fact-layer construction of discarded identity proof closures."""

import facts

from core.kernel import drain


def _offers(fact, name, a0, a1):
    return (name, a0, "" if a1 is None else a1) in fact.offers()


def historical_owner(node, workspace, device):
    """Resolve one immutable direct-member or owned-device relationship."""
    owners = {
        owner
        for fact in node.select(
            workspace, "device_key", device,
            include_suppressed=True)
        for name, key, owner in fact.offers()
        if name == "device_key" and key == device and owner
    }
    if any(
            _offers(fact, "member", device, device)
            for fact in node.select(
                workspace, "member", device, device,
                include_suppressed=True)):
        owners.add(device)
    if len(owners) != 1:
        raise ValueError("device has no unique historical owner")
    return next(iter(owners))


def identity_closure(
        node, workspace, request, request_signature, *, closures=()):
    """Close an ephemeral family request over each exact declared provider.

    Supplied original closures are preferred during first contact.  Otherwise
    the stateful authoring peer follows its disposable fact index.  The result
    is still one ordinary closed pile; no validation witness or authority
    repository is constructed or retained.
    """
    family = facts.family_for(request.t)
    if family is None or family.DURABLE:
        raise ValueError("identity request family")
    closures = tuple(tuple(closure) for closure in closures)
    supplied = {
        fact.fid: fact
        for closure in closures
        for fact in closure
    }

    def candidates(need):
        source = facts.explicit_provider(request, need.role)
        matches = {
            fact.fid: fact
            for fact in supplied.values()
            if _offers(fact, need.name, need.a0, need.a1)
            and (source is None or fact.fid == source)
        }
        matches.update({
            fact.fid: fact
            for fact in node.select(
                workspace, need.name, need.a0, need.a1,
                include_suppressed=True)
            if _offers(fact, need.name, need.a0, need.a1)
            and (source is None or fact.fid == source)
        })
        return tuple(sorted(
            matches.values(), key=lambda fact: (fact.key, fact.fid)))

    def provider_closure(provider):
        for closure in closures:
            for position, fact in enumerate(closure):
                if fact.fid != provider.fid:
                    continue
                prefix = closure[:position + 1]
                if drain(prefix, workspace).ok:
                    return prefix
        return node.sender(workspace).close((provider,), {})

    providers = []
    authors = []
    for need in family.needs(request):
        if need.name == "author":
            authors.append(need)
            continue
        choices = candidates(need)
        if not choices:
            raise ValueError(
                f"identity proof lacks {need.role} evidence")
        providers.append(choices[0])
    if len(authors) != 1 or not _offers(
            request_signature, "author", request.fid, authors[0].a1):
        raise ValueError("identity proof signature")

    closed, seen = [], set()
    for provider in providers:
        for fact in provider_closure(provider):
            if fact.fid not in seen:
                seen.add(fact.fid)
                closed.append(fact)
    closed.extend((request_signature, request))
    if not drain(closed, workspace).ok:
        raise ValueError("identity proof closure")
    return tuple(closed)


__all__ = ("historical_owner", "identity_closure")
