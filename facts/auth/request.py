"""facts/auth/request.py — ephemeral proof of workspace access."""
from core.fact import Fact, Need, source_fact
from .._commands import member_source
from .._policy import FamilyPolicy
from . import signature

TAG = "req"
POLICY = FamilyPolicy()
PURPOSES = frozenset({"sync"})


# SHAPE
def request(workspace, pk, verb, exp, ts, owner=None):
    owner = pk if owner is None else owner
    return Fact(
        TAG, ts, [],
        {"pk": pk, "owner": owner, "verb": verb, "exp": exp}, workspace)


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    owner = f.body.get("owner", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk, owner),
    )


# VALIDATE — stable shape and relationship validity only.
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "owner", "verb", "exp"} \
            and isinstance(body["pk"], str) \
            and isinstance(body["owner"], str) \
            and isinstance(body["verb"], str) \
            and isinstance(body["exp"], int) \
            and f == request(
                f.ws, body["pk"], body["verb"], body["exp"], f.ts,
                body["owner"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE — requests are judged but never enter durable validated storage.
DURABLE = False


def authorize(view, valid, stream, trusted_now, *, purpose="sync"):
    """Authorize this ephemeral closure using only bounded Worker reads.

    ``view`` is the database-free capability: authenticated Fact and
    Suppression tree point reads over one pinned authority root. The selected
    provider must reside there; a self-contained proof cannot bootstrap it.
    """
    body = valid.fact.body
    if purpose not in PURPOSES or body["verb"] != purpose \
            or body["exp"] < trusted_now:
        return None
    edges = {edge.role: edge.fid for edge in valid.edges}
    provider = {fact.fid: fact for fact in stream}.get(edges.get("member"))
    if provider is None or (
            "member", body["pk"], body["owner"]) not in provider.offers():
        return None
    try:
        current = view.fact_of(provider.fid)
    except ValueError:
        return None
    if source_fact(current) != source_fact(provider) \
            or not view.fact_active(provider.fid):
        return None
    return body["pk"], body["verb"]


# COMMANDS — build the already-topological request + auth closure for a mint.
def payload(node, workspace, verb, exp, ts):
    secret, public = node.identity(workspace)
    member, owner = member_source(node, workspace, public)
    if member is None:
        raise ValueError("local identity is not a workspace member")
    item = request(workspace, public, verb, exp, ts, owner)
    sig = signature.signature(secret, public, item, ts)
    deps = {item.fid: [sig.fid, member], sig.fid: []}
    return node.sender(workspace).close([sig, item], deps)


PROOF_COMMANDS = {
    purpose: payload
    for purpose in PURPOSES
}


# QUERIES — none.
