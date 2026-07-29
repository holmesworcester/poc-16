"""facts/auth/request.py — ephemeral proof of workspace access."""
from core.fact import Fact, Need
from .._commands import closer, offer_source
from .._policy import FamilyPolicy
from . import signature

TAG = "req"
POLICY = FamilyPolicy(authorization_guards=("member",))
VERBS = frozenset({"sync"})


# SHAPE
def request(workspace, pk, verb, exp, ts):
    return Fact(
        TAG, ts, [], {"pk": pk, "verb": verb, "exp": exp}, workspace)


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk),
    )


# VALIDATE — stable shape and relationship validity only.
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "verb", "exp"} \
            and isinstance(body["pk"], str) and isinstance(body["verb"], str) \
            and isinstance(body["exp"], int) \
            and f == request(
                f.ws, body["pk"], body["verb"], body["exp"], f.ts)
    except Exception:
        return False


# MODE — requests are judged but never enter the durable client catalog.
DURABLE = False


def authorize(view, valid, stream, trusted_now):
    """Authorize this ephemeral closure using only bounded Worker reads.

    ``view`` is the database-free CF capability: authenticated Fact,
    Authority, and Suppression tree point reads over one root.
    """
    import facts

    body = valid.fact.body
    if body["verb"] not in VERBS or body["exp"] < trusted_now:
        return None
    edges = {edge.role: edge.fid for edge in valid.edges}
    provider = {fact.fid: fact for fact in stream}.get(edges.get("member"))
    if provider is None or ("member", body["pk"], "") not in provider.offers():
        return None
    sid = facts.principal_sid("member", body["pk"])
    if not view.authority_known("member", body["pk"]):
        # A never-seen address may bootstrap from its self-contained closure.
        # A terminal pre-tombstone must fail closed.
        if view.suppression_known(sid):
            return None
    elif view.authority_provider("member", body["pk"]) is None \
            or view.suppression(sid)["state"] != "clear":
        return None
    return body["pk"], body["verb"]


# COMMANDS — build the already-topological request + auth closure for a mint.
def payload(node, workspace, verb, exp, ts):
    secret, public = node.identity(workspace)
    item = request(workspace, public, verb, exp, ts)
    sig = signature.signature(secret, public, item, ts)
    member = offer_source(node, workspace, "member", public)
    if member is None:
        raise ValueError("local identity is not a workspace member")
    newmap = {item.fid: item, sig.fid: sig}
    deps = {item.fid: [sig.fid, member], sig.fid: []}
    with node.lock:
        return closer(node, workspace, newmap, deps)


# QUERIES — none.
