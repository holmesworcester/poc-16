"""facts/auth/request.py — ephemeral proof of workspace access."""
from ...fact import Fact
from .._commands import closer, offer_source
from . import signature

TAG = "req"
VERBS = frozenset({"sync"})


# SHAPE
def request(pk, verb, exp, ts):
    return Fact(TAG, ts, [], {"pk": pk, "verb": verb, "exp": exp})


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("member", pk, None))


# VALIDATE — stable fact validity has no access to mutable globals.
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "verb", "exp"} \
            and isinstance(body["pk"], str) and isinstance(body["verb"], str) \
            and isinstance(body["exp"], int) \
            and f == request(body["pk"], body["verb"], body["exp"], f.ts)
    except Exception:
        return False


# MODE — evaluate adds the current door policy; drain treats requests as litter.
DURABLE = False


def global_rows(f):
    return ()


def evaluate(f, globals_, ctx):
    removed = {value for name, value in globals_ if name == "removal"}
    now = [value for name, value in globals_ if name == "now"]
    return f.t == TAG and f.body["verb"] in VERBS \
        and len(now) == 1 and f.body["exp"] >= now[0] \
        and f.body["pk"] not in removed and not any(
            ctx.has_offer_value("author", public) for public in removed)


def grant(f):
    """The sealed capability subject after successful evaluation."""
    return f.body["pk"], f.body["verb"]


def blob_refs(f):
    return ()


# MATERIALIZE
def materialize(db, workspace, valid):
    return None


# COMMANDS — build the already-topological request + auth closure for a mint.
def payload(node, workspace, verb, exp, ts):
    secret, public = node.identity(workspace)
    item = request(public, verb, exp, ts)
    sig = signature.signature(secret, public, item, ts)
    member = offer_source(node, workspace, "member", public)
    if member is None:
        raise ValueError("local identity is not a workspace member")
    newmap = {item.fid: item, sig.fid: sig}
    deps = {item.fid: [sig.fid, member], sig.fid: []}
    with node.lock:
        return closer(node, workspace, newmap, deps)


# QUERIES — none.
