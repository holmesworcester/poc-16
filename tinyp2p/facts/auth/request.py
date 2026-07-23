"""facts/auth/request.py — ephemeral proof of workspace access."""
from ...fact import Fact
from .._commands import closer, offer_source
from . import signature

TAG = "req"


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


def evaluate(f, globals_):
    removed = {value for name, value in globals_ if name == "removal"}
    return f.body["pk"] not in removed


def blob_refs(f):
    return ()


# MATERIALIZE
def materialize(db, workspace, valid):
    return None


# COMMANDS — build the already-topological request + auth closure for a mint.
def payload(node, workspace, verb, exp, ts):
    item = request(node.pk, verb, exp, ts)
    sig = signature.signature(node.sk, node.pk, item, ts)
    member = offer_source(node, workspace, "member", node.pk)
    newmap = {item.fid: item, sig.fid: sig}
    deps = {item.fid: [sig.fid] + ([member] if member else []), sig.fid: []}
    with node.lock:
        return closer(node, workspace, newmap, deps)


# QUERIES — none.
