"""facts/auth/removal.py — an admin-signed terminal-removal proposal."""
from core.fact import Fact, Need
from .._commands import member_key, publish
from .._policy import FamilyPolicy, SidOffer
from . import signature

TAG = "evict"
POLICY = FamilyPolicy(
    authorization_guards=("admin",),
    action_offers=(SidOffer("removed", "member"),),
)


# SHAPE
def removal(pk, target_pk, ts):
    return Fact(TAG, ts, [["offer", "removed", target_pk]], {"pk": pk})


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("admin", "admin", pk),
    )


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"pk"} or len(f.offers()) != 1:
            return False
        name, target, empty = f.offers()[0]
        return name == "removed" and empty == "" \
            and f == removal(f.body["pk"], target, f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


# COMMANDS
def evict(node, workspace, target):
    from core.node import now_ms

    target_pk = member_key(node, workspace, target)
    ts = now_ms()
    secret, public = node.identity(workspace)
    item = removal(public, target_pk, ts)
    return publish(node, workspace, item,
                   signature.signature(secret, public, item, ts), role="admin")


# QUERIES — member status is exposed by auth.user.members.
CLI = {"auth.removal.evict": evict}
