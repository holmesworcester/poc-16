"""facts/auth/workspace.py — the self-signed workspace and authority root."""
from core.crypto import h, sign, verify
from core.fact import Fact, canon
from .._policy import FamilyPolicy, SidOffer
from ._display import display

TAG = "workspace"
GENESIS = True
POLICY = FamilyPolicy(
    control_fact=True,
    principal_offers=(SidOffer("member", "member"),),
    clear_offers=(SidOffer("member", "device"),),
)


# SHAPE — constructors are the only place this family's atoms are chosen.
def _presig(ts, atoms):
    return h(canon([TAG, ts, atoms]))


def workspace(sk, pk, name, ts):
    name = display(name)
    atoms = [["offer", "member", pk, pk], ["offer", "admin", pk]]
    return Fact(TAG, ts, atoms,
                {"name": name, "pk": pk, "sig": sign(sk, _presig(ts, atoms))},
                None)


# NEEDS — normalized offer addresses; refs remain in the generic envelope.
def needs(f):
    return ()


# VALIDATE — immutable, context-only judgment; exactly bool, no host effects.
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {"name", "pk", "sig"}:
            return False
        pk, name, signature = body["pk"], body["name"], body["sig"]
        name = display(name)
        atoms = [["offer", "member", pk, pk], ["offer", "admin", pk]]
        shaped = Fact(
            TAG, f.ts, atoms, {"name": name, "pk": pk, "sig": signature},
            None)
        return f == shaped and f.fid == ctx.anchor \
            and verify(pk, _presig(f.ts, atoms), signature)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS — workspace bootstrap necessarily records its anchor in the keyring.
def create(node, name, ts=None):
    secret, public = node.identity()
    root = workspace(
        secret, public, name, node.now_ms() if ts is None else ts)
    workspace_id = root.fid
    node.add_workspace(workspace_id, name, peers=[])
    node.ingest_new(workspace_id, [root], {root.fid: []})
    return workspace_id


# QUERIES — none; membership observations belong to auth.user.
CLI = {"auth.workspace.create": create}
