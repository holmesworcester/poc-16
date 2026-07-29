"""facts/auth/workspace.py — the self-signed workspace and authority root."""
from core.crypto import h, sign, verify
from core.fact import Fact, canon
from .._policy import FamilyPolicy, SidOffer

TAG = "workspace"
TABLES = ("member_rows",)
POLICY = FamilyPolicy(
    principal_offers=(SidOffer("member", "member"),),
)


# SHAPE — constructors are the only place this family's atoms are chosen.
def _presig(ts, atoms):
    return h(canon([TAG, ts, atoms]))


def workspace(sk, pk, name, ts):
    atoms = [["offer", "member", pk], ["offer", "admin", pk]]
    return Fact(TAG, ts, atoms,
                {"name": name, "pk": pk, "sig": sign(sk, _presig(ts, atoms))})


# NEEDS — normalized offer addresses; refs remain in the generic envelope.
def needs(f):
    return ()


# VALIDATE — immutable, context-only judgment; exactly bool, never projection.
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {"name", "pk", "sig"}:
            return False
        pk, name, signature = body["pk"], body["name"], body["sig"]
        atoms = [["offer", "member", pk], ["offer", "admin", pk]]
        shaped = Fact(TAG, f.ts, atoms, {"name": name, "pk": pk, "sig": signature})
        return f == shaped and f.fid == ctx.anchor \
            and verify(pk, _presig(f.ts, atoms), signature)
    except Exception:
        return False


# MODE
DURABLE = True


# MATERIALIZE — receives only kernel-minted Valid values.
def materialize(db, workspace, valid):
    f, body = valid.fact, valid.fact.body
    db.execute(
        "INSERT INTO member_rows VALUES(?,?,?,?,?)",
        (workspace, f.fid, body["pk"], body["name"], "admin"))


# COMMANDS — workspace bootstrap necessarily records its anchor in the keyring.
def create(node, name, ts=None):
    from core.node import now_ms

    secret, public = node.identity()
    root = workspace(
        secret, public, name, now_ms() if ts is None else ts)
    workspace_id = root.fid
    node.add_workspace(workspace_id, name, peers=[])
    node.ingest_new(workspace_id, [root], {root.fid: []})
    return workspace_id


# QUERIES — none; membership observations belong to auth.user.
CLI = {"auth.workspace.create": create}
