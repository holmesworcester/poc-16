"""facts/auth/workspace.py — the self-signed workspace and authority root."""
from ...crypto import h, sign, verify
from ...fact import Fact, canon

TAG = "workspace"


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


# MODE — drain may emit globals; evaluate may add an ephemeral gate.
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return ()


# MATERIALIZE — receives only kernel-minted Valid values.
def materialize(db, workspace, valid):
    f, body = valid.fact, valid.fact.body
    db.execute("INSERT OR IGNORE INTO members VALUES(?,?,?,?,0)",
               (workspace, body["pk"], body["name"], "admin"))


# COMMANDS — workspace bootstrap necessarily records its anchor in the keyring.
def create(node, name):
    from ...node import now_ms

    root = workspace(node.sk, node.pk, name, now_ms())
    workspace_id = root.fid
    node.add_workspace(workspace_id, name, peers=[])
    node.ingest_new(workspace_id, [root], {root.fid: []})
    return workspace_id


# QUERIES — none; membership observations belong to auth.user.
