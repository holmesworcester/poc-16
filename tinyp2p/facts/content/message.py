"""facts/content/message.py — a member-signed channel message."""
from ...fact import Fact
from .._commands import publish
from ..auth import signature

TAG = "msg"


# SHAPE
def message(pk, channel, text, ts):
    return Fact(TAG, ts, [], {"pk": pk, "chan": channel, "text": text})


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("member", pk, None))


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "chan", "text"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == message(body["pk"], body["chan"], body["text"], f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return ()


# MATERIALIZE
def materialize(db, workspace, valid):
    f, body = valid.fact, valid.fact.body
    db.execute("INSERT OR IGNORE INTO messages VALUES(?,?,?,?,?,?)",
               (f.fid, workspace, body["chan"], body["pk"], body["text"], f.ts))


# COMMANDS
def post(node, workspace, channel, text, ts=None):
    from ...node import now_ms

    ts = ts or now_ms()
    item = message(node.pk, channel, text, ts)
    return publish(node, workspace, item,
                   signature.signature(node.sk, node.pk, item, ts))


# QUERIES
def messages(node, workspace, channel=None):
    query = "SELECT chan, pk, text, ts, fid FROM messages WHERE ws=?" + \
        (" AND chan=?" if channel else "") + " ORDER BY ts, fid"
    with node.lock:
        rows = node.app.execute(
            query, (workspace, channel) if channel else (workspace,)).fetchall()
        names = dict(node.app.execute(
            "SELECT pk, name FROM members WHERE ws=?", (workspace,)))
    return [{"chan": chan, "from": names.get(pk, pk[:8]), "text": text,
             "ts": ts, "fid": fid} for chan, pk, text, ts, fid in rows]
