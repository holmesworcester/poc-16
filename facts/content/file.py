"""facts/content/file.py — a member-signed immutable blob descriptor."""
from core.crypto import h
from core.fact import Fact
from core.suppression import atom as supp
from .._commands import publish
from ..auth import signature

TAG = "file"
TABLES = ("file_rows",)


# SHAPE
def file(pk, channel, name, size, blob, ts):
    return Fact(
        TAG, ts, [supp(channel)],
        {"pk": pk, "chan": channel, "name": name,
         "size": size, "blob": blob},
    )


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("member", pk, None))


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {"pk", "chan", "name", "size", "blob"}:
            return False
        if not all(isinstance(body[key], str) for key in ("pk", "chan", "name", "blob")) \
                or not isinstance(body["size"], int) or body["size"] < 0:
            return False
        return f == file(body["pk"], body["chan"], body["name"],
                         body["size"], body["blob"], f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return (f.body["blob"],)


# MATERIALIZE
def materialize(db, workspace, valid):
    f, body = valid.fact, valid.fact.body
    db.execute(
        "INSERT INTO file_rows VALUES(?,?,?,?,?,?,?,?)",
        (workspace, f.fid, body["chan"], body["name"], body["size"],
         body["blob"], body["pk"], f.ts))


# COMMANDS
def send(node, workspace, channel, name, data):
    from core.node import now_ms

    ts, blob = now_ms(), h(data)
    secret, public = node.identity(workspace)
    item = file(public, channel, name, len(data), blob, ts)
    return publish(node, workspace, item,
                   signature.signature(secret, public, item, ts),
                   blobs={blob: data})


# QUERIES
def files(node, workspace):
    with node.lock:
        rows = node.app.execute(
            "SELECT fid, chan, name, size, blob, ts FROM files "
            "WHERE ws=? ORDER BY ts", (workspace,)).fetchall()
    return [{"fid": fid, "chan": chan, "name": name, "size": size,
             "blob": blob, "ts": ts} for fid, chan, name, size, blob, ts in rows]


def bytes_for(node, workspace, fid):
    with node.lock:
        row = node.app.execute("SELECT name, blob FROM files WHERE ws=? AND fid=?",
                               (workspace, fid)).fetchone()
    if not row:
        return None
    return row[0], node.store(workspace).get("obj/" + row[1])
