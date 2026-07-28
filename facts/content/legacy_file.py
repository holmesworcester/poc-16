"""facts/content/legacy_file.py — read compatibility for whole-blob files."""
from core.crypto import h
from core.fact import Fact
from .._policy import author_selectors

TAG = "file"
TABLES = ("legacy_file_rows", "legacy_file_arrival_rows")


# SHAPE
def legacy_file(pk, channel, name, size, blob, ts):
    return Fact(
        TAG, ts, author_selectors(TAG, {}),
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
        if not all(isinstance(body[key], str)
                   for key in ("pk", "chan", "name", "blob")):
            return False
        if not isinstance(body["size"], int) or body["size"] < 0:
            return False
        return f == legacy_file(
            body["pk"], body["chan"], body["name"],
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
        "INSERT INTO legacy_file_rows VALUES(?,?,?,?,?,?,?,?)",
        (workspace, f.fid, body["chan"], body["name"], body["size"],
         body["blob"], body["pk"], f.ts))


def received(db, workspace, valid, blob_of):
    f, body = valid.fact, valid.fact.body
    blob = blob_of(body["blob"])
    if blob is None or len(blob) != body["size"] or h(blob) != body["blob"]:
        return
    db.execute(
        "INSERT OR IGNORE INTO legacy_file_arrival_rows VALUES(?,?,?,?)",
        (workspace, f.fid, body["blob"], f.ts))


# COMMANDS — compatibility handler only; new attachments use content.file.


# QUERIES — legacy and Bao files share content.file's read model.
