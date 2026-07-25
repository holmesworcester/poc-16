"""facts/content/chunk.py — the signed name of one self-proving Bao slice."""
from core import bao
from core.crypto import h
from core.fact import Fact
from core.suppression import atom as supp
from ..auth import signature

TAG = "chunk"
TABLES = ("file_slice_rows", "file_chunk_rows")


# SHAPE
def chunk(pk, channel, root, index, count, cid, ts):
    return Fact(
        TAG, ts, [supp(channel)],
        {"pk": pk, "chan": channel, "root": root,
         "i": index, "n": count, "cid": cid},
    )


# NEEDS
def needs(f):
    """Author, membership, and this author's descriptor at this geometry."""
    body = f.body
    pk, root = body.get("pk", ""), body.get("root", "")
    return (
        ("author", f.fid, pk),
        ("member", pk, None),
        ("file", root, pk,
         (("slices", root, str(body.get("n", ""))),)),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {"pk", "chan", "root", "i", "n", "cid"}:
            return False
        if not all(isinstance(body[key], str)
                   for key in ("pk", "chan", "root", "cid")):
            return False
        if not isinstance(body["i"], int) or not isinstance(body["n"], int):
            return False
        if not 0 <= body["i"] < body["n"] <= bao.MAX_SLICES:
            return False
        if len(body["root"]) != 64 or len(body["cid"]) != 64:
            return False
        if not all(
                char in "0123456789abcdef"
                for char in body["root"] + body["cid"]):
            return False
        return f == chunk(
            body["pk"], body["chan"], body["root"],
            body["i"], body["n"], body["cid"], f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return (f.body["cid"],)


# MATERIALIZE
def materialize(db, workspace, valid):
    f, body = valid.fact, valid.fact.body
    db.execute(
        "INSERT INTO file_slice_rows VALUES(?,?,?,?,?,?)",
        (workspace, f.fid, body["root"], body["i"], body["cid"], f.ts))


def received(db, workspace, valid, blob_of):
    """Count a resident slice only after its proof matches the descriptor."""
    f, body = valid.fact, valid.fact.body
    row = db.execute(
        "SELECT size FROM files WHERE ws=? AND root=? AND pk=? AND chan=?",
        (workspace, body["root"], body["pk"], body["chan"])).fetchone()
    if row is None:
        return
    try:
        blob = blob_of(body["cid"])
        if blob is None or len(blob) > bao.MAX_PROOF_BYTES \
                or h(blob) != body["cid"]:
            return
        bao.verify(blob, body["root"], body["i"], row[0])
    except Exception:
        return
    db.execute(
        "INSERT OR IGNORE INTO file_chunk_rows VALUES(?,?,?,?,?,?)",
        (workspace, f.fid, body["root"], body["i"], body["cid"], f.ts))


# COMMANDS
def author(secret, public, channel, root, index, count, cid, ts):
    item = chunk(public, channel, root, index, count, cid, ts)
    return item, signature.signature(secret, public, item, ts)


# QUERIES — chunks surface only through their descriptor's progress.
