"""facts/content/chunk.py — the signed name of one self-proving bao slice.

The bytes live in ``obj/<cid>``; this fact is their ordered, member-signed
name in the tree. It binds to its author's descriptor and to that
descriptor's geometry, so only the file's own author can name a position in
it, and a chunk cannot inflate the slice count it claims to belong to.
"""
from ... import bao
from ...fact import Fact
from ...suppression import atom as supp
from ..auth import signature

TAG = "chunk"


# SHAPE
def chunk(pk, channel, root, index, count, cid, ts):
    return Fact(
        TAG, ts, [supp(channel)],
        {"pk": pk, "chan": channel, "root": root,
         "i": index, "n": count, "cid": cid},
    )


# NEEDS
def needs(f):
    """Author, membership, and *this author's* descriptor at this geometry."""
    body = f.body
    pk, root = body.get("pk", ""), body.get("root", "")
    return (("author", f.fid, pk), ("member", pk, None),
            ("file", root, pk, (("slices", root, str(body.get("n", ""))),)))


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
        if not all(c in "0123456789abcdef" for c in body["root"] + body["cid"]):
            return False
        return f == chunk(body["pk"], body["chan"], body["root"],
                          body["i"], body["n"], body["cid"], f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    """The proof object, spilled like any oversized body."""
    return (f.body["cid"],)


# MATERIALIZE
def materialize(db, workspace, valid):
    """The *expected* set — somebody advertised this position at this cid."""
    f, body = valid.fact, valid.fact.body
    db.execute("INSERT OR IGNORE INTO file_slices VALUES(?,?,?,?,?,?)",
               (f.fid, workspace, body["root"], body["i"], body["cid"], f.ts))


def received(db, workspace, valid, blob_of):
    """The *verified-present* set. Core has already checked the bytes are
    what the fact named; this checks they are what the signed root says
    belongs at this position — the part only the family can judge. A blob
    that hashes right but fails its proof is never progress."""
    f, body = valid.fact, valid.fact.body
    row = db.execute("SELECT size FROM files WHERE ws=? AND root=?",
                     (workspace, body["root"])).fetchone()
    if row is None:
        return  # descriptor not projected yet; the rebuild fold catches up
    try:
        bao.verify(blob_of(body["cid"]), body["root"], body["i"], row[0])
    except Exception:
        return
    db.execute("INSERT OR IGNORE INTO file_chunks VALUES(?,?,?,?,?,?)",
               (f.fid, workspace, body["root"], body["i"], body["cid"], f.ts))


# COMMANDS — authored only by content.file.send, which owns the whole file.
def author(secret, public, channel, root, index, count, cid, ts):
    """Return this chunk and its detached authorship signature."""
    item = chunk(public, channel, root, index, count, cid, ts)
    return item, signature.signature(secret, public, item, ts)


# QUERIES — a chunk has no human surface; progress is the file's view.
