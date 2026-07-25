"""facts/content/file.py — a member-signed bao-rooted attachment descriptor.

The descriptor is O(1) in file size: one 32-byte BLAKE3 root commits every
byte, and each 256 KiB chunk proves itself against that root on arrival. So
the descriptor stays a small fact in the tree no matter how large the file
is, and download progress is a fold over *proven* chunks rather than a
counter somebody has to be trusted to increment.
"""
import os
import tempfile

from ... import bao
from ...crypto import h
from ...fact import Fact
from ...suppression import atom as supp
from .._commands import offer_source
from ..auth import signature
from . import chunk as chunkfam

TAG = "file"
WIDTH = bao.WIDTH
MAX_FILE_BYTES = bao.MAX_FILE_BYTES
MAX_NAME = 255
ENCODING = "clear-v1"


# SHAPE
def file(pk, channel, name, size, root, count, ts):
    return Fact(
        TAG, ts,
        [supp(channel),
         ["offer", "file", root, pk],             # this member owns this content
         ["offer", "slices", root, str(count)]],  # the geometry chunks bind to
        {"pk": pk, "chan": channel, "name": name, "size": size,
         "root": root, "width": WIDTH, "n": count, "enc": ENCODING},
    )


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("member", pk, None))


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {"pk", "chan", "name", "size", "root",
                         "width", "n", "enc"}:
            return False
        if not all(isinstance(body[key], str)
                   for key in ("pk", "chan", "name", "root", "enc")):
            return False
        if not all(isinstance(body[key], int)
                   for key in ("size", "n", "width")):
            return False
        if body["enc"] != ENCODING or body["width"] != WIDTH:
            return False
        if not 0 <= body["size"] <= MAX_FILE_BYTES:
            return False
        if not body["name"] or len(body["name"].encode()) > MAX_NAME:
            return False
        if len(body["root"]) != 64 \
                or not all(c in "0123456789abcdef" for c in body["root"]):
            return False
        if body["n"] != bao.geometry(body["size"], body["width"]):
            return False
        return f == file(body["pk"], body["chan"], body["name"], body["size"],
                         body["root"], body["n"], f.ts)
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
    db.execute("INSERT OR IGNORE INTO files VALUES(?,?,?,?,?,?,?,?,?,?)",
               (f.fid, workspace, body["chan"], body["name"], body["size"],
                body["root"], body["width"], body["n"], body["pk"], f.ts))


# COMMANDS
def send(node, workspace, channel, path, name=None, ts=None):
    """Prove the whole source locally, spill every slice, then publish the
    descriptor and its chunks as one closed pile. Nothing is authored until
    every proof has verified against the root we are about to sign."""
    from ...node import now_ms

    ts = ts or now_ms()
    source = os.path.abspath(os.fspath(path))
    if not os.path.isfile(source):
        raise ValueError("file path is not a regular file")
    size = os.path.getsize(source)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds the {MAX_FILE_BYTES >> 30} GiB limit")
    label = name or os.path.basename(source)
    if not label or len(label.encode()) > MAX_NAME:
        raise ValueError("file name is empty or too long")

    secret, public = node.identity(workspace)
    store = node.store(workspace)
    with tempfile.TemporaryDirectory(prefix="tinyp2p-bao-") as scratch:
        outboard = os.path.join(scratch, "outboard")
        root = bao.prepare(source, outboard)
        count = bao.geometry(size)
        cids = []
        for index in range(count):
            blob = bao.proof(source, outboard, index, size)
            payload = bao.verify(blob, root, index, size)  # prove before signing
            if len(payload) != bao.span(index, size)[1]:
                raise RuntimeError("bao returned a short slice")
            cid = h(blob)
            store.put_if_absent("obj/" + cid, blob)  # objects before facts
            cids.append(cid)
        if os.path.getsize(source) != size:
            raise ValueError("file changed while it was being proved")

    src = offer_source(node, workspace, "member", public)
    if src is None:
        raise ValueError("publishing identity is not a workspace member")
    descriptor = file(public, channel, label, size, root, count, ts)
    news = [signature.signature(secret, public, descriptor, ts), descriptor]
    deps = {news[0].fid: [], descriptor.fid: [news[0].fid, src]}
    for index, cid in enumerate(cids):
        item, sig = chunkfam.author(
            secret, public, channel, root, index, count, cid, ts)
        news += [sig, item]
        deps[sig.fid] = []
        deps[item.fid] = [sig.fid, src, descriptor.fid]
    node.ingest_new(workspace, news, deps)
    return descriptor.fid


def save(node, workspace, selector, out_path):
    """Re-verify every chunk against the root, then land the file atomically.
    Export never trusts the projection."""
    record = resolve(node, workspace, selector)
    if record is None:
        raise ValueError("no such file")
    if record["have"] < record["total"]:
        raise ValueError(
            f"file incomplete: have {record['have']}/{record['total']} slices")
    store, cids = node.store(workspace), _cids(node, workspace, record["root"])
    target = os.path.abspath(os.fspath(out_path))
    handle, temporary = tempfile.mkstemp(
        prefix=".tinyp2p-", dir=os.path.dirname(target) or ".")
    try:
        written = 0
        with os.fdopen(handle, "wb") as out:
            for index in range(record["total"]):
                payload = bao.verify(store.get("obj/" + cids[index]),
                                     record["root"], index, record["size"])
                out.write(payload)
                written += len(payload)
            out.flush()
            os.fsync(out.fileno())
        if written != record["size"]:
            raise ValueError("assembled length does not match the descriptor")
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return {"fid": record["fid"], "name": record["name"],
            "bytes": written, "path": target}


# QUERIES
def files(node, workspace):
    """The listing, with progress folded from verified chunks. Percent is
    computed here and never stored."""
    with node.lock:
        rows = node.app.execute(
            "SELECT fid, chan, name, size, root, total, have, ts "
            "FROM file_progress WHERE ws=? ORDER BY ts, fid",
            (workspace,)).fetchall()
    return [{"fid": fid, "chan": chan, "name": name, "size": size,
             "root": root, "total": total, "have": have,
             "complete": have >= total,
             "pct": 100 if total == 0 else have * 100 // total}
            for fid, chan, name, size, root, total, have, ts in rows]


def resolve(node, workspace, selector):
    """Accept a descriptor fid, its root, or a unique fid prefix."""
    listing = files(node, workspace)
    for record in listing:
        if selector in (record["fid"], record["root"]):
            return record
    hits = [record for record in listing if record["fid"].startswith(selector)]
    return hits[0] if len(hits) == 1 else None


def bytes_for(node, workspace, fid):
    """Assemble in memory — the control-plane surface. Only a complete,
    re-verified file has bytes; an incomplete one reports no bytes."""
    record = resolve(node, workspace, fid)
    if record is None:
        return None
    if record["have"] < record["total"]:
        return record["name"], None
    store, cids = node.store(workspace), _cids(node, workspace, record["root"])
    out = bytearray()
    for index in range(record["total"]):
        out += bao.verify(store.get("obj/" + cids[index]),
                          record["root"], index, record["size"])
    return record["name"], bytes(out)


def _cids(node, workspace, root):
    with node.lock:
        return dict(node.app.execute(
            "SELECT idx, cid FROM file_chunks WHERE ws=? AND root=?",
            (workspace, root)).fetchall())
