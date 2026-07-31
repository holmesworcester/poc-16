"""facts/content/file.py — a member-signed Bao-rooted attachment descriptor."""
import os
import tempfile

from core.fact_index import REF_INDEX, TYPE_INDEX
from core.crypto import h
from core.fact import Fact, Need
from core.shape import valid_fid
from .._policy import (
    DELETE_SELF,
    FamilyPolicy,
    Self,
    author_selectors,
)
from .._commands import direct_upload, member_source
from ..auth import signature
from .. import _bao as bao
from . import chunk as chunkfam

TAG = "file_bao"
POLICY = FamilyPolicy(
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_field="owner",
)
WIDTH = bao.WIDTH
MAX_FILE_BYTES = bao.MAX_FILE_BYTES
MAX_NAME = 255
ENCODING = "clear-v1"


# SHAPE
def file(
        workspace, pk, channel, name, size, root, count, ts, owner=None):
    owner = pk if owner is None else owner
    return Fact(
        TAG, ts,
        author_selectors(POLICY, {}) + [
            ["offer", "file", root, pk],
            ["offer", "slices", root, str(count)],
        ],
        {"pk": pk, "owner": owner, "chan": channel, "name": name, "size": size,
         "root": root, "width": WIDTH, "n": count, "enc": ENCODING},
        workspace,
    )


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    owner = f.body.get("owner", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk, owner),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {
                "pk", "owner", "chan", "name", "size", "root", "width",
                "n", "enc"}:
            return False
        if not all(isinstance(body[key], str)
                   for key in (
                       "pk", "owner", "chan", "name", "root", "enc")):
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
        if len(body["root"]) != 64 or not all(
                char in "0123456789abcdef" for char in body["root"]):
            return False
        if body["n"] != bao.geometry(body["size"], body["width"]):
            return False
        return f == file(
            f.ws, body["pk"], body["chan"], body["name"], body["size"],
            body["root"], body["n"], f.ts, body["owner"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def _prepare(node, workspace, channel, path, name, ts, put_object):
    """Author one file/chunk fact set; choose its detached object sink."""
    native = node.attachment_io()
    timestamp = node.now_ms() if ts is None else ts
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
    member, owner = member_source(node, workspace, public)
    if member is None:
        raise ValueError("publishing identity is not a workspace member")
    with tempfile.TemporaryDirectory(prefix="tinyp2p-bao-") as scratch:
        outboard = os.path.join(scratch, "outboard")
        root = native.prepare(source, outboard)
        count, cids = bao.geometry(size), []
        for index in range(count):
            blob = native.proof(source, outboard, index, size)
            payload = native.verify(blob, root, index, size)
            if len(payload) != bao.span(index, size)[1]:
                raise RuntimeError("Bao returned a short slice")
            cid = h(blob)
            put_object(cid, blob)
            cids.append(cid)
        if os.path.getsize(source) != size:
            raise ValueError("file changed while it was being proved")

    descriptor = file(
        workspace, public, channel, label, size, root, count, timestamp,
        owner)
    signed = signature.signature(
        secret, public, descriptor, timestamp)
    news = [signed, descriptor]
    deps = {signed.fid: [], descriptor.fid: [signed.fid, member]}
    for index, cid in enumerate(cids):
        item, item_signature = chunkfam.author(
            workspace, secret, public, channel, root, index, count, cid,
            timestamp, descriptor.fid, owner)
        news += [item_signature, item]
        deps[item_signature.fid] = []
        deps[item.fid] = [item_signature.fid, member, descriptor.fid]
    return descriptor, news, deps


def send(node, workspace, channel, path, name=None, ts=None):
    """Prove every slice locally, spill it, then publish one closed pile."""
    descriptor, news, deps = _prepare(
        node, workspace, channel, path, name, ts,
        lambda cid, blob: node.receive_object(workspace, cid, blob),
    )
    node.ingest_new(workspace, news, deps)
    return descriptor.fid


def upload(
        node, workspace, channel, path, broker_url, provider_origin,
        name=None, ts=None):
    """Author once, then send objects directly to exact provider PUTs."""
    builder = node.start_upload(workspace)

    def spool(cid, blob):
        if builder.add(blob) != cid:
            raise RuntimeError("upload object digest")

    try:
        descriptor, news, deps = _prepare(
            node, workspace, channel, path, name, ts,
            spool,
        )
        source = builder.finish(
            node.sender(workspace).pile(news, deps))
    except BaseException:
        builder.discard()
        raise
    result = direct_upload(
        node, workspace, source, broker_url, provider_origin)
    return {"fid": descriptor.fid, **result}


def resume_upload(
        node, workspace, upload_id, broker_url, provider_origin):
    """Resume any retained direct-upload source by its content id."""
    if not valid_fid(upload_id):
        raise ValueError("upload id")
    source = node.load_upload(upload_id)
    return direct_upload(
        node, workspace, source, broker_url, provider_origin)


def uploads(node, workspace, cursor=None):
    """List bounded local delivery state; completion does not mean published."""
    if cursor is not None and not valid_fid(cursor):
        raise ValueError("upload cursor")
    return node.upload_status(workspace, cursor)


def abandon_upload(node, workspace, upload_id):
    """Stop retrying one local source without claiming recipient publication."""
    if not valid_fid(upload_id):
        raise ValueError("upload id")
    return node.abandon_upload(workspace, upload_id)


def collect_upload(node, workspace, upload_id):
    """Remove one exact completed or safely expired abandoned local source."""
    if not valid_fid(upload_id):
        raise ValueError("upload id")
    return node.collect_upload(workspace, upload_id)


def save(node, workspace, selector, out_path):
    """Re-verify every slice, then atomically replace the requested path."""
    record, cids = _resolve_state(node, workspace, selector)
    if record is None:
        raise ValueError("no such file")
    if record["have"] < record["total"]:
        raise ValueError(
            f"file incomplete: have {record['have']}/{record['total']} slices")
    parts = _payloads(node, workspace, record, cids)
    target = os.path.abspath(os.fspath(out_path))
    handle, temporary = tempfile.mkstemp(
        prefix=".tinyp2p-", dir=os.path.dirname(target) or ".")
    try:
        written = 0
        with os.fdopen(handle, "wb") as output:
            for payload in parts:
                output.write(payload)
                written += len(payload)
            output.flush()
            os.fsync(output.fileno())
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
def _state(store, native, descriptor, chunks):
    """Verify only one descriptor's selected Bao slices."""
    body, cids = descriptor.body, {}
    for fact in chunks:
        child = fact.body
        if child["root"] != body["root"] \
                or child["n"] != body["n"] \
                or child["pk"] != body["pk"] \
                or child["owner"] != body["owner"] \
                or child["chan"] != body["chan"]:
            continue
        try:
            raw = store.get_bounded(
                "obj/" + child["cid"], bao.MAX_PROOF_BYTES)
            if raw is None or h(raw) != child["cid"]:
                continue
            native.verify(raw, body["root"], child["i"], body["size"])
        except Exception:
            continue
        cids.setdefault(child["i"], child["cid"])

    have, total = len(cids), body["n"]
    return {
        "fid": descriptor.fid,
        "chan": body["chan"],
        "name": body["name"],
        "size": body["size"],
        "root": body["root"],
        "blob": None,
        "encoding": "bao-v1",
        "total": total,
        "have": have,
        "complete": have >= total,
        "pct": 100 if total == 0 else have * 100 // total,
        "ts": descriptor.ts,
    }, cids


def _states(node, workspace, selector=None):
    """Pin one SQL snapshot, then verify its immutable bytes unlocked."""
    with node.lock:
        node._sync_sql(workspace)
        admitted = node.sql(workspace)
        def select(kind, k0=None, k1=None, **filters):
            return tuple(
                fact for fact in admitted.indexed(
                    kind, k0, k1, **filters)
                if not admitted.suppresses(fact)
            )

        if selector is None:
            descriptors, target = select(TYPE_INDEX, TAG), None
        else:
            prefixed = select(
                TYPE_INDEX, TAG, "", source_prefix=selector)
            direct = {
                fact.fid: fact for fact in prefixed if fact.fid == selector
            }
            direct.update({
                fact.fid: fact for fact in select(
                    "file", selector, source_type=TAG)
            })
            descriptor = min(
                direct.values(), key=lambda fact: (fact.ts, fact.fid)
            ) if direct else (
                prefixed[0] if len(prefixed) == 1 else None)
            descriptors = () if descriptor is None else (descriptor,)
            target = descriptor.fid if descriptor is not None else None
        chunks = () if selector is not None and not descriptors else select(
            REF_INDEX, "file", target, source_type=chunkfam.TAG)
        store, native = node.store(workspace), node.attachment_io()

    by_file = {fact.fid: [] for fact in descriptors}
    for fact in chunks:
        parent = dict(fact.refs()).get("file")
        if parent in by_file:
            by_file[parent].append(fact)
    return sorted([
        _state(store, native, descriptor, by_file[descriptor.fid])
        for descriptor in descriptors
    ], key=lambda item: (item[0]["ts"], item[0]["fid"]))


def files(node, workspace):
    return [record for record, _ in _states(node, workspace)]


def _resolve_state(node, workspace, selector):
    states = _states(node, workspace, selector)
    return states[0] if states else (None, {})


def _payloads(node, workspace, record, cids):
    store, native = node.store(workspace), node.attachment_io()
    return (
        native.verify(
            store.get_bounded(
                "obj/" + cids[index], bao.MAX_PROOF_BYTES),
            record["root"], index, record["size"])
        for index in range(record["total"])
    )


def resolve(node, workspace, selector):
    return _resolve_state(node, workspace, selector)[0]


def bytes_for(node, workspace, fid):
    record, cids = _resolve_state(node, workspace, fid)
    if record is None:
        return None
    if record["have"] < record["total"]:
        return record["name"], None
    return record["name"], b"".join(
        _payloads(node, workspace, record, cids))


CLI = {
    "content.file.abandon_upload": abandon_upload,
    "content.file.collect_upload": collect_upload,
    "content.file.list": files,
    "content.file.resume_upload": resume_upload,
    "content.file.save": save,
    "content.file.send": send,
    "content.file.upload": upload,
    "content.file.uploads": uploads,
}
