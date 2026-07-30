"""facts/content/file.py — a member-signed Bao-rooted attachment descriptor."""
import os
import tempfile

from core import bao
from core.fact_index import REF_INDEX, TYPE_INDEX
from core.crypto import h
from core.fact import Fact, Need
from core.shape import valid_fid
from core.suppression import PARENT, selector_markers
from .._policy import (
    DELETE_SELF,
    FamilyPolicy,
    Parent,
    Self,
    author_selectors,
)
from .._commands import offer_source, upload_builder, upload_source
from ..auth import signature
from . import chunk as chunkfam

TAG = "file_bao"
POLICY = FamilyPolicy(
    suppression=(Self(), Parent("member")),
    direct_targets=DELETE_SELF,
    owner_edge="member",
)
WIDTH = bao.WIDTH
MAX_FILE_BYTES = bao.MAX_FILE_BYTES
MAX_NAME = 255
ENCODING = "clear-v1"


# SHAPE
def file(workspace, pk, channel, name, size, root, count, ts, member_fid):
    return Fact(
        TAG, ts,
        author_selectors(POLICY, {"member": member_fid}) + [
            ["offer", "file", root, pk],
            ["offer", "slices", root, str(count)],
        ],
        {"pk": pk, "chan": channel, "name": name, "size": size,
         "root": root, "width": WIDTH, "n": count, "enc": ENCODING},
        workspace,
    )


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {
                "pk", "chan", "name", "size", "root", "width", "n", "enc"}:
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
        if len(body["root"]) != 64 or not all(
                char in "0123456789abcdef" for char in body["root"]):
            return False
        if body["n"] != bao.geometry(body["size"], body["width"]):
            return False
        parents = [
            marker[3] for marker in selector_markers(f)
            if marker[1] == PARENT and marker[2] == "member"
        ]
        return len(parents) == 1 and f == file(
            f.ws, body["pk"], body["chan"], body["name"], body["size"],
            body["root"], body["n"], f.ts, parents[0])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def _prepare(node, workspace, channel, path, name, ts, put_object):
    """Author one file/chunk fact set; choose its detached object sink."""
    from core.node import now_ms

    timestamp = now_ms() if ts is None else ts
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
    member = offer_source(node, workspace, "member", public)
    if member is None:
        raise ValueError("publishing identity is not a workspace member")
    with tempfile.TemporaryDirectory(prefix="tinyp2p-bao-") as scratch:
        outboard = os.path.join(scratch, "outboard")
        root = bao.prepare(source, outboard)
        count, cids = bao.geometry(size), []
        for index in range(count):
            blob = bao.proof(source, outboard, index, size)
            payload = bao.verify(blob, root, index, size)
            if len(payload) != bao.span(index, size)[1]:
                raise RuntimeError("Bao returned a short slice")
            cid = h(blob)
            put_object(cid, blob)
            cids.append(cid)
        if os.path.getsize(source) != size:
            raise ValueError("file changed while it was being proved")

    descriptor = file(
        workspace, public, channel, label, size, root, count, timestamp,
        member)
    signed = signature.signature(
        secret, public, descriptor, timestamp)
    news = [signed, descriptor]
    deps = {signed.fid: [], descriptor.fid: [signed.fid, member]}
    for index, cid in enumerate(cids):
        item, item_signature = chunkfam.author(
            workspace, secret, public, channel, root, index, count, cid,
            timestamp,
            descriptor.fid, member)
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
    builder = upload_builder(node, workspace)

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
    result = upload_source(
        node, workspace, source, broker_url, provider_origin)
    return {"fid": descriptor.fid, **result}


def resume_upload(
        node, workspace, upload_id, broker_url, provider_origin):
    """Resume any retained direct-upload source by its content id."""
    from deploy.upload_journal import UploadSource

    if not valid_fid(upload_id):
        raise ValueError("upload id")
    source = UploadSource.load(
        os.path.join(node.dir, "uploads", upload_id))
    return upload_source(
        node, workspace, source, broker_url, provider_origin)


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
def _state(store, descriptor, chunks):
    """Verify only one descriptor's selected Bao slices."""
    body, cids = descriptor.body, {}
    for fact in chunks:
        child = fact.body
        if child["root"] != body["root"] \
                or child["n"] != body["n"] \
                or child["pk"] != body["pk"] \
                or child["chan"] != body["chan"]:
            continue
        try:
            raw = store.get_bounded(
                "obj/" + child["cid"], bao.MAX_PROOF_BYTES)
            if raw is None or h(raw) != child["cid"]:
                continue
            bao.verify(raw, body["root"], child["i"], body["size"])
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
    """Pin one catalog snapshot, then verify its immutable bytes unlocked."""
    with node.lock:
        node._sync_index(workspace)
        admitted = node.catalog(workspace)
        def select(kind, k0=None, k1=None, **filters):
            return tuple(
                fact for _, fact in admitted.indexed(
                    kind, k0, k1, **filters)
                if not node.suppressed(workspace, fact)
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
        store = node.store(workspace)

    by_file = {fact.fid: [] for fact in descriptors}
    for fact in chunks:
        parent = dict(fact.refs()).get("file")
        if parent in by_file:
            by_file[parent].append(fact)
    return sorted([
        _state(store, descriptor, by_file[descriptor.fid])
        for descriptor in descriptors
    ], key=lambda item: (item[0]["ts"], item[0]["fid"]))


def files(node, workspace):
    return [record for record, _ in _states(node, workspace)]


def _resolve_state(node, workspace, selector):
    states = _states(node, workspace, selector)
    return states[0] if states else (None, {})


def _payloads(node, workspace, record, cids):
    store = node.store(workspace)
    return (
        bao.verify(
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
    "content.file.list": files,
    "content.file.resume_upload": resume_upload,
    "content.file.save": save,
    "content.file.send": send,
    "content.file.upload": upload,
}
