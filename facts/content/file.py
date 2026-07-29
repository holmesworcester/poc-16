"""facts/content/file.py — a member-signed Bao-rooted attachment descriptor."""
import os
import tempfile

from core import bao
from core.crypto import h
from core.fact import Fact, Need
from core.suppression import PARENT, selector_markers
from .._policy import (
    DELETE_SELF,
    FamilyPolicy,
    Parent,
    Self,
    author_selectors,
)
from .._commands import offer_source
from ..auth import signature
from . import chunk as chunkfam

TAG = "file_bao"
POLICY = FamilyPolicy(
    suppression=(Self(), Parent("member")),
    direct_targets=DELETE_SELF,
    owner_edge="member",
    authorization_guards=("member",),
)
WIDTH = bao.WIDTH
MAX_FILE_BYTES = bao.MAX_FILE_BYTES
MAX_NAME = 255
ENCODING = "clear-v1"


# SHAPE
def file(pk, channel, name, size, root, count, ts, member_fid):
    return Fact(
        TAG, ts,
        author_selectors(POLICY, {"member": member_fid}) + [
            ["offer", "file", root, pk],
            ["offer", "slices", root, str(count)],
        ],
        {"pk": pk, "chan": channel, "name": name, "size": size,
         "root": root, "width": WIDTH, "n": count, "enc": ENCODING},
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
            body["pk"], body["chan"], body["name"], body["size"],
            body["root"], body["n"], f.ts, parents[0])
    except Exception:
        return False


# MODE
DURABLE = True


# COMMANDS
def send(node, workspace, channel, path, name=None, ts=None):
    """Prove every slice locally, spill it, then publish one closed pile."""
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
    store = node.store(workspace)
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
            store.put_if_absent("obj/" + cid, blob)
            cids.append(cid)
        if os.path.getsize(source) != size:
            raise ValueError("file changed while it was being proved")

    descriptor = file(
        public, channel, label, size, root, count, timestamp, member)
    signed = signature.signature(
        secret, public, descriptor, timestamp)
    news = [signed, descriptor]
    deps = {signed.fid: [], descriptor.fid: [signed.fid, member]}
    for index, cid in enumerate(cids):
        item, item_signature = chunkfam.author(
            secret, public, channel, root, index, count, cid, timestamp,
            descriptor.fid, member)
        news += [item_signature, item]
        deps[item_signature.fid] = []
        deps[item.fid] = [item_signature.fid, member, descriptor.fid]
    node.ingest_new(workspace, news, deps)
    return descriptor.fid


def save(node, workspace, selector, out_path):
    """Re-verify every slice, then atomically replace the requested path."""
    record, cids = _resolve_state(node, workspace, selector)
    if record is None:
        raise ValueError("no such file")
    if record["have"] < record["total"]:
        raise ValueError(
            f"file incomplete: have {record['have']}/{record['total']} slices")
    store = node.store(workspace)
    parts = (
        bao.verify(
            store.get("obj/" + cids[index]),
            record["root"], index, record["size"])
        for index in range(record["total"])
    )
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
def _file_state(node, workspace):
    """Decode descriptors and verify resident Bao slices on demand."""
    with node.lock:
        descriptors = {
            fact.fid: fact for fact in node.by_type(workspace, TAG)
        }
        cids = {fid: {} for fid in descriptors}
        store = node.store(workspace)
        for fact in node.by_type(workspace, chunkfam.TAG):
            descriptor = descriptors.get(dict(fact.refs()).get("file"))
            if descriptor is None:
                continue
            body, parent = fact.body, descriptor.body
            if body["root"] != parent["root"] \
                    or body["n"] != parent["n"] \
                    or body["pk"] != parent["pk"] \
                    or body["chan"] != parent["chan"]:
                continue
            raw = store.get("obj/" + body["cid"])
            try:
                if raw is None or len(raw) > bao.MAX_PROOF_BYTES \
                        or h(raw) != body["cid"]:
                    continue
                bao.verify(raw, parent["root"], body["i"], parent["size"])
            except Exception:
                continue
            cids[descriptor.fid].setdefault(body["i"], body["cid"])

        records = []
        for fact in descriptors.values():
            body = fact.body
            have = len(cids[fact.fid])
            total = body["n"]
            records.append({
                "fid": fact.fid,
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
                "ts": fact.ts,
            })
    return (
        sorted(records, key=lambda row: (row["ts"], row["fid"])),
        cids,
    )


def files(node, workspace):
    return _file_state(node, workspace)[0]


def _resolve_state(node, workspace, selector):
    listing, cids = _file_state(node, workspace)
    for record in listing:
        if selector in (record["fid"], record["root"], record["blob"]):
            return record, cids[record["fid"]]
    matches = [
        record for record in listing
        if record["fid"].startswith(selector)
    ]
    record = matches[0] if len(matches) == 1 else None
    return (record, cids[record["fid"]]) if record else (None, {})


def resolve(node, workspace, selector):
    return _resolve_state(node, workspace, selector)[0]


def bytes_for(node, workspace, fid):
    record, cids = _resolve_state(node, workspace, fid)
    if record is None:
        return None
    if record["have"] < record["total"]:
        return record["name"], None
    store = node.store(workspace)
    output = bytearray()
    for index in range(record["total"]):
        output += bao.verify(
            store.get("obj/" + cids[index]),
            record["root"], index, record["size"])
    return record["name"], bytes(output)


CLI = {"content.file.send": send, "content.file.save": save,
       "content.file.list": files}
