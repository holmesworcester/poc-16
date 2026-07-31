"""facts/content/file.py — a signed Bao descriptor with inline slice facts."""
import os
import tempfile

from core.fact_index import REF_INDEX, TYPE_INDEX
from core.fact import Fact, Need
from core.shape import valid_fid
from .._policy import DELETE_SELF, FamilyPolicy, Self, author_selectors
from .._commands import direct_upload, member_source
from ..auth import signature
from .. import _bao as bao
from . import file_slice as slices


TAG = "file_bao"
POLICY = FamilyPolicy(
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_field="owner",
)
WIDTH = bao.WIDTH
MAX_FILE_BYTES = bao.MAX_FILE_BYTES
MAX_NAME = 255
ENCODING = "bao-inline-v1"


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
        {"pk": pk, "owner": owner, "chan": channel, "name": name,
         "size": size, "root": root, "width": WIDTH, "n": count,
         "enc": ENCODING},
        workspace,
    )


# NEEDS
def needs(fact):
    pk = fact.body.get("pk", "")
    owner = fact.body.get("owner", "")
    return (
        Need("author", "author", fact.fid, pk),
        Need("member", "member", pk, owner),
    )


# VALIDATE
def validate(fact, _ctx):
    try:
        body = fact.body
        if set(body) != {
                "pk", "owner", "chan", "name", "size", "root", "width",
                "n", "enc"}:
            return False
        if not all(isinstance(body[key], str) for key in (
                "pk", "owner", "chan", "name", "root", "enc")) \
                or not all(type(body[key]) is int for key in (
                    "size", "n", "width")):
            return False
        if body["enc"] != ENCODING or body["width"] != WIDTH \
                or not 0 <= body["size"] <= MAX_FILE_BYTES \
                or not body["name"] \
                or len(body["name"].encode()) > MAX_NAME \
                or len(body["root"]) != 64 \
                or any(c not in "0123456789abcdef" for c in body["root"]) \
                or body["n"] != bao.geometry(body["size"]):
            return False
        return fact == file(
            fact.ws, body["pk"], body["chan"], body["name"], body["size"],
            body["root"], body["n"], fact.ts, body["owner"])
    except (KeyError, TypeError, UnicodeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def _stable(stat):
    return (
        stat.st_dev, stat.st_ino, stat.st_size,
        stat.st_mtime_ns, stat.st_ctime_ns,
    )


def _author(node, workspace, channel, path, name, ts, emit):
    """Prove one stable source and emit descriptor-first closed piles.

    Every call to ``emit(raw, fid)`` receives one independently valid ordinary
    pile: first the signed descriptor closure, then exactly one unsigned slice
    plus that same closure. No detached completion channel exists.
    """
    native = node.attachment_io()
    timestamp = node.now_ms() if ts is None else ts
    source = os.path.abspath(os.fspath(path))
    if not os.path.isfile(source):
        raise ValueError("file path is not a regular file")
    initial = os.stat(source)
    size = initial.st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds the {MAX_FILE_BYTES >> 30} GiB limit")
    label = name or os.path.basename(source)
    if not label or len(label.encode()) > MAX_NAME:
        raise ValueError("file name is empty or too long")

    secret, public = node.identity(workspace)
    member, owner = member_source(node, workspace, public)
    if member is None:
        raise ValueError("publishing identity is not a workspace member")
    sender = node.sender(workspace)
    with tempfile.TemporaryDirectory(prefix="tinyp2p-bao-") as scratch:
        outboard = os.path.join(scratch, "outboard")
        root = native.prepare(source, outboard)
        count = bao.geometry(size)
        descriptor = file(
            workspace, public, channel, label, size, root, count, timestamp,
            owner)
        signed = signature.signature(secret, public, descriptor, timestamp)
        descriptor_closed = sender.close(
            [signed, descriptor],
            {signed.fid: [], descriptor.fid: [signed.fid, member]},
        )
        emit(sender.pack(descriptor_closed), descriptor.fid)

        for index in range(count):
            proof = native.proof(source, outboard, index, size)
            if len(bao.verify(
                    proof, root, index, size)) != bao.span(index, size)[1]:
                raise RuntimeError("Bao returned a short slice")
            item = slices.file_slice(
                workspace, descriptor.fid, index, proof, timestamp)
            emit(sender.pack((*descriptor_closed, item)), item.fid)

        if _stable(os.stat(source)) != _stable(initial):
            raise ValueError("file changed while it was being proved")
    return descriptor


def send(node, workspace, channel, path, name=None, ts=None):
    """Publish the descriptor and each inline range through the one Applier."""
    def receive(raw, expected):
        node.receive_pile(workspace, node.member_for(workspace), raw)
        if node.fact_of(workspace, expected) is None:
            raise ValueError(f"authored fact was not admitted: {expected}")

    return _author(
        node, workspace, channel, path, name, ts, receive).fid


def upload(
        node, workspace, channel, path, broker_url, provider_origin,
        name=None, ts=None):
    """Direct-upload each ordinary fact-only pile in descriptor-first order."""
    results = []

    def deliver(raw, _expected):
        builder = node.start_upload(workspace)
        try:
            source = builder.finish(raw)
        except BaseException:
            builder.discard()
            raise
        results.append(direct_upload(
            node, workspace, source, broker_url, provider_origin))

    descriptor = _author(
        node, workspace, channel, path, name, ts, deliver)
    answer = {
        "fid": descriptor.fid,
        "piles": len(results),
        "sessions": [result["session"] for result in results],
        "uploads": [result["upload"] for result in results],
    }
    if len(results) == 1:
        answer.update({
            "session": results[0]["session"],
            "upload": results[0]["upload"],
        })
    return answer


def resume_upload(
        node, workspace, upload_id, broker_url, provider_origin):
    if not valid_fid(upload_id):
        raise ValueError("upload id")
    return direct_upload(
        node, workspace, node.load_upload(upload_id),
        broker_url, provider_origin)


def uploads(node, workspace, cursor=None):
    if cursor is not None and not valid_fid(cursor):
        raise ValueError("upload cursor")
    return node.upload_status(workspace, cursor)


def abandon_upload(node, workspace, upload_id):
    if not valid_fid(upload_id):
        raise ValueError("upload id")
    return node.abandon_upload(workspace, upload_id)


def collect_upload(node, workspace, upload_id):
    if not valid_fid(upload_id):
        raise ValueError("upload id")
    return node.collect_upload(workspace, upload_id)


# QUERIES
def _record(descriptor, have):
    body, total = descriptor.body, descriptor.body["n"]
    return {
        "fid": descriptor.fid,
        "chan": body["chan"],
        "name": body["name"],
        "size": body["size"],
        "root": body["root"],
        "blob": None,
        "encoding": ENCODING,
        "total": total,
        "have": have,
        "complete": have == total,
        "pct": 100 if total == 0 else have * 100 // total,
        "ts": descriptor.ts,
    }


def _states(node, workspace, selector=None):
    """Pin only the selected descriptor's proof facts; lists count indexes."""
    with node.lock:
        node._sync_sql(workspace)
        admitted = node.sql(workspace)

        def select(kind, k0=None, k1=None, **filters):
            return tuple(
                fact for fact in admitted.indexed(kind, k0, k1, **filters)
                if not admitted.suppresses(fact)
            )

        if selector is None:
            descriptors = select(TYPE_INDEX, TAG)
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
            chosen = min(
                direct.values(), key=lambda fact: (fact.ts, fact.fid)
            ) if direct else (
                prefixed[0] if len(prefixed) == 1 else None)
            descriptors = () if chosen is None else (chosen,)

        out = []
        for descriptor in descriptors:
            if selector is None:
                have = admitted.count_indexed(
                    REF_INDEX, "file", descriptor.fid,
                    source_type=slices.TAG)
                by_index = None
            else:
                candidates = select(
                    REF_INDEX, "file", descriptor.fid,
                    source_type=slices.TAG)
                by_index = {}
                for item in candidates:
                    by_index.setdefault(slices.index_of(item), item)
                have = len(by_index)
            out.append((_record(descriptor, have), descriptor, by_index))
    return sorted(out, key=lambda item: (
        item[0]["ts"], item[0]["fid"]))


def files(node, workspace):
    return [record for record, _descriptor, _slices in _states(
        node, workspace)]


def _resolve_state(node, workspace, selector):
    states = _states(node, workspace, selector)
    return states[0] if states else (None, None, None)


def _payloads(record, descriptor, by_index):
    return (
        slices.payload(by_index[index], descriptor)
        for index in range(record["total"])
    )


def resolve(node, workspace, selector):
    return _resolve_state(node, workspace, selector)[0]


def bytes_for(node, workspace, fid):
    record, descriptor, by_index = _resolve_state(node, workspace, fid)
    if record is None:
        return None
    if not record["complete"]:
        return record["name"], None
    return record["name"], b"".join(
        _payloads(record, descriptor, by_index))


def save(node, workspace, selector, out_path):
    """Verify one slice at a time, then atomically replace the target path."""
    record, descriptor, by_index = _resolve_state(
        node, workspace, selector)
    if record is None:
        raise ValueError("no such file")
    if not record["complete"]:
        raise ValueError(
            f"file incomplete: have {record['have']}/{record['total']} slices")
    target = os.path.abspath(os.fspath(out_path))
    handle, temporary = tempfile.mkstemp(
        prefix=".tinyp2p-", dir=os.path.dirname(target) or ".")
    try:
        written = 0
        with os.fdopen(handle, "wb") as output:
            for payload in _payloads(record, descriptor, by_index):
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
    return {
        "fid": record["fid"], "name": record["name"],
        "bytes": written, "path": target,
    }


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
