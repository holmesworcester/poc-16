"""facts/content/chunk.py — the signed name of one self-proving Bao slice."""
from core import bao
from core.fact import Fact, Need
from core.suppression import PARENT, selector_markers
from .._policy import (
    DELETE_SELF,
    FamilyPolicy,
    Parent,
    Self,
    author_selectors,
)
from ..auth import signature

TAG = "chunk"
POLICY = FamilyPolicy(
    suppression=(
        Self(),
        Parent("file"),
    ),
    direct_targets=DELETE_SELF,
    owner_field="owner",
)


# SHAPE
def chunk(
        workspace, pk, channel, root, index, count, cid, ts,
        file_fid, owner=None):
    owner = pk if owner is None else owner
    return Fact(
        TAG, ts,
        author_selectors(
            POLICY,
            {"file": file_fid},
        ) + [["ref", "file", file_fid]],
        {"pk": pk, "owner": owner, "chan": channel, "root": root,
         "i": index, "n": count, "cid": cid},
        workspace,
    )


# NEEDS
def needs(f):
    """Author and membership; the descriptor is the explicit ``file`` ref."""
    body = f.body
    pk = body.get("pk", "")
    owner = body.get("owner", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk, owner),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        if set(body) != {
                "pk", "owner", "chan", "root", "i", "n", "cid"}:
            return False
        if not all(isinstance(body[key], str)
                   for key in ("pk", "owner", "chan", "root", "cid")):
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
        ((ref_role, file_fid),) = f.refs()
        if ref_role != "file":
            return False
        if ctx.offers_from(file_fid, "file") != [
                (body["root"], body["pk"])]:
            return False
        if ctx.offers_from(file_fid, "slices") != [
                (body["root"], str(body["n"]))]:
            return False
        parents = [
            marker[3] for marker in selector_markers(f)
            if marker[1] == PARENT and marker[2] == "file"
        ]
        return len(parents) == 1 and f == chunk(
            f.ws, body["pk"], body["chan"], body["root"],
            body["i"], body["n"], body["cid"], f.ts,
            parents[0], body["owner"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


def blob_refs(f):
    return (f.body.get("cid"),)


# COMMANDS
def author(
        workspace, secret, public, channel, root, index, count, cid, ts,
        file_fid, owner=None):
    item = chunk(
        workspace, public, channel, root, index, count, cid, ts,
        file_fid, owner)
    return item, signature.signature(secret, public, item, ts)


# QUERIES — chunks surface only through their descriptor's progress.
