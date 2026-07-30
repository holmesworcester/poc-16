"""facts/content/chunk.py — the signed name of one self-proving Bao slice."""
from core import bao
from core.fact import Fact, Need
from core.suppression import ANCESTOR, PARENT, selector_markers
from .._policy import (
    Ancestor,
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
        Ancestor("file", "member"),
    ),
    direct_targets=DELETE_SELF,
    owner_edge="member",
)


# SHAPE
def chunk(
        workspace, pk, channel, root, index, count, cid, ts,
        file_fid, member_fid):
    return Fact(
        TAG, ts,
        author_selectors(
            POLICY,
            {"file": file_fid, "file/member": member_fid},
        ) + [["ref", "file", file_fid]],
        {"pk": pk, "chan": channel, "root": root,
         "i": index, "n": count, "cid": cid},
        workspace,
    )


# NEEDS
def needs(f):
    """Author and membership; the descriptor is the explicit ``file`` ref."""
    body = f.body
    pk = body.get("pk", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk),
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
        ancestors = [
            marker[3] for marker in selector_markers(f)
            if marker[1] == ANCESTOR and marker[2] == "file/member"
        ]
        return len(parents) == len(ancestors) == 1 and f == chunk(
            f.ws, body["pk"], body["chan"], body["root"],
            body["i"], body["n"], body["cid"], f.ts,
            parents[0], ancestors[0])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


def blob_refs(f):
    return (f.body.get("cid"),)


# COMMANDS
def author(
        workspace, secret, public, channel, root, index, count, cid, ts,
        file_fid, member_fid):
    item = chunk(
        workspace, public, channel, root, index, count, cid, ts,
        file_fid, member_fid)
    return item, signature.signature(secret, public, item, ts)


# QUERIES — chunks surface only through their descriptor's progress.
