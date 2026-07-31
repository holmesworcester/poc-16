"""facts/content/file_slice.py — one self-authenticating Bao file range.

The ordinary fact body carries the canonical Bao proof inline. Its exact
``file`` ref supplies the descriptor root and geometry, and the family handler
verifies the proof during the same database-free kernel admission as every
other fact. No signature or detached object is needed: the signed descriptor
and its Bao root are the authority.
"""
import base64

from core.fact import Fact
from .. import _bao as bao
from .._policy import FamilyPolicy, Parent, author_selectors


TAG = "file_slice"
POLICY = FamilyPolicy(suppression=(Parent("file"),))


# SHAPE
def file_slice(workspace, file_fid, index, proof, ts):
    """Construct the one canonical inline proof for ``file_fid[index]``."""
    if not isinstance(proof, bytes):
        raise ValueError("Bao proof bytes")
    return Fact(
        TAG,
        ts,
        author_selectors(POLICY, {"file": file_fid})
        + [["ref", "file", file_fid]],
        {
            "i": index,
            "proof": base64.b64encode(proof).decode("ascii"),
        },
        workspace,
    )


# NEEDS
def needs(_fact):
    """The exact descriptor ref is this slice's complete dependency set."""
    return ()


def proof_bytes(fact):
    """Strictly decode the bounded canonical proof carried by ``fact``."""
    encoded = fact.body.get("proof")
    if not isinstance(encoded, str) \
            or len(encoded) > bao.MAX_PROOF_BASE64_BYTES:
        raise ValueError("Bao proof encoding")
    try:
        proof = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError) as error:
        raise ValueError("Bao proof encoding") from error
    if not 8 <= len(proof) <= bao.MAX_PROOF_BYTES \
            or base64.b64encode(proof).decode("ascii") != encoded:
        raise ValueError("Bao proof bounds")
    return proof


def index_of(fact):
    index = fact.body.get("i")
    if type(index) is not int:
        raise ValueError("file slice index")
    return index


def payload(fact, descriptor):
    """Return this fact's bytes after checking the descriptor's Bao root."""
    index = index_of(fact)
    if descriptor.t != "file_bao" \
            or fact.ws != descriptor.ws \
            or fact.refs() != [("file", descriptor.fid)] \
            or fact.ts != descriptor.ts \
            or not 0 <= index < descriptor.body["n"]:
        raise ValueError("file slice descriptor")
    return bao.verify(
        proof_bytes(fact), descriptor.body["root"], index,
        descriptor.body["size"])


# VALIDATE
def validate(fact, ctx):
    try:
        if set(fact.body) != {"i", "proof"}:
            return False
        ((role, file_fid),) = fact.refs()
        if role != "file":
            return False
        descriptor = ctx.fact_of(file_fid)
        proof = proof_bytes(fact)
        index = index_of(fact)
        if descriptor is None or descriptor.t != "file_bao" \
                or descriptor.ws != fact.ws \
                or fact.ts != descriptor.ts \
                or not 0 <= index < descriptor.body["n"]:
            return False
        if len(bao.verify(
                proof, descriptor.body["root"], index,
                descriptor.body["size"])) != bao.span(
                    index, descriptor.body["size"])[1]:
            return False
        return fact == file_slice(
            fact.ws, file_fid, index, proof, fact.ts)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
# Slice facts have no independent human surface; file queries assemble them.
CLI = {}


# QUERIES — slices surface only through their descriptor.
